// SPDX-License-Identifier: MIT OR Apache-2.0

//! Certificate policy processing (RFC 5280 §6.1.2 to §6.1.5).
//!
//! The valid policy tree is kept as an arena of nodes with parent indices.
//! Pruned nodes are marked dead rather than removed, so indices stay stable.
//! Each node also records its *authority* policy: the policy at the top of the
//! mapping chain it was reached through. The authorities-constrained policy set is
//! the set of authorities at the end-entity level (RFC 5280 §6.1.5 (g)).
//! [`validate_policies`] runs over the path from the trust anchor down to the
//! end-entity, and fails when the path requires an explicit policy that the
//! end-entity does not satisfy.

use alloc::vec;
use alloc::vec::Vec;

use crate::certificate::Certificate;
use crate::chain::PathError;

/// `anyPolicy` (2.5.29.32.0), as DER content octets.
const ANY_POLICY: &[u8] = &[0x55, 0x1d, 0x20, 0x00];

/// The policy inputs of RFC 5280 §6.1.1 (c) to (f).
pub(crate) struct PolicyInputs<'b> {
    /// `initial-policy-set`, as OID content octets. Empty means `anyPolicy`.
    pub initial_policy_set: &'b [&'b [u8]],
    /// `initial-explicit-policy`.
    pub explicit_policy: bool,
    /// `initial-policy-mapping-inhibit`.
    pub policy_mapping_inhibit: bool,
    /// `initial-inhibit-any-policy`.
    pub inhibit_any_policy: bool,
}

struct Node {
    /// The level of the certificate that created this node (0 for the root).
    depth: usize,
    /// `valid_policy`, as OID content octets.
    policy: Vec<u8>,
    /// `expected_policy_set`, as OID content octets.
    expected: Vec<Vec<u8>>,
    /// The authority policy at the top of this node's mapping chain.
    authority: Vec<u8>,
    parent: Option<usize>,
    alive: bool,
}

struct Tree {
    nodes: Vec<Node>,
    /// Policies that a mapping at `depth` maps away from a concrete policy one level
    /// up, as `(depth, policy)`. Such a policy cannot be reached through anyPolicy at
    /// the next level (PKITS 4.10.10).
    mapped_away: Vec<(usize, Vec<u8>)>,
}

impl Tree {
    /// RFC 5280 §6.1.2 (a): a single `anyPolicy` root.
    fn new() -> Self {
        Tree {
            mapped_away: Vec::new(),
            nodes: vec![Node {
                depth: 0,
                policy: ANY_POLICY.to_vec(),
                expected: vec![ANY_POLICY.to_vec()],
                authority: ANY_POLICY.to_vec(),
                parent: None,
                alive: true,
            }],
        }
    }

    /// The tree is null when no node survives.
    fn is_null(&self) -> bool {
        !self.nodes.iter().any(|n| n.alive)
    }

    fn at_depth(&self, depth: usize) -> Vec<usize> {
        (0..self.nodes.len())
            .filter(|&i| self.nodes[i].alive && self.nodes[i].depth == depth)
            .collect()
    }

    fn has_child(&self, parent: usize) -> bool {
        self.nodes.iter().any(|n| n.alive && n.parent == Some(parent))
    }

    /// Whether `parent` already has a live child for `policy` created at `depth`.
    fn has_child_with_policy(&self, parent: usize, policy: &[u8], depth: usize) -> bool {
        self.nodes
            .iter()
            .any(|n| n.alive && n.parent == Some(parent) && n.depth == depth && n.policy == policy)
    }

    fn add_child(
        &mut self,
        parent: usize,
        depth: usize,
        policy: &[u8],
        expected: Vec<Vec<u8>>,
        authority: Vec<u8>,
    ) -> usize {
        self.nodes.push(Node {
            depth,
            policy: policy.to_vec(),
            expected,
            authority,
            parent: Some(parent),
            alive: true,
        });
        self.nodes.len() - 1
    }

    /// RFC 5280 §6.1.3 (d)(4): remove nodes above `depth` that no longer have
    /// children, repeating until nothing changes.
    fn prune_above(&mut self, depth: usize) {
        loop {
            let leaves: Vec<usize> = (0..self.nodes.len())
                .filter(|&i| {
                    self.nodes[i].alive && self.nodes[i].depth < depth && !self.has_child(i)
                })
                .collect();
            if leaves.is_empty() {
                return;
            }
            for i in leaves {
                self.nodes[i].alive = false;
            }
        }
    }

    fn kill_all(&mut self) {
        for n in &mut self.nodes {
            n.alive = false;
        }
    }
}

/// Run RFC 5280 §6.1 policy processing over `certs`, ordered from the trust anchor
/// down to the end-entity.
pub(crate) fn validate_policies(
    certs: &[&Certificate<'_>],
    inputs: &PolicyInputs<'_>,
) -> Result<(), PathError> {
    let n = certs.len();
    let mut tree = Tree::new();

    // RFC 5280 §6.1.2 (g) to (i). Each counter is the number of certificates
    // that may still follow; 0 means "in effect now".
    let mut explicit: u64 = if inputs.explicit_policy { 0 } else { n as u64 + 1 };
    let mut mapping_inhibit: u64 = if inputs.policy_mapping_inhibit { 0 } else { n as u64 + 1 };
    let mut inhibit_any: u64 = if inputs.inhibit_any_policy { 0 } else { n as u64 + 1 };

    for (idx, cert) in certs.iter().enumerate() {
        let depth = idx + 1;
        let is_end_entity = depth == n;
        let self_issued = cert.tbs.issuer.matches(&cert.tbs.subject);

        // RFC 5280 §6.1.3 (d): process this certificate's policies. anyPolicy in
        // the certificate is honoured only when inhibitAnyPolicy is not in effect.
        // RFC 5280 §6.1.3 (d)(2): anyPolicy is honoured when inhibit_anyPolicy is
        // not in effect, or when a self-issued certificate precedes the end-entity.
        let any_allowed = inhibit_any > 0 || (!is_end_entity && self_issued);
        apply_certificate_policies(&mut tree, cert, depth, any_allowed)?;

        if is_end_entity {
            continue;
        }

        // RFC 5280 §6.1.4 (b): policy mappings, while mapping is not inhibited.
        if let Some(pm) =
            cert.tbs.extensions.policy_mappings().map_err(|_| PathError::PolicyViolation)?
        {
            // Once mapping is forbidden outright (initial-policy-mapping-inhibit, or an
            // inhibitPolicyMapping of 0), a path that still carries policy mappings is
            // rejected rather than having them silently ignored (PKITS 4.10.2, 4.11.1).
            if mapping_inhibit > 0 {
                apply_mappings(&mut tree, depth, &pm)?;
            } else {
                // RFC 5280 §6.1.4 (b)(2): with policy mapping inhibited, the
                // mapped issuer policies are deleted rather than mapped.
                delete_mapped_policies(&mut tree, depth, &pm)?;
            }
        }

        let constraints =
            cert.tbs.extensions.policy_constraints().map_err(|_| PathError::PolicyViolation)?;
        // RFC 5280 §6.1.4 (h): a certificate that is not self-issued uses up one
        // certificate of each counter.
        if !self_issued {
            explicit = explicit.saturating_sub(1);
            mapping_inhibit = mapping_inhibit.saturating_sub(1);
            inhibit_any = inhibit_any.saturating_sub(1);
        }

        // RFC 5280 §6.1.4 (i) and (j): the certificate's own constraints.
        if let Some(v) = constraints.and_then(|pc| pc.require_explicit_policy) {
            explicit = explicit.min(v);
        }
        if let Some(v) = constraints.and_then(|pc| pc.inhibit_policy_mapping) {
            mapping_inhibit = mapping_inhibit.min(v);
        }
        if let Some(ia) =
            cert.tbs.extensions.inhibit_any_policy().map_err(|_| PathError::PolicyViolation)?
        {
            inhibit_any = inhibit_any.min(ia.skip_certs);
        }
    }

    // RFC 5280 §6.1.5 (a): the wrap-up decrements explicit_policy once more.
    explicit = explicit.saturating_sub(1);
    // RFC 5280 §6.1.5 (b): the end-entity's own requireExplicitPolicy of 0 forces
    // explicit policy.
    if let Some(ee) = certs.last() {
        let ee_constraints =
            ee.tbs.extensions.policy_constraints().map_err(|_| PathError::PolicyViolation)?;
        if ee_constraints.and_then(|pc| pc.require_explicit_policy) == Some(0) {
            explicit = 0;
        }
    }

    // RFC 5280 §6.1.5 (a) and (b). When explicit policy is required, the tree must be
    // non-null, and some authority at the end-entity level must match the initial
    // policy set (or be anyPolicy).
    if explicit == 0 {
        if tree.is_null() {
            return Err(PathError::PolicyViolation);
        }
        if !inputs.initial_policy_set.is_empty() {
            let covered = tree.at_depth(n).iter().any(|&l| {
                let authority = &tree.nodes[l].authority;
                authority == ANY_POLICY
                    || inputs.initial_policy_set.iter().any(|init| *init == authority.as_slice())
            });
            if !covered {
                return Err(PathError::PolicyViolation);
            }
        }
    }
    Ok(())
}

/// RFC 5280 §6.1.3 (d)(1): create nodes for the policies asserted by `cert`.
fn apply_certificate_policies(
    tree: &mut Tree,
    cert: &Certificate<'_>,
    depth: usize,
    any_allowed: bool,
) -> Result<(), PathError> {
    if tree.is_null() {
        return Ok(());
    }
    let Some(cp) =
        cert.tbs.extensions.certificate_policies().map_err(|_| PathError::PolicyViolation)?
    else {
        // RFC 5280 §6.1.3 (d)(2): no certificatePolicies means the tree is null.
        tree.kill_all();
        return Ok(());
    };

    let prev = tree.at_depth(depth - 1);

    for info in &cp.policies {
        let policy = info.policy_id.as_bytes();
        if policy == ANY_POLICY {
            continue;
        }
        // The P-parent: a node whose expected set contains P, else the anyPolicy node.
        let mut parents: Vec<usize> = prev
            .iter()
            .copied()
            .filter(|&i| tree.nodes[i].expected.iter().any(|e| e == policy))
            .collect();
        let mapped_away = tree.mapped_away.iter().any(|(d, p)| *d + 1 == depth && p == policy);
        if parents.is_empty() && !mapped_away {
            parents =
                prev.iter().copied().filter(|&i| tree.nodes[i].policy == ANY_POLICY).collect();
        }
        for parent in parents {
            if !tree.has_child_with_policy(parent, policy, depth) {
                // Under anyPolicy, P is itself the authority. Under a specific policy,
                // the child keeps the authority its parent reached.
                let authority = if tree.nodes[parent].policy == ANY_POLICY {
                    policy.to_vec()
                } else {
                    tree.nodes[parent].authority.clone()
                };
                tree.add_child(parent, depth, policy, vec![policy.to_vec()], authority);
            }
        }
    }

    // RFC 5280 §6.1.3 (d)(1)(ii): an asserted anyPolicy carries anyPolicy nodes
    // down, whether or not specific policies from this certificate matched.
    let asserts_any = cp.policies.iter().any(|p| p.policy_id.as_bytes() == ANY_POLICY);
    if asserts_any && any_allowed {
        for parent in prev {
            if !tree.has_child_with_policy(parent, ANY_POLICY, depth) {
                let authority = tree.nodes[parent].authority.clone();
                tree.add_child(parent, depth, ANY_POLICY, vec![ANY_POLICY.to_vec()], authority);
            }
        }
    }

    tree.prune_above(depth);
    Ok(())
}

/// RFC 5280 §6.1.4 (b)(2): delete the depth-`depth` nodes whose valid policy is
/// a mapped issuer policy, then prune childless nodes above them.
fn delete_mapped_policies(
    tree: &mut Tree,
    depth: usize,
    pm: &crate::extensions::PolicyMappings<'_>,
) -> Result<(), PathError> {
    if tree.is_null() {
        return Ok(());
    }
    for m in &pm.mappings {
        let issuer = m.issuer_domain_policy.as_bytes();
        // RFC 5280 §6.1.4 (a): anyPolicy may not appear in a mapping.
        if issuer == ANY_POLICY || m.subject_domain_policy.as_bytes() == ANY_POLICY {
            return Err(PathError::PolicyViolation);
        }
        for i in tree.at_depth(depth) {
            if tree.nodes[i].policy == issuer {
                tree.nodes[i].alive = false;
            }
        }
    }
    tree.prune_above(depth);
    Ok(())
}

/// RFC 5280 §6.1.4 (b): apply the certificate's policy mappings to the nodes at
/// `depth`.
fn apply_mappings(
    tree: &mut Tree,
    depth: usize,
    pm: &crate::extensions::PolicyMappings<'_>,
) -> Result<(), PathError> {
    if tree.is_null() {
        return Ok(());
    }
    // Issuer policies whose expected set this certificate has already replaced.
    let mut replaced: Vec<&[u8]> = Vec::new();
    for m in &pm.mappings {
        let issuer = m.issuer_domain_policy.as_bytes();
        let subject = m.subject_domain_policy.as_bytes();
        // RFC 5280 §6.1.4 (b)(1): anyPolicy may not appear in a mapping.
        if issuer == ANY_POLICY || subject == ANY_POLICY {
            return Err(PathError::PolicyViolation);
        }
        let matching = tree
            .at_depth(depth)
            .into_iter()
            .filter(|&i| tree.nodes[i].policy == issuer)
            .collect::<Vec<_>>();
        if !matching.is_empty() {
            // RFC 5280 §6.1.4 (b)(1)(i): the node's expected set becomes the subject-domain
            // policies of this certificate's mappings for that issuer policy.
            let first = !replaced.contains(&issuer);
            if first {
                replaced.push(issuer);
            }
            for i in matching {
                let expected = &mut tree.nodes[i].expected;
                if first {
                    expected.clear();
                }
                if !expected.iter().any(|e| e == subject) {
                    expected.push(subject.to_vec());
                }
            }
        } else if let Some(any) =
            tree.at_depth(depth).into_iter().find(|&i| tree.nodes[i].policy == ANY_POLICY)
        {
            // A concrete issuer-level policy that is mapped here is no longer covered by
            // anyPolicy one level down (PKITS 4.10.10).
            if tree.at_depth(depth - 1).iter().any(|&i| tree.nodes[i].policy == issuer) {
                tree.mapped_away.push((depth, issuer.to_vec()));
            }
            // A policy the anyPolicy node introduces by mapping is its own authority.
            tree.add_child(any, depth, issuer, vec![subject.to_vec()], issuer.to_vec());
        }
    }
    Ok(())
}
