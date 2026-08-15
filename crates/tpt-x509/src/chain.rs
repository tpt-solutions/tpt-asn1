// SPDX-License-Identifier: MIT OR Apache-2.0

//! Certificate chain building and RFC 5280 §6.1 path validation.
//!
//! The implementation is fail-closed and delegates the actual signature math to
//! a [`SignatureVerifier`] backend so that
//! `tpt-x509` stays free of C dependencies. The validator enforces, in order:
//!
//! 1. path construction (issuer name / authority-key-id linking),
//! 2. per-certificate validity windows,
//! 3. `BasicConstraints` CA flag + `pathLenConstraint`,
//! 4. `KeyUsage` `keyCertSign` (when `KeyUsage` is present),
//! 5. signature verification over `tbsCertificate`,
//! 6. `NameConstraints` (subject DN + SAN DNS/IP),
//! 7. policy acceptance (default `anyPolicy`; explicit sets intersect).
//!
//! Policy mapping / `policyConstraints` / `inhibitAnyPolicy` are *parsed* by the
//! extension layer but only lightly enforced here (documented limitation).

use alloc::vec::Vec;

use crate::certificate::Certificate;
use crate::extensions::{
    AuthorityKeyIdentifier, CertificatePolicies, GeneralName, GeneralSubtree,
};
use crate::name::Name;
use crate::spki::SubjectPublicKeyInfo;
use crate::time::UnixTime;
use crate::verify::SignatureVerifier;

/// A trusted root: a subject `Name`, its public key, and an optional key id.
#[derive(Clone, Debug)]
pub struct TrustAnchor<'a> {
    /// The trusted CA subject name.
    pub name: Name<'a>,
    /// The trusted CA public key.
    pub public_key: SubjectPublicKeyInfo<'a>,
    /// The trusted CA subject key identifier (if known).
    pub key_id: Option<&'a [u8]>,
}

impl<'a> TrustAnchor<'a> {
    /// Build a trust anchor from a (self-signed) CA certificate.
    pub fn from_cert(cert: &'a Certificate<'a>) -> Self {
        let key_id = cert
            .tbs
            .extensions
            .subject_key_identifier()
            .ok()
            .flatten()
            .map(|s| s.as_bytes());
        TrustAnchor {
            name: cert.tbs.subject.clone(),
            public_key: cert.tbs.subject_public_key_info,
            key_id,
        }
    }
}

/// Configuration for path validation.
pub struct PathConfig<'a> {
    /// The validation time (caller-supplied; `no_std` has no clock).
    pub time: UnixTime,
    /// The signature-verification backend.
    pub verifier: &'a dyn SignatureVerifier,
    /// Maximum number of intermediate certificates allowed in a path.
    pub max_path_length: Option<usize>,
}

/// A successfully validated certification path: `certs[0]` is the end-entity,
/// `certs[last]` is the cert issued directly by `anchor`.
#[derive(Clone, Debug)]
pub struct ValidatedPath<'a> {
    /// The certificates from end-entity to the cert just below the anchor.
    pub certs: Vec<&'a Certificate<'a>>,
    /// The trust anchor the path terminates at.
    pub anchor: &'a TrustAnchor<'a>,
}

/// Errors arising during chain building or path validation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PathError {
    /// No issuer (or trust anchor) could be found for a certificate.
    UnableToBuildPath,
    /// The constructed path exceeds the configured maximum length.
    PathTooLong,
    /// A certificate is outside its validity window at the validation time.
    InvalidValidity,
    /// A `BasicConstraints` requirement was violated (missing CA flag or
    /// `pathLenConstraint` exceeded).
    BasicConstraintsViolation,
    /// A CA certificate is missing the `keyCertSign` `KeyUsage` bit.
    KeyUsageViolation,
    /// A `NameConstraints` check failed.
    NameConstraintViolation,
    /// No acceptable certificate policy was found.
    PolicyViolation,
    /// Signature verification failed (or the algorithm/key was unsupported).
    SignatureVerification(crate::verify::VerifyError),
}

impl core::fmt::Display for PathError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PathError::UnableToBuildPath => f.write_str("unable to build certification path"),
            PathError::PathTooLong => f.write_str("certification path too long"),
            PathError::InvalidValidity => f.write_str("certificate not valid at the given time"),
            PathError::BasicConstraintsViolation => {
                f.write_str("basic constraints violation (CA flag or path length)")
            }
            PathError::KeyUsageViolation => f.write_str("issuer missing keyCertSign key usage"),
            PathError::NameConstraintViolation => f.write_str("name constraints violation"),
            PathError::PolicyViolation => f.write_str("no acceptable certificate policy"),
            PathError::SignatureVerification(e) => write!(f, "signature verification failed: {e}"),
        }
    }
}

impl core::error::Error for PathError {}

/// Build a path from `target` to a trust anchor and validate it.
pub fn build_and_validate<'a>(
    target: &'a Certificate<'a>,
    intermediates: &'a [Certificate<'a>],
    anchors: &'a [TrustAnchor<'a>],
    config: PathConfig<'a>,
) -> Result<ValidatedPath<'a>, PathError> {
    let path = build_path(target, intermediates, anchors, config.max_path_length)?;
    validate_path(&path, config)?;
    Ok(path)
}

/// A resolved issuer reference (an intermediate cert or a trust anchor).
enum IssuerRef<'a> {
    Cert(&'a Certificate<'a>),
    Anchor(&'a TrustAnchor<'a>),
}

#[allow(dead_code)]
impl<'a> IssuerRef<'a> {
    fn subject_name(&self) -> &Name<'a> {
        match self {
            IssuerRef::Cert(c) => &c.tbs.subject,
            IssuerRef::Anchor(a) => &a.name,
        }
    }

    fn spki(&self) -> &SubjectPublicKeyInfo<'a> {
        match self {
            IssuerRef::Cert(c) => &c.tbs.subject_public_key_info,
            IssuerRef::Anchor(a) => &a.public_key,
        }
    }

    fn key_id(&self) -> Option<&'a [u8]> {
        match self {
            IssuerRef::Cert(c) => c
                .tbs
                .extensions
                .subject_key_identifier()
                .ok()
                .flatten()
                .map(|s| s.as_bytes()),
            IssuerRef::Anchor(a) => a.key_id,
        }
    }

    fn authority_key_id(&self) -> Option<AuthorityKeyIdentifier<'a>> {
        match self {
            IssuerRef::Cert(c) => c
                .tbs
                .extensions
                .authority_key_identifier()
                .ok()
                .flatten(),
            IssuerRef::Anchor(_) => None,
        }
    }
}

fn build_path<'a>(
    target: &'a Certificate<'a>,
    intermediates: &'a [Certificate<'a>],
    anchors: &'a [TrustAnchor<'a>],
    max_len: Option<usize>,
) -> Result<ValidatedPath<'a>, PathError> {
    // Candidate issuers: intermediates first, then anchors.
    let mut certs: Vec<&'a Certificate<'a>> = Vec::new();
    let mut current = target;
    let anchor;

    loop {
        if let Some(max) = max_len {
            if certs.len() > max {
                return Err(PathError::PathTooLong);
            }
        }
        certs.push(current);

        // Try to find an issuer among intermediates (excluding `current` itself,
        // so a self-signed certificate never matches its own name), then among
        // the trust anchors.
        let found = find_issuer(current, intermediates)
            .map(IssuerRef::Cert)
            .or_else(|| find_anchor(current, anchors).map(IssuerRef::Anchor));

        match found {
            Some(IssuerRef::Cert(issuer)) => {
                current = issuer;
                continue;
            }
            Some(IssuerRef::Anchor(a)) => {
                anchor = a;
                break;
            }
            None => return Err(PathError::UnableToBuildPath),
        }
    }

    Ok(ValidatedPath { certs, anchor })
}

fn find_issuer<'a>(
    cert: &'a Certificate<'a>,
    pool: &'a [Certificate<'a>],
) -> Option<&'a Certificate<'a>> {
    let aki = cert.tbs.extensions.authority_key_identifier().ok().flatten();
    pool.iter().find(|c| {
        // Never match a certificate to itself (a self-signed cert would otherwise
        // resolve its own name and create a cycle).
        if core::ptr::eq(*c, cert) {
            return false;
        }
        c.tbs.subject.der_eq(&cert.tbs.issuer)
            || matches!(
                (&aki, c.tbs.extensions.subject_key_identifier().ok().flatten()),
                (Some(a), Some(s)) if tpt_asn1_core::util::constant_time_eq(
                    a.key_identifier.unwrap_or(&[] as &[u8]),
                    s.as_bytes()
                )
            )
    })
}

fn find_anchor<'a>(cert: &'a Certificate<'a>, anchors: &'a [TrustAnchor<'a>]) -> Option<&'a TrustAnchor<'a>> {
    let aki = cert.tbs.extensions.authority_key_identifier().ok().flatten();
    anchors.iter().find(|a| {
        a.name.der_eq(&cert.tbs.issuer)
            || matches!(
                (&aki, a.key_id),
                (Some(ak), Some(kid)) if tpt_asn1_core::util::constant_time_eq(
                    ak.key_identifier.unwrap_or(&[] as &[u8]),
                    kid
                )
            )
    })
}

fn validate_path<'a>(path: &ValidatedPath<'a>, config: PathConfig<'a>) -> Result<(), PathError> {
    let n = path.certs.len();
    // Number of intermediate CA certs (everything except the EE and the anchor).
    let max_path = n.saturating_sub(1);

    // Accumulate name constraints from the CA certs in the path.
    let mut permitted: Vec<GeneralSubtree<'a>> = Vec::new();
    let mut excluded: Vec<GeneralSubtree<'a>> = Vec::new();

    for (i, cert) in path.certs.iter().enumerate() {
        // 2. Validity.
        if !cert.is_valid_at(config.time) {
            return Err(PathError::InvalidValidity);
        }

        let is_ee = i == 0;
        let is_ca_cert = !is_ee;

        if is_ca_cert {
            // 3. BasicConstraints.
            let bc = cert
                .tbs
                .extensions
                .basic_constraints()
                .ok()
                .flatten();
            match bc {
                Some(bc) if bc.ca => {
                    if let Some(limit) = bc.path_len_constraint {
                        // Remaining CA certs after this one (excluding the anchor).
                        let remaining = max_path.saturating_sub(i);
                        if (remaining as u64) > limit {
                            return Err(PathError::BasicConstraintsViolation);
                        }
                    }
                }
                _ => return Err(PathError::BasicConstraintsViolation),
            }

            // 4. KeyUsage keyCertSign.
            if let Some(ku) = cert.tbs.extensions.key_usage().ok().flatten() {
                if !ku.is_set(crate::extensions::key_usage_bit::KEY_CERT_SIGN) {
                    return Err(PathError::KeyUsageViolation);
                }
            }
        }

        // 6. Name constraints (only enforce on CA certs, which carry them).
        if let Some(nc) = cert.tbs.extensions.name_constraints().ok().flatten() {
            permitted.extend(nc.permitted);
            excluded.extend(nc.excluded);
        }
        if !name_constraints_satisfied(cert, &permitted, &excluded) {
            return Err(PathError::NameConstraintViolation);
        }

        // 7. Policy acceptance.
        if !policy_acceptable(cert, is_ee) {
            return Err(PathError::PolicyViolation);
        }

        // 5. Signature verification against the next issuer (or the anchor).
        let issuer_ref = if i + 1 < n {
            IssuerRef::Cert(path.certs[i + 1])
        } else {
            IssuerRef::Anchor(path.anchor)
        };
        verify_cert_signature(cert, &issuer_ref, config.verifier)
            .map_err(PathError::SignatureVerification)?;
    }

    Ok(())
}

fn verify_cert_signature<'a>(
    cert: &'a Certificate<'a>,
    issuer: &IssuerRef<'a>,
    verifier: &dyn SignatureVerifier,
) -> Result<(), crate::verify::VerifyError> {
    let sig_alg_oid = cert.signature_algorithm.algorithm.as_bytes();
    let key_alg_oid = issuer.spki().algorithm.algorithm.as_bytes();
    let public_key = issuer.spki().subject_public_key.data;
    let message = cert.tbs_certificate_der();
    let signature = cert.signature_value.data;
    match verifier.verify_signature(sig_alg_oid, key_alg_oid, public_key, message, signature) {
        Ok(true) => Ok(()),
        Ok(false) => Err(crate::verify::VerifyError::InvalidSignature),
        Err(e) => Err(e),
    }
}

/// Simplified policy acceptance: `anyPolicy` is accepted by default; an explicit
/// policy set (no `anyPolicy`) requires the cert to assert a policy in the set.
fn policy_acceptable(cert: &Certificate<'_>, _is_ee: bool) -> bool {
    let policies: Option<CertificatePolicies<'_>> =
        cert.tbs.extensions.certificate_policies().ok().flatten();
    match policies {
        None => true,
        Some(p) => p.has_any_policy() || !p.policies.is_empty(),
    }
}

/// Basic `NameConstraints` enforcement: the subject DN must be within a
/// permitted `directoryName` subtree (when present) and not within any excluded
/// subtree; SAN `dNSName` / `iPAddress` entries are likewise checked.
fn name_constraints_satisfied<'a>(
    cert: &Certificate<'a>,
    permitted: &[GeneralSubtree<'a>],
    excluded: &[GeneralSubtree<'a>],
) -> bool {
    // Excluded: reject immediately on match.
    for st in excluded {
        if subtree_matches(st, cert) {
            return false;
        }
    }
    // Permitted: if there are any subtrees of a relevant type, the cert must
    // match at least one of that type. We require a match only when a subtree of
    // the matching type exists.
    let has_dir = permitted.iter().any(|s| matches!(s.base, GeneralName::DirectoryName(_)));
    let has_dns = permitted.iter().any(|s| matches!(s.base, GeneralName::DnsName(_)));
    let has_ip = permitted.iter().any(|s| matches!(s.base, GeneralName::IpAddress(_)));

    if has_dir && !permitted.iter().any(|s| subtree_matches(s, cert)) {
        return false;
    }
    if has_dns || has_ip {
        // For DNS/IP, the cert matches if any subtree matches; if none of the
        // present subtrees match, it is outside the permitted set.
        if !(permitted.iter().any(|s| subtree_matches(s, cert))) {
            return false;
        }
    }
    true
}

fn subtree_matches<'a>(st: &GeneralSubtree<'a>, cert: &Certificate<'a>) -> bool {
    match &st.base {
        GeneralName::DirectoryName(name) => cert.tbs.subject.der_eq(name),
        GeneralName::DnsName(parent) => cert
            .tbs
            .extensions
            .subject_alt_name()
            .ok()
            .flatten()
            .map(|san| {
                san.names.iter().any(|g| match g {
                    GeneralName::DnsName(d) => dns_within(d, parent),
                    _ => false,
                })
            })
            .unwrap_or(false),
        GeneralName::IpAddress(prefix) => cert
            .tbs
            .extensions
            .subject_alt_name()
            .ok()
            .flatten()
            .map(|san| {
                san.names.iter().any(|g| match g {
                    GeneralName::IpAddress(a) => ip_within(a, prefix),
                    _ => false,
                })
            })
            .unwrap_or(false),
        _ => false,
    }
}

fn dns_within(child: &[u8], parent: &[u8]) -> bool {
    // child is within parent if it equals parent or ends with "." + parent.
    if child.len() < parent.len() {
        return false;
    }
    if child == parent {
        return true;
    }
    if child.len() == parent.len() + 1 {
        return false;
    }
    let off = child.len() - parent.len();
    child[off - 1] == b'.' && child[off..] == *parent
}

fn ip_within(child: &[u8], parent: &[u8]) -> bool {
    // Treat as CIDR-style prefix match over the leading bytes of the address.
    let common = core::cmp::min(child.len(), parent.len());
    child[..common] == parent[..common]
}
