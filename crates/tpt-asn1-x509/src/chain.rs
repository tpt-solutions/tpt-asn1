// SPDX-License-Identifier: MIT OR Apache-2.0

//! Certificate chain building and RFC 5280 §6.1 path validation.
//!
//! The implementation is fail-closed and delegates the actual signature math to
//! a [`SignatureVerifier`] backend so that `tpt-asn1-x509` stays free of C
//! dependencies.
//!
//! Path construction is a depth-first search over every certificate whose
//! subject matches the current certificate's issuer name. A complete candidate
//! path is accepted only if [`validate_path`] passes. Signatures are checked
//! there, not during the search, so key-rollover certificates that share a name
//! are resolved by signature, and DSA parameters can be inherited from the path.
//!
//! [`validate_path`] walks the path from the trust anchor down to the
//! end-entity (RFC 5280 §6.1.3–6.1.4) and enforces:
//!
//! 1. name chaining (issuer DN matches the next certificate's subject DN),
//! 2. validity windows,
//! 3. serial-number well-formedness (RFC 5280 §4.1.2.2),
//! 4. the CA flag, `keyCertSign`, and `pathLenConstraint` (with self-issued
//!    certificates excluded from the count),
//! 5. the signature, using the issuer's key and inherited parameters,
//! 6. `NameConstraints` from every CA above (DN, email, DNS, URI, IP),
//! 7. revocation against the supplied full CRLs (RFC 5280 §6.3),
//! 8. policy acceptance (default `anyPolicy`; explicit sets intersect).
//!
//! Policy processing (RFC 5280 §6.1.2–6.1.5) lives in the `policy` module.
//! Revocation covers delta CRLs and distribution-point scoping.
//!
//! Known limitations: trust anchors are always supplied by the caller (there is
//! no system trust store), and the PKITS suite has one open case (§4.4.19).

use alloc::vec::Vec;

use crate::certificate::Certificate;
use crate::crl::CertificateList;
use crate::extensions::{
    key_usage_bit, CrlDistributionPoints, GeneralName, GeneralNames, NameConstraints,
};
use crate::name::Name;
use crate::oid::ext;
use crate::policy::{validate_policies, PolicyInputs};
use crate::reader::Reader;
use crate::spki::SubjectPublicKeyInfo;
use crate::time::UnixTime;
use crate::verify::SignatureVerifier;
use tpt_asn1_core::any::Any;
use tpt_asn1_core::decode::Decode;

/// Upper bound on the number of certificates considered in one path. Guards the
/// depth-first search against pathological or cyclic certificate pools.
const MAX_PATH_DEPTH: usize = 16;

/// Upper bound on the number of search nodes visited in one
/// [`build_and_validate`] call. Without it, a pool of many certificates sharing
/// a subject name makes the depth-first search explore a number of chains that
/// grows exponentially with depth.
const MAX_SEARCH_STEPS: usize = 4096;

/// `id-emailAddress` — 1.2.840.113549.1.9.1 (PKCS #9), used in subject DNs.
const EMAIL_ADDRESS: &[u64] = &[1, 2, 840, 113549, 1, 9, 1];
/// `id-ce-invalidityDate` — 2.5.29.24 (RFC 5280 §5.3.2).
const INVALIDITY_DATE: &[u64] = &[2, 5, 29, 24];
/// `id-ce-certificateIssuer` — 2.5.29.29 (RFC 5280 §5.3.3).
const CERTIFICATE_ISSUER: &[u64] = &[2, 5, 29, 29];

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
        let key_id =
            cert.tbs.extensions.subject_key_identifier().ok().flatten().map(|s| s.as_bytes());
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
    /// Whether to check revocation at all. When `false`, `crls` is ignored.
    pub check_revocation: bool,
    /// Candidate CRLs. Each is matched to a certificate by issuer name, and its
    /// signature is checked against the certificate's issuer key. With
    /// `check_revocation` set and no CRL for a certificate's issuer, validation
    /// fails with [`PathError::CrlNotFound`].
    pub crls: &'a [CertificateList<'a>],
    /// `initial-policy-set` (RFC 5280 §6.1.1 (c)), as OID content octets. An empty
    /// slice means `anyPolicy`.
    pub initial_policy_set: &'a [&'a [u8]],
    /// `initial-explicit-policy` (§6.1.1 (e)): require a valid policy in the path.
    pub initial_explicit_policy: bool,
    /// `initial-policy-mapping-inhibit` (§6.1.1 (f)).
    pub initial_policy_mapping_inhibit: bool,
    /// `initial-inhibit-any-policy` (§6.1.1 (g)).
    pub initial_inhibit_any_policy: bool,
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
    /// The issuer search exceeded its work budget before finding a valid path.
    SearchBudgetExceeded,
    /// A certificate is outside its validity window at the validation time.
    InvalidValidity,
    /// A `BasicConstraints` requirement was violated (missing CA flag or
    /// `pathLenConstraint` exceeded).
    BasicConstraintsViolation,
    /// A CA certificate is missing the `keyCertSign` `KeyUsage` bit, or a CRL
    /// issuer is missing the `cRLSign` bit.
    KeyUsageViolation,
    /// A `NameConstraints` check failed.
    NameConstraintViolation,
    /// No acceptable certificate policy was found.
    PolicyViolation,
    /// The certificate's serial number is negative or longer than 20 octets.
    InvalidSerialNumber,
    /// A certificate is listed as revoked by its issuer's CRL.
    Revoked,
    /// No CRL for the certificate's issuer was supplied.
    CrlNotFound,
    /// A CRL was present but failed validation (signature, currency, or an
    /// unrecognised critical extension).
    CrlInvalid,
    /// Signature verification failed (or the algorithm/key was unsupported).
    SignatureVerification(crate::verify::VerifyError),
    /// A path-relevant extension could not be decoded. Failing closed here
    /// means a malformed constraint can never be silently ignored.
    MalformedExtension(tpt_asn1_core::error::Error),
}

impl core::fmt::Display for PathError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PathError::UnableToBuildPath => f.write_str("unable to build certification path"),
            PathError::PathTooLong => f.write_str("certification path too long"),
            PathError::SearchBudgetExceeded => {
                f.write_str("issuer search exceeded its work budget")
            }
            PathError::InvalidValidity => f.write_str("certificate not valid at the given time"),
            PathError::BasicConstraintsViolation => {
                f.write_str("basic constraints violation (CA flag or path length)")
            }
            PathError::KeyUsageViolation => f.write_str("issuer missing keyCertSign or cRLSign"),
            PathError::NameConstraintViolation => f.write_str("name constraints violation"),
            PathError::PolicyViolation => f.write_str("no acceptable certificate policy"),
            PathError::InvalidSerialNumber => f.write_str("invalid certificate serial number"),
            PathError::Revoked => f.write_str("certificate is revoked"),
            PathError::CrlNotFound => f.write_str("no CRL found for certificate issuer"),
            PathError::CrlInvalid => f.write_str("CRL failed validation"),
            PathError::SignatureVerification(e) => write!(f, "signature verification failed: {e}"),
            PathError::MalformedExtension(e) => write!(f, "malformed certificate extension: {e}"),
        }
    }
}

impl core::error::Error for PathError {}

/// Build a path from `target` to a trust anchor and validate it.
///
/// Every chain of name-matching issuers is tried, depth first, and the first
/// one that passes [`validate_path`] is returned. If none does, the first error
/// encountered is returned.
pub fn build_and_validate<'a>(
    target: &'a Certificate<'a>,
    intermediates: &'a [Certificate<'a>],
    anchors: &'a [TrustAnchor<'a>],
    config: PathConfig<'a>,
) -> Result<ValidatedPath<'a>, PathError> {
    let mut chain = alloc::vec![target];
    let mut first_error = None;
    let mut budget = MAX_SEARCH_STEPS;
    search(&mut chain, intermediates, anchors, &config, &mut budget, &mut first_error)
        .ok_or_else(|| first_error.unwrap_or(PathError::UnableToBuildPath))
}

/// A resolved issuer reference (an intermediate cert or a trust anchor).
enum IssuerRef<'a> {
    Cert(&'a Certificate<'a>),
    Anchor(&'a TrustAnchor<'a>),
}

impl<'a> IssuerRef<'a> {
    fn spki(&self) -> &SubjectPublicKeyInfo<'a> {
        match self {
            IssuerRef::Cert(c) => &c.tbs.subject_public_key_info,
            IssuerRef::Anchor(a) => &a.public_key,
        }
    }

    fn name(&self) -> &Name<'a> {
        match self {
            IssuerRef::Cert(c) => &c.tbs.subject,
            IssuerRef::Anchor(a) => &a.name,
        }
    }

    fn cert(&self) -> Option<&'a Certificate<'a>> {
        match self {
            IssuerRef::Cert(c) => Some(c),
            IssuerRef::Anchor(_) => None,
        }
    }
}

/// A key that may sign a CRL on the path: a path certificate or the anchor,
/// together with the resolved parameters of its `SubjectPublicKeyInfo`.
type PathKey<'a> = (IssuerRef<'a>, Option<&'a [u8]>);

/// Depth-first search for a chain that starts at `chain.last()` and ends at a
/// trust anchor. Candidate issuers are those whose subject matches the current
/// certificate's issuer name. Each complete chain is handed to
/// [`validate_path`], and the first success wins.
fn search<'a>(
    chain: &mut Vec<&'a Certificate<'a>>,
    intermediates: &'a [Certificate<'a>],
    anchors: &'a [TrustAnchor<'a>],
    config: &PathConfig<'a>,
    budget: &mut usize,
    first_error: &mut Option<PathError>,
) -> Option<ValidatedPath<'a>> {
    let current = *chain.last()?;

    if *budget == 0 {
        first_error.get_or_insert(PathError::SearchBudgetExceeded);
        return None;
    }
    *budget -= 1;

    for anchor in anchors.iter().filter(|a| a.name.matches(&current.tbs.issuer)) {
        let path = ValidatedPath { certs: chain.clone(), anchor };
        match validate_path(&path, config, intermediates) {
            Ok(()) => return Some(path),
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }

    if chain.len() >= MAX_PATH_DEPTH {
        first_error.get_or_insert(PathError::PathTooLong);
        return None;
    }

    for cand in intermediates.iter() {
        if chain.iter().any(|c| core::ptr::eq(*c, cand)) {
            continue;
        }
        if !cand.tbs.subject.matches(&current.tbs.issuer) {
            continue;
        }
        chain.push(cand);
        if let Some(path) = search(chain, intermediates, anchors, config, budget, first_error) {
            return Some(path);
        }
        chain.pop();
    }

    None
}

/// Validate a complete path against RFC 5280 §6.1 (see the module docs for the
/// ordered list of checks). Certificates are processed from the anchor down, as
/// the RFC requires for the path-length and name-constraint state.
fn validate_path<'a>(
    path: &ValidatedPath<'a>,
    config: &PathConfig<'a>,
    pool: &'a [Certificate<'a>],
) -> Result<(), PathError> {
    let n = path.certs.len();
    // `max_path_length` caps the intermediates, which are every path certificate
    // except the target (`certs[0]`).
    if let Some(limit) = config.max_path_length {
        if n.saturating_sub(1) > limit {
            return Err(PathError::PathTooLong);
        }
    }
    let key_params = resolve_key_params(path);
    // Keys that may sign a CRL for a direct issuer: the path and the anchor. A CRL
    // from an indirect issuer may also be signed by a certificate from the candidate
    // pool, since RFC 5280 §6.3.3 locates the cRLIssuer from the available certificates.
    let keys: Vec<PathKey<'a>> = (0..n)
        .map(|j| (IssuerRef::Cert(path.certs[j]), key_params[j]))
        .chain(core::iter::once((IssuerRef::Anchor(path.anchor), key_params[n])))
        .collect();
    let pool_keys: Vec<PathKey<'a>> = pool
        .iter()
        .map(|c| {
            let params =
                c.tbs.subject_public_key_info.algorithm.parameters.as_ref().map(|p| p.full);
            (IssuerRef::Cert(c), params)
        })
        .collect();
    // RFC 5280 §6.1.2 (f): max_path_length starts at n, the number of
    // certificates excluding the trust anchor.
    let mut max_path = n as u64;
    // The name constraints from each CA above the current certificate. Each set
    // is checked on its own, which is equivalent to the RFC's intersection of
    // permitted subtrees and union of excluded subtrees.
    let mut constraints: Vec<NameConstraints<'a>> = Vec::new();

    for i in (0..n).rev() {
        let cert = path.certs[i];
        let issuer = if i + 1 < n {
            IssuerRef::Cert(path.certs[i + 1])
        } else {
            IssuerRef::Anchor(path.anchor)
        };
        let issuer_params = if i + 1 < n { key_params[i + 1] } else { key_params[n] };

        check_name_chaining(cert, path, i)?;
        if !cert.is_valid_at(config.time) {
            return Err(PathError::InvalidValidity);
        }
        check_serial_number(cert)?;

        if i > 0 {
            let bc = match cert
                .tbs
                .extensions
                .basic_constraints()
                .map_err(PathError::MalformedExtension)?
            {
                Some(bc) if bc.ca => bc,
                _ => return Err(PathError::BasicConstraintsViolation),
            };
            if let Some(ku) =
                cert.tbs.extensions.key_usage().map_err(PathError::MalformedExtension)?
            {
                if !ku.is_set(key_usage_bit::KEY_CERT_SIGN) {
                    return Err(PathError::KeyUsageViolation);
                }
            }
            // RFC 5280 §6.1.4 (k) and (l).
            if !is_self_issued(cert) {
                if max_path == 0 {
                    return Err(PathError::BasicConstraintsViolation);
                }
                max_path -= 1;
            }
            if let Some(limit) = bc.path_len_constraint {
                if limit < max_path {
                    max_path = limit;
                }
            }
        }

        verify_cert_signature(cert, &issuer, issuer_params, config.verifier)
            .map_err(PathError::SignatureVerification)?;

        // A CA's own constraints apply to the certificates below it, not to itself,
        // so they are added only after this certificate has been checked.
        // RFC 5280 §6.1.4 (b): the subject of a self-issued intermediate is not
        // checked against the constraints above it.
        let check_subject = i == 0 || !is_self_issued(cert);
        if !constraints.is_empty() {
            // Decode the SAN once and fail closed: a malformed SAN must not
            // make every name-constraint check vacuously pass.
            let san =
                cert.tbs.extensions.subject_alt_name().map_err(PathError::MalformedExtension)?;
            for nc in &constraints {
                if !name_constraints_hold(cert, san.as_ref(), nc, check_subject) {
                    return Err(PathError::NameConstraintViolation);
                }
            }
        }
        if i > 0 {
            if let Some(nc) =
                cert.tbs.extensions.name_constraints().map_err(PathError::MalformedExtension)?
            {
                constraints.push(nc);
            }
        }

        if config.check_revocation {
            check_revocation(cert, &keys, &pool_keys, config)?;
        }
    }

    let top_down: Vec<&Certificate<'a>> = path.certs.iter().rev().copied().collect();
    let inputs = PolicyInputs {
        initial_policy_set: config.initial_policy_set,
        explicit_policy: config.initial_explicit_policy,
        policy_mapping_inhibit: config.initial_policy_mapping_inhibit,
        inhibit_any_policy: config.initial_inhibit_any_policy,
    };
    validate_policies(&top_down, &inputs)
}

/// Resolve the `AlgorithmIdentifier` parameters for each key in the path.
///
/// Entry `j` is the key of certificate `j`; entry `n` is the anchor's key. A key
/// with absent parameters inherits them from the key above it, which is the
/// DSA inheritance rule of RFC 5280 §7.3.3.
fn resolve_key_params<'a>(path: &ValidatedPath<'a>) -> Vec<Option<&'a [u8]>> {
    let n = path.certs.len();
    let mut out = alloc::vec![None; n + 1];
    let mut above = path.anchor.public_key.algorithm.parameters.as_ref().map(|p| p.full);
    out[n] = above;
    for j in (0..n).rev() {
        let own =
            path.certs[j].tbs.subject_public_key_info.algorithm.parameters.as_ref().map(|p| p.full);
        let resolved = own.or(above);
        out[j] = resolved;
        above = resolved;
    }
    out
}

/// RFC 5280 §6.1.3 (a)(1): the certificate's issuer must match the subject of the
/// certificate (or anchor) that comes next in the path.
fn check_name_chaining(
    cert: &Certificate<'_>,
    path: &ValidatedPath<'_>,
    i: usize,
) -> Result<(), PathError> {
    let issuer_name: &Name<'_> = match path.certs.get(i + 1) {
        Some(next) => &next.tbs.subject,
        None => &path.anchor.name,
    };
    if cert.tbs.issuer.matches(issuer_name) {
        Ok(())
    } else {
        Err(PathError::UnableToBuildPath)
    }
}

/// RFC 5280 §4.1.2.2: serial numbers are positive and at most 20 octets.
fn check_serial_number(cert: &Certificate<'_>) -> Result<(), PathError> {
    let serial = cert.tbs.serial_number.as_bytes();
    if serial.first().is_some_and(|b| b & 0x80 != 0) {
        return Err(PathError::InvalidSerialNumber);
    }
    // A single leading 0x00 is the DER sign octet, not part of the value.
    let significant = match serial {
        [0x00, rest @ ..] if !rest.is_empty() => rest,
        other => other,
    };
    if significant.len() > 20 {
        return Err(PathError::InvalidSerialNumber);
    }
    Ok(())
}

/// A certificate is self-issued when its issuer and subject names match
/// (RFC 5280 §6.1.4 (k)).
fn is_self_issued(cert: &Certificate<'_>) -> bool {
    cert.tbs.issuer.matches(&cert.tbs.subject)
}

/// Verify `cert`'s signature with the issuer's key.
fn verify_cert_signature<'a>(
    cert: &'a Certificate<'a>,
    issuer: &IssuerRef<'a>,
    issuer_params: Option<&[u8]>,
    verifier: &dyn SignatureVerifier,
) -> Result<(), crate::verify::VerifyError> {
    let sig_alg_oid = cert.signature_algorithm.algorithm.as_bytes();
    let spki = issuer.spki();
    let key_alg_oid = spki.algorithm.algorithm.as_bytes();
    let public_key = spki.subject_public_key.data;
    let message = cert.tbs_certificate_der();
    let signature = cert.signature_value.data;
    match verifier.verify_signature_with_params(
        sig_alg_oid,
        key_alg_oid,
        issuer_params,
        public_key,
        message,
        signature,
    ) {
        Ok(true) => Ok(()),
        Ok(false) => Err(crate::verify::VerifyError::InvalidSignature),
        Err(e) => Err(e),
    }
}

/// Every reason code that a full set of CRL reasons must cover (RFC 5280 §5.2.5):
/// keyCompromise (1) through aACompromise (8), the reason bits of RFC 5280 §5.3.1 and
/// §5.2.5. `unspecified` (0) is excluded.
const ALL_REASONS: u32 = 0x1FE;

/// RFC 5280 §6.3: decide whether `cert` is revoked, from the CRLs that apply to it.
///
/// A CRL applies when its issuer is the certificate issuer, or a `cRLIssuer`
/// named in the certificate's CRL distribution points (an indirect CRL). The
/// scope rules of §6.3.3 decide whether a given CRL covers the certificate. The
/// applicable CRLs must together cover every reason code, or the status is unknown.
///
/// A CRL is used only if one of the path's keys whose subject matches the CRL's
/// issuer verifies it, so a bad CRL signature cannot mask a valid one.
fn check_revocation(
    cert: &Certificate<'_>,
    keys: &[PathKey<'_>],
    pool_keys: &[PathKey<'_>],
    config: &PathConfig<'_>,
) -> Result<(), PathError> {
    let serial = cert.tbs.serial_number_bytes();
    let is_ca = cert.tbs.is_ca();
    let points =
        cert.tbs.extensions.crl_distribution_points().map_err(PathError::MalformedExtension)?;
    let indirect_issuers: Vec<&Name<'_>> = points
        .iter()
        .flat_map(|p| p.points.iter())
        .filter_map(|p| p.crl_issuer.as_ref())
        .flat_map(|g| g.names.iter())
        .filter_map(|g| match g {
            GeneralName::DirectoryName(n) => Some(n),
            _ => None,
        })
        .collect();

    let mut revoked = false;
    let mut applicable = false;
    let mut coverage = 0u32;
    let mut first_error = None;
    for crl in config.crls {
        // A delta CRL is not a complete CRL. It is applied to its base CRL below.
        if is_delta_crl(crl) {
            continue;
        }
        // With a cRLIssuer in the certificate's distribution points, only CRLs from
        // those issuers apply (RFC 5280 §6.3.3 (a)(1)); otherwise the issuer is the CRL issuer.
        let indirect = indirect_issuers.iter().any(|n| crl.issuer.matches(n));
        let direct = indirect_issuers.is_empty() && crl.issuer.matches(&cert.tbs.issuer);
        if !direct && !indirect {
            continue;
        }
        let reasons = match crl_scope(crl, is_ca, points.as_ref(), indirect) {
            Ok(Some(reasons)) => reasons,
            Ok(None) => continue,
            Err(e) => {
                first_error.get_or_insert(e);
                continue;
            }
        };
        let signers = crl_signers(indirect, keys, pool_keys, &crl.issuer, config.verifier);
        if let Err(e) = verify_crl_with_path_key(crl, &signers, config) {
            first_error.get_or_insert(e);
            continue;
        }
        applicable = true;
        coverage |= reasons;
        // A delta CRL for this base can change the base's answer for the certificate.
        let base_status = crl_revokes(crl, serial, &cert.tbs.issuer, config.time);
        let status = delta_status(cert, crl, indirect, points.as_ref(), keys, pool_keys, config)
            .unwrap_or(base_status);
        if status {
            revoked = true;
        }
    }

    if revoked {
        return Err(PathError::Revoked);
    }
    if !applicable {
        return Err(first_error.unwrap_or(PathError::CrlNotFound));
    }
    if coverage & ALL_REASONS != ALL_REASONS {
        return Err(PathError::CrlNotFound);
    }
    Ok(())
}

/// Whether `crl` is a delta CRL (it carries the deltaCRLIndicator extension).
fn is_delta_crl(crl: &CertificateList<'_>) -> bool {
    crl.crl_extensions.find(ext::DELTA_CRL_INDICATOR).is_some()
}

/// The keys that may sign a CRL for a certificate. An indirect CRL may come from any
/// candidate that names the cRLIssuer. A direct CRL may also come from a self-issued
/// candidate, which is how a CA signs across a key rollover (PKITS 4.5.4, 4.5.6).
///
/// A self-issued pool candidate is accepted only if one of the path keys (or the
/// anchor) verifies its signature. Otherwise any self-signed certificate in the
/// pool could sign a CRL for the CA's name, with no trust in its key.
fn crl_signers<'b>(
    indirect: bool,
    keys: &'b [PathKey<'b>],
    pool_keys: &'b [PathKey<'b>],
    crl_issuer: &Name<'_>,
    verifier: &dyn SignatureVerifier,
) -> Vec<&'b PathKey<'b>> {
    if indirect {
        keys.iter().chain(pool_keys.iter()).collect()
    } else {
        keys.iter()
            .chain(pool_keys.iter().filter(|(k, _)| match k {
                // A self-issued certificate, or a certificate issued by the CRL issuer,
                // whose signature a key already on the path verifies. The check on
                // the signature stops an unchained certificate from signing.
                IssuerRef::Cert(c) => {
                    (c.tbs.issuer.matches(&c.tbs.subject) || c.tbs.issuer.matches(crl_issuer))
                        && vouched(c, keys, verifier)
                }
                IssuerRef::Anchor(_) => false,
            }))
            .collect()
    }
}

/// Whether `cert` is signed by one of the keys already on the path.
fn vouched(cert: &Certificate<'_>, keys: &[PathKey<'_>], verifier: &dyn SignatureVerifier) -> bool {
    keys.iter()
        .any(|(issuer, params)| verify_cert_signature(cert, issuer, *params, verifier).is_ok())
}

/// RFC 5280 §6.3.3 (d): the certificate's status in the delta CRL that complements
/// `base`, if a valid one applies. `Some(true)` is revoked, and `Some(false)` means
/// the delta removes the certificate from the base (`removeFromCRL`).
///
/// A delta applies only when its deltaCRLIndicator names the base's CRL number, and
/// it is issued under the same name and scope as the base.
fn delta_status(
    cert: &Certificate<'_>,
    base: &CertificateList<'_>,
    indirect: bool,
    points: Option<&CrlDistributionPoints<'_>>,
    keys: &[PathKey<'_>],
    pool_keys: &[PathKey<'_>],
    config: &PathConfig<'_>,
) -> Option<bool> {
    let base_number = base.crl_extensions.crl_number().ok().flatten()?;
    for delta in config.crls {
        let Some(indicator) = delta.crl_extensions.delta_crl_indicator().ok().flatten() else {
            continue;
        };
        if indicator != base_number || !delta.issuer.matches(&base.issuer) {
            continue;
        }
        if crl_scope(delta, cert.tbs.is_ca(), points, indirect).ok().flatten().is_none() {
            continue;
        }
        let signers = crl_signers(indirect, keys, pool_keys, &delta.issuer, config.verifier);
        if verify_crl_with_path_key(delta, &signers, config).is_err() {
            continue;
        }
        return entry_status(delta, cert.tbs.serial_number_bytes(), &cert.tbs.issuer, config.time);
    }
    None
}

/// RFC 5280 §6.3.3 (b): whether `crl` covers the certificate, and the reason codes it
/// covers. `None` means the CRL is out of scope.
fn crl_scope(
    crl: &CertificateList<'_>,
    is_ca: bool,
    points: Option<&CrlDistributionPoints<'_>>,
    indirect: bool,
) -> Result<Option<u32>, PathError> {
    let idp = match crl.crl_extensions.issuing_distribution_point() {
        Ok(Some(idp)) => idp,
        // Without an issuing distribution point the CRL is a direct CRL, so it
        // cannot cover a certificate reached through a cRLIssuer (indirectCRL is
        // false by default).
        Ok(None) => return Ok(if indirect { None } else { Some(0xFFFF) }),
        Err(_) => return Err(PathError::CrlInvalid),
    };
    if idp.only_contains_attribute_certs
        || (idp.only_contains_user_certs && is_ca)
        || (idp.only_contains_ca_certs && !is_ca)
        || (indirect && !idp.indirect_crl)
    {
        return Ok(None);
    }
    if idp.distribution_point.is_some() || idp.relative_name.is_some() {
        // The certificate's own distribution point must be one the CRL covers. The
        // CRL's point is its fullName, or its nameRelativeToCRLIssuer appended to the
        // CRL issuer's name.
        let crl_covers = |cert_name: &GeneralName<'_>| {
            let by_full_name = idp
                .distribution_point
                .iter()
                .flat_map(|d| d.names.iter())
                .any(|crl_name| same_distribution_name(cert_name, crl_name));
            let by_relative_name = matches!(
                (cert_name, &idp.relative_name),
                (GeneralName::DirectoryName(n), Some(rdn)) if n.is_extended_by(&crl.issuer, rdn)
            );
            by_full_name || by_relative_name
        };
        let covered = points.is_some_and(|ps| {
            ps.points.iter().any(|p| {
                let by_full_name = p.full_name.iter().flat_map(|g| g.names.iter()).any(crl_covers);
                // The certificate's nameRelativeToCRLIssuer, appended to the CRL issuer.
                let by_relative_name = p.relative_name.as_ref().is_some_and(|rdn| {
                    idp.relative_name.as_ref().is_some_and(|irdn| rdn.matches(irdn))
                        || idp.distribution_point.iter().flat_map(|d| d.names.iter()).any(|crl_name| {
                            matches!(crl_name, GeneralName::DirectoryName(n) if n.is_extended_by(&crl.issuer, rdn))
                        })
                });
                by_full_name || by_relative_name
            })
        });
        if !covered {
            return Ok(None);
        }
    }
    Ok(Some(idp.only_some_reasons.map_or(0xFFFF, |r| u32::from(r.mask()))))
}

/// Whether two distribution-point names identify the same point.
fn same_distribution_name(a: &GeneralName<'_>, b: &GeneralName<'_>) -> bool {
    match (a, b) {
        (GeneralName::Uri(x), GeneralName::Uri(y)) => x == y,
        (GeneralName::DirectoryName(x), GeneralName::DirectoryName(y)) => x.matches(y),
        _ => false,
    }
}

/// Verify `crl` with the first path key whose subject matches the CRL's issuer.
/// Whether `signer` may sign a CRL from `issuer`: its name is the CRL issuer, or it
/// is a certificate issued by the CRL issuer (a separate CRL-signing certificate).
fn crl_signer_candidate(signer: &IssuerRef<'_>, issuer: &Name<'_>) -> bool {
    match signer {
        IssuerRef::Cert(c) => {
            let named = signer.name().matches(issuer) || c.tbs.issuer.matches(issuer);
            // A certificate whose keyUsage omits cRLSign cannot sign a CRL, so it is
            // not a candidate. Trying it would only report a key-usage error.
            named && may_sign_crl(c)
        }
        IssuerRef::Anchor(_) => signer.name().matches(issuer),
    }
}

/// Whether `cert` may sign a CRL: it has no keyUsage, or keyUsage includes cRLSign.
fn may_sign_crl(cert: &Certificate<'_>) -> bool {
    match cert.tbs.extensions.key_usage() {
        Ok(Some(ku)) => ku.is_set(key_usage_bit::CRL_SIGN),
        Ok(None) => true,
        Err(_) => false,
    }
}

fn verify_crl_with_path_key(
    crl: &CertificateList<'_>,
    keys: &[&PathKey<'_>],
    config: &PathConfig<'_>,
) -> Result<(), PathError> {
    let mut first_error = None;
    // A candidate is either named as the CRL issuer, or it is a path certificate
    // issued by the CRL issuer: a separate CRL-signing certificate (PKITS 4.4.19).
    // Its key still has to verify the CRL, and it must carry cRLSign.
    // RFC 5280 §5.2.1: when the CRL names its signing key in an authorityKeyIdentifier,
    // a candidate whose subjectKeyIdentifier differs cannot be the signer (PKITS 4.4.21).
    let crl_aki = crl
        .crl_extensions
        .authority_key_identifier()
        .ok()
        .flatten()
        .and_then(|aki| aki.key_identifier);
    let aki_matches = |signer: &IssuerRef<'_>| match (crl_aki, signer) {
        (Some(aki), IssuerRef::Cert(c)) => match c.tbs.extensions.subject_key_identifier() {
            Ok(Some(ski)) => ski.0 == aki,
            _ => true,
        },
        _ => true,
    };
    for entry in
        keys.iter().filter(|e| crl_signer_candidate(&e.0, &crl.issuer) && aki_matches(&e.0))
    {
        let (signer, params) = (&entry.0, entry.1);
        match validate_crl(crl, signer, params, config) {
            Ok(()) => return Ok(()),
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    Err(first_error.unwrap_or(PathError::CrlNotFound))
}

/// The revocation state of `serial` in `crl`, for a certificate issued by `issuer`,
/// as of `now`. `Some(true)` is revoked, and `Some(false)` is an entry that removes
/// the certificate (`removeFromCRL`, RFC 5280 §5.3.1). `None` means no entry applies.
///
/// For an indirect CRL, an entry applies only to certificates issued by the issuer
/// named by the most recent `certificateIssuer` entry extension (RFC 5280 §5.3.3).
/// Before any such extension, the CRL's own issuer applies.
fn entry_status(
    crl: &CertificateList<'_>,
    serial: &[u8],
    issuer: &Name<'_>,
    now: UnixTime,
) -> Option<bool> {
    use crate::extensions::crl_reason::REMOVE_FROM_CRL;

    let mut entry_issuer: Option<Name<'_>> = None;
    for entry in &crl.revoked {
        if let Some(ext) = entry.entry_extensions.find(CERTIFICATE_ISSUER) {
            // The extension value is a GeneralNames SEQUENCE; decode its body.
            let config = crate::reader::Config::der();
            let mut r = Reader::new(ext.extn_value, config);
            if let Ok(seq) = Any::decode(&mut r) {
                if let Ok(names) = GeneralNames::from_content(seq.value, config) {
                    entry_issuer = names.names.into_iter().find_map(|g| match g {
                        GeneralName::DirectoryName(n) => Some(n),
                        _ => None,
                    });
                }
            }
        }
        let applies = match &entry_issuer {
            Some(n) => n.matches(issuer),
            None => crl.issuer.matches(issuer),
        };
        if applies && entry.serial_number_bytes() == serial && entry.is_revoked_at(now) {
            return Some(entry.reason() != Some(REMOVE_FROM_CRL));
        }
    }
    None
}

/// Whether `crl` revokes the certificate with `serial` issued by `issuer`, as of
/// `now`. See [`entry_status`].
fn crl_revokes(crl: &CertificateList<'_>, serial: &[u8], issuer: &Name<'_>, now: UnixTime) -> bool {
    entry_status(crl, serial, issuer, now) == Some(true)
}

/// Check a CRL's signature, currency, critical extensions, and the issuer's
/// `cRLSign` key usage.
fn validate_crl(
    crl: &CertificateList<'_>,
    issuer: &IssuerRef<'_>,
    issuer_params: Option<&[u8]>,
    config: &PathConfig<'_>,
) -> Result<(), PathError> {
    if let Some(ca) = issuer.cert() {
        if let Some(ku) = ca.tbs.extensions.key_usage().map_err(PathError::MalformedExtension)? {
            if !ku.is_set(key_usage_bit::CRL_SIGN) {
                return Err(PathError::KeyUsageViolation);
            }
        }
    }

    let spki = issuer.spki();
    match config.verifier.verify_signature_with_params(
        crl.signature_algorithm.algorithm.as_bytes(),
        spki.algorithm.algorithm.as_bytes(),
        issuer_params,
        spki.subject_public_key.data,
        crl.tbs_cert_list_der(),
        crl.signature_value.data,
    ) {
        Ok(true) => {}
        Ok(false) => return Err(PathError::CrlInvalid),
        Err(e) => return Err(PathError::SignatureVerification(e)),
    }

    let this_update = crl.this_update.to_unix().map_err(|_| PathError::CrlInvalid)?;
    if this_update > config.time {
        return Err(PathError::CrlInvalid);
    }
    if let Some(next) = &crl.next_update {
        let next = next.to_unix().map_err(|_| PathError::CrlInvalid)?;
        if next < config.time {
            return Err(PathError::CrlInvalid);
        }
    }

    // RFC 5280 §5.2 / §5.3: an unrecognised critical extension makes the CRL
    // unusable (fail closed).
    let known_crl_ext = [
        ext::AUTHORITY_KEY_IDENTIFIER,
        ext::CRL_NUMBER,
        ext::ISSUING_DISTRIBUTION_POINT,
        ext::DELTA_CRL_INDICATOR,
        ext::FRESHEST_CRL,
    ];
    let known_entry_ext = [ext::CRL_REASON, INVALIDITY_DATE, CERTIFICATE_ISSUER];
    if crl.crl_extensions.iter().any(|e| e.critical && !known_crl_ext.iter().any(|k| e.is(k))) {
        return Err(PathError::CrlInvalid);
    }
    for entry in &crl.revoked {
        if entry
            .entry_extensions
            .iter()
            .any(|e| e.critical && !known_entry_ext.iter().any(|k| e.is(k)))
        {
            return Err(PathError::CrlInvalid);
        }
    }
    Ok(())
}

/// The kinds of name that `NameConstraints` can restrict (RFC 5280 §4.2.1.10).
#[derive(Clone, Copy, PartialEq, Eq)]
enum NameKind {
    Dn,
    Email,
    Dns,
    Uri,
    Ip,
}

fn base_kind(base: &GeneralName<'_>) -> Option<NameKind> {
    match base {
        GeneralName::DirectoryName(_) => Some(NameKind::Dn),
        GeneralName::Rfc822Name(_) => Some(NameKind::Email),
        GeneralName::DnsName(_) => Some(NameKind::Dns),
        GeneralName::Uri(_) => Some(NameKind::Uri),
        GeneralName::IpAddress(_) => Some(NameKind::Ip),
        _ => None,
    }
}

/// Apply one CA's constraints to a single name of `kind`.
///
/// `within` reports whether the name lies within a given base. It is only called
/// with bases of the same kind. If any permitted subtree of that kind exists, the
/// name must lie within one; no excluded subtree of that kind may contain it.
fn constrained(
    nc: &NameConstraints<'_>,
    kind: NameKind,
    within: &dyn Fn(&GeneralName<'_>) -> bool,
) -> bool {
    let mut restricted = false;
    let mut permitted = false;
    for st in &nc.permitted {
        if base_kind(&st.base) == Some(kind) {
            restricted = true;
            if within(&st.base) {
                permitted = true;
            }
        }
    }
    if restricted && !permitted {
        return false;
    }
    !nc.excluded.iter().any(|st| base_kind(&st.base) == Some(kind) && within(&st.base))
}

/// Check the names in `cert` against one CA's `NameConstraints`: the subject DN and
/// subject email when `check_subject` is set, and always the SAN.
fn name_constraints_hold(
    cert: &Certificate<'_>,
    san: Option<&GeneralNames<'_>>,
    nc: &NameConstraints<'_>,
    check_subject: bool,
) -> bool {
    let subject = &cert.tbs.subject;
    if check_subject {
        if !subject.is_empty()
            && !constrained(
                nc,
                NameKind::Dn,
                &|b| matches!(b, GeneralName::DirectoryName(base) if subject.within_subtree(base, 0)),
            )
        {
            return false;
        }
        if let Some(email) = subject.find(EMAIL_ADDRESS).map(|v| v.as_bytes()) {
            if !email_ok(nc, email) {
                return false;
            }
        }
    }
    for name in san.iter().flat_map(|s| s.names.iter()) {
        let ok = match name {
            GeneralName::DnsName(d) => constrained(
                nc,
                NameKind::Dns,
                &|b| matches!(b, GeneralName::DnsName(base) if dns_within(d, base)),
            ),
            GeneralName::Rfc822Name(e) => email_ok(nc, e),
            GeneralName::Uri(u) => match uri_host(u) {
                Some(host) => constrained(
                    nc,
                    NameKind::Uri,
                    &|b| matches!(b, GeneralName::Uri(base) if host_within(host, base)),
                ),
                // A URI with no host is outside any URI constraint.
                None => nc.permitted.iter().all(|st| base_kind(&st.base) != Some(NameKind::Uri)),
            },
            GeneralName::IpAddress(a) => constrained(
                nc,
                NameKind::Ip,
                &|b| matches!(b, GeneralName::IpAddress(base) if ip_within(a, base)),
            ),
            GeneralName::DirectoryName(n) => constrained(
                nc,
                NameKind::Dn,
                &|b| matches!(b, GeneralName::DirectoryName(base) if n.within_subtree(base, 0)),
            ),
            _ => true,
        };
        if !ok {
            return false;
        }
    }
    true
}

fn email_ok(nc: &NameConstraints<'_>, email: &[u8]) -> bool {
    constrained(
        nc,
        NameKind::Email,
        &|b| matches!(b, GeneralName::Rfc822Name(base) if email_within(email, base)),
    )
}

/// RFC 5280 §4.2.1.10 for an rfc822Name: a constraint containing `@` names one
/// mailbox; otherwise it names a host, and every mailbox at that host (or a
/// subdomain of it) is within the constraint.
fn email_within(email: &[u8], base: &[u8]) -> bool {
    let Some(at) = email.iter().rposition(|&b| b == b'@') else {
        return false;
    };
    let (local, domain) = (&email[..at], &email[at + 1..]);
    if base.contains(&b'@') {
        let Some(bat) = base.iter().rposition(|&b| b == b'@') else {
            return false;
        };
        local == &base[..bat] && domain.eq_ignore_ascii_case(&base[bat + 1..])
    } else {
        host_within(domain, base)
    }
}

/// Host matching for rfc822 and URI constraints (RFC 5280 §4.2.1.10): a bare host
/// matches only itself, and a leading dot matches only proper subdomains.
fn host_within(host: &[u8], base: &[u8]) -> bool {
    match base.strip_prefix(b".") {
        Some(_) => host.len() > base.len() && ends_with_ignore_case(host, base),
        None => host.eq_ignore_ascii_case(base),
    }
}

fn ends_with_ignore_case(s: &[u8], suffix: &[u8]) -> bool {
    s.len() >= suffix.len() && s[s.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// The host component of a URI (`scheme://[userinfo@]host[:port]/...`), if any.
fn uri_host(uri: &[u8]) -> Option<&[u8]> {
    let start = uri.windows(3).position(|w| w == b"://")? + 3;
    let rest = &uri[start..];
    let authority_end =
        rest.iter().position(|&b| b == b'/' || b == b'?' || b == b'#').unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host_port = match authority.iter().rposition(|&b| b == b'@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    let host = match host_port.iter().position(|&b| b == b':') {
        Some(colon) => &host_port[..colon],
        None => host_port,
    };
    (!host.is_empty()).then_some(host)
}

fn dns_within(child: &[u8], parent: &[u8]) -> bool {
    // A leading dot names proper subdomains only.
    if parent.first() == Some(&b'.') {
        return child.len() > parent.len() && ends_with_ignore_case(child, parent);
    }
    // child is within parent if it equals parent or ends with "." + parent.
    // DNS names compare case-insensitively (RFC 1035); a name constraint
    // naming "example.com" also covers "Example.COM".
    if child.len() < parent.len() {
        return false;
    }
    if child.eq_ignore_ascii_case(parent) {
        return true;
    }
    if child.len() == parent.len() {
        return false;
    }
    let off = child.len() - parent.len();
    child[off - 1] == b'.' && child[off..].eq_ignore_ascii_case(parent)
}

fn ip_within(child: &[u8], parent: &[u8]) -> bool {
    // A name-constraint iPAddress is `[address][mask]` (8 octets for IPv4,
    // 32 for IPv6, RFC 5280 §4.2.1.10); a SAN iPAddress is the bare address
    // (4 or 16 octets). Match the address's bits set in the mask. A bare
    // constraint of the same size as the child is an exact-address match.
    match (child.len(), parent.len()) {
        (4, 8) => masked_ip_match(child, &parent[..4], &parent[4..]),
        (16, 32) => masked_ip_match(child, &parent[..16], &parent[16..]),
        (n, m) if n == m => child == parent,
        _ => false,
    }
}

fn masked_ip_match(child: &[u8], addr: &[u8], mask: &[u8]) -> bool {
    child.iter().zip(addr.iter().zip(mask.iter())).all(|(c, (a, m))| c & m == a & m)
}
