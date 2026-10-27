// SPDX-License-Identifier: MIT OR Apache-2.0

//! Data-driven NIST PKITS harness (sections 4.1–4.16).
//!
//! The case table in `pkits_suite.rs.in` is generated from the PKITS test
//! description by `tools/gen_pkits_cases.py`; the certificates and CRLs it
//! names live in `tests/pkits_data/`. Each case is run through
//! `build_and_validate` and the outcome compared with the expected result.
//!
//! This is a regression gate, not a pass-or-fail claim about full PKITS
//! conformance. `KNOWN_FAILURES` lists the subcases that still fail. The test
//! fails on any other failure, and also on any listed subcase that now passes,
//! so the list must be pruned as each gap is closed (see `todo.md`, Phase 7).
//!
//! The test-only signature backend below implements RSA PKCS#1 v1.5 with
//! SHA-1/256/384/512, and DSA with SHA-1/256.

use std::fs;
use std::path::PathBuf;

use num_bigint::BigUint;
use sha2::Digest;
use tpt_asn1_x509::chain::{build_and_validate, PathConfig, TrustAnchor};
use tpt_asn1_x509::core::decode::read_sequence;
use tpt_asn1_x509::core::reader::{Config, Reader};
use tpt_asn1_x509::core::types::Integer;
use tpt_asn1_x509::core::Decode;
use tpt_asn1_x509::crl::CertificateList;
use tpt_asn1_x509::spki::RsaPublicKey;
use tpt_asn1_x509::verify::{SignatureVerifier, VerifyError};
use tpt_asn1_x509::{decode, Certificate, UnixTime};

/// One PKITS subcase, as emitted by `tools/gen_pkits_cases.py`.
pub struct Case {
    pub id: &'static str,
    pub ee: &'static str,
    pub expect_valid: bool,
    pub explicit: bool,
    pub inhibit_mapping: bool,
    pub inhibit_any: bool,
    pub policy_set: &'static [&'static str],
    /// Trust anchor first, then intermediates and CRLs, end-entity last.
    pub path: &'static [&'static str],
}

include!("pkits_suite.rs.in");

/// Validation time: 2026-10-26 00:00:00 UTC. The fixtures are valid until 2030,
/// and the PKITS cases that expect rejection for an expired certificate (4.2.5,
/// 4.2.6) use a notAfter of 2011, so the run must be later than that.
const VALIDATION_TIME: UnixTime = UnixTime(1_792_972_800);

// --- Test-only RSA backend -------------------------------------------------

const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

#[derive(Clone, Copy)]
enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    /// DER `DigestInfo` prefix (RFC 8017 §9.2 Note 1) for this hash, excluding the digest.
    fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            Hash::Sha1 => &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14,
            ],
            Hash::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Hash::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            Hash::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }

    fn compute(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Hash::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Hash::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Hash::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

/// Map a digest-algorithm OID (raw content octets) to a hash.
fn digest_hash(oid: &[u8]) -> Option<Hash> {
    match oid {
        [0x2b, 0x0e, 0x03, 0x02, 0x1a] => Some(Hash::Sha1),
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => Some(Hash::Sha256),
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02] => Some(Hash::Sha384),
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03] => Some(Hash::Sha512),
        _ => None,
    }
}

/// Map an `*WithRSAEncryption` signature OID to its hash.
fn rsa_signature_hash(oid: &[u8]) -> Option<Hash> {
    match oid {
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05] => Some(Hash::Sha1),
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b] => Some(Hash::Sha256),
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c] => Some(Hash::Sha384),
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d] => Some(Hash::Sha512),
        _ => None,
    }
}

/// id-dsa — 1.2.840.10040.4.1.
const DSA_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01];

/// Map a DSA signature OID to its hash: dsa-with-sha1 (1.2.840.10040.4.3) and
/// dsa-with-sha256 (2.16.840.1.101.3.4.3.2).
fn dsa_signature_hash(oid: &[u8]) -> Option<Hash> {
    match oid {
        [0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x03] => Some(Hash::Sha1),
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02] => Some(Hash::Sha256),
        _ => None,
    }
}

/// Parse `Dss-Parms ::= SEQUENCE { p, q, g }`.
fn dss_params(der: &[u8]) -> Result<(BigUint, BigUint, BigUint), VerifyError> {
    let mut r = Reader::new(der, Config::der());
    read_sequence(&mut r, |s| {
        let p = Integer::decode(s)?;
        let q = Integer::decode(s)?;
        let g = Integer::decode(s)?;
        Ok((
            BigUint::from_bytes_be(p.as_bytes()),
            BigUint::from_bytes_be(q.as_bytes()),
            BigUint::from_bytes_be(g.as_bytes()),
        ))
    })
    .map_err(|_| VerifyError::InvalidKey)
}

/// FIPS 186-4 §4.7 DSA verification. `params` must be the key's `Dss-Parms`,
/// possibly inherited from the issuer (RFC 5280 §7.3.3).
fn dsa_verify(
    hash: Hash,
    params: Option<&[u8]>,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    let (p, q, g) = dss_params(params.ok_or(VerifyError::InvalidKey)?)?;
    let y = BigUint::from_bytes_be(
        decode::<Integer<'_>>(public_key).map_err(|_| VerifyError::InvalidKey)?.as_bytes(),
    );
    let mut r_in = Reader::new(signature, Config::der());
    let (r, s) = read_sequence(&mut r_in, |s| {
        let r = Integer::decode(s)?;
        let sv = Integer::decode(s)?;
        Ok((BigUint::from_bytes_be(r.as_bytes()), BigUint::from_bytes_be(sv.as_bytes())))
    })
    .map_err(|_| VerifyError::InvalidSignature)?;

    if r == BigUint::from(0u32) || r >= q || s == BigUint::from(0u32) || s >= q {
        return Ok(false);
    }

    // z is the leftmost min(|q|, |hash|) bits of the digest.
    let digest = hash.compute(message);
    let mut z = BigUint::from_bytes_be(&digest);
    let (qbits, hbits) = (q.bits() as usize, digest.len() * 8);
    if hbits > qbits {
        z >>= hbits - qbits;
    }

    // q is prime, so s^-1 mod q = s^(q-2) mod q (Fermat).
    let w = s.modpow(&(q.clone() - BigUint::from(2u32)), &q);
    let u1 = (&z * &w) % &q;
    let u2 = (&r * &w) % &q;
    let v = ((g.modpow(&u1, &p) * y.modpow(&u2, &p)) % &p) % &q;
    Ok(v == r)
}

struct PkitsCrypto;

impl SignatureVerifier for PkitsCrypto {
    fn digest(&self, alg_oid: &[u8], data: &[u8]) -> Result<Vec<u8>, VerifyError> {
        digest_hash(alg_oid).map(|h| h.compute(data)).ok_or(VerifyError::UnsupportedAlgorithm)
    }

    fn verify_signature(
        &self,
        sig_alg_oid: &[u8],
        key_alg_oid: &[u8],
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, VerifyError> {
        self.verify_signature_with_params(
            sig_alg_oid,
            key_alg_oid,
            None,
            public_key,
            message,
            signature,
        )
    }

    fn verify_signature_with_params(
        &self,
        sig_alg_oid: &[u8],
        key_alg_oid: &[u8],
        key_params: Option<&[u8]>,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, VerifyError> {
        if key_alg_oid == DSA_KEY {
            let hash = dsa_signature_hash(sig_alg_oid).ok_or(VerifyError::UnsupportedAlgorithm)?;
            return dsa_verify(hash, key_params, public_key, message, signature);
        }
        if key_alg_oid != RSA_ENCRYPTION {
            return Err(VerifyError::UnsupportedAlgorithm);
        }
        let hash = rsa_signature_hash(sig_alg_oid).ok_or(VerifyError::UnsupportedAlgorithm)?;
        let key: RsaPublicKey<'_> = decode(public_key).map_err(|_| VerifyError::InvalidKey)?;
        let n = BigUint::from_bytes_be(key.modulus.as_bytes());
        let e = BigUint::from_bytes_be(key.public_exponent.as_bytes());
        let s = BigUint::from_bytes_be(signature);
        if n.bits() == 0 || s >= n {
            return Ok(false);
        }
        let k = n.to_bytes_be().len();

        // EMSA-PKCS1-v1_5 encoding: 00 01 FF..FF 00 || DigestInfo || digest.
        let digest = hash.compute(message);
        let prefix = hash.digest_info_prefix();
        let t_len = prefix.len() + digest.len();
        if k < t_len + 11 {
            return Ok(false);
        }
        let mut expected = vec![0u8; k];
        expected[1] = 0x01;
        let pad_end = k - t_len - 1;
        for b in &mut expected[2..pad_end] {
            *b = 0xff;
        }
        expected[pad_end + 1..pad_end + 1 + prefix.len()].copy_from_slice(prefix);
        expected[k - digest.len()..].copy_from_slice(&digest);

        let em = s.modpow(&e, &n).to_bytes_be();
        let mut padded = vec![0u8; k - em.len()];
        padded.extend_from_slice(&em);
        Ok(padded == expected)
    }
}

// --- Policies --------------------------------------------------------------

/// Map a PKITS policy name to its OID content octets. The NIST test policies are
/// 2.16.840.1.101.3.2.1.48.N (N = 1..=6).
fn nist_policy_oid(name: &str) -> Result<&'static [u8], String> {
    const POLICIES: [&[u8]; 6] = [
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x30, 0x01],
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x30, 0x02],
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x30, 0x03],
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x30, 0x04],
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x30, 0x05],
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x30, 0x06],
    ];
    (1..=POLICIES.len())
        .find(|n| name == format!("NIST-test-policy-{n}"))
        .map(|n| POLICIES[n - 1])
        .ok_or_else(|| format!("unknown policy {name}"))
}

// --- Fixture loading -------------------------------------------------------

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("pkits_data")
}

/// Load `certs/<name>` or `crls/<name>` bytes, leaked to `'static` for the test run.
fn load(item: &str) -> Result<&'static [u8], String> {
    let (dir, ext) = match item.split_once('/') {
        Some(("certs", _)) => ("certs", "crt"),
        Some(("crls", _)) => ("crls", "crl"),
        _ => return Err(format!("bad path item {item}")),
    };
    let name = item.split_once('/').map(|(_, n)| n).unwrap_or(item);
    let path = data_dir().join(dir).join(format!("{name}.{ext}"));
    let bytes = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(Box::leak(bytes.into_boxed_slice()))
}

fn load_cert(item: &str) -> Result<Certificate<'static>, String> {
    let der = load(item)?;
    decode::<Certificate<'static>>(der).map_err(|e| format!("decode {item}: {e:?}"))
}

// --- Runner ----------------------------------------------------------------

/// Build and validate the case's path, returning the rejection reason if any.
/// A fixture that fails to decode is a rejection: the decoders fail closed.
fn validate(case: &Case) -> Result<(), String> {
    let (anchor_item, rest) = case.path.split_first().ok_or("empty path")?;
    let anchor_cert: &'static Certificate<'static> = Box::leak(Box::new(load_cert(anchor_item)?));
    let anchors: &'static [TrustAnchor<'static>] =
        Box::leak(vec![TrustAnchor::from_cert(anchor_cert)].into_boxed_slice());

    let cert_items: Vec<&str> = rest.iter().copied().filter(|p| p.starts_with("certs/")).collect();
    let (ee_item, inter_items) = cert_items.split_last().ok_or("no end-entity certificate")?;

    let intermediates: Vec<Certificate<'static>> =
        inter_items.iter().map(|p| load_cert(p)).collect::<Result<_, _>>()?;
    let intermediates: &'static [Certificate<'static>] =
        Box::leak(intermediates.into_boxed_slice());
    let target: &'static Certificate<'static> = Box::leak(Box::new(load_cert(ee_item)?));

    let crls: Vec<CertificateList<'static>> = rest
        .iter()
        .filter(|p| p.starts_with("crls/"))
        .map(|p| {
            let der = load(p)?;
            decode::<CertificateList<'static>>(der).map_err(|e| format!("decode {p}: {e:?}"))
        })
        .collect::<Result<_, String>>()?;
    let crls: &'static [CertificateList<'static>] = Box::leak(crls.into_boxed_slice());

    let policy_set: Vec<&'static [u8]> =
        case.policy_set.iter().map(|name| nist_policy_oid(name)).collect::<Result<_, _>>()?;
    let policy_set: &'static [&'static [u8]] = Box::leak(policy_set.into_boxed_slice());

    let config = PathConfig {
        time: VALIDATION_TIME,
        verifier: &PkitsCrypto,
        max_path_length: None,
        check_revocation: true,
        crls,
        initial_policy_set: policy_set,
        initial_explicit_policy: case.explicit,
        initial_policy_mapping_inhibit: case.inhibit_mapping,
        initial_inhibit_any_policy: case.inhibit_any,
        extended_key_usage: None,
    };
    build_and_validate(target, intermediates, anchors, config)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Run one subcase. `Ok` means the actual outcome matched the expected one.
fn run_case(case: &Case) -> Result<(), String> {
    match (case.expect_valid, validate(case)) {
        (true, Ok(())) | (false, Err(_)) => Ok(()),
        (true, Err(e)) => Err(format!("expected valid, got {e}")),
        (false, Ok(())) => Err("expected rejection, path validated".to_string()),
    }
}

/// PKITS subcases this validator does not yet pass, as `"<id> <ee> <valid|rejection>"`
/// (one entry per failing subcase). Each group names an open gap. The gate fails on
/// any failure missing from this list, and on any entry that now passes, so the list
/// is pruned as each gap is closed.
const KNOWN_FAILURES: &[&str] = &[
    // CRL signing by a separate CRL-only certificate (PKITS §4.4).
    "4.4.19 ValidSeparateCertificateandCRLKeysTest19EE valid",
];

/// The entries of `a` that are not matched by an entry of `b`, counting duplicates.
fn multiset_difference(a: &[String], b: &[String]) -> Vec<String> {
    let mut remaining = b.to_vec();
    let mut out = Vec::new();
    for x in a {
        match remaining.iter().position(|y| y == x) {
            Some(i) => {
                remaining.swap_remove(i);
            }
            None => out.push(x.clone()),
        }
    }
    out
}

#[test]
fn pkits_suite() {
    let mut actual = Vec::new();
    let mut messages = Vec::new();
    for case in CASES {
        if let Err(why) = run_case(case) {
            let kind = if case.expect_valid { "valid" } else { "rejection" };
            actual.push(format!("{} {} {kind}", case.id, case.ee));
            messages.push(format!("  FAIL {} ({}): {why}", case.id, case.ee));
        }
    }
    let expected: Vec<String> = KNOWN_FAILURES.iter().map(|s| s.to_string()).collect();
    let total = CASES.len();
    eprintln!(
        "PKITS: {} passed, {} failed, {total} total ({} known failures)",
        total - actual.len(),
        actual.len(),
        expected.len()
    );

    let new_failures = multiset_difference(&actual, &expected);
    let now_passing = multiset_difference(&expected, &actual);
    for m in &messages {
        eprintln!("{m}");
    }
    assert!(
        new_failures.is_empty() && now_passing.is_empty(),
        "PKITS regression gate: new failures {new_failures:?}; known failures now passing {now_passing:?}"
    );
}
