//! End-to-end: build and validate a PKITS certification path with the real
//! RustCrypto backend, instead of the test-only backend used by the harness.

use tpt_asn1_core::decode;
use tpt_asn1_crypto::RustCryptoVerifier;
use tpt_asn1_x509::chain::{build_and_validate, PathConfig, TrustAnchor};
use tpt_asn1_x509::{Certificate, UnixTime};

/// Same validation time the PKITS harness uses. It falls inside the fixtures' validity.
const VALIDATION_TIME: UnixTime = UnixTime(1_792_972_800);

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../tpt-asn1-x509/tests/pkits_data/certs/{name}.crt",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// Decode a leaked buffer so the certificate can be borrowed for `'static`.
fn leak_cert(der: Vec<u8>) -> &'static Certificate<'static> {
    let bytes: &'static [u8] = Box::leak(der.into_boxed_slice());
    Box::leak(Box::new(decode::<Certificate<'static>>(bytes).expect("certificate decodes")))
}

fn validate(ee_der: Vec<u8>) -> Result<(), String> {
    let anchor = leak_cert(fixture("TrustAnchorRootCertificate"));
    let ca = leak_cert(fixture("GoodCACert"));
    let target = leak_cert(ee_der);
    let intermediates: &'static [Certificate<'static>] = Box::leak(Box::new([ca.clone()]));
    let anchors: &'static [TrustAnchor<'static>] =
        Box::leak(vec![TrustAnchor::from_cert(anchor)].into_boxed_slice());
    let verifier = RustCryptoVerifier;
    let config = PathConfig {
        time: VALIDATION_TIME,
        verifier: &verifier,
        max_path_length: None,
        check_revocation: false,
        crls: &[],
        initial_policy_set: &[],
        initial_explicit_policy: false,
        initial_policy_mapping_inhibit: false,
        initial_inhibit_any_policy: false,
        extended_key_usage: None,
    };
    build_and_validate(target, intermediates, anchors, config)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[test]
fn pkits_valid_path_validates_with_rustcrypto() {
    validate(fixture("ValidCertificatePathTest1EE")).expect("PKITS 4.1.1 path must validate");
}

#[test]
fn pkits_path_with_corrupted_end_entity_signature_is_rejected() {
    let mut ee = fixture("ValidCertificatePathTest1EE");
    // The signature value is the last field of the certificate.
    let last = ee.len() - 1;
    ee[last] ^= 0x01;
    assert!(validate(ee).is_err(), "a corrupted signature must not validate");
}
