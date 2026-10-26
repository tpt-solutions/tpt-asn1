//! Build certificates with `tpt_asn1_x509::builder`, then decode them and verify the
//! signatures with the RustCrypto backend. This checks the encoder against the
//! decoder and against an independent signature check.

use ed25519_dalek::{Signer as _, SigningKey};
use tpt_asn1_crypto::RustCryptoVerifier;
use tpt_asn1_x509::builder::{usage, CertificateBuilder};
use tpt_asn1_x509::extensions::key_usage_bit;
use tpt_asn1_x509::verify::SignatureVerifier;
use tpt_asn1_x509::{Certificate, UnixTime};

const ED25519: &[u64] = &[1, 3, 101, 112];
const COMMON_NAME: &[u64] = &[2, 5, 4, 3];
/// 2024-01-01T00:00:00Z and 2025-01-01T00:00:00Z.
const NOT_BEFORE: i64 = 1_704_067_200;
const NOT_AFTER: i64 = 1_735_689_600;

fn ca_certificate(key: &SigningKey) -> Vec<u8> {
    let public = key.verifying_key().to_bytes();
    CertificateBuilder::new(&[0x01, 0x23], ED25519)
        .issuer_attribute(COMMON_NAME, "tpt-asn1 Test CA")
        .subject_attribute(COMMON_NAME, "tpt-asn1 Test CA")
        .validity(NOT_BEFORE, NOT_AFTER)
        .public_key(ED25519, None, &public)
        .basic_constraints(true, Some(0))
        .key_usage(usage::KEY_CERT_SIGN | usage::CRL_SIGN)
        .build(|tbs| key.sign(tbs).to_bytes().to_vec())
}

#[test]
fn built_ca_certificate_decodes_with_the_expected_fields() {
    let key = SigningKey::from_bytes(&[3u8; 32]);
    let der = ca_certificate(&key);
    let cert: Certificate<'_> = tpt_asn1_core::decode(&der).expect("certificate decodes");

    assert_eq!(cert.subject().rdns().len(), 1);
    assert_eq!(cert.serial_number().as_bytes(), &[0x01, 0x23]);
    assert!(cert.tbs.is_ca(), "basicConstraints must mark a CA");
    assert!(cert.is_valid_at(UnixTime::from_secs(NOT_BEFORE + 1)));
    assert!(!cert.is_valid_at(UnixTime::from_secs(NOT_AFTER + 1)));

    let ku = cert.tbs.extensions.key_usage().expect("keyUsage decodes").expect("keyUsage present");
    assert!(ku.is_set(key_usage_bit::KEY_CERT_SIGN));
    assert!(ku.is_set(key_usage_bit::CRL_SIGN));
    assert!(!ku.is_set(key_usage_bit::DIGITAL_SIGNATURE));
}

#[test]
fn built_certificate_signature_verifies_with_rustcrypto() {
    let key = SigningKey::from_bytes(&[3u8; 32]);
    let der = ca_certificate(&key);
    let cert: Certificate<'_> = tpt_asn1_core::decode(&der).expect("certificate decodes");
    let spki = &cert.tbs.subject_public_key_info;
    let verdict = RustCryptoVerifier.verify_signature(
        cert.signature_algorithm.algorithm.as_bytes(),
        spki.algorithm.algorithm.as_bytes(),
        spki.subject_public_key.data,
        cert.tbs_certificate_der(),
        cert.signature_value.data,
    );
    assert_eq!(verdict, Ok(true));
}

#[test]
fn built_certificate_is_a_valid_one_anchor_path() {
    use tpt_asn1_x509::chain::{build_and_validate, PathConfig, TrustAnchor};

    let key = SigningKey::from_bytes(&[3u8; 32]);
    let der: &'static [u8] = Box::leak(ca_certificate(&key).into_boxed_slice());
    let cert: &'static Certificate<'static> =
        Box::leak(Box::new(tpt_asn1_core::decode::<Certificate<'static>>(der).expect("decodes")));
    let anchors: &'static [TrustAnchor<'static>] =
        Box::leak(vec![TrustAnchor::from_cert(cert)].into_boxed_slice());
    let verifier = RustCryptoVerifier;
    let config = PathConfig {
        time: UnixTime::from_secs(NOT_BEFORE + 1),
        verifier: &verifier,
        max_path_length: None,
        check_revocation: false,
        crls: &[],
        initial_policy_set: &[],
        initial_explicit_policy: false,
        initial_policy_mapping_inhibit: false,
        initial_inhibit_any_policy: false,
    };
    // A self-signed trust anchor is its own target: the path is just the anchor.
    let result = build_and_validate(cert, &[], anchors, config);
    assert!(result.is_ok(), "self-signed anchor validates: {result:?}");
}
