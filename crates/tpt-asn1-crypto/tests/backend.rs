//! Tests for the RustCrypto verifier: a real RSA certificate from the PKITS
//! fixtures, and generated ECDSA and Ed25519 signatures.

use ed25519_dalek::{Signer as _, SigningKey};
use tpt_asn1_crypto::RustCryptoVerifier;
use tpt_asn1_x509::oid;
use tpt_asn1_x509::verify::{SignatureVerifier, VerifyError};
use tpt_asn1_x509::Certificate;

/// DER content octets of an OID given as arcs (what the verifier receives).
fn oid_content(arcs: &[u64]) -> Vec<u8> {
    let mut out = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut groups = vec![(arc & 0x7f) as u8];
        let mut rest = arc >> 7;
        while rest > 0 {
            groups.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        groups.reverse();
        out.extend(groups);
    }
    out
}

#[test]
fn sha256_digest_matches_known_vector() {
    let digest = RustCryptoVerifier
        .digest(&oid_content(oid::digest::SHA256), b"abc")
        .expect("SHA-256 is supported");
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

#[test]
fn rsa_signature_on_pkits_certificate_verifies() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tpt-asn1-x509/tests/pkits_data/certs/TrustAnchorRootCertificate.crt"
    );
    let der = std::fs::read(path).expect("PKITS fixture present");
    let cert: Certificate<'_> = tpt_asn1_core::decode(&der).expect("certificate decodes");
    let spki = &cert.tbs.subject_public_key_info;
    let ok = RustCryptoVerifier
        .verify_signature(
            cert.signature_algorithm.algorithm.as_bytes(),
            spki.algorithm.algorithm.as_bytes(),
            spki.subject_public_key.data,
            cert.tbs_certificate_der(),
            cert.signature_value.data,
        )
        .expect("supported algorithm");
    assert!(ok, "self-signature of the trust anchor must verify");

    // Flipping one byte of the signed data must fail verification.
    let mut tampered = cert.tbs_certificate_der().to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let ok = RustCryptoVerifier
        .verify_signature(
            cert.signature_algorithm.algorithm.as_bytes(),
            spki.algorithm.algorithm.as_bytes(),
            spki.subject_public_key.data,
            &tampered,
            cert.signature_value.data,
        )
        .expect("supported algorithm");
    assert!(!ok);
}

#[test]
fn ed25519_round_trip_and_tamper() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let public = key.verifying_key().to_bytes();
    let message = b"tpt-asn1 ed25519";
    let sig = key.sign(message).to_bytes();
    let verify = |msg: &[u8]| {
        RustCryptoVerifier.verify_signature(
            &oid_content(oid::sig::ED25519),
            &oid_content(oid::pk::ED25519),
            &public,
            msg,
            &sig,
        )
    };
    assert_eq!(verify(message), Ok(true));
    assert_eq!(verify(b"tpt-asn1 ed25519!"), Ok(false));
}

#[test]
fn ecdsa_p256_sha256_round_trip() {
    let key = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).expect("valid scalar");
    let message = b"ecdsa p-256";
    let sig: p256::ecdsa::Signature = key.sign(message);
    let public = key.verifying_key().to_encoded_point(false);
    let ok = RustCryptoVerifier.verify_signature(
        &oid_content(oid::sig::SHA256_ECDSA),
        &oid_content(oid::pk::EC),
        public.as_bytes(),
        message,
        sig.to_der().as_bytes(),
    );
    assert_eq!(ok, Ok(true));
}

#[test]
fn ecdsa_p384_sha384_round_trip() {
    let key = p384::ecdsa::SigningKey::from_slice(&[9u8; 48]).expect("valid scalar");
    let message = b"ecdsa p-384";
    let sig: p384::ecdsa::Signature = key.sign(message);
    let public = key.verifying_key().to_encoded_point(false);
    let ok = RustCryptoVerifier.verify_signature(
        &oid_content(oid::sig::SHA384_ECDSA),
        &oid_content(oid::pk::EC),
        public.as_bytes(),
        message,
        sig.to_der().as_bytes(),
    );
    assert_eq!(ok, Ok(true));
}

#[test]
fn malformed_signature_fails_closed_without_error() {
    let public = SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_bytes();
    let ok = RustCryptoVerifier.verify_signature(
        &oid_content(oid::sig::ED25519),
        &oid_content(oid::pk::ED25519),
        &public,
        b"msg",
        &[0u8; 3],
    );
    assert_eq!(ok, Ok(false));
}

#[test]
fn unsupported_algorithm_is_reported() {
    let result = RustCryptoVerifier.verify_signature(&oid_content(&[1, 2, 3]), &[], &[], b"", b"");
    assert_eq!(result, Err(VerifyError::UnsupportedAlgorithm));
}
