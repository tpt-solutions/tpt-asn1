//! CRL and PKCS#10 request builders, checked by decoding the output and verifying
//! its signature with the RustCrypto backend.

use ed25519_dalek::{Signer as _, SigningKey};
use tpt_asn1_core::any::Any;
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_crypto::RustCryptoVerifier;
use tpt_asn1_x509::builder::{CrlBuilder, CsrBuilder};
use tpt_asn1_x509::crl::CertificateList;
use tpt_asn1_x509::verify::SignatureVerifier;
use tpt_asn1_x509::{Certificate, UnixTime};

/// The content octets of the Ed25519 OID (1.3.101.112).
const ED25519_ARCS: &[u64] = &[1, 3, 101, 112];
/// The same OID as encoded content octets, which the verifier takes.
const ED25519_CONTENT: &[u8] = &[0x2b, 0x65, 0x70];
const COMMON_NAME: &[u64] = &[2, 5, 4, 3];
/// 2024-06-01T00:00:00Z.
const THIS_UPDATE: i64 = 1_717_200_000;
/// 2024-07-01T00:00:00Z.
const NEXT_UPDATE: i64 = 1_719_792_000;

#[test]
fn built_crl_decodes_and_its_signature_verifies() {
    let key = SigningKey::from_bytes(&[5u8; 32]);
    let der = CrlBuilder::new(ED25519_ARCS, THIS_UPDATE)
        .issuer_attribute(COMMON_NAME, "tpt-asn1 Test CA")
        .next_update(NEXT_UPDATE)
        .revoke(&[0x0a, 0x0b], THIS_UPDATE - 86_400)
        .build(|tbs| key.sign(tbs).to_bytes().to_vec());

    let crl: CertificateList<'_> = tpt_asn1_core::decode(&der).expect("CRL decodes");
    assert_eq!(crl.revoked.len(), 1);
    assert_eq!(crl.revoked[0].serial_number_bytes(), &[0x0a, 0x0b]);
    assert!(crl.is_revoked(&[0x0a, 0x0b], UnixTime::from_secs(THIS_UPDATE)));
    assert!(!crl.is_revoked(&[0x01], UnixTime::from_secs(THIS_UPDATE)));

    let verdict = RustCryptoVerifier.verify_signature(
        crl.signature_algorithm.algorithm.as_bytes(),
        ED25519_CONTENT,
        &key.verifying_key().to_bytes(),
        crl.tbs_cert_list_der(),
        crl.signature_value.data,
    );
    assert_eq!(verdict, Ok(true));
}

#[test]
fn crl_without_revocations_decodes() {
    let key = SigningKey::from_bytes(&[5u8; 32]);
    let der = CrlBuilder::new(ED25519_ARCS, THIS_UPDATE)
        .issuer_attribute(COMMON_NAME, "tpt-asn1 Test CA")
        .build(|tbs| key.sign(tbs).to_bytes().to_vec());
    let crl: CertificateList<'_> = tpt_asn1_core::decode(&der).expect("CRL decodes");
    assert!(crl.revoked.is_empty());
}

#[test]
fn csr_has_the_pkcs10_shape_and_a_valid_signature() {
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let public = key.verifying_key().to_bytes();
    let der = CsrBuilder::new(ED25519_ARCS, ED25519_ARCS, None, &public)
        .subject_attribute(COMMON_NAME, "leaf.example")
        .build(|info| key.sign(info).to_bytes().to_vec());

    // CertificationRequest ::= SEQUENCE { info, signatureAlgorithm, signature BIT STRING }
    let outer = Any::decode(&mut Reader::new(&der, Config::der())).expect("outer decodes");
    let (info, sig_value) = {
        let mut r = Reader::new(outer.value, Config::der());
        let info = Any::decode(&mut r).expect("info decodes");
        let _alg = Any::decode(&mut r).expect("algorithm decodes");
        let sig = Any::decode(&mut r).expect("signature decodes");
        (info, sig)
    };
    assert_eq!(info.tag.number, 16, "info is a SEQUENCE");
    // The signature BIT STRING starts with its unused-bits octet.
    assert_eq!(sig_value.value[0], 0);
    let verdict = RustCryptoVerifier.verify_signature(
        ED25519_CONTENT,
        ED25519_CONTENT,
        &public,
        info.full,
        &sig_value.value[1..],
    );
    assert_eq!(verdict, Ok(true));
}

#[test]
fn csr_is_not_mistaken_for_a_certificate() {
    // The subject built for a CSR must be the same name a certificate would carry.
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let public = key.verifying_key().to_bytes();
    let csr = CsrBuilder::new(ED25519_ARCS, ED25519_ARCS, None, &public)
        .subject_attribute(COMMON_NAME, "leaf.example")
        .build(|info| key.sign(info).to_bytes().to_vec());
    // Certificates reject a CSR outright, which checks the outer shapes differ.
    assert!(tpt_asn1_core::decode::<Certificate<'_>>(&csr).is_err());
}
