// SPDX-License-Identifier: MIT OR Apache-2.0

//! OCSP response signature plumbing: the signature must cover the raw
//! `tbsResponseData`, use the responder's key, and the responder must be
//! authorized for the issuer.

#![allow(clippy::expect_used, clippy::panic)]

use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_x509::algorithm::AlgorithmIdentifier;
use tpt_asn1_x509::certificate::Certificate;
use tpt_asn1_x509::ocsp::{is_authorized_responder, verify_response_signature, BasicOcspResponse};
use tpt_asn1_x509::verify::{SignatureVerifier, VerifyError};

const CERT_A: &[u8] =
    include_bytes!("../tests/umbrella_corpus/1.courier-push-apple.com.akadns.net_.der");
const CERT_B: &[u8] = include_bytes!("../tests/umbrella_corpus/1.cpm.ak-is2.net_.der");

fn cert(der: &[u8]) -> Certificate<'_> {
    let Ok(cert) = Certificate::decode(&mut Reader::new(der, Config::der())) else {
        panic!("fixture must decode");
    };
    cert
}

/// Accepts exactly one (public key, message) pair with signature `b"sig"`.
struct Expect<'a> {
    key: &'a [u8],
    message: &'a [u8],
}

impl SignatureVerifier for Expect<'_> {
    fn digest(&self, _alg_oid: &[u8], _data: &[u8]) -> Result<Vec<u8>, VerifyError> {
        Err(VerifyError::UnsupportedAlgorithm)
    }

    fn verify_signature(
        &self,
        _sig_alg_oid: &[u8],
        _key_alg_oid: &[u8],
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, VerifyError> {
        Ok(public_key == self.key && message == self.message && signature == b"sig")
    }
}

/// ed25519 AlgorithmIdentifier: SEQUENCE { OID 1.3.101.112 }.
const ED25519_ALG: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

fn basic_response(tbs: &[u8]) -> BasicOcspResponse<'_> {
    let Ok(signature_algorithm) =
        AlgorithmIdentifier::decode(&mut Reader::new(ED25519_ALG, Config::der()))
    else {
        panic!("algorithm identifier must decode");
    };
    BasicOcspResponse {
        tbs_response_data_der: tbs,
        signature_algorithm,
        signature: b"sig",
        responses: Vec::new(),
    }
}

#[test]
fn signature_covers_tbs_bytes_with_the_responder_key() {
    let responder = cert(CERT_A);
    let key = responder.tbs.subject_public_key_info.subject_public_key.data;
    let tbs = b"tbsResponseData";
    let basic = basic_response(tbs);

    let good = Expect { key, message: tbs };
    assert_eq!(verify_response_signature(&basic, &responder, &good), Ok(true));

    let wrong_message = Expect { key, message: b"something else" };
    assert_eq!(verify_response_signature(&basic, &responder, &wrong_message), Ok(false));

    let wrong_key = Expect { key: &[0u8; 4], message: tbs };
    assert_eq!(verify_response_signature(&basic, &responder, &wrong_key), Ok(false));
}

#[test]
fn issuer_is_an_authorized_responder_for_itself() {
    let issuer = cert(CERT_A);
    assert!(is_authorized_responder(&issuer, &issuer));
}

#[test]
fn unrelated_certificate_is_not_an_authorized_responder() {
    let responder = cert(CERT_A);
    let issuer = cert(CERT_B);
    assert!(!is_authorized_responder(&responder, &issuer));
}
