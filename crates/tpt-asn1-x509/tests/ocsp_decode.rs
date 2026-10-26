//! Regression tests for RFC 6960 structures. The fixtures are hand-built DER so
//! each optional field that real responders send is present.

use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_x509::ocsp::{BasicOcspResponse, CertStatus, OcspResponse, SingleResponse};

/// Encode one TLV. Handles the short and one-byte long forms of length.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else {
        out.push(0x81);
        out.push(content.len() as u8);
    }
    out.extend_from_slice(content);
    out
}

fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

fn generalized_time(s: &str) -> Vec<u8> {
    tlv(0x18, s.as_bytes())
}

fn sha1_alg() -> Vec<u8> {
    tlv(0x30, &concat(&[tlv(0x06, &[0x2b, 0x0e, 0x03, 0x02, 0x1a]), tlv(0x05, &[])]))
}

fn cert_id() -> Vec<u8> {
    tlv(0x30, &concat(&[sha1_alg(), tlv(0x04, &[0xaa]), tlv(0x04, &[0xbb]), tlv(0x02, &[0x05])]))
}

/// `revoked [1] IMPLICIT RevokedInfo` with reason keyCompromise (1).
fn revoked_status() -> Vec<u8> {
    tlv(0xa1, &concat(&[generalized_time("20260101000000Z"), tlv(0xa0, &tlv(0x0a, &[0x01]))]))
}

fn good_status() -> Vec<u8> {
    tlv(0x80, &[])
}

/// A `SingleResponse` with `nextUpdate [0] EXPLICIT`.
fn single_response(status: &[u8]) -> Vec<u8> {
    tlv(
        0x30,
        &concat(&[
            cert_id(),
            status.to_vec(),
            generalized_time("20260101000000Z"),
            tlv(0xa0, &generalized_time("20260102000000Z")),
        ]),
    )
}

#[test]
fn single_response_with_next_update_and_reason_decodes() {
    let bytes = single_response(&revoked_status());
    let mut r = Reader::new(&bytes, Config::der());
    let sr = SingleResponse::decode(&mut r).expect("SingleResponse must decode");
    assert!(matches!(sr.cert_status, CertStatus::Revoked { reason: Some(1), .. }));
    assert!(sr.next_update.is_some());
}

#[test]
fn single_response_good_without_optional_fields_decodes() {
    let bytes =
        tlv(0x30, &concat(&[cert_id(), good_status(), generalized_time("20260101000000Z")]));
    let mut r = Reader::new(&bytes, Config::der());
    let sr = SingleResponse::decode(&mut r).expect("minimal SingleResponse must decode");
    assert_eq!(sr.cert_status, CertStatus::Good);
    assert!(sr.next_update.is_none());
}

#[test]
fn basic_response_with_certs_and_bitstring_signature_decodes() {
    let tbs = tlv(
        0x30,
        &concat(&[
            // responderID byKey [2] EXPLICIT KeyHash
            tlv(0xa2, &tlv(0x04, &[0xaa])),
            generalized_time("20260101000000Z"),
            tlv(0x30, &single_response(&good_status())),
        ]),
    );
    let basic = tlv(
        0x30,
        &concat(&[
            tbs.clone(),
            sha1_alg(),
            // BIT STRING: 0 unused bits, signature AA BB
            tlv(0x03, &[0x00, 0xaa, 0xbb]),
            // certs [0] EXPLICIT SEQUENCE OF Certificate (empty here)
            tlv(0xa0, &tlv(0x30, &[])),
        ]),
    );
    let mut r = Reader::new(&basic, Config::der());
    let resp = BasicOcspResponse::decode(&mut r).expect("BasicOCSPResponse must decode");
    assert_eq!(resp.signature, &[0xaa, 0xbb]);
    assert_eq!(resp.responses.len(), 1);
    assert_eq!(resp.tbs_response_data_der, tbs.as_slice());
}

#[test]
fn ocsp_response_with_response_bytes_decodes() {
    // OCSPResponse { responseStatus successful, responseBytes [0] EXPLICIT {...} }
    let response_bytes = tlv(
        0x30,
        &concat(&[
            // id-pkix-ocsp-basic
            tlv(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]),
            tlv(0x04, &[]),
        ]),
    );
    let bytes = tlv(0x30, &concat(&[tlv(0x0a, &[0x00]), tlv(0xa0, &response_bytes)]));
    let mut r = Reader::new(&bytes, Config::der());
    let resp = OcspResponse::decode(&mut r).expect("OCSPResponse must decode");
    assert_eq!(resp.status, 0);
    let rb = resp.response_bytes.expect("responseBytes must be present");
    assert_eq!(rb.response_type.len(), 9);
}
