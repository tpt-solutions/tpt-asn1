// SPDX-License-Identifier: MIT OR Apache-2.0

//! Round trip for the OCSP request builder: what it writes must decode with the
//! crate's own `OcspRequest` parser and carry the same `CertID`s.

#![allow(clippy::expect_used, clippy::panic)]

use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_x509::builder::OcspRequestBuilder;
use tpt_asn1_x509::ocsp::OcspRequest;
use tpt_asn1_x509::oid::digest;

#[test]
fn built_request_decodes_with_the_same_cert_ids() {
    let name_hash = [0x11u8; 32];
    let key_hash = [0x22u8; 32];
    let der = OcspRequestBuilder::new()
        // High bit set, so the INTEGER needs a leading zero octet.
        .cert_id(digest::SHA256, &name_hash, &key_hash, &[0x80, 0x01])
        .cert_id(digest::SHA256, &name_hash, &key_hash, &[0x00, 0x00, 0x05])
        .build();

    let req = OcspRequest::decode(&mut Reader::new(&der, Config::der())).expect("decodes");
    let requests = &req.tbs_request.requests;
    assert_eq!(requests.len(), 2);

    let first = &requests[0].req_cert;
    assert!(first.hash_algorithm.is_oid(digest::SHA256));
    assert_eq!(first.issuer_name_hash, &name_hash[..]);
    assert_eq!(first.issuer_key_hash, &key_hash[..]);
    assert_eq!(first.serial_number_bytes(), &[0x00, 0x80, 0x01][..]);

    // Leading zeros in the input are not part of the encoded integer.
    assert_eq!(requests[1].req_cert.serial_number_bytes(), &[0x05][..]);
}

#[test]
fn request_encoding_is_der() {
    // id-sha1, 1.3.14.3.2.26
    const SHA1: &[u64] = &[1, 3, 14, 3, 2, 26];
    let der = OcspRequestBuilder::new().cert_id(SHA1, &[0; 20], &[0; 20], &[1]).build();
    // The outer SEQUENCE uses a definite, minimal length, so strict DER accepts it.
    let mut r = Reader::new(&der, Config::der());
    assert!(r.read_tlv().is_ok());
    assert!(r.is_empty());
}
