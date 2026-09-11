// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz target: OCSP request / response parsing (RFC 6960).
//!
//! Exercises `OcspRequest`, `BasicOcspResponse`, `OcspResponse`, and their
//! sub-structures (`CertId`, `TbsRequest`, `SingleResponse`, `ResponseBytes`)
//! against arbitrary bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_asn1_core::decode;
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_x509::ocsp::{
    BasicOcspResponse, CertId, OcspRequest, OcspResponse, Request, ResponseBytes, SingleResponse,
    TbsRequest,
};
use tpt_asn1_x509::oid;

fuzz_target!(|data: &[u8]| {
    let configs = [Config::der(), Config::ber()];
    for config in configs {
        let mut r = Reader::new(data, config);
        let _ = OcspRequest::decode(&mut r);

        let mut r = Reader::new(data, config);
        let _ = TbsRequest::decode(&mut r);

        let mut r = Reader::new(data, config);
        let _ = Request::decode(&mut r);

        let mut r = Reader::new(data, config);
        let _ = CertId::decode(&mut r);

        let mut r = Reader::new(data, config);
        let _ = BasicOcspResponse::decode(&mut r);

        let mut r = Reader::new(data, config);
        let _ = OcspResponse::decode(&mut r);

        let mut r = Reader::new(data, config);
        let _ = SingleResponse::decode(&mut r);

        let mut r = Reader::new(data, config);
        let _ = ResponseBytes::decode(&mut r);
    }

    // Strict-DER whole-buffer entry points plus their predicate surface.
    let _ = decode::<OcspRequest<'_>>(data);
    let _ = decode::<OcspResponse<'_>>(data);
    let _ = oid::oid_eq_bytes(data, oid::pkix::OCSP);
});