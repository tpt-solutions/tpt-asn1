// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz target: X.509 `Certificate` decoding (RFC 5280 §4.1).
//!
//! The invariant under test is that arbitrary bytes never cause a panic, OOM,
//! or stack overflow in the certificate / `TBSCertificate` / extension / SPKI /
//! name parsing paths.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_asn1_core::any::Any;
use tpt_asn1_core::decode;
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_x509::certificate::Certificate;
use tpt_asn1_x509::extensions::Extensions;
use tpt_asn1_x509::name::Name;
use tpt_asn1_x509::spki::SubjectPublicKeyInfo;

fuzz_target!(|data: &[u8]| {
    for config in [Config::der(), Config::ber()] {
        let mut r = Reader::new(data, config);
        let _ = Certificate::decode(&mut r);

        let mut r = Reader::new(data, config);
        let _ = Name::decode(&mut r);

        let mut r = Reader::new(data, config);
        let _ = SubjectPublicKeyInfo::decode(&mut r);

        let _ = Extensions::from_content(data, config);

        let mut r = Reader::new(data, config);
        let _ = Any::decode(&mut r);
    }

    // Whole-buffer strict-DER entry points (rejects trailing bytes).
    let _ = decode::<Certificate<'_>>(data);

    // If the certificate decodes, drive the derived accessor surface.
    if let Ok(cert) = decode::<Certificate<'_>>(data) {
        let _ = cert.tbs_certificate_der();
        let _ = cert.signature_value;
        let _ = cert.is_self_signed_name();
    }
});