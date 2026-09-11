// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz target: X.509 `CertificateList` (CRL) decoding (RFC 5280 §5).
//!
//! Exercises `CertificateList`, its `RevokedCertificate` entries, CRL
//! extensions, and the `tbsCertList` retention logic against arbitrary bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_x509::crl::CertificateList;
use tpt_asn1_x509::time::UnixTime;

fuzz_target!(|data: &[u8]| {
    for config in [Config::der(), Config::ber()] {
        let mut r = Reader::new(data, config);
        let _ = CertificateList::decode(&mut r);
    }

    // If a full CRL decodes, touch its accessor surface (never panics, but
    // keeps the derived `is_revoked` logic within coverage range).
    if let Ok(crl) = tpt_asn1_core::decode_with::<CertificateList<'_>>(data, Config::der()) {
        let now = UnixTime(0);
        for entry in &crl.revoked {
            let _ = entry.user_certificate.as_bytes();
            let _ = entry.revocation_date.to_unix();
            let _ = entry.is_revoked_at(now);
        }
        let _ = crl.is_revoked(&[0x01], now);
        let _ = crl.tbs_cert_list_der();
    }
});