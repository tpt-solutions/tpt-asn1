// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz target: CMS `ContentInfo` outer wrapper (RFC 5652 / PKCS#7).
//!
//! Exercises the top-level `ContentInfo` decode entry points used by `tpt-cms`,
//! plus the OID recognition and content-typing helpers.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};

fuzz_target!(|data: &[u8]| {
    for config in [Config::der(), Config::ber()] {
        let mut r = Reader::new(data, config);
        let _ = tpt_cms::content_info::ContentInfo::decode(&mut r);
    }

    let _ = tpt_cms::content_info::decode(data);
    let _ = tpt_cms::content_info::decode_partial(data);
});