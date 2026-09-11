// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz target: universal type decoders in `tpt-asn1-core`.
//!
//! Drives the `Decode` implementations for the built-in ASN.1 universal types
//! (and the `Any` deferred decoder) against arbitrary bytes under DER, BER, and
//! CER. The invariant under test is that no universal-type decoder ever panics
//! or OOMs on adversarial input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_asn1_core::any::Any;
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_core::types::*;

fn try_decode<'a, T: Decode<'a>>(data: &'a [u8], config: Config) {
    let mut r = Reader::new(data, config);
    let _ = T::decode(&mut r);
}

fuzz_target!(|data: &[u8]| {
    for config in [Config::der(), Config::ber(), Config::cer()] {
        // Primitive / content types.
        try_decode::<Boolean>(data, config);
        try_decode::<Integer>(data, config);
        try_decode::<Enumerated>(data, config);
        try_decode::<BitString>(data, config);
        try_decode::<OctetString>(data, config);
        try_decode::<Null>(data, config);
        try_decode::<ObjectIdentifier>(data, config);
        try_decode::<RelativeOid>(data, config);

        // OID arcs: decode is complete on success, but `arcs()`/`matches()` are
        // a separate public surface that must never panic on oversized
        // base-128 subidentifiers, so exercise the full iterator.
        let mut r = Reader::new(data, config);
        if let Ok(oid) = ObjectIdentifier::decode(&mut r) {
            for _ in oid.arcs() {}
            let _ = oid.matches(&[u64::MAX, u64::MAX, u64::MAX]);
        }

        // Time types.
        try_decode::<UtcTime>(data, config);
        try_decode::<GeneralizedTime>(data, config);

        // String types.
        try_decode::<Utf8String>(data, config);
        try_decode::<PrintableString>(data, config);
        try_decode::<Ia5String>(data, config);
        try_decode::<NumericString>(data, config);
        try_decode::<VisibleString>(data, config);
        try_decode::<TeletexString>(data, config);
        try_decode::<VideotexString>(data, config);
        try_decode::<UniversalString>(data, config);
        try_decode::<BmpString>(data, config);
        try_decode::<GeneralString>(data, config);
        try_decode::<ObjectDescriptor>(data, config);

        // Deferred / recursive decode of arbitrary content.
        try_decode::<Any>(data, config);
    }
});