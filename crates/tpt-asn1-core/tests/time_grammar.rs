//! Regression tests for time and string grammar checks that previously accepted
//! invalid input at decode time or in the wrong encoding rule.

use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_core::types::{GeneralizedTime, UtcTime, VisibleString};

fn primitive(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag, content.len() as u8];
    out.extend_from_slice(content);
    out
}

fn utc(s: &str, config: Config) -> tpt_asn1_core::error::Result<UtcTime<'static>> {
    let bytes: &'static [u8] = Box::leak(primitive(0x17, s.as_bytes()).into_boxed_slice());
    let mut r = Reader::new(bytes, config);
    UtcTime::decode(&mut r)
}

fn generalized(s: &str, config: Config) -> tpt_asn1_core::error::Result<GeneralizedTime<'static>> {
    let bytes: &'static [u8] = Box::leak(primitive(0x18, s.as_bytes()).into_boxed_slice());
    let mut r = Reader::new(bytes, config);
    GeneralizedTime::decode(&mut r)
}

#[test]
fn utc_time_rejects_feb_29_in_non_leap_year() {
    assert!(utc("260229000000Z", Config::der()).is_err());
}

#[test]
fn utc_time_accepts_feb_29_in_leap_year() {
    assert!(utc("240229000000Z", Config::der()).is_ok());
}

#[test]
fn generalized_time_rejects_trailing_data_after_z() {
    assert!(generalized("20260814120000Zjunk", Config::ber()).is_err());
}

#[test]
fn der_rejects_utc_time_with_offset() {
    assert!(utc("260101000000+0100", Config::der()).is_err());
    // BER permits the offset form, so it still decodes there.
    assert!(utc("260101000000+0100", Config::ber()).is_ok());
}

#[test]
fn der_rejects_generalized_time_fraction_with_trailing_zero() {
    assert!(generalized("20260101000000.10Z", Config::der()).is_err());
    assert!(generalized("20260101000000.1Z", Config::der()).is_ok());
}

#[test]
fn visible_string_accepts_space() {
    let bytes = primitive(0x1a, b"a b");
    let mut r = Reader::new(&bytes, Config::der());
    assert!(VisibleString::decode(&mut r).is_ok());
}
