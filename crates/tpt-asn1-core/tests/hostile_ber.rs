//! Regression tests for hostile BER length encodings. These previously hit
//! unchecked arithmetic in the end-of-contents scanner (debug panic, release
//! wrap-around and a possible infinite loop).

use tpt_asn1_core::any::Any;
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};

fn decode_any_ber(bytes: &[u8]) -> tpt_asn1_core::error::Result<Any<'_>> {
    let mut r = Reader::new(bytes, Config::ber());
    Any::decode(&mut r)
}

#[test]
fn ber_indefinite_child_with_huge_length_is_rejected_not_panicking() {
    // SEQUENCE (indefinite) containing an OCTET STRING whose 8-octet length
    // is usize::MAX. Its value end would overflow `after_header + n`.
    let bytes =
        [0x30, 0x80, 0x04, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00];
    assert!(decode_any_ber(&bytes).is_err());
}

#[test]
fn ber_length_wider_than_usize_is_rejected() {
    // A 9-octet length cannot be represented in `usize`; it must be rejected
    // rather than having its high bits silently shifted out.
    let bytes = [0x30, 0x80, 0x04, 0x89, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00];
    assert!(decode_any_ber(&bytes).is_err());
}

#[test]
fn ber_valid_indefinite_length_still_decodes() {
    // SEQUENCE (indefinite) { OCTET STRING "A" } with its end-of-contents.
    let bytes = [0x30, 0x80, 0x04, 0x01, 0xaa, 0x00, 0x00];
    assert!(decode_any_ber(&bytes).is_ok());
}
