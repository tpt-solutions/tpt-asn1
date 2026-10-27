// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hand-picked malformed encodings for the universal types. Each entry says what
//! DER must do with it, and whether BER still accepts it.

use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_core::types::{BitString, Boolean, Integer, Null, ObjectIdentifier};

/// Whether `T` decodes `bytes` under `config`.
fn accepts<'a, T: Decode<'a>>(bytes: &'a [u8], config: Config) -> bool {
    T::decode(&mut Reader::new(bytes, config)).is_ok()
}

#[test]
fn integer_non_minimal_forms_are_der_errors() {
    // Redundant leading zero, and redundant leading 0xFF.
    let redundant_zero = [0x02, 0x02, 0x00, 0x7f];
    let redundant_ones = [0x02, 0x02, 0xff, 0x80];
    for bytes in [&redundant_zero[..], &redundant_ones[..]] {
        assert!(!accepts::<Integer<'_>>(bytes, Config::der()), "{bytes:02x?}");
        assert!(accepts::<Integer<'_>>(bytes, Config::ber()), "{bytes:02x?}");
    }
}

#[test]
fn integer_necessary_padding_is_accepted() {
    // 0x80 needs its 0x00 pad only if positive; as a negative value 0x80 is minimal.
    let negative = [0x02, 0x01, 0x80];
    let positive_with_pad = [0x02, 0x02, 0x00, 0x80];
    assert!(accepts::<Integer<'_>>(&negative, Config::der()));
    assert!(accepts::<Integer<'_>>(&positive_with_pad, Config::der()));
}

#[test]
fn integer_empty_content_is_rejected() {
    let empty = [0x02, 0x00];
    assert!(!accepts::<Integer<'_>>(&empty, Config::ber()));
}

#[test]
fn boolean_true_must_be_0xff_in_der_but_any_nonzero_in_ber() {
    let true_01 = [0x01, 0x01, 0x01];
    let true_ff = [0x01, 0x01, 0xff];
    let false_00 = [0x01, 0x01, 0x00];
    let empty = [0x01, 0x00];
    assert!(!accepts::<Boolean>(&true_01, Config::der()));
    assert!(accepts::<Boolean>(&true_01, Config::ber()));
    assert!(accepts::<Boolean>(&true_ff, Config::der()));
    assert!(accepts::<Boolean>(&false_00, Config::der()));
    assert!(!accepts::<Boolean>(&empty, Config::ber()));
}

#[test]
fn bit_string_padding_rules() {
    // Unused-bit count above 7.
    assert!(!accepts::<BitString<'_>>(&[0x03, 0x02, 0x08, 0xff], Config::ber()));
    // Empty content has no unused-bit octet.
    assert!(!accepts::<BitString<'_>>(&[0x03, 0x00], Config::ber()));
    // Unused bits with no data bytes to hold them.
    assert!(!accepts::<BitString<'_>>(&[0x03, 0x01, 0x03], Config::ber()));
    // One unused bit: the lowest bit of the final octet must be zero. 0x81 sets it.
    assert!(!accepts::<BitString<'_>>(&[0x03, 0x02, 0x01, 0x81], Config::der()));
    assert!(accepts::<BitString<'_>>(&[0x03, 0x02, 0x01, 0x80], Config::der()));
    // A zero-length, zero-padding BIT STRING is valid.
    assert!(accepts::<BitString<'_>>(&[0x03, 0x01, 0x00], Config::der()));
}

#[test]
fn oid_and_null_edge_cases() {
    // An OID needs at least one subidentifier.
    assert!(!accepts::<ObjectIdentifier<'_>>(&[0x06, 0x00], Config::ber()));
    // NULL carries no content.
    assert!(!accepts::<Null>(&[0x05, 0x01, 0x00], Config::ber()));
    assert!(accepts::<Null>(&[0x05, 0x00], Config::der()));
}
