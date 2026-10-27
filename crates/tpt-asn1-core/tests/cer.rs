// SPDX-License-Identifier: MIT OR Apache-2.0

//! CER restrictions (X.690 §9 and §11.1) that BER accepts and DER/CER share.

use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_core::types::{Boolean, OctetString};

#[test]
fn cer_boolean_true_must_be_0xff() {
    let bytes = [0x01, 0x01, 0x01];
    assert!(Boolean::decode(&mut Reader::new(&bytes, Config::cer())).is_err());
    assert!(Boolean::decode(&mut Reader::new(&bytes, Config::ber())).is_ok());

    let bytes = [0x01, 0x01, 0xff];
    assert_eq!(Boolean::decode(&mut Reader::new(&bytes, Config::cer())).unwrap(), Boolean(true));
}

#[test]
fn cer_primitive_octet_string_limited_to_1000_octets() {
    let mut ok = vec![0x04, 0x82, 0x03, 0xe8];
    ok.extend(core::iter::repeat(0xaa).take(1000));
    assert!(OctetString::decode(&mut Reader::new(&ok, Config::cer())).is_ok());

    let mut too_long = vec![0x04, 0x82, 0x03, 0xe9];
    too_long.extend(core::iter::repeat(0xaa).take(1001));
    assert!(OctetString::decode(&mut Reader::new(&too_long, Config::cer())).is_err());
    assert!(OctetString::decode(&mut Reader::new(&too_long, Config::ber())).is_ok());
}

#[test]
fn cer_constructed_element_must_use_indefinite_length() {
    let definite = [0x30, 0x00];
    assert!(Reader::new(&definite, Config::cer()).read_tlv().is_err());
    assert!(Reader::new(&definite, Config::ber()).read_tlv().is_ok());

    let indefinite = [0x30, 0x80, 0x00, 0x00];
    assert!(Reader::new(&indefinite, Config::cer()).read_tlv().is_ok());
}

#[test]
fn cer_primitive_element_must_use_definite_length() {
    let indefinite = [0x04, 0x80, 0x00, 0x00];
    assert!(Reader::new(&indefinite, Config::cer()).read_tlv().is_err());
    assert!(Reader::new(&indefinite, Config::ber()).read_tlv().is_ok());
}

#[test]
fn cer_non_minimal_definite_length_is_rejected() {
    // Long form for a value below 0x80.
    let long_small = [0x04, 0x81, 0x01, 0xaa];
    assert!(Reader::new(&long_small, Config::cer()).read_tlv().is_err());
    assert!(Reader::new(&long_small, Config::ber()).read_tlv().is_ok());

    // Leading zero octet in the long form.
    let leading_zero = [0x04, 0x82, 0x00, 0x80];
    let mut bytes = leading_zero.to_vec();
    bytes.extend(core::iter::repeat(0xaa).take(0x80));
    assert!(Reader::new(&bytes, Config::cer()).read_tlv().is_err());
}
