//! Non-canonical encodings that DER forbids must be rejected, while BER keeps
//! accepting the forms it allows.

use tpt_asn1_core::any::Any;
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_core::tag::Tag;
use tpt_asn1_core::types::{Enumerated, ObjectIdentifier};

fn primitive(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag, content.len() as u8];
    out.extend_from_slice(content);
    out
}

#[test]
fn oid_with_non_minimal_subidentifier_is_rejected() {
    // Subidentifier starting with 0x80 is non-minimal.
    let bytes = primitive(0x06, &[0x2a, 0x80, 0x01]);
    assert!(ObjectIdentifier::decode(&mut Reader::new(&bytes, Config::der())).is_err());
}

#[test]
fn oid_ending_mid_subidentifier_is_rejected() {
    let bytes = primitive(0x06, &[0x2a, 0x81]);
    assert!(ObjectIdentifier::decode(&mut Reader::new(&bytes, Config::der())).is_err());
}

#[test]
fn well_formed_oid_is_accepted() {
    let bytes = primitive(0x06, &[0x2a, 0x86, 0x48]);
    assert!(ObjectIdentifier::decode(&mut Reader::new(&bytes, Config::der())).is_ok());
}

#[test]
fn enumerated_non_minimal_is_rejected_in_der() {
    let bytes = primitive(0x0a, &[0x00, 0x01]);
    assert!(Enumerated::decode(&mut Reader::new(&bytes, Config::der())).is_err());
    assert!(Enumerated::decode(&mut Reader::new(&bytes, Config::ber())).is_ok());
}

#[test]
fn high_tag_number_with_leading_padding_is_rejected() {
    // Context class, constructed, long-form tag number 31 with a 0x80 pad octet.
    let bytes = [0xbf, 0x80, 0x1f];
    assert!(Tag::decode(&mut Reader::new(&bytes, Config::der())).is_err());
}

#[test]
fn high_tag_number_minimal_form_is_accepted() {
    let bytes = [0xbf, 0x1f];
    assert!(Tag::decode(&mut Reader::new(&bytes, Config::der())).is_ok());
}

#[test]
fn any_still_decodes_der_element() {
    let bytes = primitive(0x02, &[0x05]);
    assert!(Any::decode(&mut Reader::new(&bytes, Config::der())).is_ok());
}
