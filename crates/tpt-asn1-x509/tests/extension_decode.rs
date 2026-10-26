//! Regression tests for extension decoders that previously mis-handled
//! IMPLICIT tags, which made constraints silently fail open.

use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_x509::extensions::{crl_reason, GeneralName, NameConstraints};

#[test]
fn san_other_name_upn_decodes() {
    // [0] IMPLICIT OtherName: content = OID 1.3.6.1 followed by
    // [0] EXPLICIT UTF8String "A". No SEQUENCE header is present.
    let bytes = [0xa0, 0x0a, 0x06, 0x03, 0x2b, 0x06, 0x01, 0xa0, 0x03, 0x0c, 0x01, 0x41];
    let mut r = Reader::new(&bytes, Config::der());
    let name = GeneralName::decode(&mut r).expect("otherName must decode");
    assert!(matches!(name, GeneralName::OtherName { .. }));
}

#[test]
fn san_registered_id_decodes() {
    // [8] IMPLICIT OBJECT IDENTIFIER: content octets are the OID content
    // (2.5.4 encoded as 0x55 0x04), with no universal tag or length.
    let bytes = [0x88, 0x02, 0x55, 0x04];
    let mut r = Reader::new(&bytes, Config::der());
    let name = GeneralName::decode(&mut r).expect("registeredID must decode");
    assert!(matches!(name, GeneralName::RegisteredId(_)));
}

#[test]
fn name_constraints_with_minimum_decodes() {
    // SEQUENCE { permitted [0] { SEQUENCE { dNSName "a.com", minimum [0] 1 } } }
    let bytes = [
        0x30, 0x0e, 0xa0, 0x0c, 0x30, 0x0a, 0x82, 0x05, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x80, 0x01,
        0x01,
    ];
    let mut r = Reader::new(&bytes, Config::der());
    let nc = NameConstraints::decode(&mut r).expect("minimum must decode");
    assert_eq!(nc.permitted.len(), 1);
    assert_eq!(nc.permitted[0].minimum, 1);
}

#[test]
fn crl_reason_codes_match_rfc5280() {
    // RFC 5280 §5.3.1: removeFromCRL = 8, privilegeWithdrawn = 9, aACompromise = 10.
    assert_eq!(crl_reason::REMOVE_FROM_CRL, 8);
    assert_eq!(crl_reason::PRIVILEGE_WITHDRAWN, 9);
    assert_eq!(crl_reason::AA_COMPROMISE, 10);
}

#[test]
fn explicit_critical_false_is_rejected_in_der_only() {
    use tpt_asn1_x509::extensions::Extension;
    // SEQUENCE { OID 2.5.29.15, BOOLEAN FALSE (explicit), OCTET STRING { 0x00 } }
    let bytes =
        [0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0x00, 0x04, 0x02, 0x04, 0x00];
    assert!(Extension::decode(&mut Reader::new(&bytes, Config::der())).is_err());
    assert!(Extension::decode(&mut Reader::new(&bytes, Config::ber())).is_ok());
}

#[test]
fn duplicate_certificate_extension_is_rejected() {
    use tpt_asn1_x509::extensions::Extensions;
    // Two identical extensions inside the SEQUENCE OF wrapper.
    let ext = [0x30, 0x08, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x01, 0x00];
    let mut content = vec![0x30, 0x14];
    content.extend_from_slice(&ext);
    content.extend_from_slice(&ext);
    assert!(Extensions::from_content(&content, Config::der()).is_err());
}
