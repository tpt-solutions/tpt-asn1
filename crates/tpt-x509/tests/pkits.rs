// SPDX-License-Identifier: MIT OR Apache-2.0

//! Best-effort PKITS-style validation harness.
//!
//! The official NIST PKITS suite (~1,600 certificate fixtures) requires a network
//! download that is unavailable here. This file instead documents the canonical
//! PKITS test-group taxonomy and wires self-contained, known-answer validation
//! tests built from the in-repo DER encoders. It is a structural stand-in: once
//! the official vectors are acquired, map each group to a function here and feed
//! the real fixtures through `build_and_validate`.

use tpt_asn1_core::tag::Tag;
use tpt_asn1_core::writer::{encode_to_vec, Writer};
use tpt_asn1_core::decode;

use tpt_x509::chain::{build_and_validate, PathConfig, TrustAnchor};
use tpt_x509::verify::{SignatureVerifier, VerifyError};
use tpt_x509::{Certificate, UnixTime};

// --- DER construction helpers (mirrors tests/x509.rs) ----------------------

fn utc_time(s: &str) -> Vec<u8> {
    let mut w = Writer::new_vec();
    w.write_primitive(Tag::universal(Tag::UTC_TIME), s.as_bytes()).unwrap();
    w.into_vec()
}

fn generalized_time(s: &str) -> Vec<u8> {
    let mut w = Writer::new_vec();
    w.write_primitive(Tag::universal(Tag::GENERALIZED_TIME), s.as_bytes()).unwrap();
    w.into_vec()
}

fn name(cn: &str) -> Vec<u8> {
    encode_to_vec(&NameBuilder { cn }).unwrap()
}

struct NameBuilder<'a> { cn: &'a str }

impl tpt_asn1_core::Encode for NameBuilder<'_> {
    fn encode<W: tpt_asn1_core::writer::WriteBackend>(
        &self, w: &mut Writer<W>,
    ) -> tpt_asn1_core::error::Result<()> {
        w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
            w.nested(Tag::universal_constructed(Tag::SET), |w| {
                w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
                    w.write_primitive(Tag::universal(Tag::OBJECT_IDENTIFIER), &[0x55, 0x04, 0x03])?;
                    w.write_primitive(Tag::universal(Tag::PRINTABLE_STRING), self.cn.as_bytes())?;
                    Ok(())
                })
            })
        })
    }
}

fn build_cert(
    issuer_cn: &str, subject_cn: &str, is_ca: bool, serial: &[u8], extensions: &[Vec<u8>],
) -> Vec<u8> {
    let tbs = build_tbs(issuer_cn, subject_cn, is_ca, serial, extensions);
    encode_to_vec(&CertBuilder { tbs }).unwrap()
}

struct CertBuilder { tbs: Vec<u8> }

impl tpt_asn1_core::Encode for CertBuilder {
    fn encode<W: tpt_asn1_core::writer::WriteBackend>(
        &self, w: &mut Writer<W>,
    ) -> tpt_asn1_core::error::Result<()> {
        w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
            w.write_bytes(&self.tbs)?;
            w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
                w.write_primitive(Tag::universal(Tag::OBJECT_IDENTIFIER), &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b])?;
                w.write_primitive(Tag::universal(Tag::NULL), &[])?;
                Ok(())
            })?;
            w.write_primitive(Tag::universal(Tag::BIT_STRING), &[0x00, 0x00])?;
            Ok(())
        })
    }
}

fn build_tbs(
    issuer_cn: &str, subject_cn: &str, is_ca: bool, serial: &[u8], extensions: &[Vec<u8>],
) -> Vec<u8> {
    encode_to_vec(&TbsBuilder {
        issuer_cn, subject_cn, is_ca, serial: serial.to_vec(), extensions,
    })
    .unwrap()
}

struct TbsBuilder<'a> {
    issuer_cn: &'a str,
    subject_cn: &'a str,
    #[allow(dead_code)]
    is_ca: bool,
    serial: Vec<u8>,
    extensions: &'a [Vec<u8>],
}

impl tpt_asn1_core::Encode for TbsBuilder<'_> {
    fn encode<W: tpt_asn1_core::writer::WriteBackend>(
        &self, w: &mut Writer<W>,
    ) -> tpt_asn1_core::error::Result<()> {
        w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
            w.nested(Tag::context(true, 0), |w| {
                w.write_primitive(Tag::universal(Tag::INTEGER), &[0x02])
            })?;
            w.write_primitive(Tag::universal(Tag::INTEGER), &self.serial)?;
            w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
                w.write_primitive(Tag::universal(Tag::OBJECT_IDENTIFIER), &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b])?;
                w.write_primitive(Tag::universal(Tag::NULL), &[])
            })?;
            w.write_bytes(&name(self.issuer_cn))?;
            w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
                w.write_bytes(&utc_time("000101000000Z"))?;
                w.write_bytes(&generalized_time("20500101000000Z"))
            })?;
            w.write_bytes(&name(self.subject_cn))?;
            w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
                w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
                    w.write_primitive(Tag::universal(Tag::OBJECT_IDENTIFIER), &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])?;
                    w.write_primitive(Tag::universal(Tag::NULL), &[])
                })?;
                w.write_primitive(Tag::universal(Tag::BIT_STRING), &[0x00, 0x01, 0x02, 0x03])
            })?;
            if !self.extensions.is_empty() {
                w.nested(Tag::context(true, 3), |w| {
                    w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
                        for ext in self.extensions {
                            w.write_bytes(ext)?;
                        }
                        Ok(())
                    })
                })?;
            }
            Ok(())
        })
    }
}

fn extension(oid_content: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    encode_to_vec(&ExtBuilder { oid_content, critical, value }).unwrap()
}

struct ExtBuilder<'a> { oid_content: &'a [u8], critical: bool, value: &'a [u8] }

impl tpt_asn1_core::Encode for ExtBuilder<'_> {
    fn encode<W: tpt_asn1_core::writer::WriteBackend>(
        &self, w: &mut Writer<W>,
    ) -> tpt_asn1_core::error::Result<()> {
        w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
            w.write_primitive(Tag::universal(Tag::OBJECT_IDENTIFIER), self.oid_content)?;
            if self.critical {
                w.write_primitive(Tag::universal(Tag::BOOLEAN), &[0xFF])?;
            }
            w.write_primitive(Tag::universal(Tag::OCTET_STRING), self.value)?;
            Ok(())
        })
    }
}

const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];

fn basic_constraints_ca_true() -> Vec<u8> {
    let mut w = Writer::new_vec();
    w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
        w.write_primitive(Tag::universal(Tag::BOOLEAN), &[0xFF])
    })
    .unwrap();
    w.into_vec()
}

fn key_usage_key_cert_sign() -> Vec<u8> {
    let mut w = Writer::new_vec();
    w.write_primitive(Tag::universal(Tag::BIT_STRING), &[0x02, 0x04]).unwrap();
    w.into_vec()
}

// KeyUsage present but WITHOUT the keyCertSign bit (digitalSignature only).
fn key_usage_without_keycertsign() -> Vec<u8> {
    let mut w = Writer::new_vec();
    w.write_primitive(Tag::universal(Tag::BIT_STRING), &[0x07, 0x80]).unwrap();
    w.into_vec()
}

struct AcceptAll;

impl SignatureVerifier for AcceptAll {
    fn digest(&self, _alg_oid: &[u8], _data: &[u8]) -> Result<Vec<u8>, VerifyError> {
        Ok(Vec::new())
    }
    fn verify_signature(
        &self, _sig_alg_oid: &[u8], _key_alg_oid: &[u8], _public_key: &[u8],
        _message: &[u8], _signature: &[u8],
    ) -> Result<bool, VerifyError> {
        Ok(true)
    }
}

const VALID_TIME: UnixTime = UnixTime(1_893_196_800); // 2030-01-01
const AFTER_EXPIRY: UnixTime = UnixTime(4_102_444_800); // 2100-01-01

// --- PKITS Group 4.1: Valid Certificate Path ---------------------------------
#[test]
fn pkits_4_1_valid_path() {
    let root_exts = vec![extension(OID_BASIC_CONSTRAINTS, true, &basic_constraints_ca_true()),
                         extension(OID_KEY_USAGE, false, &key_usage_key_cert_sign())];
    let root_der = build_cert("Root", "Root", true, &[0x01], &root_exts);
    let root = decode::<Certificate>(&root_der).unwrap();
    let anchor = TrustAnchor::from_cert(&root);

    let ee_der = build_cert("Root", "EE", false, &[0x02], &[]);
    let ee = decode::<Certificate>(&ee_der).unwrap();

    let anchors = [anchor];
    let result = build_and_validate(
        &ee, &[], &anchors,
        PathConfig { time: VALID_TIME, verifier: &AcceptAll, max_path_length: None },
    );
    assert!(result.is_ok(), "valid path should validate: {:?}", result.err());
}

// --- PKITS Group 4.1.2.2: Invalid validity period ---------------------------
#[test]
fn pkits_4_1_2_2_expired() {
    let root_exts = vec![extension(OID_BASIC_CONSTRAINTS, true, &basic_constraints_ca_true()),
                         extension(OID_KEY_USAGE, false, &key_usage_key_cert_sign())];
    let root_der = build_cert("Root", "Root", true, &[0x01], &root_exts);
    let root = decode::<Certificate>(&root_der).unwrap();
    let anchor = TrustAnchor::from_cert(&root);

    let ee_der = build_cert("Root", "EE", false, &[0x02], &[]);
    let ee = decode::<Certificate>(&ee_der).unwrap();

    let anchors = [anchor];
    let result = build_and_validate(
        &ee, &[], &anchors,
        PathConfig { time: AFTER_EXPIRY, verifier: &AcceptAll, max_path_length: None },
    );
    assert!(result.is_err(), "expired cert must be rejected");
}

// --- PKITS Group 4.3.1: BasicConstraints -- CA cert required ----------------
#[test]
fn pkits_4_3_1_non_ca_intermediate() {
    let root_exts = vec![extension(OID_BASIC_CONSTRAINTS, true, &basic_constraints_ca_true()),
                         extension(OID_KEY_USAGE, false, &key_usage_key_cert_sign())];
    let root_der = build_cert("Root", "Root", true, &[0x01], &root_exts);
    let root = decode::<Certificate>(&root_der).unwrap();
    let anchor = TrustAnchor::from_cert(&root);

    let inter_der = build_cert("Root", "Inter", false, &[0x03], &[]);
    let inter = decode::<Certificate>(&inter_der).unwrap();
    let ee_der = build_cert("Inter", "EE", false, &[0x04], &[]);
    let ee = decode::<Certificate>(&ee_der).unwrap();

    let intermediates = [inter];
    let anchors = [anchor];
    let result = build_and_validate(
        &ee, &intermediates, &anchors,
        PathConfig { time: VALID_TIME, verifier: &AcceptAll, max_path_length: None },
    );
    assert!(result.is_err(), "non-CA intermediate must be rejected");
}

// --- PKITS Group 4.4.1: Unknown critical extension --------------------------
#[test]
fn pkits_4_4_1_unknown_critical() {
    let exts = vec![extension(&[0x2a, 0x03, 0x04], true, &[0x05, 0x00])];
    let der = build_cert("Root", "Root", true, &[0x09], &exts);
    assert!(decode::<Certificate>(&der).is_err());
}

// --- PKITS Group 4.5.1: KeyUsage keyCertSign required on CA ----------------
#[test]
fn pkits_4_5_1_ca_missing_keycertsign() {
    // Root anchor is fine; the *intermediate* CA has a KeyUsage that omits
    // keyCertSign, which must be rejected during path validation.
    let root_exts = vec![extension(OID_BASIC_CONSTRAINTS, true, &basic_constraints_ca_true()),
                         extension(OID_KEY_USAGE, false, &key_usage_key_cert_sign())];
    let root_der = build_cert("Root", "Root", true, &[0x01], &root_exts);
    let root = decode::<Certificate>(&root_der).unwrap();
    let anchor = TrustAnchor::from_cert(&root);

    let inter_exts = vec![extension(OID_BASIC_CONSTRAINTS, true, &basic_constraints_ca_true()),
                          extension(OID_KEY_USAGE, false, &key_usage_without_keycertsign())];
    let inter_der = build_cert("Root", "Inter", true, &[0x03], &inter_exts);
    let inter = decode::<Certificate>(&inter_der).unwrap();
    let ee_der = build_cert("Inter", "EE", false, &[0x04], &[]);
    let ee = decode::<Certificate>(&ee_der).unwrap();

    let intermediates = [inter];
    let anchors = [anchor];
    let result = build_and_validate(
        &ee, &intermediates, &anchors,
        PathConfig { time: VALID_TIME, verifier: &AcceptAll, max_path_length: None },
    );
    assert!(result.is_err(), "CA missing keyCertSign must be rejected");
}
