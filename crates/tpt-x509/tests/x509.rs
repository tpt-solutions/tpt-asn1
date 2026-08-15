// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for `tpt-x509`: decode real-shaped X.509 structures built
//! with the core writer, plus RFC 5280 §6.1 path-building/validation.

use tpt_asn1_core::tag::Tag;
use tpt_asn1_core::writer::{encode_to_vec, Writer};
use tpt_asn1_core::decode;

use tpt_x509::chain::{build_and_validate, PathConfig, TrustAnchor};
use tpt_x509::extensions::key_usage_bit;
use tpt_x509::verify::{SignatureVerifier, VerifyError};
use tpt_x509::{Certificate, Time, UnixTime};

// --- DER construction helpers ------------------------------------------------

/// `UTCTime` from a `YYMMDDHHMMSSZ` string.
fn utc_time(s: &str) -> Vec<u8> {
    let mut w = Writer::new_vec();
    w.write_primitive(Tag::universal(Tag::UTC_TIME), s.as_bytes()).unwrap();
    w.into_vec()
}

/// `GeneralizedTime` from a `YYYYMMDDHHMMSSZ` string.
fn generalized_time(s: &str) -> Vec<u8> {
    let mut w = Writer::new_vec();
    w.write_primitive(Tag::universal(Tag::GENERALIZED_TIME), s.as_bytes()).unwrap();
    w.into_vec()
}

/// A `Name` whose only RDN is `CN = cn` (PrintableString).
fn name(cn: &str) -> Vec<u8> {
    encode_to_vec(&NameBuilder { cn }).unwrap()
}

struct NameBuilder<'a> {
    cn: &'a str,
}

impl tpt_asn1_core::Encode for NameBuilder<'_> {
    fn encode<W: tpt_asn1_core::writer::WriteBackend>(
        &self,
        w: &mut Writer<W>,
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

/// Sign a `TBSCertificate`-shaped `content` into a full `Certificate`.
fn build_cert(cn: &str, is_ca: bool, serial: &[u8], extensions: &[Vec<u8>]) -> Vec<u8> {
    let tbs = build_tbs(cn, is_ca, serial, extensions);
    encode_to_vec(&CertBuilder { tbs }).unwrap()
}

struct CertBuilder {
    tbs: Vec<u8>,
}

impl tpt_asn1_core::Encode for CertBuilder {
    fn encode<W: tpt_asn1_core::writer::WriteBackend>(
        &self,
        w: &mut Writer<W>,
    ) -> tpt_asn1_core::error::Result<()> {
        w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
            w.write_bytes(&self.tbs)?;
            // signatureAlgorithm: sha256WithRSAEncryption + NULL
            w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
                w.write_primitive(
                    Tag::universal(Tag::OBJECT_IDENTIFIER),
                    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
                )?;
                w.write_primitive(Tag::universal(Tag::NULL), &[])?;
                Ok(())
            })?;
            // signatureValue BIT STRING (dummy)
            w.write_primitive(Tag::universal(Tag::BIT_STRING), &[0x00, 0x00])?;
            Ok(())
        })
    }
}

fn build_tbs(cn: &str, is_ca: bool, serial: &[u8], extensions: &[Vec<u8>]) -> Vec<u8> {
    encode_to_vec(&TbsBuilder { cn, is_ca, serial: serial.to_vec(), extensions }).unwrap()
}

struct TbsBuilder<'a> {
    cn: &'a str,
    // `is_ca` documents intent at call sites; CA-ness is encoded explicitly via
    // the `basicConstraints` extension passed in `extensions`.
    #[allow(dead_code)]
    is_ca: bool,
    serial: Vec<u8>,
    extensions: &'a [Vec<u8>],
}

impl tpt_asn1_core::Encode for TbsBuilder<'_> {
    fn encode<W: tpt_asn1_core::writer::WriteBackend>(
        &self,
        w: &mut Writer<W>,
    ) -> tpt_asn1_core::error::Result<()> {
        w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
            // version [0] EXPLICIT INTEGER 2 (v3)
            w.nested(Tag::context(true, 0), |w| {
                w.write_primitive(Tag::universal(Tag::INTEGER), &[0x02])
            })?;
            // serialNumber
            w.write_primitive(Tag::universal(Tag::INTEGER), &self.serial)?;
            // signature AlgorithmIdentifier sha256WithRSAEncryption + NULL
            w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
                w.write_primitive(
                    Tag::universal(Tag::OBJECT_IDENTIFIER),
                    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
                )?;
                w.write_primitive(Tag::universal(Tag::NULL), &[])
            })?;
            // issuer Name
            w.write_bytes(&name(self.cn))?;
            // validity
            w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
                w.write_bytes(&utc_time("000101000000Z"))?;
                w.write_bytes(&generalized_time("20500101000000Z"))
            })?;
            // subject Name
            w.write_bytes(&name(self.cn))?;
            // subjectPublicKeyInfo rsaEncryption + dummy BIT STRING
            w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
                w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
                    w.write_primitive(
                        Tag::universal(Tag::OBJECT_IDENTIFIER),
                        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
                    )?;
                    w.write_primitive(Tag::universal(Tag::NULL), &[])
                })?;
                w.write_primitive(Tag::universal(Tag::BIT_STRING), &[0x00, 0x01, 0x02, 0x03])
            })?;
            // extensions [3] EXPLICIT SEQUENCE OF Extension
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

/// Build an `Extension`: `SEQUENCE { OID, [BOOLEAN TRUE if critical], OCTET STRING value }`.
fn extension(oid_content: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    encode_to_vec(&ExtBuilder { oid_content, critical, value }).unwrap()
}

struct ExtBuilder<'a> {
    oid_content: &'a [u8],
    critical: bool,
    value: &'a [u8],
}

impl tpt_asn1_core::Encode for ExtBuilder<'_> {
    fn encode<W: tpt_asn1_core::writer::WriteBackend>(
        &self,
        w: &mut Writer<W>,
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

// OID contents
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];

// Pre-encoded extension values.
fn basic_constraints_ca_true() -> Vec<u8> {
    // SEQUENCE { BOOLEAN TRUE }
    let mut w = Writer::new_vec();
    w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
        w.write_primitive(Tag::universal(Tag::BOOLEAN), &[0xFF])
    })
    .unwrap();
    w.into_vec()
}

fn key_usage_key_cert_sign() -> Vec<u8> {
    // BIT STRING: unused=2, data=0x04 (keyCertSign set)
    let mut w = Writer::new_vec();
    w.write_primitive(Tag::universal(Tag::BIT_STRING), &[0x02, 0x04]).unwrap();
    w.into_vec()
}

fn subject_alt_name_dns(dns: &str) -> Vec<u8> {
    // SEQUENCE { [2] dNSName }
    let mut w = Writer::new_vec();
    w.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
        w.write_primitive(Tag::context(false, 2), dns.as_bytes())
    })
    .unwrap();
    w.into_vec()
}

// --- A permissive verifier for structural (non-crypto) validation tests -------

struct AcceptAll;

impl SignatureVerifier for AcceptAll {
    fn digest(&self, _alg_oid: &[u8], _data: &[u8]) -> Result<Vec<u8>, VerifyError> {
        Ok(Vec::new())
    }
    fn verify_signature(
        &self,
        _sig_alg_oid: &[u8],
        _key_alg_oid: &[u8],
        _public_key: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<bool, VerifyError> {
        Ok(true)
    }
}

// --- Tests --------------------------------------------------------------------

#[test]
fn decode_ca_certificate() {
    let bc_val = basic_constraints_ca_true();
    let ku_val = key_usage_key_cert_sign();
    let exts = vec![
        extension(OID_BASIC_CONSTRAINTS, true, &bc_val),
        extension(OID_KEY_USAGE, false, &ku_val),
    ];
    let der = build_cert("Test CA", true, &[0x01], &exts);
    let cert = decode::<Certificate<'_>>(&der).expect("decode CA cert");

    assert_eq!(cert.tbs.version, 3);
    assert_eq!(cert.tbs.serial_number.as_bytes(), &[0x01]);
    assert_eq!(cert.tbs.issuer.rdns().len(), 1);
    assert!(cert.tbs.is_ca());

    let bc = cert
        .tbs
        .extensions
        .basic_constraints()
        .expect("bc decode")
        .expect("bc present");
    assert!(bc.ca);
    assert_eq!(bc.path_len_constraint, None);

    let ku = cert
        .tbs
        .extensions
        .key_usage()
        .expect("ku decode")
        .expect("ku present");
    assert!(ku.is_set(key_usage_bit::KEY_CERT_SIGN));
    assert!(!ku.is_set(key_usage_bit::DIGITAL_SIGNATURE));
}

#[test]
fn decode_ee_with_san() {
    let san = subject_alt_name_dns("example.com");
    let exts = vec![extension(OID_SUBJECT_ALT_NAME, false, &san)];
    let der = build_cert("example.com", false, &[0x02], &exts);
    let cert = decode::<Certificate<'_>>(&der).expect("decode EE");

    assert!(!cert.tbs.is_ca());
    let san = cert
        .tbs
        .extensions
        .subject_alt_name()
        .expect("san decode")
        .expect("san present");
    let dns = san.names.iter().find_map(|n| n.dns()).expect("has dns");
    assert_eq!(dns, b"example.com");
}

#[test]
fn unknown_critical_extension_is_rejected() {
    // 1.2.3.4 is not in the known-extension set, marked critical => fail-closed.
    let exts = vec![extension(&[0x2a, 0x03, 0x04], true, &[0x05, 0x00])];
    let der = build_cert("Critical Co", true, &[0x09], &exts);
    let err = decode::<Certificate<'_>>(&der).expect_err("must reject unknown critical ext");
    assert_eq!(err, tpt_asn1_core::error::Error::UnknownCriticalExtension);
}

#[test]
fn name_normalization_matches_rfc5280_7_1() {
    let der_a = name("  Example  CORP ");
    let a = decode::<tpt_x509::Name<'_>>(&der_a).unwrap();
    let der_b = name("EXAMPLE CORP");
    let b = decode::<tpt_x509::Name<'_>>(&der_b).unwrap();
    assert!(a.matches(&b), "normalized names should match");

    let der_c = name("OTHER");
    let c = decode::<tpt_x509::Name<'_>>(&der_c).unwrap();
    assert!(!a.matches(&c));
}

#[test]
fn validity_window_check() {
    let der = build_cert("V", true, &[0x01], &[]);
    let cert = decode::<Certificate<'_>>(&der).unwrap();
    let tbs = &cert.tbs;
    // 2030-01-01 is within [2000, 2050].
    assert!(tbs.validity.contains(UnixTime::from_secs(1_893_196_800)));
    // 1990 is before notBefore.
    assert!(!tbs.validity.contains(UnixTime::from_secs(631_152_000)));
    // 2070 is after notAfter.
    assert!(!tbs.validity.contains(UnixTime::from_secs(3_174_724_800)));
}

#[test]
fn chain_build_and_validate_ok() {
    let bc_val = basic_constraints_ca_true();
    let ca_exts = vec![extension(OID_BASIC_CONSTRAINTS, true, &bc_val)];
    let ca_der = build_cert("Root CA", true, &[0x01], &ca_exts);
    let ca = decode::<Certificate<'_>>(&ca_der).unwrap();
    let anchor = TrustAnchor::from_cert(&ca);

    let ee_der = build_cert("Root CA", false, &[0x02], &[]);
    let ee = decode::<Certificate<'_>>(&ee_der).unwrap();

    let anchors = [anchor];
    let path = build_and_validate(
        &ee,
        &[],
        &anchors,
        PathConfig { time: UnixTime::from_secs(1_893_196_800), verifier: &AcceptAll, max_path_length: None },
    )
    .expect("path validates");
    assert_eq!(path.certs.len(), 1);
}

#[test]
fn chain_unable_to_build_without_issuer() {
    let ee_der = build_cert("Nobody", false, &[0x02], &[]);
    let ee = decode::<Certificate<'_>>(&ee_der).unwrap();
    let result = build_and_validate(
        &ee,
        &[],
        &[],
        PathConfig { time: UnixTime::from_secs(1_893_196_800), verifier: &AcceptAll, max_path_length: None },
    );
    assert!(result.is_err());
}

#[test]
fn chain_rejects_non_ca_intermediate() {
    let bc_val = basic_constraints_ca_true();
    let root_exts = vec![extension(OID_BASIC_CONSTRAINTS, true, &bc_val)];
    let root_der = build_cert("Root CA", true, &[0x01], &root_exts);
    let root = decode::<Certificate<'_>>(&root_der).unwrap();
    let anchor = TrustAnchor::from_cert(&root);

    // Intermediate claims CA:FALSE.
    let inter_der = build_cert("Root CA", false, &[0x03], &[]);
    let inter = decode::<Certificate<'_>>(&inter_der).unwrap();

    // EE issued by the (non-CA) intermediate.
    let ee_der = build_cert("Root CA", false, &[0x04], &[]);
    let ee = decode::<Certificate<'_>>(&ee_der).unwrap();

    let intermediates = [inter];
    let anchors = [anchor];
    let result = build_and_validate(
        &ee,
        &intermediates,
        &anchors,
        PathConfig { time: UnixTime::from_secs(1_893_196_800), verifier: &AcceptAll, max_path_length: None },
    );
    assert!(result.is_err());
}

#[test]
fn time_parse_unix() {
    let der = utc_time("000101000000Z");
    let t = decode::<Time<'_>>(&der).unwrap();
    let u = t.to_unix().unwrap();
    assert_eq!(u.as_secs(), 946_684_800);
}

