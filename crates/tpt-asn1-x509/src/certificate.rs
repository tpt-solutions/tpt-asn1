// SPDX-License-Identifier: MIT OR Apache-2.0

//! `TBSCertificate` and `Certificate` decoding (RFC 5280 §4.1).

use tpt_asn1_core::any::Any;
use tpt_asn1_core::decode::{read_sequence, Decode};
use tpt_asn1_core::error::Result;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_core::tag::Tag;
use tpt_asn1_core::types::{BitString, Integer};

use crate::algorithm::AlgorithmIdentifier;
use crate::extensions::Extensions;
use crate::name::Name;
use crate::spki::SubjectPublicKeyInfo;
use crate::time::{UnixTime, Validity};

/// The encoded body of a `TBSCertificate`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TBSCertificate<'a> {
    /// The certificate version: 1 (default), 2, or 3.
    pub version: u8,
    /// The certificate serial number.
    pub serial_number: Integer<'a>,
    /// The signature algorithm asserted by the issuer.
    pub signature: AlgorithmIdentifier<'a>,
    /// The issuer `Name`.
    pub issuer: Name<'a>,
    /// The validity period.
    pub validity: Validity<'a>,
    /// The subject `Name`.
    pub subject: Name<'a>,
    /// The subject's public key.
    pub subject_public_key_info: SubjectPublicKeyInfo<'a>,
    /// The extensions (empty if this is not a v3 certificate).
    pub extensions: Extensions<'a>,
}

impl<'a> TBSCertificate<'a> {
    /// The serial number as raw bytes.
    pub fn serial_number_bytes(&self) -> &'a [u8] {
        self.serial_number.as_bytes()
    }

    /// Whether the certificate is a CA (per `BasicConstraints`).
    pub fn is_ca(&self) -> bool {
        self.extensions.basic_constraints().ok().flatten().map(|bc| bc.ca).unwrap_or(false)
    }
}

/// An X.509v3 `Certificate`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate<'a> {
    /// The to-be-signed certificate body.
    pub tbs: TBSCertificate<'a>,
    /// The signature algorithm (outer, asserted by the issuer).
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    /// The signature value (`BIT STRING` data octets).
    pub signature_value: BitString<'a>,
    /// The raw DER of `tbsCertificate`, retained for signature verification.
    tbs_der: &'a [u8],
}

impl<'a> Certificate<'a> {
    /// The raw DER of the `TBSCertificate` (the signed message).
    pub fn tbs_certificate_der(&self) -> &'a [u8] {
        self.tbs_der
    }

    /// The issuer `Name`.
    pub fn issuer(&self) -> &Name<'a> {
        &self.tbs.issuer
    }

    /// The subject `Name`.
    pub fn subject(&self) -> &Name<'a> {
        &self.tbs.subject
    }

    /// The subject public key info.
    pub fn subject_public_key_info(&self) -> &SubjectPublicKeyInfo<'a> {
        &self.tbs.subject_public_key_info
    }

    /// The serial number.
    pub fn serial_number(&self) -> Integer<'a> {
        self.tbs.serial_number
    }

    /// Whether the certificate is currently within its validity period.
    pub fn is_valid_at(&self, now: UnixTime) -> bool {
        self.tbs.validity.contains(now)
    }

    /// Returns `true` if this certificate is self-signed (subject == issuer by
    /// DER), ignoring the signature itself.
    pub fn is_self_signed_name(&self) -> bool {
        self.tbs.issuer.der_eq(&self.tbs.subject)
    }
}

impl<'a> Decode<'a> for Certificate<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let tbs_any = Any::decode(inner)?;
            if !tbs_any.tag.is_universal(Tag::SEQUENCE) || !tbs_any.tag.constructed {
                return Err(tpt_asn1_core::error::Error::UnexpectedTag {
                    expected: Tag::universal(Tag::SEQUENCE),
                    actual: tbs_any.tag,
                });
            }
            let tbs = decode_tbs(tbs_any.value, *inner.config())?;
            let signature_algorithm = AlgorithmIdentifier::decode(inner)?;
            // RFC 5280 §4.1.1.2: the signature algorithm in the TBS must match the
            // outer one, since a verifier may use either.
            if tbs.signature != signature_algorithm {
                return Err(tpt_asn1_core::error::Error::Custom(
                    "tbsCertificate signature algorithm differs from certificate",
                ));
            }
            let signature_value = BitString::decode(inner)?;
            Ok(Certificate { tbs, signature_algorithm, signature_value, tbs_der: tbs_any.full })
        })
    }
}

fn decode_tbs(content: &[u8], config: Config) -> Result<TBSCertificate<'_>> {
    let mut r = Reader::new(content, config);
    // version [0] EXPLICIT Version DEFAULT v1. Only v1, v2 and v3 exist, which
    // are encoded as 0, 1 and 2.
    let mut version = 1u8;
    if r.peek_tag() == Ok(Tag::context(true, 0)) {
        let v_any = Any::decode(&mut r)?;
        let mut sub = Reader::new(v_any.value, config);
        let v = Integer::decode(&mut sub)?
            .as_u64()
            .ok_or(tpt_asn1_core::error::Error::Custom("version too large"))?;
        version = match v {
            0..=2 => v as u8 + 1,
            _ => return Err(tpt_asn1_core::error::Error::Custom("unknown certificate version")),
        };
    }
    let serial_number = Integer::decode(&mut r)?;
    let signature = AlgorithmIdentifier::decode(&mut r)?;
    let issuer = Name::decode(&mut r)?;
    let validity = Validity::decode(&mut r)?;
    let subject = Name::decode(&mut r)?;
    let subject_public_key_info = SubjectPublicKeyInfo::decode(&mut r)?;

    // Skip optional issuerUniqueID [1] / subjectUniqueID [2] (rare, v2/v1).
    while r.peek_tag() == Ok(Tag::context(false, 1)) || r.peek_tag() == Ok(Tag::context(false, 2)) {
        Any::decode(&mut r)?;
    }

    // extensions [3] EXPLICIT Extensions exist only in v3 certificates.
    let mut extensions = Extensions::empty();
    if r.peek_tag() == Ok(Tag::context(true, 3)) {
        if version != 3 {
            return Err(tpt_asn1_core::error::Error::Custom(
                "extensions present in a non-v3 certificate",
            ));
        }
        let e_any = Any::decode(&mut r)?;
        extensions = Extensions::from_content(e_any.value, config)?;
    }
    if !r.is_empty() {
        return Err(tpt_asn1_core::error::Error::TrailingData);
    }

    Ok(TBSCertificate {
        version,
        serial_number,
        signature,
        issuer,
        validity,
        subject,
        subject_public_key_info,
        extensions,
    })
}
