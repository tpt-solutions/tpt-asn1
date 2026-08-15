// SPDX-License-Identifier: MIT OR Apache-2.0

//! `SignerInfo` — the per-signer signature metadata inside `SignedData`.
//!
//! ```asn1
//! SignerInfo ::= SEQUENCE {
//!     version            CMSVersion,
//!     sid                SignerIdentifier,
//!     digestAlgorithm    DigestAlgorithmIdentifier,
//!     signedAttrs   [0] IMPLICIT SET OF Attribute OPTIONAL,
//!     signatureAlgorithm SignatureAlgorithmIdentifier,
//!     signature          SignatureValue,
//!     unsignedAttrs [1] IMPLICIT SET OF Attribute OPTIONAL }
//!
//! SignerIdentifier ::= CHOICE {
//!     issuerAndSerialNumber IssuerAndSerialNumber,
//!     subjectKeyIdentifier  [0] IMPLICIT SubjectKeyIdentifier }
//! ```

use crate::attributes::{Attribute, decode_attribute_set};
use crate::error::{Error, Result};
use crate::oid;
use crate::algorithm::AlgorithmIdentifier;
use crate::cert::CertFields;
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::Reader;
use tpt_asn1_core::tag::Tag;
use tpt_asn1_core::types::{Integer, OctetString};
use tpt_asn1_core::util::constant_time_eq;

/// How a `SignerInfo` identifies its signing certificate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignerIdentifier<'a> {
    /// An `IssuerAndSerialNumber` (CMS `SignedData` version 1).
    IssuerAndSerialNumber {
        /// The issuer `Name` TLV (tag + length + value).
        issuer: &'a [u8],
        /// The raw `serialNumber` INTEGER bytes.
        serial: &'a [u8],
    },
    /// A `SubjectKeyIdentifier` (CMS `SignedData` version 3).
    SubjectKeyIdentifier(&'a [u8]),
}

/// The `signedAttrs` of a `SignerInfo`: the `SET OF Attribute` payload plus the
/// raw bytes needed to re-encode it as a canonical `SET` for signature
/// verification (OpenSSL signs over the `SET`, not the `[0]` implicit tag).
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct SignedAttributes<'a> {
    /// The `SET OF Attribute` content bytes (between the `SET` tag/length).
    pub raw: &'a [u8],
    /// The decoded attributes.
    pub attributes: alloc::vec::Vec<Attribute<'a>>,
}

#[cfg(feature = "alloc")]
impl<'a> SignedAttributes<'a> {
    /// Re-encode the attributes as a canonical DER `SET` (tag `0x31`), which is
    /// the exact byte string a signature is computed over when `signedAttrs`
    /// are present.
    pub fn der(&self) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::with_capacity(self.raw.len() + 8);
        out.push(Tag::universal_constructed(Tag::SET).to_byte()); // 0x31
        let len = self.raw.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let mut n = len;
            let mut tmp = [0u8; 5];
            let mut i = tmp.len();
            while n > 0 {
                i -= 1;
                tmp[i] = (n & 0xff) as u8;
                n >>= 8;
            }
            let count = (tmp.len() - i) as u8;
            out.push(0x80 | count);
            out.extend_from_slice(&tmp[i..]);
        }
        out.extend_from_slice(self.raw);
        out
    }

    /// Find a signed attribute by OID bytes.
    pub fn find(&self, oid: &[u8]) -> Option<&Attribute<'a>> {
        self.attributes.iter().find(|a| a.type_id.0 == oid)
    }
}

/// A decoded `SignerInfo`.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct SignerInfo<'a> {
    /// CMS version (1 for `IssuerAndSerialNumber`, 3 for `SubjectKeyIdentifier`).
    pub version: u64,
    /// The signer identifier.
    pub sid: SignerIdentifier<'a>,
    /// The digest algorithm applied to the encapsulated content.
    pub digest_algorithm: AlgorithmIdentifier<'a>,
    /// The signed attributes (present in essentially all modern CMS).
    pub signed_attrs: Option<SignedAttributes<'a>>,
    /// The signature algorithm.
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    /// The raw signature value.
    pub signature: &'a [u8],
    /// The unsigned attributes (e.g. countersignatures), if present.
    pub unsigned_attrs: Option<alloc::vec::Vec<Attribute<'a>>>,
}

#[cfg(feature = "alloc")]
impl<'a> SignerInfo<'a> {
    /// The digest-algorithm OID bytes.
    pub fn digest_algorithm_bytes(&self) -> &'a [u8] {
        self.digest_algorithm.algorithm_bytes()
    }

    /// The signature-algorithm OID bytes.
    pub fn signature_algorithm_bytes(&self) -> &'a [u8] {
        self.signature_algorithm.algorithm_bytes()
    }

    /// Constant-time match of this signer against an extracted certificate.
    pub fn matches_cert(&self, cert: &CertFields<'a>) -> bool {
        match &self.sid {
            SignerIdentifier::SubjectKeyIdentifier(id) => {
                match cert.subject_key_id {
                    Some(ski) => constant_time_eq(ski, id),
                    None => false,
                }
            }
            SignerIdentifier::IssuerAndSerialNumber { issuer, serial } => {
                constant_time_eq(cert.issuer, issuer) && constant_time_eq(cert.serial, serial)
            }
        }
    }
}

#[cfg(feature = "alloc")]
impl<'a> Decode<'a> for SignerInfo<'a> {
    fn decode(r: &mut Reader<'a>) -> tpt_asn1_core::error::Result<Self> {
        tpt_asn1_core::decode::read_sequence(r, |s| {
            // version
            let version = Integer::decode(s)?.as_u64().ok_or(Error::UnsupportedVersion)?;

            // sid
            let sid = {
                let (tag, _, value) = s.read_tlv()?;
                if tag == Tag::context(false, 0) {
                    SignerIdentifier::SubjectKeyIdentifier(value)
                } else if tag.is_universal(Tag::SEQUENCE) {
                    let mut ias = Reader::new(value, tpt_asn1_core::reader::Config::der());
                    let issuer = full_tlv(&mut ias)?;
                    let (_, _, serial) = ias.read_tlv()?;
                    SignerIdentifier::IssuerAndSerialNumber { issuer, serial }
                } else {
                    return Err(Error::UnexpectedStructure.into());
                }
            };

            let digest_algorithm = AlgorithmIdentifier::decode(s)?;

            // Optional signedAttrs [0] IMPLICIT SET OF Attribute.
            let signed_attrs = {
                let start = s.position();
                let (tag, _, value) = s.read_tlv()?;
                if tag == Tag::context(false, 0) {
                    let attributes = decode_attribute_set(value)?;
                    Some(SignedAttributes { raw: value, attributes })
                } else {
                    // This TLV is actually the signatureAlgorithm; re-parse it.
                    let full = s.slice(start, s.position());
                    let mut sig_r = Reader::new(full, tpt_asn1_core::reader::Config::der());
                    let signature_algorithm = AlgorithmIdentifier::decode(&mut sig_r)?;
                    return finish_signer(s, version, sid, digest_algorithm, None, signature_algorithm)
                        .map_err(Into::into);
                }
            };

            let signature_algorithm = AlgorithmIdentifier::decode(s)?;
            finish_signer(s, version, sid, digest_algorithm, signed_attrs, signature_algorithm)
                .map_err(Into::into)
        })
    }
}

#[cfg(feature = "alloc")]
fn finish_signer<'a>(
    s: &mut Reader<'a>,
    version: u64,
    sid: SignerIdentifier<'a>,
    digest_algorithm: AlgorithmIdentifier<'a>,
    signed_attrs: Option<SignedAttributes<'a>>,
    signature_algorithm: AlgorithmIdentifier<'a>,
) -> Result<SignerInfo<'a>> {
    let signature = OctetString::decode(s)?.0;
    let unsigned_attrs = if s.is_empty() {
        None
    } else {
        let (tag, _, value) = s.read_tlv()?;
        if tag != Tag::context(false, 1) {
            return Err(Error::UnexpectedStructure);
        }
        Some(decode_attribute_set(value)?)
    };
    Ok(SignerInfo {
        version,
        sid,
        digest_algorithm,
        signed_attrs,
        signature_algorithm,
        signature,
        unsigned_attrs,
    })
}

/// Read the next whole TLV and return it (tag + length + value) as borrowed bytes.
fn full_tlv<'a>(r: &mut Reader<'a>) -> Result<&'a [u8]> {
    let start = r.position();
    r.read_tlv()?;
    let end = r.position();
    Ok(r.slice(start, end))
}

/// Suppress an unused-import warning when `oid` is only referenced in docs.
#[allow(dead_code)]
fn _oid_ref() -> &'static [u8] {
    oid::ATTR_MESSAGE_DIGEST
}
