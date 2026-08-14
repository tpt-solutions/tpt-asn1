// SPDX-License-Identifier: MIT OR Apache-2.0

//! X.501 `Name` / `RDNSequence` parsing and RFC 5280 §7.1 normalization.

use alloc::vec::Vec;

use tpt_asn1_core::any::Any;
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::error::Result;
use tpt_asn1_core::reader::Reader;
use tpt_asn1_core::tag::Tag;
use tpt_asn1_core::types::ObjectIdentifier;

use crate::oid;

/// A single directory string value (the `value` of an `AttributeTypeAndValue`).
///
/// Only the ASCII-compatible string types get a meaningful `as_str()`; the
/// wide-character types (`BmpString`, `UniversalString`) are exposed as raw
/// bytes and compared byte-for-byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttributeValue<'a> {
    /// `UTF8String`.
    Utf8(&'a [u8]),
    /// `PrintableString`.
    Printable(&'a [u8]),
    /// `IA5String`.
    Ia5(&'a [u8]),
    /// `NumericString`.
    Numeric(&'a [u8]),
    /// `VisibleString`.
    Visible(&'a [u8]),
    /// `TeletexString` / `T61String`.
    Teletex(&'a [u8]),
    /// `BMPString` (UCS-2) — raw 2-octet units.
    Bmp(&'a [u8]),
    /// `UniversalString` (UCS-4) — raw 4-octet units.
    Universal(&'a [u8]),
    /// Any other (unexpected) string tag — raw bytes preserved verbatim.
    Other {
        /// The universal tag number of the value.
        tag_number: u32,
        /// The raw value bytes.
        bytes: &'a [u8],
    },
}

impl<'a> AttributeValue<'a> {
    /// Build an `AttributeValue` from a decoded `Any`.
    pub fn from_any(any: &Any<'a>) -> Result<Self> {
        let t = any.tag;
        let b = any.value;
        let mk = |n: u32| AttributeValue::Other { tag_number: n, bytes: b };
        if t.class != Tag::Universal {
            return Ok(mk(t.number));
        }
        Ok(match t.number {
            Tag::UTF8_STRING => AttributeValue::Utf8(b),
            Tag::PRINTABLE_STRING => AttributeValue::Printable(b),
            Tag::IA5_STRING => AttributeValue::Ia5(b),
            Tag::NUMERIC_STRING => AttributeValue::Numeric(b),
            Tag::VISIBLE_STRING => AttributeValue::Visible(b),
            Tag::TELETEX_STRING => AttributeValue::Teletex(b),
            Tag::BMP_STRING => AttributeValue::Bmp(b),
            Tag::UNIVERSAL_STRING => AttributeValue::Universal(b),
            n => mk(n),
        })
    }

    /// The raw bytes of the value (before any normalization).
    pub fn as_bytes(&self) -> &'a [u8] {
        match self {
            AttributeValue::Utf8(b)
            | AttributeValue::Printable(b)
            | AttributeValue::Ia5(b)
            | AttributeValue::Numeric(b)
            | AttributeValue::Visible(b)
            | AttributeValue::Teletex(b)
            | AttributeValue::Bmp(b)
            | AttributeValue::Universal(b) => b,
            AttributeValue::Other { bytes, .. } => bytes,
        }
    }

    /// Best-effort UTF-8 view. Returns `None` for wide-character or invalid
    /// encodings; those callers should fall back to [`as_bytes`].
    pub fn as_str(&self) -> Option<&'a str> {
        core::str::from_utf8(self.as_bytes()).ok()
    }
}

/// An `AttributeTypeAndValue` — `{ type OID, value ANY }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttributeTypeAndValue<'a> {
    /// The attribute type OID (e.g. `id-at-commonName`).
    pub type_id: ObjectIdentifier<'a>,
    /// The (string) value.
    pub value: AttributeValue<'a>,
}

impl<'a> AttributeTypeAndValue<'a> {
    /// The attribute type OID.
    pub fn type_oid(&self) -> &'a [u8] {
        self.type_id.as_bytes()
    }
}

impl<'a> Decode<'a> for AttributeTypeAndValue<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        tpt_asn1_core::decode::read_sequence(r, |inner| {
            let type_id = ObjectIdentifier::decode(inner)?;
            let val_any = Any::decode(inner)?;
            let value = AttributeValue::from_any(&val_any)?;
            Ok(AttributeTypeAndValue { type_id, value })
        })
    }
}

/// A `RelativeDistinguishedName` — a `SET OF AttributeTypeAndValue` (usually
/// a single AVA, but multiple are legal).
#[derive(Debug, PartialEq, Eq)]
pub struct RelativeDistinguishedName<'a> {
    /// The attribute/value assertions in this RDN.
    pub attributes: Vec<AttributeTypeAndValue<'a>>,
}

impl<'a> RelativeDistinguishedName<'a> {
    /// Find the first attribute whose type OID equals `expected`.
    pub fn find(&self, expected: oid::Oid) -> Option<&AttributeValue<'a>> {
        self.attributes
            .iter()
            .find(|a| oid::oid_eq(&a.type_id, expected))
            .map(|a| &a.value)
    }
}

/// An X.501 `Name` (the `RDNSequence`).
///
/// The full DER of the `Name` is retained so that chain-building can perform
/// exact issuer/subject matching; [`Name::matches`] additionally offers the
/// RFC 5280 §7.1 normalized comparison.
#[derive(Debug, PartialEq, Eq)]
pub struct Name<'a> {
    rdns: Vec<RelativeDistinguishedName<'a>>,
    der: &'a [u8],
}

impl<'a> Name<'a> {
    /// The retained DER encoding of this `Name` (exact-match source).
    pub fn as_der(&self) -> &'a [u8] {
        self.der
    }

    /// The sequence of relative distinguished names, in order.
    pub fn rdns(&self) -> &[RelativeDistinguishedName<'a>] {
        &self.rdns
    }

    /// Returns `true` if the two names are byte-for-byte identical in DER.
    pub fn der_eq(&self, other: &Name<'a>) -> bool {
        self.der == other.der
    }

    /// Find the first attribute of the given type anywhere in the DN.
    pub fn find(&self, expected: oid::Oid) -> Option<&AttributeValue<'a>> {
        self.rdns.iter().find_map(|rdn| rdn.find(expected))
    }

    /// Returns `true` if `self` and `other` match under RFC 5280 §7.1 rules.
    ///
    /// RDNs are compared positionally; within each RDN the AVAs are compared as
    /// a set, matching by attribute type and then by the normalized value.
    pub fn matches(&self, other: &Name<'a>) -> bool {
        if self.rdns.len() != other.rdns.len() {
            return false;
        }
        for (a, b) in self.rdns.iter().zip(other.rdns.iter()) {
            if a.attributes.len() != b.attributes.len() {
                return false;
            }
            for ava in &a.attributes {
                let Some(other_ava) = b
                    .attributes
                    .iter()
                    .find(|x| x.type_id.as_bytes() == ava.type_id.as_bytes())
                else {
                    return false;
                };
                if normalize_value(ava.value) != normalize_value(other_ava.value) {
                    return false;
                }
            }
        }
        true
    }
}

impl<'a> Decode<'a> for Name<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let any = Any::decode(r)?;
        let der = any.full;
        if !any.tag.is_universal(Tag::SEQUENCE) {
            return Err(tpt_asn1_core::error::Error::UnexpectedTag {
                expected: Tag::universal_constructed(Tag::SEQUENCE),
                actual: any.tag,
            });
        }
        let mut sub = Reader::new(any.value, *r.config());
        let mut rdns = Vec::new();
        while !sub.is_empty() {
            let rdn_any = Any::decode(&mut sub)?;
            if !rdn_any.tag.is_universal(Tag::SET) {
                return Err(tpt_asn1_core::error::Error::UnexpectedTag {
                    expected: Tag::universal_constructed(Tag::SET),
                    actual: rdn_any.tag,
                });
            }
            let mut rdn_sub = Reader::new(rdn_any.value, *r.config());
            let mut attributes = Vec::new();
            while !rdn_sub.is_empty() {
                attributes.push(AttributeTypeAndValue::decode(&mut rdn_sub)?);
            }
            rdns.push(RelativeDistinguishedName { attributes });
        }
        Ok(Name { rdns, der })
    }
}

/// Normalize a directory-string value per RFC 5280 §7.1:
///
/// - strip leading/trailing space (`0x20`),
/// - collapse runs of internal space to a single space,
/// - fold ASCII letters to upper case.
///
/// Wide-character strings (`BmpString`/`UniversalString`) are compared raw.
fn normalize_value(v: AttributeValue<'_>) -> Vec<u8> {
    let bytes = v.as_bytes();
    let fold = matches!(
        v,
        AttributeValue::Utf8(_)
            | AttributeValue::Printable(_)
            | AttributeValue::Ia5(_)
            | AttributeValue::Numeric(_)
            | AttributeValue::Visible(_)
            | AttributeValue::Teletex(_)
    );
    if !fold {
        return bytes.to_vec();
    }
    let mut out = Vec::new();
    let mut in_ws = false;
    let mut leading = true;
    for &c in bytes {
        if c == 0x20 {
            in_ws = true;
            continue;
        }
        if in_ws {
            if !leading {
                out.push(0x20);
            }
            in_ws = false;
        }
        leading = false;
        out.push(c.to_ascii_uppercase());
    }
    out
}
