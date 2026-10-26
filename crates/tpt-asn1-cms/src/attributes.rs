// SPDX-License-Identifier: MIT OR Apache-2.0

//! CMS attribute decode: `Attribute` and the `SET OF Attribute` used for the
//! signed/unsigned attribute sets of a `SignerInfo`.
//!
//! ```asn1
//! Attribute ::= SEQUENCE {
//!     type        OBJECT IDENTIFIER,
//!     values      SET OF AttributeValue }
//! ```
//!
//! Note: when a `SET OF Attribute` appears as a *signed* or *unsigned* attribute
//! set it is wrapped in an `[0]`/`[1]` IMPLICIT tag (see `signer_info.rs`); the
//! present module only handles the `SET OF` payload itself.

use crate::error::Result;
use tpt_asn1_core::any::Any;
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::Reader;
use tpt_asn1_core::tag::Tag;
use tpt_asn1_core::types::ObjectIdentifier;

/// A single CMS attribute.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Attribute<'a> {
    /// The attribute type OID.
    pub type_id: ObjectIdentifier<'a>,
    /// The contents of the `attrValues` `SET OF`: the concatenated TLVs of its
    /// elements, typically one.
    pub values: &'a [u8],
}

impl<'a> Attribute<'a> {
    /// Iterate the raw TLVs of each value in the `SET OF`.
    pub fn value_tlvs(&self) -> impl Iterator<Item = Any<'a>> {
        let mut r = Reader::new(self.values, tpt_asn1_core::reader::Config::ber());
        core::iter::from_fn(move || if r.is_empty() { None } else { Any::decode(&mut r).ok() })
    }

    /// Return the first value as an `Any`, if present.
    pub fn first_value(&self) -> Option<Any<'a>> {
        self.value_tlvs().next()
    }

    /// Decode every value, reporting a malformed value as an error. Unlike
    /// [`Attribute::value_tlvs`], a bad value is not silently dropped.
    #[cfg(feature = "alloc")]
    pub fn checked_values(&self) -> Result<alloc::vec::Vec<Any<'a>>> {
        let mut r = Reader::new(self.values, tpt_asn1_core::reader::Config::ber());
        let mut out = alloc::vec::Vec::new();
        while !r.is_empty() {
            out.push(Any::decode(&mut r)?);
        }
        Ok(out)
    }
}

impl<'a> Decode<'a> for Attribute<'a> {
    fn decode(r: &mut Reader<'a>) -> tpt_asn1_core::error::Result<Self> {
        tpt_asn1_core::decode::read_sequence(r, |inner| {
            let type_id = ObjectIdentifier::decode(inner)?;
            // attrValues SET OF AttributeValue: keep the elements, not the SET wrapper.
            let set = tpt_asn1_core::any::Any::decode(inner)?;
            if set.tag != Tag::universal_constructed(Tag::SET) {
                return Err(tpt_asn1_core::error::Error::UnexpectedTag {
                    expected: Tag::universal_constructed(Tag::SET),
                    actual: set.tag,
                });
            }
            Ok(Attribute { type_id, values: set.value })
        })
    }
}

/// Decode a `SET OF Attribute` payload (the content of the implicit `[0]`/`[1]`
/// tag) into a slice of [`Attribute`]s.
#[cfg(feature = "alloc")]
pub fn decode_attribute_set<'a>(content: &'a [u8]) -> Result<alloc::vec::Vec<Attribute<'a>>> {
    use alloc::vec::Vec;
    let mut r = Reader::new(content, tpt_asn1_core::reader::Config::ber());
    let mut attrs: Vec<Attribute<'a>> = Vec::new();
    while !r.is_empty() {
        attrs.push(Attribute::decode(&mut r)?);
    }
    Ok(attrs)
}
