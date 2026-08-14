// SPDX-License-Identifier: MIT OR Apache-2.0

//! `Any`: a lazily/deferred-decoded ASN.1 value.

use crate::decode::Decode;
use crate::error::{Error, Result};
use crate::length::Length;
use crate::reader::Reader;
use crate::tag::Tag;

/// A decoded TLV whose tagged value has not yet been interpreted into a
/// concrete type. Useful for passing through unknown or `CHOICE`-like content.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Any<'a> {
    /// The tag.
    pub tag: Tag,
    /// The length.
    pub length: Length,
    /// The raw value bytes (for an indefinite length, the inner content).
    pub value: &'a [u8],
    /// The complete TLV encoding (tag + length + value), for re-decoding.
    pub full: &'a [u8],
}

impl<'a> Any<'a> {
    /// The tag.
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// The length.
    pub fn length(&self) -> Length {
        self.length
    }

    /// Decode the contained value as `T`, re-parsing the full TLV.
    pub fn decode_as<T: Decode<'a>>(&self) -> Result<T> {
        let mut r = Reader::new(self.full, crate::reader::Config::der());
        let v = T::decode(&mut r)?;
        if !r.is_empty() {
            return Err(Error::TrailingData);
        }
        Ok(v)
    }

    /// Interpret this value as a `SEQUENCE` for structured decoding.
    pub fn sequence<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Reader<'a>) -> Result<R>,
    {
        let mut r = Reader::new(self.full, crate::reader::Config::der());
        crate::decode::read_sequence(&mut r, f)
    }
}

impl<'a> Decode<'a> for Any<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let start = r.position();
        let (tag, length, value) = r.read_tlv()?;
        let end = r.position();
        let full = r.slice(start, end);
        Ok(Any { tag, length, value, full })
    }
}
