// SPDX-License-Identifier: MIT OR Apache-2.0

//! The [`Decode`] / [`Encode`] traits and structured-value helpers.

use crate::error::{Error, Result};
use crate::reader::Reader;
#[cfg(feature = "alloc")]
use crate::reader::EncodingRule;
use crate::tag::Tag;
use crate::writer::{WriteBackend, Writer};

/// A type that can be decoded from ASN.1, borrowing from the input where possible.
pub trait Decode<'a>: Sized {
    /// Decode `Self` from `r`.
    fn decode(r: &mut Reader<'a>) -> Result<Self>;
}

/// A type that can be encoded to ASN.1 (DER/BER/CER).
pub trait Encode {
    /// Encode `self` into `w`.
    fn encode<W: WriteBackend>(&self, w: &mut Writer<W>) -> Result<()>;
}

/// Assert that the next tag equals `expected`.
pub fn expect_tag(r: &mut Reader<'_>, expected: Tag) -> Result<()> {
    let actual = r.read_tag()?;
    if actual == expected {
        Ok(())
    } else {
        Err(Error::UnexpectedTag { expected, actual })
    }
}

/// Read a primitive value, asserting its tag is `expected`, and return the
/// value bytes (borrowed from the input).
pub fn read_primitive<'a>(r: &mut Reader<'a>, expected: Tag) -> Result<&'a [u8]> {
    let (tag, _len, value) = r.read_tlv()?;
    if tag == expected {
        Ok(value)
    } else {
        Err(Error::UnexpectedTag { expected, actual: tag })
    }
}

/// Read an EXPLICIT-tagged value: the outer `tag` wraps the encoded `T`.
pub fn read_explicit<'a, T: Decode<'a>>(r: &mut Reader<'a>, tag: Tag) -> Result<T> {
    let (actual, _len, content) = r.read_tlv()?;
    if actual != tag {
        return Err(Error::UnexpectedTag { expected: tag, actual });
    }
    let mut inner = r.sub_reader(content)?;
    let v = T::decode(&mut inner)?;
    if !inner.is_empty() {
        return Err(Error::TrailingData);
    }
    Ok(v)
}

/// Decode a `SEQUENCE` (or `SEQUENCE OF`), passing a sub-reader over its
/// content to `f`. Trailing data inside the sequence is rejected.
pub fn read_sequence<'a, F, R>(r: &mut Reader<'a>, f: F) -> Result<R>
where
    F: FnOnce(&mut Reader<'a>) -> Result<R>,
{
    let expected = Tag::universal_constructed(Tag::SEQUENCE);
    let (tag, _len, content) = r.read_tlv()?;
    if tag != expected {
        return Err(Error::UnexpectedTag { expected, actual: tag });
    }
    let mut inner = r.sub_reader(content)?;
    let out = f(&mut inner)?;
    if !inner.is_empty() {
        return Err(Error::TrailingData);
    }
    Ok(out)
}

/// Decode a `SET` (heterogeneous, tagged fields), passing a sub-reader over its
/// content to `f`.
pub fn read_set<'a, F, R>(r: &mut Reader<'a>, f: F) -> Result<R>
where
    F: FnOnce(&mut Reader<'a>) -> Result<R>,
{
    let expected = Tag::universal_constructed(Tag::SET);
    let (tag, _len, content) = r.read_tlv()?;
    if tag != expected {
        return Err(Error::UnexpectedTag { expected, actual: tag });
    }
    let mut inner = r.sub_reader(content)?;
    let out = f(&mut inner)?;
    if !inner.is_empty() {
        return Err(Error::TrailingData);
    }
    Ok(out)
}

/// Re-tag a previously encoded TLV with `new_tag`, preserving its length and
/// content. Used to implement IMPLICIT tagging: the wrapped value's bytes are
/// unchanged; only its leading tag is replaced. Returns the re-tagged encoding.
#[cfg(feature = "alloc")]
pub fn retag_implicit(encoded: &[u8], new_tag: Tag) -> Result<alloc::vec::Vec<u8>> {
    if encoded.is_empty() {
        return Err(Error::InvalidTag);
    }
    // Determine the byte length of the original leading tag.
    let tag_len = if (encoded[0] & 0x1f) == 0x1f {
        let mut t = 1usize;
        while t < encoded.len() && encoded[t] & 0x80 != 0 {
            t += 1;
        }
        if t >= encoded.len() {
            return Err(Error::InvalidTag);
        }
        t + 1
    } else {
        1
    };
    let mut w = Writer::new_vec();
    new_tag.encode(&mut w)?;
    w.write_bytes(&encoded[tag_len..])?;
    Ok(w.into_vec())
}

/// Decode a `SET OF T` (homogeneous), returning the elements in canonical order.
///
/// Under DER/CER the elements are validated to appear in canonical (ascending
/// encoded) order.
#[cfg(feature = "alloc")]
pub fn read_set_of<'a, T: Decode<'a>>(r: &mut Reader<'a>) -> Result<alloc::vec::Vec<T>> {
    let expected = Tag::universal_constructed(Tag::SET);
    let (tag, _len, content) = r.read_tlv()?;
    if tag != expected {
        return Err(Error::UnexpectedTag { expected, actual: tag });
    }
    let mut inner = r.sub_reader(content)?;
    read_set_of_content(&mut inner)
}

/// Like [`read_set_of`] but decodes from a reader already positioned at the
/// `SET OF` content (used for IMPLICIT-tagged `SET OF`).
#[cfg(feature = "alloc")]
pub fn read_set_of_content<'a, T: Decode<'a>>(r: &mut Reader<'a>) -> Result<alloc::vec::Vec<T>> {
    use alloc::vec::Vec;
    let config = *r.config();
    let mut out: Vec<T> = Vec::new();
    let mut prev: Option<alloc::vec::Vec<u8>> = None;
    while !r.is_empty() {
        let start = r.position();
        let v = T::decode(r)?;
        let end = r.position();
        if config.rule != EncodingRule::Ber {
            let elem = r.slice(start, end);
            if let Some(p) = &prev {
                if p.as_slice() > elem {
                    return Err(Error::SetOfNotSorted);
                }
            }
            prev = Some(elem.to_vec());
        }
        out.push(v);
    }
    Ok(out)
}

/// Decode a `SEQUENCE OF T` (homogeneous), returning the elements in order.
#[cfg(feature = "alloc")]
pub fn read_sequence_of<'a, T: Decode<'a>>(r: &mut Reader<'a>) -> Result<alloc::vec::Vec<T>> {
    let expected = Tag::universal_constructed(Tag::SEQUENCE);
    let (tag, _len, content) = r.read_tlv()?;
    if tag != expected {
        return Err(Error::UnexpectedTag { expected, actual: tag });
    }
    let mut inner = r.sub_reader(content)?;
    read_sequence_of_content(&mut inner)
}

/// Like [`read_sequence_of`] but decodes from a reader already positioned at
/// the `SEQUENCE OF` content (used for IMPLICIT-tagged `SEQUENCE OF`).
#[cfg(feature = "alloc")]
pub fn read_sequence_of_content<'a, T: Decode<'a>>(
    r: &mut Reader<'a>,
) -> Result<alloc::vec::Vec<T>> {
    use alloc::vec::Vec;
    let mut out: Vec<T> = Vec::new();
    while !r.is_empty() {
        out.push(T::decode(r)?);
    }
    Ok(out)
}
