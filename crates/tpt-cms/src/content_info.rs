// SPDX-License-Identifier: MIT OR Apache-2.0

//! `ContentInfo` — the outer wrapper of every CMS/PKCS#7 message.
//!
//! ```asn1
//! ContentInfo ::= SEQUENCE {
//!     contentType  CONTENT-TYPE.,
//!     content      [0] EXPLICIT CONTENT-TYPE. OPTIONAL }
//! ```

use crate::error::Result;
use tpt_asn1_core::any::Any;
use tpt_asn1_core::decode::{Decode, read_sequence};
use tpt_asn1_core::reader::Reader;
use tpt_asn1_core::types::ObjectIdentifier;

/// The outer CMS `ContentInfo`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ContentInfo<'a> {
    /// The contentType OID (e.g. `id-signedData`).
    pub content_type: ObjectIdentifier<'a>,
    /// The `[0] EXPLICIT` content value (raw inner bytes of the explicit tag).
    pub content: Any<'a>,
}

impl<'a> ContentInfo<'a> {
    /// Borrow the raw bytes of the explicit `[0]` content (the actual inner
    /// structure, e.g. the `SignedData` SEQUENCE).
    pub fn content_bytes(&self) -> &'a [u8] {
        self.content.value
    }

    /// Decode the explicit `[0]` content as `T` (e.g. `SignedData`).
    pub fn decode_content<T: Decode<'a>>(&self) -> Result<T> {
        let mut r = Reader::new(self.content.value, tpt_asn1_core::reader::Config::der());
        let v = T::decode(&mut r)?;
        if !r.is_empty() {
            return Err(crate::error::Error::UnexpectedStructure);
        }
        Ok(v)
    }
}

impl<'a> Decode<'a> for ContentInfo<'a> {
    fn decode(r: &mut Reader<'a>) -> tpt_asn1_core::error::Result<Self> {
        read_sequence(r, |inner| {
            let content_type = ObjectIdentifier::decode(inner)?;
            let content = Any::decode(inner)?;
            Ok(ContentInfo { content_type, content })
        })
    }
}

/// Decode a complete CMS message (strict DER) from `bytes`, returning its
/// [`ContentInfo`]. Trailing bytes are rejected.
pub fn decode(bytes: &[u8]) -> Result<ContentInfo<'_>> {
    tpt_asn1_core::decode::<ContentInfo<'_>>(bytes).map_err(Into::into)
}

/// Decode a complete CMS message allowing trailing data (useful when the input
/// carries extra framing).
pub fn decode_partial(bytes: &[u8]) -> Result<ContentInfo<'_>> {
    tpt_asn1_core::decode_partial::<ContentInfo<'_>>(bytes).map_err(Into::into)
}
