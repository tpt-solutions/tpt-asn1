// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-asn1-core
//!
//! A zero-copy, `no_std` + `no_alloc` capable ASN.1 **DER / BER / CER**
//! tag-length-value (TLV) codec. The core parsing path is `#![forbid(unsafe_code)]`
//! and borrows directly from the input buffer (`&[u8]`) without allocating.
//!
//! ## TLV model
//!
//! Every ASN.1 value is a triple of *tag*, *length*, and *value*:
//!
//! - [`Tag`] — class (Universal/Application/Context/Private), primitive vs
//!   constructed, and the tag number (with multi-byte high-tag-number form).
//! - [`Length`] — definite (short/long form) or indefinite (BER/CER only).
//! - The *value* bytes are borrowed from the input whenever possible.
//!
//! ## Encoding rules
//!
//! Parsing is driven by an [`EncodingRule`] selected on the [`Reader`]:
//!
//! - [`EncodingRule::Der`] — strict DER: definite lengths only, rejects
//!   non-minimal (overlong) length encodings and indefinite lengths.
//! - [`EncodingRule::Ber`] — lenient BER: definite or indefinite lengths.
//! - [`EncodingRule::Cer`] — canonical CER: like BER plus canonical-order
//!   validation (e.g. `SET OF` sort order).
//!
//! ## Example
//!
//! ```
//! use tpt_asn1_core::{decode, tag::Class};
//!
//! let der = [0x02, 0x01, 0x05]; // INTEGER 5
//! let (tag, len, value) = tpt_asn1_core::reader::read_tlv(&der).unwrap();
//! assert_eq!(tag.class, Class::Universal);
//! assert_eq!(tag.number, 2); // INTEGER
//! assert_eq!(value, &[0x05]);
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(rust_2018_idioms)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod any;
pub mod decode;
pub mod error;
pub mod length;
pub mod reader;
pub mod tag;
pub mod types;
pub mod util;
pub mod writer;

pub use any::Any;
pub use decode::{
    read_sequence, read_sequence_of, read_sequence_of_content, read_set, read_set_of,
    read_set_of_content, retag_implicit, Decode, Encode,
};
pub use error::Error;
pub use length::Length;
pub use reader::{Config, EncodingRule, Reader};
pub use tag::{Class, Tag};
pub use writer::Writer;

#[cfg(feature = "alloc")]
pub use alloc::vec::Vec;

/// Decode a single `T` from `bytes` using strict DER, requiring that the entire
/// input is consumed. Trailing bytes are rejected.
pub fn decode<'a, T: Decode<'a>>(bytes: &'a [u8]) -> Result<T, Error> {
    decode_with(bytes, Config::der())
}

/// Decode a single `T` from `bytes` using the supplied [`Config`]. Trailing
/// bytes are rejected.
pub fn decode_with<'a, T: Decode<'a>>(bytes: &'a [u8], config: Config) -> Result<T, Error> {
    let mut reader = Reader::new(bytes, config);
    let value = T::decode(&mut reader)?;
    if reader.is_empty() {
        Ok(value)
    } else {
        Err(Error::TrailingData)
    }
}

/// Decode a single `T` from `bytes`, allowing (and ignoring) trailing data.
pub fn decode_partial<'a, T: Decode<'a>>(bytes: &'a [u8]) -> Result<T, Error> {
    decode_partial_with(bytes, Config::der())
}

/// Decode a single `T` from `bytes` with the supplied [`Config`], allowing
/// trailing data.
pub fn decode_partial_with<'a, T: Decode<'a>>(bytes: &'a [u8], config: Config) -> Result<T, Error> {
    let mut reader = Reader::new(bytes, config);
    T::decode(&mut reader)
}
