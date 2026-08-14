// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types returned by the codec.

use core::fmt;

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced while parsing or encoding ASN.1.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The input ended before a complete TLV could be read.
    Truncated,
    /// The input contained bytes after the expected end of a value.
    TrailingData,
    /// A tag byte could not be interpreted.
    InvalidTag,
    /// A length field was malformed.
    InvalidLength,
    /// A length was encoded using more bytes than necessary (DER only).
    NonMinimalLength,
    /// An indefinite length appeared where definite lengths are required (DER).
    IndefiniteLength,
    /// A tag number exceeded the supported range.
    UnsupportedTagNumber(u32),
    /// Nesting exceeded the configured recursion limit.
    RecursionLimitExceeded,
    /// A length claimed more bytes than the remaining input allows (DoS guard).
    ElementTooLarge,
    /// A BOOLEAN value did not use the canonical encoding.
    MalformedBoolean,
    /// An INTEGER was encoded with a leading redundant byte.
    IntegerNotMinimal,
    /// An OBJECT IDENTIFIER was malformed.
    BadObjectIdentifier,
    /// A BIT STRING had an invalid unused-bits count.
    BadBitString,
    /// A string value was not valid UTF-8 where required.
    BadUtf8,
    /// A string value violated its permitted character set (BER strictness).
    BadStringType,
    /// A time value did not match its grammar.
    BadTime,
    /// A `SET OF` was not in canonical (DER/CER) sort order.
    SetOfNotSorted,
    /// A tag was found where a different tag was expected.
    UnexpectedTag {
        /// The tag that was expected.
        expected: crate::Tag,
        /// The tag that was actually present.
        actual: crate::Tag,
    },
    /// A critical extension could not be processed (fail-closed).
    UnknownCriticalExtension,
    /// A caller-supplied invariant was violated.
    Custom(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated => f.write_str("truncated input"),
            Error::TrailingData => f.write_str("trailing data after value"),
            Error::InvalidTag => f.write_str("invalid tag"),
            Error::InvalidLength => f.write_str("invalid length encoding"),
            Error::NonMinimalLength => f.write_str("non-minimal length encoding"),
            Error::IndefiniteLength => f.write_str("indefinite length not allowed"),
            Error::UnsupportedTagNumber(n) => write!(f, "unsupported tag number {n}"),
            Error::RecursionLimitExceeded => f.write_str("recursion limit exceeded"),
            Error::ElementTooLarge => f.write_str("element size exceeds configured limit"),
            Error::MalformedBoolean => f.write_str("malformed BOOLEAN"),
            Error::IntegerNotMinimal => f.write_str("INTEGER not minimally encoded"),
            Error::BadObjectIdentifier => f.write_str("malformed OBJECT IDENTIFIER"),
            Error::BadBitString => f.write_str("invalid BIT STRING"),
            Error::BadUtf8 => f.write_str("invalid UTF-8"),
            Error::BadStringType => f.write_str("string violates character set"),
            Error::BadTime => f.write_str("malformed time value"),
            Error::SetOfNotSorted => f.write_str("SET OF not in canonical order"),
            Error::UnexpectedTag { expected, actual } => {
                write!(f, "unexpected tag: expected {expected:?}, got {actual:?}")
            }
            Error::UnknownCriticalExtension => {
                f.write_str("unhandled critical extension (fail-closed)")
            }
            Error::Custom(msg) => f.write_str(msg),
        }
    }
}

impl core::error::Error for Error {}
