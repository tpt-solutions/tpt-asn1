// SPDX-License-Identifier: MIT OR Apache-2.0

//! ASN.1 [`Length`] handling for definite and indefinite forms.

use crate::error::{Error, Result};
use crate::reader::Reader;
use crate::writer::{WriteBackend, Writer};

/// An ASN.1 length: either a definite byte count or indefinite.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Length {
    /// A definite length: exactly this many value bytes.
    Definite(usize),
    /// An indefinite length (BER/CER), terminated by end-of-contents octets.
    Indefinite,
}

impl Length {
    /// Construct a definite length.
    pub const fn definite(n: usize) -> Self {
        Length::Definite(n)
    }

    /// Returns `true` if this is a definite length.
    pub fn is_definite(self) -> bool {
        matches!(self, Length::Definite(_))
    }

    /// Returns the definite byte count, or `None` for indefinite.
    pub fn value(self) -> Option<usize> {
        match self {
            Length::Definite(n) => Some(n),
            Length::Indefinite => None,
        }
    }

    /// Encode the length in DER/BER definite form (minimal encoding).
    pub fn encode<B: WriteBackend>(&self, w: &mut Writer<B>) -> Result<()> {
        match self {
            Length::Indefinite => w.write_u8(0x80),
            Length::Definite(n) => {
                if *n < 0x80 {
                    w.write_u8(*n as u8)
                } else {
                    // Big enough for any `usize` length, which is at most
                    // `size_of::<usize>()` octets in the long form.
                    let mut buf = [0u8; core::mem::size_of::<usize>()];
                    let mut i = buf.len();
                    let mut v = *n;
                    while v > 0 {
                        i -= 1;
                        buf[i] = (v & 0xff) as u8;
                        v >>= 8;
                    }
                    let len = (buf.len() - i) as u8;
                    w.write_u8(0x80 | len)?;
                    w.write_bytes(&buf[i..])
                }
            }
        }
    }

    /// Decode a length from `r` according to the active [`EncodingRule`](crate::EncodingRule).
    pub fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let first = r.read_u8()?;
        if first < 0x80 {
            return Ok(Length::Definite(first as usize));
        }
        match first {
            0x80 => {
                if r.config().rule == crate::EncodingRule::Der {
                    return Err(Error::IndefiniteLength);
                }
                Ok(Length::Indefinite)
            }
            0xff => Err(Error::InvalidLength),
            n => {
                let num_bytes = (n & 0x7f) as usize;
                if num_bytes > core::mem::size_of::<usize>() {
                    return Err(Error::ElementTooLarge);
                }
                let mut value: usize = 0;
                let mut first_octet: Option<u8> = None;
                for _ in 0..num_bytes {
                    let b = r.read_u8()?;
                    first_octet.get_or_insert(b);
                    value = (value << 8) | b as usize;
                }
                // DER requires the shortest possible length encoding: reject
                // long forms for values < 0x80 and any leading zero octet
                // (e.g. `82 00 80` must be encoded as `81 80`).
                if r.config().rule == crate::EncodingRule::Der
                    && (value < 0x80 || first_octet == Some(0))
                {
                    return Err(Error::NonMinimalLength);
                }
                if value > r.remaining() {
                    return Err(Error::ElementTooLarge);
                }
                Ok(Length::Definite(value))
            }
        }
    }
}
