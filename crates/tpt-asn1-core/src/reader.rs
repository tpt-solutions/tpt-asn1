// SPDX-License-Identifier: MIT OR Apache-2.0

//! Zero-copy ASN.1 reader with recursion-depth and element-size guards.

use crate::error::{Error, Result};
use crate::length::Length;
use crate::tag::Tag;

/// The ASN.1 encoding rule that governs parsing strictness.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum EncodingRule {
    /// ITU-T X.690 DER: definite lengths only, minimal length encoding,
    /// canonical ordering. Indefinite and non-minimal lengths are rejected.
    Der,
    /// ITU-T X.690 BER: definite or indefinite lengths accepted.
    Ber,
    /// ITU-T X.690 CER: like BER plus canonical-order validation.
    Cer,
}

impl EncodingRule {
    /// Whether this rule permits indefinite-length encodings.
    pub fn allows_indefinite(self) -> bool {
        self != EncodingRule::Der
    }
}

/// Parser configuration: rule, recursion cap, and maximum element size.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Config {
    /// Active encoding rule.
    pub rule: EncodingRule,
    /// Maximum nesting depth of constructed types (DoS guard).
    pub max_recursion: usize,
    /// Maximum size, in bytes, of any single element (DoS guard).
    pub max_element_size: usize,
}

impl Config {
    /// Strict DER configuration with conservative guards.
    pub fn der() -> Self {
        Config { rule: EncodingRule::Der, max_recursion: 32, max_element_size: 64 * 1024 * 1024 }
    }

    /// Lenient BER configuration.
    pub fn ber() -> Self {
        Config { rule: EncodingRule::Ber, max_recursion: 32, max_element_size: 64 * 1024 * 1024 }
    }

    /// Canonical CER configuration.
    pub fn cer() -> Self {
        Config { rule: EncodingRule::Cer, max_recursion: 32, max_element_size: 64 * 1024 * 1024 }
    }
}

/// A zero-copy reader over a byte slice.
pub struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
    config: Config,
    depth: usize,
}

impl<'a> Reader<'a> {
    /// Create a reader over `input` with the given `config`.
    pub fn new(input: &'a [u8], config: Config) -> Self {
        Reader { input, pos: 0, config, depth: 0 }
    }

    /// The active parser configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Number of unread bytes remaining.
    pub fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    /// Borrow the `input[start..end]` span (used to capture a full TLV).
    pub fn slice(&self, start: usize, end: usize) -> &'a [u8] {
        &self.input[start..end]
    }

    /// Whether the input is fully consumed.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.input.len()
    }

    /// Current read offset.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Borrow all remaining unread bytes and advance to the end of input.
    ///
    /// Used when an outer tag has already been consumed and only the value
    /// content remains to be interpreted (e.g. decoding the content of an
    /// IMPLICIT-tagged value, whose tag was replaced but whose bytes are
    /// identical to the underlying type's content).
    pub fn read_remaining(&mut self) -> Result<&'a [u8]> {
        let slice = &self.input[self.pos..];
        self.pos = self.input.len();
        Ok(slice)
    }

    /// Read a single byte.
    pub fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.input.len() {
            return Err(Error::Truncated);
        }
        let b = self.input[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Read `n` bytes as a zero-copy slice borrowed from the input.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(Error::Truncated);
        }
        let slice = &self.input[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Read a [`Tag`].
    pub fn read_tag(&mut self) -> Result<Tag> {
        Tag::decode(self)
    }

    /// Peek the next [`Tag`] without consuming any input.
    pub fn peek_tag(&self) -> Result<Tag> {
        let mut tmp = Reader { input: self.input, pos: self.pos, config: self.config, depth: self.depth };
        Tag::decode(&mut tmp)
    }

    /// Read a [`Length`].
    pub fn read_length(&mut self) -> Result<Length> {
        Length::decode(self)
    }

    /// Read a complete TLV, returning its `(tag, length, value_bytes)`.
    ///
    /// The returned `value_bytes` are borrowed directly from the input:
    /// for a definite length it is the exact value; for an indefinite length
    /// it is the inner content (excluding the terminating end-of-contents
    /// octets), which itself contains a sequence of nested TLVs.
    pub fn read_tlv(&mut self) -> Result<(Tag, Length, &'a [u8])> {
        let tag = self.read_tag()?;
        let length = self.read_length()?;
        match length {
            Length::Definite(n) => {
                if n > self.config.max_element_size {
                    return Err(Error::ElementTooLarge);
                }
                let value = self.read_bytes(n)?;
                Ok((tag, length, value))
            }
            Length::Indefinite => {
                let content_end = find_eoc(self.input, self.pos, self.config.max_recursion)?;
                let value = &self.input[self.pos..content_end];
                if value.len() > self.config.max_element_size {
                    return Err(Error::ElementTooLarge);
                }
                self.pos = content_end + 2; // consume the EOC (00 00)
                Ok((tag, length, value))
            }
        }
    }

    /// Create a sub-reader over `content` that inherits this reader's config
    /// and enforces the recursion-depth guard. Used by constructed decoders.
    pub(crate) fn sub_reader(&self, content: &'a [u8]) -> Result<Reader<'a>> {
        if self.depth + 1 > self.config.max_recursion {
            return Err(Error::RecursionLimitExceeded);
        }
        let sub = Reader { input: content, pos: 0, config: self.config, depth: self.depth + 1 };
        Ok(sub)
    }
}

/// Scan `input` from `start` for the end-of-contents (EOC, `00 00`) octets that
/// terminate the enclosing indefinite-length element, respecting nesting
/// depth. Returns the offset of the EOC octets.
fn find_eoc(input: &[u8], start: usize, max_recursion: usize) -> Result<usize> {
    find_eoc_inner(input, start, 0, max_recursion)
}

fn find_eoc_inner(
    input: &[u8],
    mut pos: usize,
    depth: usize,
    max_recursion: usize,
) -> Result<usize> {
    if depth > max_recursion {
        return Err(Error::RecursionLimitExceeded);
    }
    while pos < input.len() {
        // End-of-contents terminates an indefinite element at this depth.
        if input[pos] == 0x00 && pos + 1 < input.len() && input[pos + 1] == 0x00 {
            if depth == 0 {
                return Ok(pos);
            }
            // An EOC at a deeper level belongs to a nested indefinite element;
            // caller handles those via recursion, so reaching one here is an
            // unbalanced encoding.
            return Err(Error::InvalidTag);
        }

        // Parse tag to discover how many bytes it occupies.
        let first = input[pos];
        let tag_len = if (first & 0x1f) == 0x1f {
            // high-tag-number form: count continuation bytes
            let mut t = pos + 1;
            loop {
                if t >= input.len() {
                    return Err(Error::Truncated);
                }
                let b = input[t];
                t += 1;
                if b & 0x80 == 0 {
                    break;
                }
            }
            t - pos
        } else {
            1
        };

        let len_pos = pos + tag_len;
        if len_pos >= input.len() {
            return Err(Error::Truncated);
        }
        let len_byte = input[len_pos];
        let (value_len, after_header) = if len_byte < 0x80 {
            (Some(len_byte as usize), len_pos + 1)
        } else if len_byte == 0x80 {
            (None, len_pos + 1)
        } else if len_byte == 0xff {
            return Err(Error::InvalidLength);
        } else {
            let num = (len_byte & 0x7f) as usize;
            if len_pos + 1 + num > input.len() {
                return Err(Error::Truncated);
            }
            let mut v: usize = 0;
            for i in 0..num {
                v = (v << 8) | input[len_pos + 1 + i] as usize;
            }
            (Some(v), len_pos + 1 + num)
        };

        match value_len {
            Some(n) => {
                if after_header + n > input.len() {
                    return Err(Error::Truncated);
                }
                pos = after_header + n;
            }
            None => {
                // Indefinite: descend to find this element's own EOC.
                let eoc = find_eoc_inner(input, after_header, depth + 1, max_recursion)?;
                pos = eoc + 2;
            }
        }
    }
    Err(Error::Truncated)
}

/// Read a single top-level TLV from `bytes` using strict DER.
pub fn read_tlv(bytes: &[u8]) -> Result<(Tag, Length, &[u8])> {
    let mut reader = Reader::new(bytes, Config::der());
    reader.read_tlv()
}
