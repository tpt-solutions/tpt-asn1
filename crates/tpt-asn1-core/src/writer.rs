// SPDX-License-Identifier: MIT OR Apache-2.0

//! DER/BER/CER encoding primitives.
//!
//! The [`Writer`] writes into a caller-supplied buffer (`&mut [u8]`) so that
//! encoding can be `no_alloc`-friendly. Constructed values are emitted via
//! [`Writer::nested`], which requires the `alloc` feature (it buffers the inner
//! content to compute a minimal definite length).

use crate::error::Result;
use crate::length::Length;
use crate::tag::Tag;

/// A write backend abstracts over the destination of encoded bytes so that the
/// same encoding logic works for a stack buffer or a growable vector.
pub trait WriteBackend {
    /// Append a single byte. Fails if the destination cannot hold it.
    fn put(&mut self, b: u8) -> Result<()>;
    /// Append a slice of bytes. Fails if the destination cannot hold it.
    fn put_slice(&mut self, s: &[u8]) -> Result<()>;
}

/// A [`WriteBackend`] backed by a growable vector (requires `alloc`).
#[cfg(feature = "alloc")]
pub struct VecBackend(pub alloc::vec::Vec<u8>);

#[cfg(feature = "alloc")]
impl WriteBackend for VecBackend {
    fn put(&mut self, b: u8) -> Result<()> {
        self.0.push(b);
        Ok(())
    }
    fn put_slice(&mut self, s: &[u8]) -> Result<()> {
        self.0.extend_from_slice(s);
        Ok(())
    }
}

/// A [`WriteBackend`] backed by a fixed slice. Writing past the end returns
/// [`crate::error::Error::OutputTooSmall`] and leaves the buffer and position unchanged.
pub struct SliceBackend<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl WriteBackend for SliceBackend<'_> {
    fn put(&mut self, b: u8) -> Result<()> {
        if self.pos >= self.buf.len() {
            return Err(crate::error::Error::OutputTooSmall);
        }
        self.buf[self.pos] = b;
        self.pos += 1;
        Ok(())
    }
    fn put_slice(&mut self, s: &[u8]) -> Result<()> {
        let end = self
            .pos
            .checked_add(s.len())
            .filter(|&end| end <= self.buf.len())
            .ok_or(crate::error::Error::OutputTooSmall)?;
        self.buf[self.pos..end].copy_from_slice(s);
        self.pos = end;
        Ok(())
    }
}

/// An ASN.1 DER/BER/CER writer.
pub struct Writer<B: WriteBackend> {
    backend: B,
}

impl<'a> Writer<SliceBackend<'a>> {
    /// Create a writer over a caller-provided buffer.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Writer { backend: SliceBackend { buf, pos: 0 } }
    }

    /// The number of bytes written so far.
    pub fn position(&self) -> usize {
        self.backend.pos
    }

    /// The encoded bytes written so far.
    pub fn as_written(&self) -> &[u8] {
        &self.backend.buf[..self.backend.pos]
    }
}

#[cfg(feature = "alloc")]
impl Writer<VecBackend> {
    /// Create a writer backed by a fresh vector (requires `alloc`).
    pub fn new_vec() -> Self {
        Writer { backend: VecBackend(alloc::vec::Vec::new()) }
    }

    /// Consume the writer and return the encoded bytes (requires `alloc`).
    pub fn into_vec(self) -> alloc::vec::Vec<u8> {
        self.backend.0
    }
}

impl<B: WriteBackend> Writer<B> {
    /// Write a single byte.
    pub fn write_u8(&mut self, b: u8) -> Result<()> {
        self.backend.put(b)
    }

    /// Write a slice of bytes.
    pub fn write_bytes(&mut self, b: &[u8]) -> Result<()> {
        self.backend.put_slice(b)
    }

    /// Encode a tag.
    pub fn write_tag(&mut self, t: Tag) -> Result<()> {
        t.encode(self)
    }

    /// Encode a length.
    pub fn write_length(&mut self, l: Length) -> Result<()> {
        l.encode(self)
    }

    /// Encode a primitive value: `tag` then `length` then `content`.
    pub fn write_primitive(&mut self, tag: Tag, content: &[u8]) -> Result<()> {
        self.write_tag(tag)?;
        self.write_length(Length::Definite(content.len()))?;
        self.write_bytes(content)
    }

    /// Encode a constructed value. The closure `f` writes the inner content
    /// (requires `alloc` to buffer it and compute a minimal length).
    #[cfg(feature = "alloc")]
    pub fn nested<F>(&mut self, tag: Tag, f: F) -> Result<()>
    where
        F: FnOnce(&mut Writer<VecBackend>) -> Result<()>,
    {
        let mut inner = Writer::new_vec();
        f(&mut inner)?;
        let bytes = inner.into_vec();
        self.write_tag(tag)?;
        self.write_length(Length::Definite(bytes.len()))?;
        self.write_bytes(&bytes)
    }
}

/// Encode `value` into a freshly allocated vector (requires `alloc`).
#[cfg(feature = "alloc")]
pub fn encode_to_vec<T: crate::Encode>(value: &T) -> Result<alloc::vec::Vec<u8>> {
    let mut w = Writer::new_vec();
    value.encode(&mut w)?;
    Ok(w.into_vec())
}

/// The `Encode` trait is imported at the crate root; this re-export keeps the
/// public surface discoverable from this module.
pub use crate::decode::Encode;
