// SPDX-License-Identifier: MIT OR Apache-2.0

//! PEM framing (RFC 7468) around DER: detection, decoding, and encoding.
//!
//! Only the outer text is handled here. The base64 is strict: data may not follow
//! the padding, and any unused bits in the final character must be zero.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

/// Errors from PEM decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PemError {
    /// The input contains no `-----BEGIN` block.
    NoBlocks,
    /// A `BEGIN` line has no matching `END` line. The label is the block's label.
    Unterminated(String),
    /// The base64 body is malformed.
    BadBase64(&'static str),
}

impl fmt::Display for PemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PemError::NoBlocks => f.write_str("no PEM blocks found"),
            PemError::Unterminated(label) => write!(f, "unterminated PEM block '{label}'"),
            PemError::BadBase64(why) => write!(f, "invalid PEM base64: {why}"),
        }
    }
}

impl core::error::Error for PemError {}

/// A decoded PEM block: its `-----BEGIN <label>-----` label and DER contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PemBlock {
    /// The label from the `-----BEGIN <label>-----` header.
    pub label: String,
    /// The decoded DER bytes.
    pub der: Vec<u8>,
}

/// Returns `true` if `bytes` contains a `-----BEGIN ` header.
pub fn detect_pem(bytes: &[u8]) -> bool {
    bytes.windows(11).any(|w| w == b"-----BEGIN ")
}

/// Map a single base64 character to its 6-bit value.
fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn is_ws(c: u8) -> bool {
    matches!(c, b'\n' | b'\r' | b' ' | b'\t')
}

/// Decode standard base64, tolerating whitespace and `=` padding.
fn b64_decode(input: &[u8]) -> Result<Vec<u8>, PemError> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    // Padding may only appear at the very end of the data.
    let mut padded = false;
    for &c in input {
        if is_ws(c) {
            continue;
        }
        if c == b'=' {
            padded = true;
            continue;
        }
        if padded {
            return Err(PemError::BadBase64("data after padding"));
        }
        let v = b64_val(c).ok_or(PemError::BadBase64("character outside the base64 alphabet"))?;
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    // Leftover bits must be zero in a canonical encoding.
    if buf & ((1 << bits) - 1) != 0 {
        return Err(PemError::BadBase64("non-zero unused bits"));
    }
    Ok(out)
}

/// Decode every PEM block in `bytes`.
pub fn decode_pem(bytes: &[u8]) -> Result<Vec<PemBlock>, PemError> {
    let text = String::from_utf8_lossy(bytes);
    let lines: Vec<&str> = text.lines().collect();
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            let label = rest.strip_suffix("-----").unwrap_or(rest).trim().to_string();
            let mut body = String::new();
            i += 1;
            while i < lines.len() && !lines[i].starts_with("-----END ") {
                body.push_str(lines[i]);
                i += 1;
            }
            if i >= lines.len() {
                return Err(PemError::Unterminated(label));
            }
            i += 1; // consume the END line
            let der = b64_decode(body.as_bytes())?;
            blocks.push(PemBlock { label, der });
        } else {
            i += 1;
        }
    }
    if blocks.is_empty() {
        return Err(PemError::NoBlocks);
    }
    Ok(blocks)
}

/// Encode `der` as a PEM block with `label`, with 64-character base64 lines.
pub fn encode_pem(label: &str, der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for chunk in der.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        let digits = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        // Each chunk of 1 or 2 bytes ends in padding characters.
        let keep = chunk.len() + 1;
        for (k, &d) in digits.iter().enumerate() {
            b64.push(if k < keep { ALPHABET[d as usize] as char } else { '=' });
        }
    }
    let mut out = String::new();
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for line in b64.as_bytes().chunks(64) {
        // The base64 alphabet is ASCII, so each line is valid UTF-8.
        out.push_str(core::str::from_utf8(line).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn encode_then_decode_round_trips() {
        for len in 0..40usize {
            let der: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let text = encode_pem("TEST", &der);
            let blocks = decode_pem(text.as_bytes()).expect("decodes");
            assert_eq!(blocks.len(), 1);
            assert_eq!(blocks[0].label, "TEST");
            assert_eq!(blocks[0].der, der, "length {len}");
        }
    }

    #[test]
    fn rejects_data_after_padding_and_nonzero_unused_bits() {
        // "QQ==" is "A"; "QR==" has non-zero unused bits; "QQ==QQ" has data after padding.
        assert!(decode_pem(b"-----BEGIN X-----\nQQ==\n-----END X-----\n").is_ok());
        assert!(decode_pem(b"-----BEGIN X-----\nQR==\n-----END X-----\n").is_err());
        assert!(decode_pem(b"-----BEGIN X-----\nQQ==QQ\n-----END X-----\n").is_err());
    }

    #[test]
    fn unterminated_block_is_an_error() {
        assert_eq!(
            decode_pem(b"-----BEGIN X-----\nQQ==\n"),
            Err(PemError::Unterminated("X".to_string()))
        );
    }

    #[test]
    fn no_blocks_is_an_error() {
        assert_eq!(decode_pem(b"plain text"), Err(PemError::NoBlocks));
        assert!(!detect_pem(b"plain text"));
        assert!(detect_pem(b"-----BEGIN X-----"));
    }
}
