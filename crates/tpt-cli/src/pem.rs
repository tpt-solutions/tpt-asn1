// SPDX-License-Identifier: MIT OR Apache-2.0

//! PEM detection and decoding (RFC 7468 framing + standard base64).

/// Returns `true` if `bytes` look like a PEM document (contains a
/// `-----BEGIN ` header line).
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
fn b64_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &c in input {
        if is_ws(c) || c == b'=' {
            continue;
        }
        let v = b64_val(c).ok_or_else(|| format!("invalid base64 character {:?}", c as char))?;
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// A decoded PEM block: its `-----BEGIN <label>-----` label and DER contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemBlock {
    /// The label from the `-----BEGIN <label>-----` header.
    pub label: String,
    /// The decoded DER bytes.
    pub der: Vec<u8>,
}

/// Decode all PEM blocks found in `bytes`.
pub fn decode_pem(bytes: &[u8]) -> Result<Vec<PemBlock>, String> {
    let text = String::from_utf8_lossy(bytes);
    let lines: Vec<&str> = text.lines().collect();
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            let label = rest
                .strip_suffix("-----")
                .unwrap_or(rest)
                .trim()
                .to_string();
            let mut body = String::new();
            i += 1;
            while i < lines.len() && !lines[i].starts_with("-----END ") {
                body.push_str(lines[i]);
                i += 1;
            }
            if i >= lines.len() {
                return Err(format!("unterminated PEM block '{label}'"));
            }
            i += 1; // consume END line
            let der = b64_decode(body.as_bytes())?;
            blocks.push(PemBlock { label, der });
        } else {
            i += 1;
        }
    }
    if blocks.is_empty() {
        return Err("no PEM blocks found".to_string());
    }
    Ok(blocks)
}
