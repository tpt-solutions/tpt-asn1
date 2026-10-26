// SPDX-License-Identifier: MIT OR Apache-2.0

//! PEM handling for the CLI. The framing and base64 live in `tpt_asn1_core::pem`;
//! this module keeps the CLI's `String` error type.

pub use tpt_asn1_core::pem::{detect_pem, PemBlock};

/// Decode all PEM blocks found in `bytes`, reporting errors as text.
pub fn decode_pem(bytes: &[u8]) -> Result<Vec<PemBlock>, String> {
    tpt_asn1_core::pem::decode_pem(bytes).map_err(|e| e.to_string())
}
