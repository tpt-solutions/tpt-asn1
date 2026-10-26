// SPDX-License-Identifier: MIT OR Apache-2.0

//! `tpt-asn1-cms` — Cryptographic Message Syntax (PKCS#7 / CMS, RFC 5652).
//!
//! This crate implements the CMS `ContentInfo` family (`SignedData`,
//! `EnvelopedData`, `DigestedData`, `EncryptedData`) on top of
//! `tpt-asn1-core`, plus PKCS#7 v1.5 (RFC 2315) legacy compatibility. All
//! cryptographic math is delegated to a pluggable backend (the same
//! [`SignatureVerifier`](tpt_asn1_x509::verify::SignatureVerifier) trait defined in
//! `tpt-asn1-x509`), keeping this crate free of C dependencies and `unsafe` code.
//!
//! ## Quick start
//!
//! ```
//! use tpt_asn1_core::decode::Decode;
//! use tpt_asn1_core::reader::Config;
//! // Parse a top-level CMS message:
//! let ci = tpt_asn1_cms::content_info::ContentInfo::decode(&mut tpt_asn1_core::reader::Reader::new(
//!     &[], Config::der()));
//! # let _ = ci;
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

// CMS structures own `Vec`s and the signature-verification path allocates, so the
// crate cannot build without `alloc`. Say so directly rather than failing later
// with unresolved imports.
#[cfg(not(feature = "alloc"))]
compile_error!("tpt-asn1-cms requires the `alloc` feature; enable default features");

#[cfg(feature = "alloc")]
extern crate alloc;

/// Re-export of the core codec this crate builds on.
pub use tpt_asn1_core as core;

pub mod algorithm;
pub mod attributes;
pub mod cert;
pub mod content_info;
pub mod enveloped_data;
pub mod error;
pub mod oid;
pub mod recipient_info;
pub mod signed_data;
pub mod signer_info;
pub mod verify;

#[cfg(feature = "alloc")]
pub use content_info::{decode, decode_partial};

/// The CMS error type.
pub use error::Error;
/// The CMS result alias.
pub use error::Result;
