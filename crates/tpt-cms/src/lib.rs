// SPDX-License-Identifier: MIT OR Apache-2.0

//! `tpt-cms` — Cryptographic Message Syntax (PKCS#7 / CMS, RFC 5652).
//!
//! This crate implements the CMS `ContentInfo` family (`SignedData`,
//! `EnvelopedData`, `DigestedData`, `EncryptedData`) on top of
//! `tpt-asn1-core`, plus PKCS#7 v1.5 (RFC 2315) legacy compatibility. All
//! cryptographic math is delegated to a pluggable backend (the same
//! [`SignatureVerifier`](tpt_x509::crypto::SignatureVerifier) trait defined in
//! `tpt-x509`), keeping this crate free of C dependencies and `unsafe` code.
//!
//! ## Quick start
//!
//! ```
//! use tpt_asn1_core::reader::Config;
//! // Parse a top-level CMS message:
//! let ci = tpt_cms::content_info::ContentInfo::decode(&mut tpt_asn1_core::reader::Reader::new(
//!     &[], Config::der()));
//! # let _ = ci;
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// Re-export of the core codec this crate builds on.
pub use tpt_asn1_core as core;

pub mod algorithm;
pub mod attributes;
pub mod cert;
pub mod content_info;
pub mod error;
pub mod oid;
pub mod recipient_info;
pub mod signer_info;
pub mod signed_data;
pub mod enveloped_data;
pub mod verify;

#[cfg(feature = "alloc")]
pub use content_info::{decode, decode_partial};

/// The CMS error type.
pub use error::Error;
/// The CMS result alias.
pub use error::Result;
