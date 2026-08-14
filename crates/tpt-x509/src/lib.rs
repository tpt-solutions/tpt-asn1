// SPDX-License-Identifier: MIT OR Apache-2.0

//! `tpt-x509` — X.509v3 certificate parsing, validation, and chain building.
//!
//! This crate is built on top of `tpt-asn1-core`. The pluggable cryptographic
//! backend ([`verify::SignatureVerifier`]) is implemented here (Phase 4 item 75)
//! and reused by `tpt-cms` for CMS signature verification.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// Re-export of the core codec this crate builds on.
pub use tpt_asn1_core as core;

/// Pluggable cryptographic backend used for signature verification (Phase 4
/// item 75). `tpt-cms` reuses this same trait for CMS signature verification.
#[cfg(feature = "alloc")]
pub mod verify;

#[cfg(feature = "alloc")]
pub use verify::{SignatureVerifier, VerifyError};
