// SPDX-License-Identifier: MIT OR Apache-2.0

//! `tpt-x509` — X.509v3 certificate parsing, validation, and chain building.
//!
//! This crate is built on top of [`tpt_asn1_core`]. The pluggable cryptographic
//! backend ([`verify::SignatureVerifier`]) is defined here (Phase 4 item 75)
//! and reused by `tpt-cms` for CMS signature verification.
//!
//! ## Layout
//!
//! - [`oid`] — well-known PKIX OIDs (algorithms, extensions, attributes).
//! - [`algorithm`] — `AlgorithmIdentifier` and algorithm recognition helpers.
//! - [`spki`] — `SubjectPublicKeyInfo` and per-key-type accessors.
//! - [`time`] — X.509 `Time` / `Validity` and a `no_std`-friendly `UnixTime`.
//! - [`name`] — X.501 `Name` / `RDNSequence` parsing (RFC 5280 §7.1).
//! - [`extensions`] — typed X.509v3 extensions (fail-closed on unknown critical).
//! - [`certificate`] — `TBSCertificate` / `Certificate` decoding.
//! - [`crl`] — `CertificateList` (CRL) decoding.
//! - [`ocsp`] — OCSP request / response parsing and matching.
//! - [`chain`] — certification-path building and RFC 5280 §6.1 validation.
//!
//! The parsing path is `#![forbid(unsafe_code)]`. Signature math is delegated to
//! a caller-supplied [`verify::SignatureVerifier`] so this crate stays free of C
//! dependencies and any cryptographic primitives of its own.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(rust_2018_idioms)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// Re-export of the core codec this crate builds on.
pub use tpt_asn1_core as core;

// Re-export the core modules under their old crate-root paths so the typed
// decoders (`crate::decode`, `crate::reader`, …) resolve against `tpt_asn1_core`.
pub use tpt_asn1_core::{any, decode, error, length, reader, tag, types, util, writer};

// --- no_std-compatible, always-available modules ---------------------------------

pub mod oid;
pub mod algorithm;
pub mod spki;
pub mod time;

// --- alloc-gated modules --------------------------------------------------------

#[cfg(feature = "alloc")]
pub mod name;
#[cfg(feature = "alloc")]
pub mod extensions;
#[cfg(feature = "alloc")]
pub mod certificate;
#[cfg(feature = "alloc")]
pub mod crl;
#[cfg(feature = "alloc")]
pub mod ocsp;
#[cfg(feature = "alloc")]
pub mod chain;

/// Pluggable cryptographic backend used for signature verification (Phase 4
/// item 75). `tpt-cms` reuses this same trait for CMS signature verification.
#[cfg(feature = "alloc")]
pub mod verify;

#[cfg(feature = "alloc")]
pub use verify::{SignatureVerifier, VerifyError};

// Convenience re-exports of the most-used public types.
#[cfg(feature = "alloc")]
pub use certificate::{Certificate, TBSCertificate};
#[cfg(feature = "alloc")]
pub use name::Name;
#[cfg(feature = "alloc")]
pub use spki::SubjectPublicKeyInfo;
#[cfg(feature = "alloc")]
pub use time::{Time, UnixTime, Validity};
