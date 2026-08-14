// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pluggable cryptographic backend for signature verification and hashing.
//!
//! `tpt-x509` and `tpt-cms` intentionally contain **no cryptographic
//! primitives** of their own: all signature math is delegated to a caller-supplied
//! [`SignatureVerifier`] implementation (for example one backed by `ring`,
//! `RustCrypto`, or a hardware token). This keeps the parsing crates free of C
//! dependencies and lets downstream users pick their own crypto provider.
//!
//! The backend is intentionally minimal and allocation-friendly: digests and
//! signatures are passed as borrowed byte slices, and the backend returns a
//! freshly allocated digest (the only place `alloc` is required here).

use alloc::vec::Vec;

/// Errors reported by a [`SignatureVerifier`] backend.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum VerifyError {
    /// The backend does not implement the requested algorithm.
    UnsupportedAlgorithm,
    /// The supplied key material could not be parsed.
    InvalidKey,
    /// The signature did not verify (cryptographically invalid).
    InvalidSignature,
    /// The backend encountered an internal error.
    Internal,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::UnsupportedAlgorithm => f.write_str("unsupported algorithm"),
            VerifyError::InvalidKey => f.write_str("invalid key material"),
            VerifyError::InvalidSignature => f.write_str("invalid signature"),
            VerifyError::Internal => f.write_str("internal crypto backend error"),
        }
    }
}

impl core::error::Error for VerifyError {}

/// A pluggable signature-verification and digest backend.
///
/// All algorithm selection is by raw OID bytes (the on-wire encoding of an
/// `OBJECT IDENTIFIER`), so the backend is not tied to any particular registry.
pub trait SignatureVerifier {
    /// Compute the digest of `data` using the algorithm identified by `alg_oid`
    /// (e.g. `id-sha256`). Returns the raw digest bytes.
    fn digest(&self, alg_oid: &[u8], data: &[u8]) -> Result<Vec<u8>, VerifyError>;

    /// Verify `signature` over `message`.
    ///
    /// * `sig_alg_oid` — the signature scheme OID (e.g. `sha256WithRSAEncryption`,
    ///   `ecdsaWithSHA256`, `id-Ed25519`).
    /// * `key_alg_oid` — the public-key algorithm OID from the signer's
    ///   `SubjectPublicKeyInfo` (e.g. `rsaEncryption`, `id-ecPublicKey`,
    ///   `id-Ed25519`).
    /// * `public_key` — the raw `subjectPublicKey` BIT STRING *data* (the key
    ///   bits, not including the unused-bits count), borrowed from the cert.
    fn verify_signature(
        &self,
        sig_alg_oid: &[u8],
        key_alg_oid: &[u8],
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, VerifyError>;
}
