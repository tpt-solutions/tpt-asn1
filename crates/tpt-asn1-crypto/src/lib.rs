// SPDX-License-Identifier: MIT OR Apache-2.0

//! RustCrypto-backed [`SignatureVerifier`] for `tpt-asn1-x509` and `tpt-asn1-cms`.
//!
//! The parsing crates do no cryptography themselves. This crate supplies the math:
//!
//! - RSA PKCS#1 v1.5 with SHA-1, SHA-256, SHA-384 and SHA-512.
//! - ECDSA on P-256 with SHA-256, and on P-384 with SHA-384.
//! - Ed25519 (strict verification).
//!
//! Anything else is reported as [`VerifyError::UnsupportedAlgorithm`]. A signature
//! that is well-formed but does not verify returns `Ok(false)`. A malformed
//! signature also returns `Ok(false)`, so it fails closed without an error.
//!
//! ```no_run
//! use tpt_asn1_crypto::RustCryptoVerifier;
//! use tpt_asn1_x509::chain::{build_and_validate, PathConfig};
//!
//! let verifier = RustCryptoVerifier;
//! // Pass `&verifier` as `PathConfig::verifier` when building and validating a path.
//! ```

use sha1::Digest as _;
use tpt_asn1_x509::oid;
use tpt_asn1_x509::verify::{SignatureVerifier, VerifyError};

/// The signature backend. It holds no state, so it is cheap to copy.
#[derive(Clone, Copy, Debug, Default)]
pub struct RustCryptoVerifier;

/// The digest algorithms this backend supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

/// `id-sha1`, which `tpt_asn1_x509::oid` does not list.
const SHA1: &[u64] = &[1, 3, 14, 3, 2, 26];
/// `sha1WithRSAEncryption`, which `tpt_asn1_x509::oid` does not list.
const SHA1_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 5];

fn hash_for_digest(alg: &[u8]) -> Option<Hash> {
    use oid::digest::{SHA256, SHA384, SHA512};
    if oid::oid_eq_bytes(alg, SHA1) {
        Some(Hash::Sha1)
    } else if oid::oid_eq_bytes(alg, SHA256) {
        Some(Hash::Sha256)
    } else if oid::oid_eq_bytes(alg, SHA384) {
        Some(Hash::Sha384)
    } else if oid::oid_eq_bytes(alg, SHA512) {
        Some(Hash::Sha512)
    } else {
        None
    }
}

fn digest_with(hash: Hash, data: &[u8]) -> Vec<u8> {
    match hash {
        Hash::Sha1 => sha1::Sha1::digest(data).to_vec(),
        Hash::Sha256 => sha2::Sha256::digest(data).to_vec(),
        Hash::Sha384 => sha2::Sha384::digest(data).to_vec(),
        Hash::Sha512 => sha2::Sha512::digest(data).to_vec(),
    }
}

impl SignatureVerifier for RustCryptoVerifier {
    fn digest(&self, alg_oid: &[u8], data: &[u8]) -> Result<Vec<u8>, VerifyError> {
        let hash = hash_for_digest(alg_oid).ok_or(VerifyError::UnsupportedAlgorithm)?;
        Ok(digest_with(hash, data))
    }

    fn verify_signature(
        &self,
        sig_alg_oid: &[u8],
        key_alg_oid: &[u8],
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, VerifyError> {
        use oid::sig::{ED25519, SHA256_ECDSA, SHA384_ECDSA};
        if let Some(hash) = rsa_hash(sig_alg_oid) {
            return rsa_verify(hash, key_alg_oid, public_key, message, signature);
        }
        if oid::oid_eq_bytes(sig_alg_oid, SHA256_ECDSA) {
            return ecdsa_verify(Hash::Sha256, key_alg_oid, public_key, message, signature);
        }
        if oid::oid_eq_bytes(sig_alg_oid, SHA384_ECDSA) {
            return ecdsa_verify(Hash::Sha384, key_alg_oid, public_key, message, signature);
        }
        if oid::oid_eq_bytes(sig_alg_oid, ED25519) {
            return ed25519_verify(key_alg_oid, public_key, message, signature);
        }
        Err(VerifyError::UnsupportedAlgorithm)
    }
}

/// The digest of an `*WithRSAEncryption` signature OID, if it is one we support.
fn rsa_hash(sig_alg_oid: &[u8]) -> Option<Hash> {
    use oid::sig::{SHA256_RSA, SHA384_RSA, SHA512_RSA};
    if oid::oid_eq_bytes(sig_alg_oid, SHA1_RSA) {
        Some(Hash::Sha1)
    } else if oid::oid_eq_bytes(sig_alg_oid, SHA256_RSA) {
        Some(Hash::Sha256)
    } else if oid::oid_eq_bytes(sig_alg_oid, SHA384_RSA) {
        Some(Hash::Sha384)
    } else if oid::oid_eq_bytes(sig_alg_oid, SHA512_RSA) {
        Some(Hash::Sha512)
    } else {
        None
    }
}

fn rsa_verify(
    hash: Hash,
    key_alg_oid: &[u8],
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::RsaPublicKey;
    use signature::Verifier;

    if !oid::oid_eq_bytes(key_alg_oid, oid::pk::RSA) {
        return Err(VerifyError::InvalidKey);
    }
    let key = RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| VerifyError::InvalidKey)?;
    let Ok(sig) = Signature::try_from(signature) else {
        return Ok(false);
    };
    let verdict = match hash {
        Hash::Sha1 => VerifyingKey::<sha1::Sha1>::new(key).verify(message, &sig),
        Hash::Sha256 => VerifyingKey::<sha2::Sha256>::new(key).verify(message, &sig),
        Hash::Sha384 => VerifyingKey::<sha2::Sha384>::new(key).verify(message, &sig),
        Hash::Sha512 => VerifyingKey::<sha2::Sha512>::new(key).verify(message, &sig),
    };
    Ok(verdict.is_ok())
}

fn ecdsa_verify(
    hash: Hash,
    key_alg_oid: &[u8],
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    use signature::Verifier;

    if !oid::oid_eq_bytes(key_alg_oid, oid::pk::EC) {
        return Err(VerifyError::InvalidKey);
    }
    // An uncompressed SEC1 point is 65 octets for P-256 and 97 for P-384. The curve
    // OID in the key parameters is not needed to tell them apart.
    match (public_key.len(), hash) {
        (65, Hash::Sha256) => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| VerifyError::InvalidKey)?;
            let Ok(sig) = p256::ecdsa::Signature::from_der(signature) else {
                return Ok(false);
            };
            Ok(key.verify(message, &sig).is_ok())
        }
        (97, Hash::Sha384) => {
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| VerifyError::InvalidKey)?;
            let Ok(sig) = p384::ecdsa::Signature::from_der(signature) else {
                return Ok(false);
            };
            Ok(key.verify(message, &sig).is_ok())
        }
        // Other curve and hash pairings are not supported here.
        _ => Err(VerifyError::UnsupportedAlgorithm),
    }
}

fn ed25519_verify(
    key_alg_oid: &[u8],
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    use ed25519_dalek::{Signature, VerifyingKey};

    if !oid::oid_eq_bytes(key_alg_oid, oid::pk::ED25519) {
        return Err(VerifyError::InvalidKey);
    }
    let bytes: [u8; 32] = public_key.try_into().map_err(|_| VerifyError::InvalidKey)?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| VerifyError::InvalidKey)?;
    let Ok(sig) = Signature::from_slice(signature) else {
        return Ok(false);
    };
    Ok(key.verify_strict(message, &sig).is_ok())
}
