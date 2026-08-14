// SPDX-License-Identifier: MIT OR Apache-2.0

//! OID registry for CMS / PKCS#7 content types, digest and signature schemes.
//!
//! Each constant is the raw on-wire `OBJECT IDENTIFIER` subidentifier encoding
//! (the bytes that follow the `OBJECT IDENTIFIER` tag and length). Comparison is
//! performed by matching these byte slices directly, which avoids any allocation
//! and works uniformly for DER/BER/CER.

/// `id-data` — `1.2.840.113549.1.7.1`.
pub const CONTENT_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
/// `id-signedData` — `1.2.840.113549.1.7.2`.
pub const CONTENT_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
/// `id-envelopedData` — `1.2.840.113549.1.7.3`.
pub const CONTENT_ENVELOPED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03];
/// `id-digestedData` — `1.2.840.113549.1.7.5`.
pub const CONTENT_DIGESTED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x05];
/// `id-encryptedData` — `1.2.840.113549.1.7.6`.
pub const CONTENT_ENCRYPTED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06];
/// `id-authenticatedData` — `1.2.840.113549.1.7.16`.
pub const CONTENT_AUTHENTICATED_DATA: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x10];

// --- Digest algorithms -----------------------------------------------------

/// `id-sha1` — `1.3.14.3.2.26`.
pub const DIGEST_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
/// `id-sha256` — `2.16.840.1.101.3.4.2.1`.
pub const DIGEST_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// `id-sha384` — `2.16.840.1.101.3.4.2.2`.
pub const DIGEST_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
/// `id-sha512` — `2.16.840.1.101.3.4.2.3`.
pub const DIGEST_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

// --- Public-key algorithms (SubjectPublicKeyInfo.algorithm) ----------------

/// `rsaEncryption` — `1.2.840.113549.1.1.1`.
pub const KEY_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// `id-ecPublicKey` — `1.2.840.10045.2.1`.
pub const KEY_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `id-Ed25519` — `1.3.101.112`.
pub const KEY_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

// --- Signature algorithms (SignerInfo.signatureAlgorithm) ------------------

/// `sha1WithRSAEncryption` — `1.2.840.113549.1.1.5`.
pub const SIG_RSA_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
/// `sha256WithRSAEncryption` — `1.2.840.113549.1.1.11`.
pub const SIG_RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
/// `sha384WithRSAEncryption` — `1.2.840.113549.1.1.12`.
pub const SIG_RSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
/// `sha512WithRSAEncryption` — `1.2.840.113549.1.1.13`.
pub const SIG_RSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
/// `ecdsaWithSHA256` — `1.2.840.10045.4.3.2`.
pub const SIG_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// `ecdsaWithSHA384` — `1.2.840.10045.4.3.3`.
pub const SIG_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
/// `ecdsaWithSHA512` — `1.2.840.10045.4.3.4`.
pub const SIG_ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
/// `id-Ed25519` (used as both key and signature algorithm) — `1.3.101.112`.
pub const SIG_ED25519: &[u8] = KEY_ED25519;

// --- Signed-attribute OIDs -------------------------------------------------

/// `id-contentType` — `1.2.840.113549.1.9.3`.
pub const ATTR_CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
/// `id-messageDigest` — `1.2.840.113549.1.9.4`.
pub const ATTR_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
/// `id-signingTime` — `1.2.840.113549.1.9.5`.
pub const ATTR_SIGNING_TIME: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05];

/// Return a human-readable name for a CMS content-type OID, if recognised.
pub fn content_type_name(oid: &[u8]) -> Option<&'static str> {
    match oid {
        CONTENT_DATA => Some("Data"),
        CONTENT_SIGNED_DATA => Some("SignedData"),
        CONTENT_ENVELOPED_DATA => Some("EnvelopedData"),
        CONTENT_DIGESTED_DATA => Some("DigestedData"),
        CONTENT_ENCRYPTED_DATA => Some("EncryptedData"),
        CONTENT_AUTHENTICATED_DATA => Some("AuthenticatedData"),
        _ => None,
    }
}
