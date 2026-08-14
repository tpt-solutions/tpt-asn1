// SPDX-License-Identifier: MIT OR Apache-2.0

//! Well-known ASN.1 object identifiers used by X.509 / PKIX.
//!
//! OIDs are expressed as plain `&[u64]` arcs and matched against a parsed
//! [`ObjectIdentifier`](tpt_asn1_core::types::ObjectIdentifier) via
//! [`oid_eq`]. Keeping them as arc slices (rather than pre-encoded bytes) means
//! the same constants drive both matching and any future re-encoding.

use tpt_asn1_core::types::ObjectIdentifier;

/// A PKIX object identifier expressed as its arc components.
pub type Oid = &'static [u64];

/// Returns `true` if `oid` equals `expected`.
pub fn oid_eq(oid: &ObjectIdentifier<'_>, expected: Oid) -> bool {
    oid.matches(expected)
}

/// Returns `true` if `oid` is equal to one of `candidates`.
pub fn oid_in(oid: &ObjectIdentifier<'_>, candidates: &[Oid]) -> bool {
    candidates.iter().any(|c| oid.matches(c))
}

/// Returns `true` if raw `OBJECT IDENTIFIER` *content* bytes equal `expected`.
///
/// Useful when an OID is available as bare base-128 subidentifier bytes (e.g. an
/// `responseType` payload) rather than a decoded [`ObjectIdentifier`].
pub fn oid_eq_bytes(bytes: &[u8], expected: Oid) -> bool {
    if bytes.len() > 126 {
        return false;
    }
    let mut buf = [0u8; 128];
    buf[0] = 0x06;
    buf[1] = bytes.len() as u8;
    buf[2..2 + bytes.len()].copy_from_slice(bytes);
    crate::core::decode::<crate::core::types::ObjectIdentifier>(&buf[..2 + bytes.len()])
        .map(|o| o.matches(expected))
        .unwrap_or(false)
}

/// All known *public-key* algorithm OIDs (used to gate key handling).
pub mod pk {
    /// `rsaEncryption` — 1.2.840.113549.1.1.1
    pub const RSA: Oid = &[1, 2, 840, 113549, 1, 1, 1];
    /// `id-RSASSA-PSS` — 1.2.840.113549.1.1.10
    pub const RSA_PSS: Oid = &[1, 2, 840, 113549, 1, 1, 10];
    /// `id-dsa` — 1.2.840.10040.4.1
    pub const DSA: Oid = &[1, 2, 840, 10040, 4, 1];
    /// `ecPublicKey` — 1.2.840.10045.2.1
    pub const EC: Oid = &[1, 2, 840, 10045, 2, 1];
    /// `id-Ed25519` — 1.3.101.112
    pub const ED25519: Oid = &[1, 3, 101, 112];
    /// `id-Ed448` — 1.3.101.113
    pub const ED448: Oid = &[1, 3, 101, 113];
}

/// Signature algorithm OIDs (`AlgorithmIdentifier.algorithm`).
pub mod sig {
    /// `sha256WithRSAEncryption` — 1.2.840.113549.1.1.11
    pub const SHA256_RSA: Oid = &[1, 2, 840, 113549, 1, 1, 11];
    /// `sha384WithRSAEncryption` — 1.2.840.113549.1.1.12
    pub const SHA384_RSA: Oid = &[1, 2, 840, 113549, 1, 1, 12];
    /// `sha512WithRSAEncryption` — 1.2.840.113549.1.1.13
    pub const SHA512_RSA: Oid = &[1, 2, 840, 113549, 1, 1, 13];
    /// `ecdsa-with-SHA256` — 1.2.840.10045.4.3.2
    pub const SHA256_ECDSA: Oid = &[1, 2, 840, 10045, 4, 3, 2];
    /// `ecdsa-with-SHA384` — 1.2.840.10045.4.3.3
    pub const SHA384_ECDSA: Oid = &[1, 2, 840, 10045, 4, 3, 3];
    /// `ecdsa-with-SHA512` — 1.2.840.10045.4.3.4
    pub const SHA512_ECDSA: Oid = &[1, 2, 840, 10045, 4, 3, 4];
    /// `id-dsa-with-sha256` — 2.16.840.1.101.3.4.3.2
    pub const SHA256_DSA: Oid = &[2, 16, 840, 1, 101, 3, 4, 3, 2];
    /// `id-Ed25519` — 1.3.101.112 (params absent)
    pub const ED25519: Oid = &[1, 3, 101, 112];
    /// `id-Ed448` — 1.3.101.113
    pub const ED448: Oid = &[1, 3, 101, 113];
}

/// Hash algorithm OIDs (used by `DigestAlgorithm` and `SignedAttributes`).
pub mod digest {
    /// `id-sha256` — 2.16.840.1.101.3.4.2.1
    pub const SHA256: Oid = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
    /// `id-sha384` — 2.16.840.1.101.3.4.2.2
    pub const SHA384: Oid = &[2, 16, 840, 1, 101, 3, 4, 2, 2];
    /// `id-sha512` — 2.16.840.1.101.3.4.2.3
    pub const SHA512: Oid = &[2, 16, 840, 1, 101, 3, 4, 2, 3];
}

/// Named curve OIDs (domain parameters for `ecPublicKey`).
pub mod curve {
    /// `prime256v1` / P-256 — 1.2.840.10045.3.1.7
    pub const P256: Oid = &[1, 2, 840, 10045, 3, 1, 7];
    /// `secp384r1` / P-384 — 1.3.132.0.34
    pub const P384: Oid = &[1, 3, 132, 0, 34];
    /// `secp521r1` / P-521 — 1.3.132.0.35
    pub const P521: Oid = &[1, 3, 132, 0, 35];
    /// `secp256k1` — 1.3.132.0.10
    pub const SECP256K1: Oid = &[1, 3, 132, 0, 10];
}

/// PKIX *extension* OIDs (X.509 v3 certificate extensions).
pub mod ext {
    /// `id-ce-basicConstraints` — 2.5.29.19
    pub const BASIC_CONSTRAINTS: Oid = &[2, 5, 29, 19];
    /// `id-ce-keyUsage` — 2.5.29.15
    pub const KEY_USAGE: Oid = &[2, 5, 29, 15];
    /// `id-ce-extKeyUsage` — 2.5.29.37
    pub const EXT_KEY_USAGE: Oid = &[2, 5, 29, 37];
    /// `id-ce-subjectAltName` — 2.5.29.17
    pub const SUBJECT_ALT_NAME: Oid = &[2, 5, 29, 17];
    /// `id-ce-issuerAltName` — 2.5.29.18
    pub const ISSUER_ALT_NAME: Oid = &[2, 5, 29, 18];
    /// `id-ce-subjectKeyIdentifier` — 2.5.29.14
    pub const SUBJECT_KEY_IDENTIFIER: Oid = &[2, 5, 29, 14];
    /// `id-ce-authorityKeyIdentifier` — 2.5.29.35
    pub const AUTHORITY_KEY_IDENTIFIER: Oid = &[2, 5, 29, 35];
    /// `id-ce-cRLDistributionPoints` — 2.5.29.31
    pub const CRL_DISTRIBUTION_POINTS: Oid = &[2, 5, 29, 31];
    /// `id-pe-authorityInfoAccess` — 1.3.6.1.5.5.7.1.1
    pub const AUTHORITY_INFO_ACCESS: Oid = &[1, 3, 6, 1, 5, 5, 7, 1, 1];
    /// `id-ce-certificatePolicies` — 2.5.29.32
    pub const CERTIFICATE_POLICIES: Oid = &[2, 5, 29, 32];
    /// `id-ce-policyConstraints` — 2.5.29.36
    pub const POLICY_CONSTRAINTS: Oid = &[2, 5, 29, 36];
    /// `id-ce-nameConstraints` — 2.5.29.30
    pub const NAME_CONSTRAINTS: Oid = &[2, 5, 29, 30];
    /// `id-ce-inhibitAnyPolicy` — 2.5.29.54
    pub const INHIBIT_ANY_POLICY: Oid = &[2, 5, 29, 54];
    /// `id-ce-freshestCRL` — 2.5.29.46
    pub const FRESHEST_CRL: Oid = &[2, 5, 29, 46];
    /// `id-ce-cRLNumber` — 2.5.29.20
    pub const CRL_NUMBER: Oid = &[2, 5, 29, 20];
    /// `id-ce-deltaCRLIndicator` — 2.5.29.27
    pub const DELTA_CRL_INDICATOR: Oid = &[2, 5, 29, 27];
    /// `id-ce-issuingDistributionPoint` — 2.5.29.28
    pub const ISSUING_DISTRIBUTION_POINT: Oid = &[2, 5, 29, 28];
}

/// X.520 `AttributeType` OIDs used inside `RelativeDistinguishedName`.
pub mod attr {
    /// `id-at-commonName` (CN) — 2.5.4.3
    pub const COMMON_NAME: Oid = &[2, 5, 4, 3];
    /// `id-at-surname` (SN) — 2.5.4.4
    pub const SURNAME: Oid = &[2, 5, 4, 4];
    /// `id-at-serialNumber` — 2.5.4.5
    pub const SERIAL_NUMBER: Oid = &[2, 5, 4, 5];
    /// `id-at-countryName` (C) — 2.5.4.6
    pub const COUNTRY: Oid = &[2, 5, 4, 6];
    /// `id-at-localityName` (L) — 2.5.4.7
    pub const LOCALITY: Oid = &[2, 5, 4, 7];
    /// `id-at-stateOrProvinceName` (ST) — 2.5.4.8
    pub const STATE: Oid = &[2, 5, 4, 8];
    /// `id-at-organizationName` (O) — 2.5.4.10
    pub const ORGANIZATION: Oid = &[2, 5, 4, 10];
    /// `id-at-organizationalUnitName` (OU) — 2.5.4.11
    pub const ORG_UNIT: Oid = &[2, 5, 4, 11];
    /// `id-at-title` — 2.5.4.12
    pub const TITLE: Oid = &[2, 5, 4, 12];
    /// `id-at-pseudonym` — 2.5.4.65
    pub const PSEUDONYM: Oid = &[2, 5, 4, 65];
    /// `pkcs-9 emailAddress` — 1.2.840.113549.1.9.1
    pub const EMAIL: Oid = &[1, 2, 840, 113549, 1, 9, 1];
}

/// Extended Key Usage (`id-kp`) purpose OIDs.
pub mod eku {
    /// `id-kp-serverAuth` — 1.3.6.1.5.5.7.3.1
    pub const SERVER_AUTH: Oid = &[1, 3, 6, 1, 5, 5, 7, 3, 1];
    /// `id-kp-clientAuth` — 1.3.6.1.5.5.7.3.2
    pub const CLIENT_AUTH: Oid = &[1, 3, 6, 1, 5, 5, 7, 3, 2];
    /// `id-kp-codeSigning` — 1.3.6.1.5.5.7.3.3
    pub const CODE_SIGNING: Oid = &[1, 3, 6, 1, 5, 5, 7, 3, 3];
    /// `id-kp-emailProtection` — 1.3.6.1.5.5.7.3.4
    pub const EMAIL_PROTECTION: Oid = &[1, 3, 6, 1, 5, 5, 7, 3, 4];
    /// `id-kp-timeStamping` — 1.3.6.1.5.5.7.3.8
    pub const TIME_STAMPING: Oid = &[1, 3, 6, 1, 5, 5, 7, 3, 8];
    /// `id-kp-OCSPSigning` — 1.3.6.1.5.5.7.3.9
    pub const OCSP_SIGNING: Oid = &[1, 3, 6, 1, 5, 5, 7, 3, 9];
}

/// Other PKIX OIDs.
pub mod pkix {
    /// `id-pkix-ocsp` (OCSP response type) — 1.3.6.1.5.5.7.48.1
    pub const OCSP: Oid = &[1, 3, 6, 1, 5, 5, 7, 48, 1];
    /// `id-ad-ocsp` (AIA access method) — 1.3.6.1.5.5.7.48.1
    pub const AD_OCSP: Oid = &[1, 3, 6, 1, 5, 5, 7, 48, 1];
    /// `id-ad-caIssuers` (AIA access method) — 1.3.6.1.5.5.7.48.2
    pub const AD_CA_ISSUERS: Oid = &[1, 3, 6, 1, 5, 5, 7, 48, 2];
    /// `anyPolicy` — 2.5.29.32.0
    pub const ANY_POLICY: Oid = &[2, 5, 29, 32, 0];
}
