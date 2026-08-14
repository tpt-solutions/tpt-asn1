// SPDX-License-Identifier: MIT OR Apache-2.0

//! `AlgorithmIdentifier` and helpers for recognizing signature / public-key
//! algorithms from their OIDs.

use crate::oid;
use tpt_asn1_core::any::Any;
use tpt_asn1_core::decode::{read_sequence, Decode};
use tpt_asn1_core::error::Result as CoreResult;
use tpt_asn1_core::reader::Reader;
use tpt_asn1_core::types::ObjectIdentifier;

/// `AlgorithmIdentifier` — `SEQUENCE { algorithm OID, parameters ANY OPTIONAL }`.
///
/// The `parameters` field is captured raw (as an [`Any`]) because its meaning
/// depends on `algorithm`. Callers interpret it via the typed accessors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlgorithmIdentifier<'a> {
    /// The algorithm OID.
    pub algorithm: ObjectIdentifier<'a>,
    /// Optional parameters (`None` means the field was absent).
    pub parameters: Option<Any<'a>>,
}

impl<'a> AlgorithmIdentifier<'a> {
    /// The raw algorithm OID bytes.
    pub fn oid(&self) -> &'a [u8] {
        self.algorithm.as_bytes()
    }

    /// Returns `true` if the algorithm OID equals `expected`.
    pub fn is_oid(&self, expected: oid::Oid) -> bool {
        oid::oid_eq(&self.algorithm, expected)
    }

    /// Returns `true` if this identifies an RSA key (`rsaEncryption`).
    pub fn is_rsa_key(&self) -> bool {
        self.is_oid(oid::pk::RSA)
    }

    /// Returns `true` if this identifies an `ecPublicKey`.
    pub fn is_ec_key(&self) -> bool {
        self.is_oid(oid::pk::EC)
    }

    /// Returns `true` if this identifies an Ed25519 key.
    pub fn is_ed25519_key(&self) -> bool {
        self.is_oid(oid::pk::ED25519)
    }

    /// Returns `true` if this is an RSA *signature* scheme (PKCS#1 v1.5).
    pub fn is_rsa_signature(&self) -> bool {
        self.is_oid(oid::sig::SHA256_RSA)
            || self.is_oid(oid::sig::SHA384_RSA)
            || self.is_oid(oid::sig::SHA512_RSA)
    }

    /// Returns `true` if this is an ECDSA signature scheme.
    pub fn is_ecdsa_signature(&self) -> bool {
        self.is_oid(oid::sig::SHA256_ECDSA)
            || self.is_oid(oid::sig::SHA384_ECDSA)
            || self.is_oid(oid::sig::SHA512_ECDSA)
    }

    /// Returns `true` if this is the Ed25519 signature scheme (`params` absent).
    pub fn is_ed25519_signature(&self) -> bool {
        self.is_oid(oid::sig::ED25519)
    }

    /// The hash OID implied by this signature algorithm, if it carries one.
    ///
    /// Used when verifying `SignedAttributes` / `SignedData` digest algorithms.
    pub fn digest_oid(&self) -> Option<oid::Oid> {
        if self.is_rsa_signature() || self.is_ecdsa_signature() {
            if self.is_oid(oid::sig::SHA256_RSA) || self.is_oid(oid::sig::SHA256_ECDSA) {
                return Some(oid::digest::SHA256);
            }
            if self.is_oid(oid::sig::SHA384_RSA) || self.is_oid(oid::sig::SHA384_ECDSA) {
                return Some(oid::digest::SHA384);
            }
            if self.is_oid(oid::sig::SHA512_RSA) || self.is_oid(oid::sig::SHA512_ECDSA) {
                return Some(oid::digest::SHA512);
            }
        }
        None
    }
}

impl<'a> Decode<'a> for AlgorithmIdentifier<'a> {
    fn decode(r: &mut Reader<'a>) -> CoreResult<Self> {
        read_sequence(r, |inner| {
            let algorithm = ObjectIdentifier::decode(inner)?;
            let parameters = if inner.is_empty() {
                None
            } else {
                Some(Any::decode(inner)?)
            };
            Ok(AlgorithmIdentifier { algorithm, parameters })
        })
    }
}

/// Decode an `AlgorithmIdentifier` from a complete DER `SEQUENCE`.
pub fn decode_algorithm_identifier(
    bytes: &[u8],
) -> CoreResult<AlgorithmIdentifier<'_>> {
    crate::decode::<AlgorithmIdentifier<'_>>(bytes)
}
