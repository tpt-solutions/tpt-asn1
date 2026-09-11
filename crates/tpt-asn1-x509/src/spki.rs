// SPDX-License-Identifier: MIT OR Apache-2.0

//! `SubjectPublicKeyInfo` (SPKI) decoding and per-algorithm key accessors.

use tpt_asn1_core::decode::{read_sequence, Decode};
use tpt_asn1_core::error::Result;
use tpt_asn1_core::reader::Reader;
use tpt_asn1_core::types::{BitString, Integer};

use crate::algorithm::AlgorithmIdentifier;

/// `SubjectPublicKeyInfo` — `SEQUENCE { algorithm AlgorithmIdentifier,
/// subjectPublicKey BIT STRING }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubjectPublicKeyInfo<'a> {
    /// The key's algorithm (and any parameters, e.g. the EC named curve).
    pub algorithm: AlgorithmIdentifier<'a>,
    /// The subject public key, as a `BIT STRING`.
    pub subject_public_key: BitString<'a>,
}

impl<'a> SubjectPublicKeyInfo<'a> {
    /// The raw key material bytes (the `BIT STRING` data octets).
    pub fn key_data(&self) -> &'a [u8] {
        self.subject_public_key.data
    }

    /// Decode the key as an RSA public key (`RSAPublicKey` SEQUENCE).
    pub fn rsa_public_key(&self) -> Result<RsaPublicKey<'a>> {
        crate::decode::<RsaPublicKey<'_>>(self.key_data())
    }

    /// Return the raw EC point bytes (the `BIT STRING` data) for `ecPublicKey`.
    pub fn ec_point(&self) -> &'a [u8] {
        self.key_data()
    }

    /// Return the raw Ed25519 / Ed448 public-key bytes (the `BIT STRING` data).
    pub fn edwards_key(&self) -> &'a [u8] {
        self.key_data()
    }
}

impl<'a> Decode<'a> for SubjectPublicKeyInfo<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let algorithm = AlgorithmIdentifier::decode(inner)?;
            let subject_public_key = BitString::decode(inner)?;
            Ok(SubjectPublicKeyInfo { algorithm, subject_public_key })
        })
    }
}

/// `RSAPublicKey` — `SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RsaPublicKey<'a> {
    /// The RSA modulus *n*.
    pub modulus: Integer<'a>,
    /// The RSA public exponent *e*.
    pub public_exponent: Integer<'a>,
}

impl<'a> Decode<'a> for RsaPublicKey<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let modulus = Integer::decode(inner)?;
            let public_exponent = Integer::decode(inner)?;
            Ok(RsaPublicKey { modulus, public_exponent })
        })
    }
}
