// SPDX-License-Identifier: MIT OR Apache-2.0

//! `RecipientInfo` choices for `EnvelopedData` (RFC 5652 §6.2), plus the
//! pluggable key-unwrap/decrypt backend used to actually recover the
//! content-encryption key and decrypt the content.
//!
//! ```asn1
//! RecipientInfo ::= CHOICE {
//!     ktri  KeyTransRecipientInfo,
//!     kari  [0] KeyAgreeRecipientInfo,
//!     kekri [1] KEKRecipientInfo,
//!     pwri  [2] PasswordRecipientInfo,
//!     ori   [3] OtherRecipientInfo }
//! ```

use crate::algorithm::AlgorithmIdentifier;
use crate::error::{Error, Result};
use tpt_asn1_core::any::Any;
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::Reader;
use tpt_asn1_core::tag::Tag;
use tpt_asn1_core::types::{Integer, OctetString};

/// `RecipientIdentifier` — how a `KeyTransRecipientInfo` names its recipient.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecipientIdentifier<'a> {
    /// `IssuerAndSerialNumber`.
    IssuerAndSerialNumber {
        /// Issuer `Name` TLV.
        issuer: &'a [u8],
        /// `serialNumber` INTEGER bytes.
        serial: &'a [u8],
    },
    /// `SubjectKeyIdentifier` (raw key-identifier bytes).
    SubjectKeyIdentifier(&'a [u8]),
}

/// `KeyTransRecipientInfo` — RSA (or similar) public-key key transport.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyTransRecipientInfo<'a> {
    /// CMS version (must be 0 or 2).
    pub version: u64,
    /// The recipient identifier.
    pub rid: RecipientIdentifier<'a>,
    /// The key-encryption algorithm (e.g. `rsaEncryption`).
    pub key_encryption_algorithm: AlgorithmIdentifier<'a>,
    /// The encrypted content-encryption key.
    pub encrypted_key: &'a [u8],
}

/// `RecipientEncryptedKey` — one recipient's encrypted key within a `KeyAgreeRecipientInfo`.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct RecipientEncryptedKey<'a> {
    /// The recipient identifier (could be `subjectKeyIdentifier`).
    pub rid: Any<'a>,
    /// The encrypted key.
    pub encrypted_key: &'a [u8],
}

/// `KeyAgreeRecipientInfo` — ECDH (or similar) key agreement.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct KeyAgreeRecipientInfo<'a> {
    /// CMS version (must be 3).
    pub version: u64,
    /// The originator's key (opaque here).
    pub originator: Any<'a>,
    /// The key-encryption algorithm (e.g. `dhSinglePass-stdHmac`).
    pub key_encryption_algorithm: AlgorithmIdentifier<'a>,
    /// The per-recipient encrypted keys.
    pub recipient_encrypted_keys: alloc::vec::Vec<RecipientEncryptedKey<'a>>,
}

/// A `RecipientInfo`, decoding the common choices and retaining the rest opaque.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub enum RecipientInfo<'a> {
    /// RSA-style key transport.
    KeyTrans(KeyTransRecipientInfo<'a>),
    /// ECDH-style key agreement.
    KeyAgree(KeyAgreeRecipientInfo<'a>),
    /// KEK key transport (opaque).
    Kek(Any<'a>),
    /// Password-based (opaque).
    Password(Any<'a>),
    /// Other/unknown recipient info (opaque).
    Other(Any<'a>),
}

#[cfg(feature = "alloc")]
impl<'a> RecipientInfo<'a> {
    /// The key-transport recipient, if this is a `KeyTransRecipientInfo`.
    pub fn as_key_trans(&self) -> Option<&KeyTransRecipientInfo<'a>> {
        match self {
            RecipientInfo::KeyTrans(k) => Some(k),
            _ => None,
        }
    }
}

#[cfg(feature = "alloc")]
impl<'a> tpt_asn1_core::decode::Decode<'a> for RecipientInfo<'a> {
    fn decode(r: &mut Reader<'a>) -> tpt_asn1_core::error::Result<Self> {
        let any = Any::decode(r)?;
        if any.tag.is_universal(Tag::SEQUENCE) {
            // KeyTransRecipientInfo
            let mut ir = Reader::new(any.value, tpt_asn1_core::reader::Config::der());
            let version = Integer::decode(&mut ir)?.as_u64().ok_or(Error::UnsupportedVersion)?;
            let rid = {
                let (tag, _, value) = ir.read_tlv()?;
                if tag == Tag::context(false, 0) {
                    RecipientIdentifier::SubjectKeyIdentifier(value)
                } else if tag.is_universal(Tag::SEQUENCE) {
                    let mut ias = Reader::new(value, tpt_asn1_core::reader::Config::der());
                    let issuer = full_tlv(&mut ias)?;
                    let (_, _, serial) = ias.read_tlv()?;
                    RecipientIdentifier::IssuerAndSerialNumber { issuer, serial }
                } else {
                    return Err(Error::UnexpectedStructure.into());
                }
            };
            let key_encryption_algorithm = AlgorithmIdentifier::decode(&mut ir)?;
            let encrypted_key = OctetString::decode(&mut ir)?.0;
            Ok(RecipientInfo::KeyTrans(KeyTransRecipientInfo {
                version,
                rid,
                key_encryption_algorithm,
                encrypted_key,
            }))
        } else if any.tag == Tag::context(true, 0) {
            Ok(RecipientInfo::KeyAgree(decode_key_agree(any.value)?))
        } else if any.tag == Tag::context(true, 1) {
            Ok(RecipientInfo::Kek(any))
        } else if any.tag == Tag::context(true, 2) {
            Ok(RecipientInfo::Password(any))
        } else {
            Ok(RecipientInfo::Other(any))
        }
    }
}

#[cfg(feature = "alloc")]
fn decode_key_agree<'a>(value: &'a [u8]) -> Result<KeyAgreeRecipientInfo<'a>> {
    use alloc::vec::Vec;
    let mut r = Reader::new(value, tpt_asn1_core::reader::Config::der());
    let version = Integer::decode(&mut r)?.as_u64().ok_or(Error::UnsupportedVersion)?;
    // originator [0] EXPLICIT
    let (otag, _, ovalue) = r.read_tlv()?;
    if otag != Tag::context(true, 0) {
        return Err(Error::UnexpectedStructure);
    }
    let originator = {
        let mut or = Reader::new(ovalue, tpt_asn1_core::reader::Config::der());
        Any::decode(&mut or)?
    };
    // ukm [1] IMPLICIT BIT STRING OPTIONAL
    if !r.is_empty() {
        let (utag, _, _) = r.read_tlv()?;
        if utag != Tag::context(true, 1) {
            return Err(Error::UnexpectedStructure);
        }
    }
    let key_encryption_algorithm = AlgorithmIdentifier::decode(&mut r)?;
    // recipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey
    let (rtag, _, rvalue) = r.read_tlv()?;
    if !rtag.is_universal(Tag::SEQUENCE) {
        return Err(Error::UnexpectedStructure);
    }
    let mut rr = Reader::new(rvalue, tpt_asn1_core::reader::Config::der());
    let mut recipient_encrypted_keys: Vec<RecipientEncryptedKey<'a>> = Vec::new();
    while !rr.is_empty() {
        let (_, _, rek) = rr.read_tlv()?;
        let mut kr = Reader::new(rek, tpt_asn1_core::reader::Config::der());
        let rid = Any::decode(&mut kr)?;
        let encrypted_key = OctetString::decode(&mut kr)?.0;
        recipient_encrypted_keys.push(RecipientEncryptedKey { rid, encrypted_key });
    }
    Ok(KeyAgreeRecipientInfo { version, originator, key_encryption_algorithm, recipient_encrypted_keys })
}

/// A pluggable backend for `EnvelopedData` key recovery and content decryption.
///
/// Implementations delegate the actual RSA/ECDH/symmetric math to a chosen
/// crypto provider (no cryptographic primitives live in `tpt-cms`).
pub trait EnvelopeBackend {
    /// RSA key transport: recover the content-encryption key by decrypting
    /// `encrypted_key` with the RSA `private_key_der` (PKCS#8 / RSAPrivateKey).
    fn rsa_unwrap(
        &self,
        encrypted_key: &[u8],
        private_key_der: &[u8],
    ) -> Result<alloc::vec::Vec<u8>>;

    /// Decrypt `encrypted_content` with the recovered content-encryption key
    /// `cek` under the algorithm `content_enc_alg` (e.g. `aes256-CBC`).
    fn decrypt_content(
        &self,
        content_enc_alg: &[u8],
        cek: &[u8],
        encrypted_content: &[u8],
    ) -> Result<alloc::vec::Vec<u8>>;
}

fn full_tlv<'a>(r: &mut Reader<'a>) -> Result<&'a [u8]> {
    let start = r.position();
    r.read_tlv()?;
    let end = r.position();
    Ok(r.slice(start, end))
}
