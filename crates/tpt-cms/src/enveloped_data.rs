// SPDX-License-Identifier: MIT OR Apache-2.0

//! `EnvelopedData` (RFC 5652 §6), plus `DigestedData` and `EncryptedData`.
//!
//! ```asn1
//! EnvelopedData ::= SEQUENCE {
//!     version              CMSVersion,
//!     originatorInfo  [0] IMPLICIT OriginatorInfo OPTIONAL,
//!     recipientInfos       RecipientInfos,
//!     encryptedContentInfo EncryptedContentInfo,
//!     unprotectedAttrs [1] IMPLICIT SET OF Attribute OPTIONAL }
//!
//! EncryptedContentInfo ::= SEQUENCE {
//!     contentType                ContentType,
//!     contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
//!     encryptedContent      [0] IMPLICIT EncryptedContent OPTIONAL }
//! ```

use crate::algorithm::AlgorithmIdentifier;
use crate::attributes::decode_attribute_set;
use crate::error::{Error, Result};
use crate::recipient_info::{EnvelopeBackend, RecipientInfo};
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::Reader;
use tpt_asn1_core::tag::Tag;
use tpt_asn1_core::types::{Integer, ObjectIdentifier, OctetString};

/// The encrypted-content container inside `EnvelopedData`.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct EncryptedContentInfo<'a> {
    /// The content type OID.
    pub content_type: ObjectIdentifier<'a>,
    /// The content-encryption algorithm.
    pub content_encryption_algorithm: AlgorithmIdentifier<'a>,
    /// The encrypted content (absent for streaming/detached cases).
    pub encrypted_content: Option<OctetString<'a>>,
}

#[cfg(feature = "alloc")]
impl<'a> EncryptedContentInfo<'a> {
    /// The raw content-encryption algorithm OID bytes.
    pub fn content_enc_alg_bytes(&self) -> &'a [u8] {
        self.content_encryption_algorithm.algorithm_bytes()
    }
}

/// A decoded `EnvelopedData` message.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct EnvelopedData<'a> {
    /// CMS version (0 for `IssuerAndSerialNumber`, 3 for `KeyAgreeRecipientInfo`).
    pub version: u64,
    /// The recipient infos.
    pub recipient_infos: alloc::vec::Vec<RecipientInfo<'a>>,
    /// The encrypted content info.
    pub encrypted_content_info: EncryptedContentInfo<'a>,
}

#[cfg(feature = "alloc")]
impl<'a> Decode<'a> for EnvelopedData<'a> {
    fn decode(r: &mut Reader<'a>) -> tpt_asn1_core::error::Result<Self> {
        tpt_asn1_core::decode::read_sequence(r, |inner| {
            let version = Integer::decode(inner)?.as_u64().ok_or(Error::UnsupportedVersion)?;

            // Optional originatorInfo [0] IMPLICIT.
            let start = inner.position();
            let (tag, _, value) = inner.read_tlv()?;
            let recipient_infos_content = if tag == Tag::context(true, 0) {
                // skip originatorInfo, then read recipientInfos (SET).
                let (t2, _, v2) = inner.read_tlv()?;
                if !t2.is_universal(Tag::SET) {
                    return Err(Error::UnexpectedStructure.into());
                }
                v2
            } else {
                // This TLV is recipientInfos (SET).
                let full = inner.slice(start, inner.position());
                let mut rr = Reader::new(full, tpt_asn1_core::reader::Config::der());
                let (t, _, v) = rr.read_tlv()?;
                if !t.is_universal(Tag::SET) {
                    return Err(Error::UnexpectedStructure.into());
                }
                v
            };
            let _ = value; // originatorInfo content (unused for decrypt here)

            let mut ri_r = Reader::new(recipient_infos_content, tpt_asn1_core::reader::Config::der());
            let mut recipient_infos = alloc::vec::Vec::new();
            while !ri_r.is_empty() {
                recipient_infos.push(RecipientInfo::decode(&mut ri_r)?);
            }

            let encrypted_content_info = decode_encrypted_content_info(inner)?;

            // Optional unprotectedAttrs [1] IMPLICIT SET OF Attribute.
            if !inner.is_empty() {
                let (atag, _, avalue) = inner.read_tlv()?;
                if atag != Tag::context(true, 1) {
                    return Err(Error::UnexpectedStructure.into());
                }
                decode_attribute_set(avalue)?;
            }

            Ok(EnvelopedData { version, recipient_infos, encrypted_content_info })
        })
    }
}

fn decode_encrypted_content_info<'a>(
    r: &mut Reader<'a>,
) -> tpt_asn1_core::error::Result<EncryptedContentInfo<'a>> {
    tpt_asn1_core::decode::read_sequence(r, |inner| {
        let content_type = ObjectIdentifier::decode(inner)?;
        let content_encryption_algorithm = AlgorithmIdentifier::decode(inner)?;
        let encrypted_content = if inner.is_empty() {
            None
        } else {
            let (tag, _, value) = inner.read_tlv()?;
            if tag != Tag::context(false, 0) {
                return Err(Error::UnexpectedStructure.into());
            }
            Some(OctetString(value))
        };
        Ok(EncryptedContentInfo { content_type, content_encryption_algorithm, encrypted_content })
    })
}

/// Decrypt `EnvelopedData` using the key-transport (`KeyTransRecipientInfo`)
/// recipient at `recipient_index` and the recipient's RSA `private_key_der`.
///
/// The actual RSA and symmetric decryption are delegated to the pluggable
/// [`EnvelopeBackend`]. Returns the plaintext content.
#[cfg(feature = "alloc")]
pub fn decrypt<B: EnvelopeBackend>(
    ed: &EnvelopedData<'_>,
    recipient_index: usize,
    private_key_der: &[u8],
    backend: &B,
) -> Result<alloc::vec::Vec<u8>> {
    let recipient = ed
        .recipient_infos
        .get(recipient_index)
        .ok_or(Error::UnexpectedStructure)?;
    let ktri = recipient.as_key_trans().ok_or(Error::UnsupportedAlgorithm)?;

    let cek = backend.rsa_unwrap(ktri.encrypted_key, private_key_der)?;
    let encrypted_content = ed.encrypted_content_info.encrypted_content.ok_or(Error::MissingContent)?;
    backend.decrypt_content(
        ed.encrypted_content_info.content_enc_alg_bytes(),
        &cek,
        encrypted_content.0,
    )
}

/// `DigestedData` (RFC 5652 §7) — a content type + its message digest.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct DigestedData<'a> {
    /// CMS version (must be 0).
    pub version: u64,
    /// The digest algorithm.
    pub digest_algorithm: AlgorithmIdentifier<'a>,
    /// The encapsulated content (opaque here).
    pub content: crate::content_info::ContentInfo<'a>,
    /// The message digest.
    pub digest: &'a [u8],
}

#[cfg(feature = "alloc")]
impl<'a> Decode<'a> for DigestedData<'a> {
    fn decode(r: &mut Reader<'a>) -> tpt_asn1_core::error::Result<Self> {
        tpt_asn1_core::decode::read_sequence(r, |inner| {
            let version = Integer::decode(inner)?.as_u64().ok_or(Error::UnsupportedVersion)?;
            let digest_algorithm = AlgorithmIdentifier::decode(inner)?;
            let content = crate::content_info::ContentInfo::decode(inner)?;
            let digest = OctetString::decode(inner)?.0;
            Ok(DigestedData { version, digest_algorithm, content, digest })
        })
    }
}

/// `EncryptedData` (RFC 5652 §8) — content encrypted without key management.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct EncryptedData<'a> {
    /// CMS version (0 or 2).
    pub version: u64,
    /// The encrypted content info.
    pub encrypted_content_info: EncryptedContentInfo<'a>,
    /// Optional unprotected attributes.
    pub unprotected_attrs: Option<alloc::vec::Vec<crate::attributes::Attribute<'a>>>,
}

#[cfg(feature = "alloc")]
impl<'a> Decode<'a> for EncryptedData<'a> {
    fn decode(r: &mut Reader<'a>) -> tpt_asn1_core::error::Result<Self> {
        tpt_asn1_core::decode::read_sequence(r, |inner| {
            let version = Integer::decode(inner)?.as_u64().ok_or(Error::UnsupportedVersion)?;
            let encrypted_content_info = decode_encrypted_content_info(inner)?;
            let unprotected_attrs = if inner.is_empty() {
                None
            } else {
                let (tag, _, value) = inner.read_tlv()?;
                if tag != Tag::context(true, 1) {
                    return Err(Error::UnexpectedStructure.into());
                }
                Some(decode_attribute_set(value)?)
            };
            Ok(EncryptedData { version, encrypted_content_info, unprotected_attrs })
        })
    }
}
