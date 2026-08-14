// SPDX-License-Identifier: MIT OR Apache-2.0

//! `SignedData` — the CMS signed-message content type (RFC 5652 §5.1), plus the
//! legacy PKCS#7 v1.5 (`SignedData`) layout it supersedes.
//!
//! ```asn1
//! SignedData ::= SEQUENCE {
//!     version           CMSVersion,
//!     digestAlgorithms  DigestAlgorithmIdentifiers,
//!     encapContentInfo  EncapsulatedContentInfo,
//!     certificates  [0] IMPLICIT CertificateSet OPTIONAL,
//!     crls          [1] IMPLICIT CertificateRevocationLists OPTIONAL,
//!     signerInfos       SignerInfos }
//!
//! EncapsulatedContentInfo ::= SEQUENCE {
//!     eContentType ContentType,
//!     eContent   [0] EXPLICIT OCTET STRING OPTIONAL }
//! ```

use crate::algorithm::AlgorithmIdentifier;
use crate::cert;
use crate::error::{Error, Result};
use crate::signer_info::SignerInfo;
use tpt_asn1_core::any::Any;
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::Reader;
use tpt_asn1_core::tag::Tag;
use tpt_asn1_core::types::{Integer, ObjectIdentifier, OctetString};

/// A decoded `SignedData` message.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct SignedData<'a> {
    /// CMS version (`1` for `IssuerAndSerialNumber`, `3` for `SubjectKeyIdentifier`).
    pub version: u64,
    /// The `digestAlgorithms` set.
    pub digest_algorithms: alloc::vec::Vec<AlgorithmIdentifier<'a>>,
    /// The encapsulated content type OID.
    pub e_content_type: ObjectIdentifier<'a>,
    /// The encapsulated (eContent) bytes, if present (absent for detached signatures).
    pub e_content: Option<OctetString<'a>>,
    /// Embedded certificates (`CertificateSet`), stored opaque for later decode.
    pub certificates: alloc::vec::Vec<Any<'a>>,
    /// Embedded CRLs (`CertificateRevocationLists`), stored opaque.
    pub crls: alloc::vec::Vec<Any<'a>>,
    /// The signer infos.
    pub signer_infos: alloc::vec::Vec<SignerInfo<'a>>,
}

#[cfg(feature = "alloc")]
impl<'a> SignedData<'a> {
    /// Detect legacy PKCS#7 v1.5 (`SignedData`): RFC 2315 uses version `1` and
    /// lacks the `SubjectKeyIdentifier` signer-identifier choice. CMS (RFC 5652)
    /// uses version `3` (or `1` with `IssuerAndSerialNumber`); the on-wire
    /// structures otherwise decode identically.
    pub fn is_pkcs7_legacy(&self) -> bool {
        self.version == 1
            && self
                .signer_infos
                .iter()
                .all(|si| matches!(si.sid, crate::signer_info::SignerIdentifier::IssuerAndSerialNumber { .. }))
    }

    /// The encapsulated content bytes, or `None` if this is a detached signature.
    pub fn content_bytes(&self) -> Option<&'a [u8]> {
        self.e_content.map(|o| o.0)
    }

    /// Extract the verification fields of every embedded certificate.
    ///
    /// Embedded certificates arrive inside a `CertificateChoices` wrapper: a
    /// plain X.509 `Certificate` is `[0] EXPLICIT Certificate`, so we unwrap the
    /// explicit tag to recover the `Certificate` SEQUENCE before extracting.
    pub fn embedded_certs(&self) -> impl Iterator<Item = Result<cert::CertFields<'a>>> + '_ {
        self.certificates.iter().map(|c| {
            let der = if c.tag == Tag::context(true, 0) { c.value } else { c.full };
            cert::extract_cert_fields(der)
        })
    }
}

#[cfg(feature = "alloc")]
impl<'a> Decode<'a> for SignedData<'a> {
    fn decode(r: &mut Reader<'a>) -> tpt_asn1_core::error::Result<Self> {
        tpt_asn1_core::decode::read_sequence(r, |inner| {
            let version = Integer::decode(inner)?.as_u64().ok_or(Error::UnsupportedVersion)?;

            // digestAlgorithms ::= SET OF AlgorithmIdentifier
            let digest_algorithms = tpt_asn1_core::decode::read_set_of::<AlgorithmIdentifier<'_>>(inner)
                .map_err(Error::from)?;

            // encapContentInfo
            let (e_content_type, e_content) = decode_encap_content_info(inner)?;

            // Optional certificates [0] and crls [1].
            let mut certificates: alloc::vec::Vec<Any<'a>> = alloc::vec::Vec::new();
            let mut crls: alloc::vec::Vec<Any<'a>> = alloc::vec::Vec::new();

            let _start = inner.position();
            let (tag, _, value) = inner.read_tlv()?;
            if tag == Tag::context(true, 0) {
                certificates = split_any_set(value)?;
                let _start2 = inner.position();
                let (tag2, _, value2) = inner.read_tlv()?;
                if tag2 == Tag::context(true, 1) {
                    crls = split_any_set(value2)?;
                } else {
                    // Not crls: this is signerInfos (SET). Re-parse as SET OF SignerInfo.
                    let signer_infos = decode_signer_infos(value2)?;
                    return Ok(SignedData {
                        version,
                        digest_algorithms,
                        e_content_type,
                        e_content,
                        certificates,
                        crls,
                        signer_infos,
                    });
                }
            } else if tag == Tag::context(true, 1) {
                crls = split_any_set(value)?;
            } else {
                // Neither certificates nor crls: this TLV is signerInfos.
                let signer_infos = decode_signer_infos(value)?;
                return Ok(SignedData {
                    version,
                    digest_algorithms,
                    e_content_type,
                    e_content,
                    certificates,
                    crls,
                    signer_infos,
                });
            }

            // signerInfos ::= SET OF SignerInfo
            let signer_infos = {
                let (st, _, sval) = inner.read_tlv()?;
                if !st.is_universal(Tag::SET) {
                    return Err(Error::UnexpectedStructure.into());
                }
                decode_signer_infos(sval)?
            };

            Ok(SignedData {
                version,
                digest_algorithms,
                e_content_type,
                e_content,
                certificates,
                crls,
                signer_infos,
            })
        })
    }
}

/// Decode an `EncapsulatedContentInfo` (or legacy PKCS#7 `contentInfo`, which is
/// structurally identical at this level).
fn decode_encap_content_info<'a>(
    r: &mut Reader<'a>,
) -> tpt_asn1_core::error::Result<(ObjectIdentifier<'a>, Option<OctetString<'a>>)> {
    tpt_asn1_core::decode::read_sequence(r, |inner| {
        let e_content_type = ObjectIdentifier::decode(inner)?;
        let e_content = if inner.is_empty() {
            None
        } else {
            let (tag, _, value) = inner.read_tlv()?;
            if tag != Tag::context(true, 0) {
                return Err(Error::UnexpectedStructure.into());
            }
            // value is the inner OCTET STRING TLV.
            let os = OctetString::decode(&mut Reader::new(value, tpt_asn1_core::reader::Config::der()))?;
            Some(os)
        };
        Ok((e_content_type, e_content))
    })
}

/// Split a SET OF content into its constituent `Any` elements.
fn split_any_set<'a>(content: &'a [u8]) -> Result<alloc::vec::Vec<Any<'a>>> {
    let mut r = Reader::new(content, tpt_asn1_core::reader::Config::ber());
    let mut out = alloc::vec::Vec::new();
    while !r.is_empty() {
        out.push(Any::decode(&mut r)?);
    }
    Ok(out)
}

/// Decode a `SET OF SignerInfo` from its raw content bytes.
fn decode_signer_infos<'a>(content: &'a [u8]) -> Result<alloc::vec::Vec<SignerInfo<'a>>> {
    let mut r = Reader::new(content, tpt_asn1_core::reader::Config::der());
    let mut out = alloc::vec::Vec::new();
    while !r.is_empty() {
        out.push(SignerInfo::decode(&mut r)?);
    }
    Ok(out)
}
