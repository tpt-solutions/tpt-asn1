// SPDX-License-Identifier: MIT OR Apache-2.0

//! Helpers for extracting the fields needed to verify a `SignerInfo` from an
//! embedded X.509 certificate, without pulling in the full `tpt-x509` decoder.
//!
//! These walk the DER of a `Certificate` directly (fail-closed) to recover:
//! * the `serialNumber` and issuer `Name` (to match an `IssuerAndSerialNumber`),
//! * the `SubjectPublicKeyInfo` algorithm OID and raw public-key bits, and
//! * the `SubjectKeyIdentifier` extension (to match a `SubjectKeyIdentifier` sid).

use crate::error::{Error, Result};
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::Reader;
use tpt_asn1_core::tag::Tag;
use tpt_asn1_core::types::{BitString, ObjectIdentifier};

/// `id-ce-subjectKeyIdentifier` — `2.5.29.14`.
pub const OID_SUBJECT_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x0e];

/// Fields extracted from a certificate that CMS signature verification needs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CertFields<'a> {
    /// Raw `serialNumber` INTEGER bytes (minimal encoding).
    pub serial: &'a [u8],
    /// Raw issuer `Name` TLV (tag + length + value) for byte-exact matching.
    pub issuer: &'a [u8],
    /// Raw `SubjectPublicKeyInfo` algorithm OID bytes.
    pub spki_algorithm: &'a [u8],
    /// Raw `subjectPublicKey` BIT STRING data (key bits only).
    pub spki_key: &'a [u8],
    /// The `SubjectKeyIdentifier` extension value, if present.
    pub subject_key_id: Option<&'a [u8]>,
}

/// Extract the verification-relevant fields from a DER-encoded `Certificate`.
pub fn extract_cert_fields(cert_der: &[u8]) -> Result<CertFields<'_>> {
    let mut outer = Reader::new(cert_der, tpt_asn1_core::reader::Config::der());
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (tag, _, value) = outer.read_tlv()?;
    if !tag.is_universal(Tag::SEQUENCE) {
        return Err(Error::UnexpectedStructure);
    }
    // `value` is the Certificate content; parse tbsCertificate from it.
    let mut inner = Reader::new(value, tpt_asn1_core::reader::Config::der());
    let (tbs_tag, _, tbs_value) = inner.read_tlv()?;
    if !tbs_tag.is_universal(Tag::SEQUENCE) {
        return Err(Error::UnexpectedStructure);
    }
    let mut tbs = Reader::new(tbs_value, tpt_asn1_core::reader::Config::der());

    // Optional [0] EXPLICIT version — consume it if present; otherwise the
    // first TLV is the serialNumber.
    if !tbs.is_empty() {
        let (vtag, _, vval) = tbs.read_tlv()?;
        if vtag == Tag::context(true, 0) {
            // version tag consumed; serialNumber follows below.
        } else if vtag.is_universal(Tag::INTEGER) {
            return finish_tbs(tbs, vval);
        } else {
            return Err(Error::UnexpectedStructure);
        }
    }

    // serialNumber INTEGER (value holds the minimal integer bytes).
    let (stag, _, serial) = tbs.read_tlv()?;
    if !stag.is_universal(Tag::INTEGER) {
        return Err(Error::UnexpectedStructure);
    }
    finish_tbs(tbs, serial)
}

/// Walk the remainder of `TBSCertificate` (positioned just after `serialNumber`)
/// to recover the issuer, SPKI and SKI.
fn finish_tbs<'a>(mut tbs: Reader<'a>, serial: &'a [u8]) -> Result<CertFields<'a>> {
    // signature AlgorithmIdentifier — skip.
    skip_tlv(&mut tbs)?;
    // issuer Name (SEQUENCE) — capture full TLV for byte-exact matching.
    let issuer = read_full_tlv(&mut tbs)?;
    // validity — skip, then subject — skip.
    skip_tlv(&mut tbs)?;
    skip_tlv(&mut tbs)?;

    // subjectPublicKeyInfo SEQUENCE { algorithm, subjectPublicKey BIT STRING }
    let spki = read_full_tlv(&mut tbs)?;
    let (spki_algorithm, spki_key) = parse_spki(spki)?;

    // Remaining: optional [1]/[2] unique IDs and [3] EXPLICIT extensions.
    let mut subject_key_id = None;
    while !tbs.is_empty() {
        let (etag, _, evalue) = tbs.read_tlv()?;
        if etag == Tag::context(true, 3) {
            subject_key_id = find_ski(evalue)?;
        }
    }

    Ok(CertFields { serial, issuer, spki_algorithm, spki_key, subject_key_id })
}

fn parse_spki(spki: &[u8]) -> Result<(&[u8], &[u8])> {
    let mut r = Reader::new(spki, tpt_asn1_core::reader::Config::der());
    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, ... }
    let (tag, _, spki_inner) = r.read_tlv()?;
    if !tag.is_universal(Tag::SEQUENCE) {
        return Err(Error::UnexpectedStructure);
    }
    let mut r2 = Reader::new(spki_inner, tpt_asn1_core::reader::Config::der());
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }
    let (atag, _, alg_inner) = r2.read_tlv()?;
    if !atag.is_universal(Tag::SEQUENCE) {
        return Err(Error::UnexpectedStructure);
    }
    let alg = ObjectIdentifier::decode(&mut Reader::new(alg_inner, tpt_asn1_core::reader::Config::der()))?;
    let key = BitString::decode(&mut r2)?;
    Ok((alg.0, key.data))
}

fn find_ski(exts: &[u8]) -> Result<Option<&[u8]>> {
    let mut r = Reader::new(exts, tpt_asn1_core::reader::Config::der());
    let (tag, _, inner) = r.read_tlv()?;
    if !tag.is_universal(Tag::SEQUENCE) {
        return Err(Error::UnexpectedStructure);
    }
    let mut er = Reader::new(inner, tpt_asn1_core::reader::Config::der());
    while !er.is_empty() {
        let (ext_tag, _, ext_inner) = er.read_tlv()?;
        if !ext_tag.is_universal(Tag::SEQUENCE) {
            return Err(Error::UnexpectedStructure);
        }
        let mut xr = Reader::new(ext_inner, tpt_asn1_core::reader::Config::der());
        let oid = ObjectIdentifier::decode(&mut xr)?;
        // critical BOOLEAN DEFAULT FALSE — consume it if present.
        if !xr.is_empty() {
            let (ctag, _, cval) = xr.read_tlv()?;
            if ctag.is_universal(Tag::BOOLEAN) {
                let _ = cval;
            } else {
                // This TLV is actually extnValue; process it now.
                if !ctag.is_universal(Tag::OCTET_STRING) {
                    return Err(Error::UnexpectedStructure);
                }
                if oid.0 == OID_SUBJECT_KEY_IDENTIFIER {
                    return Ok(Some(unwrap_octet(cval)?));
                }
                continue;
            }
        }
        // extnValue OCTET STRING (contains the DER of the extension value).
        let (vtag, _, vval) = xr.read_tlv()?;
        if !vtag.is_universal(Tag::OCTET_STRING) {
            return Err(Error::UnexpectedStructure);
        }
        if oid.0 == OID_SUBJECT_KEY_IDENTIFIER {
            // extnValue wraps a SubjectKeyIdentifier ::= OCTET STRING.
            return Ok(Some(unwrap_octet(vval)?));
        }
    }
    Ok(None)
}

fn unwrap_octet(inner: &[u8]) -> Result<&[u8]> {
    let mut vr = Reader::new(inner, tpt_asn1_core::reader::Config::der());
    let (sktag, _, skval) = vr.read_tlv()?;
    if !sktag.is_universal(Tag::OCTET_STRING) {
        return Err(Error::UnexpectedStructure);
    }
    Ok(skval)
}

// --- low-level TLV helpers ------------------------------------------------

fn read_full_tlv<'a>(r: &mut Reader<'a>) -> Result<&'a [u8]> {
    let start = r.position();
    r.read_tlv()?;
    let end = r.position();
    Ok(r.slice(start, end))
}

fn skip_tlv(r: &mut Reader<'_>) -> Result<()> {
    r.read_tlv()?;
    Ok(())
}
