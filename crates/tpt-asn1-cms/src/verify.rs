// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signature verification over `SignedData` (RFC 5652 §5.4 / RFC 2315 §7).
//!
//! This reuses the pluggable [`SignatureVerifier`](tpt_asn1_x509::verify::SignatureVerifier)
//! backend defined in `tpt-asn1-x509` (Phase 4 item 75): no cryptographic primitives
//! live in this crate. For each `SignerInfo` we:
//!
//! 1. locate the signing certificate among the embedded/`extra` set by matching
//!    its `SignerIdentifier` (constant-time),
//! 2. compute the message digest over the encapsulated (or externally supplied)
//!    content and check it against the `message-digest` signed attribute,
//! 3. build the to-be-signed byte string (the canonical `SET OF` of signed
//!    attributes, or the raw content when `signedAttrs` are absent), and
//! 4. delegate the actual signature math to the backend.

use crate::cert;
use crate::error::{Error, Result};
use crate::oid;
use crate::signed_data::SignedData;
use crate::signer_info::{SignedAttributes, SignerInfo};
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_core::tag::Tag;
use tpt_asn1_core::types::{ObjectIdentifier, OctetString};
use tpt_asn1_core::util::constant_time_eq;

/// Per-signer verification outcome.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum VerificationResult {
    /// The signature verified successfully.
    Success,
    /// No embedded/extra certificate matched this signer's identifier.
    NoMatchingCertificate,
    /// The `message-digest` attribute did not match the computed digest.
    DigestMismatch,
    /// The cryptographic backend reported an invalid signature.
    SignatureInvalid,
    /// The backend could not check this signer at all: an unsupported algorithm,
    /// an unparsable key, or an internal error. Other signers are still checked.
    Unverifiable,
}

/// Verify every `SignerInfo` in `sd`.
///
/// * `backend` — the pluggable crypto backend (digest + signature verify).
/// * `external_content` — required for *detached* signatures; for attached
///   messages pass `None` to use the encapsulated `eContent`.
/// * `extra_certs` — additional DER certificates (e.g. from a trust store) to
///   consider alongside those embedded in the message.
///
/// Returns one [`VerificationResult`] per `SignerInfo`, in order.
///
/// # Trust
///
/// [`VerificationResult::Success`] only means the signer's key verified the
/// signature over the content. It does **not** establish that the signer's
/// certificate is trusted: this function does no chain building, validity or
/// key-usage checks. Validate the signer certificate with
/// `tpt_asn1_x509::chain::build_and_validate` before relying on the result.
///
/// Returns [`Error::AmbiguousContent`] if the message has embedded `eContent`
/// and `external_content` is also supplied.
#[cfg(feature = "alloc")]
pub fn verify<B: tpt_asn1_x509::verify::SignatureVerifier>(
    sd: &SignedData<'_>,
    backend: &B,
    external_content: Option<&[u8]>,
    extra_certs: &[&[u8]],
) -> Result<alloc::vec::Vec<VerificationResult>> {
    use alloc::vec::Vec;

    // Collect candidate certificate DER (X.509 `Certificate` SEQUENCEs).
    let mut certs: Vec<&[u8]> = Vec::with_capacity(sd.certificates.len() + extra_certs.len());
    // Only plain certificates (bare SEQUENCEs) can match a signer. The other
    // CertificateChoices alternatives are not X.509 certificates.
    for c in sd.certificates.iter().filter(|c| c.tag.is_universal(Tag::SEQUENCE)) {
        certs.push(c.full);
    }
    certs.extend_from_slice(extra_certs);

    let mut out = Vec::with_capacity(sd.signer_infos.len());
    for signer in &sd.signer_infos {
        out.push(verify_signer(sd, signer, backend, external_content, &certs)?);
    }
    Ok(out)
}

/// RFC 5652 §11.1 and §11.2: a `message-digest` attribute must have exactly one
/// value. A `content-type` attribute, when present, must also have exactly one
/// value, and it must name the encapsulated content type (`eContentType`).
#[cfg(feature = "alloc")]
fn check_signed_attributes(
    attrs: &SignedAttributes<'_>,
    e_content_type: &ObjectIdentifier<'_>,
) -> Result<()> {
    if let Some(md) = attrs.find(oid::ATTR_MESSAGE_DIGEST) {
        if md.checked_values()?.len() != 1 {
            return Err(Error::UnexpectedStructure);
        }
    }
    if let Some(ct) = attrs.find(oid::ATTR_CONTENT_TYPE) {
        let values = ct.checked_values()?;
        let [value] = values.as_slice() else {
            return Err(Error::UnexpectedStructure);
        };
        let attr_type = ObjectIdentifier::decode(&mut Reader::new(value.full, Config::der()))?;
        if attr_type.as_bytes() != e_content_type.as_bytes() {
            return Err(Error::UnexpectedStructure);
        }
    }
    Ok(())
}

#[cfg(feature = "alloc")]
fn verify_signer<B: tpt_asn1_x509::verify::SignatureVerifier>(
    sd: &SignedData<'_>,
    signer: &SignerInfo<'_>,
    backend: &B,
    external_content: Option<&[u8]>,
    certs: &[&[u8]],
) -> Result<VerificationResult> {
    // 1. Determine the content to digest / sign over. A message must carry
    // either embedded eContent or detached content, never both: preferring one
    // would let a caller's detached payload go unchecked.
    let content = match (sd.content_bytes(), external_content) {
        (Some(_), Some(_)) => return Err(Error::AmbiguousContent),
        (embedded, detached) => embedded.or(detached),
    };
    let tbs = match &signer.signed_attrs {
        Some(attrs) => {
            let content = content.ok_or(Error::MissingContent)?;
            // Compute the digest and check the message-digest attribute.
            // A backend failure for this signer must not abort the others.
            let Ok(digest) = backend.digest(signer.digest_algorithm_bytes(), content) else {
                return Ok(VerificationResult::Unverifiable);
            };
            check_signed_attributes(attrs, &sd.e_content_type)?;
            match attrs.find(oid::ATTR_MESSAGE_DIGEST).and_then(|a| a.first_value()) {
                Some(md) => {
                    let md_bytes = OctetString::decode(&mut Reader::new(md.full, Config::der()))
                        .map_err(Error::from)?
                        .0;
                    if !constant_time_eq(md_bytes, &digest) {
                        return Ok(VerificationResult::DigestMismatch);
                    }
                }
                None => return Ok(VerificationResult::DigestMismatch),
            }
            // The signature is over the canonical SET OF signed attributes.
            attrs.der()?
        }
        None => {
            let content = content.ok_or(Error::MissingContent)?;
            alloc::vec::Vec::from(content)
        }
    };

    // 2. Locate the signing certificate.
    let mut matched: Option<cert::CertFields<'_>> = None;
    for der in certs {
        match cert::extract_cert_fields(der) {
            Ok(fields) if signer.matches_cert(&fields) => {
                matched = Some(fields);
                break;
            }
            _ => continue,
        }
    }
    let fields = match matched {
        Some(f) => f,
        None => return Ok(VerificationResult::NoMatchingCertificate),
    };

    // 3. Delegate the signature math to the backend.
    let verdict = backend.verify_signature_with_params(
        signer.signature_algorithm_bytes(),
        fields.spki_algorithm,
        fields.spki_params,
        fields.spki_key,
        &tbs,
        signer.signature,
    );
    match verdict {
        Ok(true) => Ok(VerificationResult::Success),
        Ok(false) => Ok(VerificationResult::SignatureInvalid),
        Err(_) => Ok(VerificationResult::Unverifiable),
    }
}
