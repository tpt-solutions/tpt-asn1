// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signature verification over `SignedData` (RFC 5652 §5.4 / RFC 2315 §7).
//!
//! This reuses the pluggable [`SignatureVerifier`](tpt_x509::verify::SignatureVerifier)
//! backend defined in `tpt-x509` (Phase 4 item 75): no cryptographic primitives
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
use crate::signer_info::SignerInfo;
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::tag::Tag;
use tpt_asn1_core::types::OctetString;
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
#[cfg(feature = "alloc")]
pub fn verify<B: tpt_x509::verify::SignatureVerifier>(
    sd: &SignedData<'_>,
    backend: &B,
    external_content: Option<&[u8]>,
    extra_certs: &[&[u8]],
) -> Result<alloc::vec::Vec<VerificationResult>> {
    use alloc::vec::Vec;

    // Collect candidate certificate DER (X.509 `Certificate` SEQUENCEs).
    let mut certs: Vec<&[u8]> = Vec::with_capacity(sd.certificates.len() + extra_certs.len());
    for c in &sd.certificates {
        certs.push(if c.tag == Tag::context(true, 0) { c.value } else { c.full });
    }
    certs.extend_from_slice(extra_certs);

    let mut out = Vec::with_capacity(sd.signer_infos.len());
    for signer in &sd.signer_infos {
        out.push(verify_signer(sd, signer, backend, external_content, &certs)?);
    }
    Ok(out)
}

#[cfg(feature = "alloc")]
fn verify_signer<B: tpt_x509::verify::SignatureVerifier>(
    sd: &SignedData<'_>,
    signer: &SignerInfo<'_>,
    backend: &B,
    external_content: Option<&[u8]>,
    certs: &[&[u8]],
) -> Result<VerificationResult> {
    // 1. Determine the content to digest / sign over.
    let content = sd.content_bytes().or(external_content);
    let tbs = match &signer.signed_attrs {
        Some(attrs) => {
            let content = content.ok_or(Error::MissingContent)?;
            // Compute the digest and check the message-digest attribute.
            let digest = backend
                .digest(signer.digest_algorithm_bytes(), content)
                .map_err(map_verify_err)?;
            match attrs.find(oid::ATTR_MESSAGE_DIGEST).and_then(|a| a.first_value()) {
                Some(md) => {
                    let md_bytes = OctetString::decode(&mut tpt_asn1_core::reader::Reader::new(
                        md.value,
                        tpt_asn1_core::reader::Config::der(),
                    ))
                    .map_err(Error::from)?
                    .0;
                    if !constant_time_eq(md_bytes, &digest) {
                        return Ok(VerificationResult::DigestMismatch);
                    }
                }
                None => return Ok(VerificationResult::DigestMismatch),
            }
            // The signature is over the canonical SET OF signed attributes.
            alloc::vec::Vec::from(attrs.der().as_slice())
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
    let ok = backend
        .verify_signature(
            signer.signature_algorithm_bytes(),
            fields.spki_algorithm,
            fields.spki_key,
            &tbs,
            signer.signature,
        )
        .map_err(map_verify_err)?;
    if ok {
        Ok(VerificationResult::Success)
    } else {
        Ok(VerificationResult::SignatureInvalid)
    }
}

fn map_verify_err(e: tpt_x509::verify::VerifyError) -> Error {
    match e {
        tpt_x509::verify::VerifyError::UnsupportedAlgorithm => Error::UnsupportedAlgorithm,
        tpt_x509::verify::VerifyError::InvalidKey => Error::UnexpectedStructure,
        tpt_x509::verify::VerifyError::InvalidSignature => Error::VerificationFailed,
        tpt_x509::verify::VerifyError::Internal => Error::UnexpectedStructure,
    }
}
