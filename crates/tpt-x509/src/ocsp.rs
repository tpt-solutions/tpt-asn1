// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal OCSP request / response parsing and matching (RFC 6960).
//!
//! Scope (per Phase 4 item 78): this module *parses* OCSP structures and lets a
//! caller match a `CertID` to a `SingleResponse`. It does **not** fetch
//! responses or perform the signature verification itself — that is delegated
//! to the [`SignatureVerifier`](crate::verify::SignatureVerifier) backend via
//! the `tbsResponseData` bytes exposed here.

use alloc::vec::Vec;

use tpt_asn1_core::any::Any;
use tpt_asn1_core::decode::{read_sequence, Decode};
use tpt_asn1_core::error::Result;
use tpt_asn1_core::reader::Reader;
use tpt_asn1_core::tag::Tag;
use tpt_asn1_core::types::{Integer, OctetString};

use crate::algorithm::AlgorithmIdentifier;
use crate::time::Time;
use crate::oid;

/// An OCSP `CertID` — identifies a cert by issuer name/key hashes + serial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertId<'a> {
    /// The hash algorithm used for the name/key hashes.
    pub hash_algorithm: AlgorithmIdentifier<'a>,
    /// Hash of the issuer's DN.
    pub issuer_name_hash: &'a [u8],
    /// Hash of the issuer's public key.
    pub issuer_key_hash: &'a [u8],
    /// The target certificate's serial number.
    pub serial_number: Integer<'a>,
}

impl<'a> CertId<'a> {
    /// The serial number as raw bytes.
    pub fn serial_number_bytes(&self) -> &'a [u8] {
        self.serial_number.as_bytes()
    }
}

impl<'a> Decode<'a> for CertId<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let hash_algorithm = AlgorithmIdentifier::decode(inner)?;
            let issuer_name_hash = OctetString::decode(inner)?.0;
            let issuer_key_hash = OctetString::decode(inner)?.0;
            let serial_number = Integer::decode(inner)?;
            Ok(CertId { hash_algorithm, issuer_name_hash, issuer_key_hash, serial_number })
        })
    }
}

/// An OCSP `Request` (one `CertID`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    /// The requested certificate ID.
    pub req_cert: CertId<'a>,
}

impl<'a> Decode<'a> for Request<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let req_cert = CertId::decode(inner)?;
            Ok(Request { req_cert })
        })
    }
}

/// An OCSP `TBSRequest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TbsRequest<'a> {
    /// The requested certificate IDs.
    pub requests: Vec<Request<'a>>,
}

impl<'a> Decode<'a> for TbsRequest<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            // Skip optional version [0] and requestorName [1].
            while inner.peek_tag() == Ok(Tag::context(false, 0))
                || inner.peek_tag() == Ok(Tag::context(true, 1))
            {
                Any::decode(inner)?;
            }
            let req_any = Any::decode(inner)?;
            let mut reqs = Reader::new(req_any.value, *inner.config());
            let mut requests = Vec::new();
            while !reqs.is_empty() {
                requests.push(Request::decode(&mut reqs)?);
            }
            Ok(TbsRequest { requests })
        })
    }
}

/// An OCSP `OCSPRequest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OcspRequest<'a> {
    /// The to-be-signed request.
    pub tbs_request: TbsRequest<'a>,
}

impl<'a> Decode<'a> for OcspRequest<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let tbs_request = TbsRequest::decode(inner)?;
            // optionalSignature (ANY) is skipped if present.
            Ok(OcspRequest { tbs_request })
        })
    }
}

/// OCSP `CertStatus` — `CHOICE { good, revoked, unknown }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertStatus<'a> {
    /// The certificate is not revoked.
    Good,
    /// The certificate has been revoked.
    Revoked {
        /// The revocation time.
        revocation_time: Time<'a>,
        /// The revocation reason, if present.
        reason: Option<u8>,
    },
    /// The responder does not know the status.
    Unknown,
}

impl<'a> Decode<'a> for CertStatus<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let any = Any::decode(r)?;
        let t = any.tag;
        if t == Tag::context(false, 0) {
            Ok(CertStatus::Good)
        } else if t == Tag::context(true, 1) {
            let mut sub = Reader::new(any.value, *r.config());
            let revocation_time = Time::decode(&mut sub)?;
            let reason = if !sub.is_empty() {
                Some(Integer::decode(&mut sub)?.as_u64().ok_or(
                    tpt_asn1_core::error::Error::Custom("revocation reason too large"),
                )? as u8)
            } else {
                None
            };
            Ok(CertStatus::Revoked { revocation_time, reason })
        } else if t == Tag::context(false, 2) {
            Ok(CertStatus::Unknown)
        } else {
            Err(tpt_asn1_core::error::Error::UnexpectedTag {
                expected: Tag::context(false, 0),
                actual: t,
            })
        }
    }
}

/// A `SingleResponse` in a `BasicOCSPResponse`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SingleResponse<'a> {
    /// The cert this response is about.
    pub cert_id: CertId<'a>,
    /// Its status.
    pub cert_status: CertStatus<'a>,
    /// `thisUpdate` time.
    pub this_update: Time<'a>,
}

impl<'a> SingleResponse<'a> {
    /// Returns `true` if this response matches `cert_id` by serial number.
    pub fn matches_serial(&self, serial: &[u8]) -> bool {
        self.cert_id.serial_number_bytes() == serial
    }
}

impl<'a> Decode<'a> for SingleResponse<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let cert_id = CertId::decode(inner)?;
            let cert_status = CertStatus::decode(inner)?;
            let this_update = Time::decode(inner)?;
            Ok(SingleResponse { cert_id, cert_status, this_update })
        })
    }
}

/// A `BasicOCSPResponse`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicOcspResponse<'a> {
    /// The raw DER of `tbsResponseData` (for signature verification).
    pub tbs_response_data_der: &'a [u8],
    /// The responder's signature algorithm.
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    /// The signature value.
    pub signature: &'a [u8],
    /// The contained `SingleResponse`s.
    pub responses: Vec<SingleResponse<'a>>,
}

impl<'a> Decode<'a> for BasicOcspResponse<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let tbs_any = Any::decode(inner)?;
            let config = *inner.config();
            let mut tbs = Reader::new(tbs_any.value, config);
            // version [0] OPTIONAL
            if tbs.peek_tag() == Ok(Tag::context(false, 0)) {
                Any::decode(&mut tbs)?;
            }
            // responderID CHOICE — byName [1] or byKey [2].
            let _ = Any::decode(&mut tbs)?;
            let _ = Time::decode(&mut tbs)?; // producedAt
            let resp_any = Any::decode(&mut tbs)?;
            let mut resp = Reader::new(resp_any.value, config);
            let mut responses = Vec::new();
            while !resp.is_empty() {
                responses.push(SingleResponse::decode(&mut resp)?);
            }
            let signature_algorithm = AlgorithmIdentifier::decode(inner)?;
            let sig_any = Any::decode(inner)?;
            let signature = sig_any.value;
            Ok(BasicOcspResponse {
                tbs_response_data_der: tbs_any.full,
                signature_algorithm,
                signature,
                responses,
            })
        })
    }
}

/// The OCSP `ResponseBytes` wrapper (`responseType` OID + `response` OCTET STRING).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseBytes<'a> {
    /// The response type OID (e.g. `id-pkix-ocsp-basic`).
    pub response_type: &'a [u8],
    /// The inner response DER (e.g. a `BasicOCSPResponse`).
    pub response: &'a [u8],
}

impl<'a> Decode<'a> for ResponseBytes<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let oid = tpt_asn1_core::types::ObjectIdentifier::decode(inner)?;
            let response = OctetString::decode(inner)?.0;
            Ok(ResponseBytes { response_type: oid.as_bytes(), response })
        })
    }
}

/// An OCSP `OCSPResponse`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OcspResponse<'a> {
    /// The response status: `0` = successful.
    pub status: u8,
    /// The response bytes, if present.
    pub response_bytes: Option<ResponseBytes<'a>>,
}

impl<'a> Decode<'a> for OcspResponse<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let status = tpt_asn1_core::types::Enumerated::decode(inner)?
                .as_i64()
                .ok_or(tpt_asn1_core::error::Error::Custom("bad OCSP status"))? as u8;
            let response_bytes = if inner.is_empty() {
                None
            } else {
                Some(ResponseBytes::decode(inner)?)
            };
            Ok(OcspResponse { status, response_bytes })
        })
    }
}

/// Decode a `BasicOCSPResponse` from a `response` OCTET STRING payload.
pub fn decode_basic_response(bytes: &[u8]) -> Result<BasicOcspResponse<'_>> {
    crate::decode::<BasicOcspResponse<'_>>(bytes)
}

/// Returns `true` if `response_type` is the OCSP basic response type.
pub fn is_basic_response_type(response_type: &[u8]) -> bool {
    oid::oid_eq_bytes(response_type, oid::pkix::OCSP)
}
