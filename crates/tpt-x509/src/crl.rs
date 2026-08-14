// SPDX-License-Identifier: MIT OR Apache-2.0

//! X.509 `CertificateList` (CRL) decoding (RFC 5280 §5).

use alloc::vec::Vec;

use tpt_asn1_core::any::Any;
use tpt_asn1_core::decode::{read_sequence, Decode};
use tpt_asn1_core::error::Result;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_core::tag::Tag;
use tpt_asn1_core::types::{BitString, Integer};

use crate::algorithm::AlgorithmIdentifier;
use crate::extensions::Extensions;
use crate::name::Name;
use crate::time::{Time, UnixTime};

/// A `RevokedCertificate` entry in a CRL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevokedCertificate<'a> {
    /// The revoked certificate's serial number.
    pub user_certificate: Integer<'a>,
    /// The revocation date.
    pub revocation_date: Time<'a>,
}

impl<'a> RevokedCertificate<'a> {
    /// The serial number as raw bytes.
    pub fn serial_number_bytes(&self) -> &'a [u8] {
        self.user_certificate.as_bytes()
    }

    /// Returns `true` if `now` is on or after the revocation date.
    pub fn is_revoked_at(&self, now: UnixTime) -> bool {
        match self.revocation_date.to_unix() {
            Ok(t) => t <= now,
            Err(_) => false,
        }
    }
}

/// An X.509 `CertificateList` (CRL).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateList<'a> {
    /// The issuer `Name`.
    pub issuer: Name<'a>,
    /// `thisUpdate` time.
    pub this_update: Time<'a>,
    /// `nextUpdate` time, if present.
    pub next_update: Option<Time<'a>>,
    /// The revoked certificates.
    pub revoked: Vec<RevokedCertificate<'a>>,
    /// CRL extensions (e.g. `cRLNumber`, authority key identifier).
    pub crl_extensions: Extensions<'a>,
    /// The signature algorithm.
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    /// The signature value.
    pub signature_value: BitString<'a>,
    tbs_der: &'a [u8],
}

impl<'a> CertificateList<'a> {
    /// The raw DER of `tbsCertList` (the signed message).
    pub fn tbs_cert_list_der(&self) -> &'a [u8] {
        self.tbs_der
    }

    /// Returns `true` if `serial` (raw bytes) is present and revoked as of `now`.
    pub fn is_revoked(&self, serial: &[u8], now: UnixTime) -> bool {
        self.revoked
            .iter()
            .any(|r| r.serial_number_bytes() == serial && r.is_revoked_at(now))
    }
}

impl<'a> Decode<'a> for CertificateList<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let tbs_any = Any::decode(inner)?;
            let config = *inner.config();
            let mut r2 = Reader::new(tbs_any.value, config);

            // version OPTIONAL (INTEGER, v2 == 1).
            if r2.peek_tag() == Ok(Tag::universal(Tag::INTEGER)) {
                let _version = Integer::decode(&mut r2)?;
            }
            let signature_algorithm = AlgorithmIdentifier::decode(&mut r2)?;
            let issuer = Name::decode(&mut r2)?;
            let this_update = Time::decode(&mut r2)?;
            let next_update = if !r2.is_empty()
                && (r2.peek_tag() == Ok(Tag::universal(Tag::UTC_TIME))
                    || r2.peek_tag() == Ok(Tag::universal(Tag::GENERALIZED_TIME)))
            {
                Some(Time::decode(&mut r2)?)
            } else {
                None
            };

            let mut revoked = Vec::new();
            if !r2.is_empty() && r2.peek_tag() == Ok(Tag::universal_constructed(Tag::SEQUENCE)) {
                let rc_any = Any::decode(&mut r2)?;
                let mut rc = Reader::new(rc_any.value, config);
                while !rc.is_empty() {
                    let entry = read_sequence(&mut rc, |e| {
                        let user_certificate = Integer::decode(e)?;
                        let revocation_date = Time::decode(e)?;
                        Ok(RevokedCertificate { user_certificate, revocation_date })
                    })?;
                    revoked.push(entry);
                }
            }

            let mut crl_extensions = Extensions::empty();
            if r2.peek_tag() == Ok(Tag::context(true, 0)) {
                let ext_any = Any::decode(&mut r2)?;
                crl_extensions = Extensions::from_content(ext_any.value, config)?;
            }

            let signature_algorithm = AlgorithmIdentifier::decode(inner)?;
            let signature_value = BitString::decode(inner)?;
            Ok(CertificateList {
                issuer,
                this_update,
                next_update,
                revoked,
                crl_extensions,
                signature_algorithm,
                signature_value,
                tbs_der: tbs_any.full,
            })
        })
    }
}
