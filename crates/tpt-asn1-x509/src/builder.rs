// SPDX-License-Identifier: MIT OR Apache-2.0

//! Build DER-encoded X.509 v3 certificates.
//!
//! The builder writes the `TBSCertificate`, then asks the caller for a signature
//! over those bytes, so the signing key stays outside this crate. It supports the
//! fields a typical leaf or CA certificate needs: serial number, names with
//! string-valued attributes, validity, the subject public key, and the basic
//! constraints and key usage extensions.
//!
//! The output is a `Certificate` that [`crate::Certificate`] decodes back. The
//! tests in `tpt-asn1-crypto` verify the signatures it produces.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// `keyUsage` bit values (RFC 5280 §4.2.1.3), for [`CertificateBuilder::key_usage`].
pub mod usage {
    /// `digitalSignature`.
    pub const DIGITAL_SIGNATURE: u16 = 1 << 0;
    /// `keyCertSign`.
    pub const KEY_CERT_SIGN: u16 = 1 << 5;
    /// `cRLSign`.
    pub const CRL_SIGN: u16 = 1 << 6;
}

/// The seconds from 1970-01-01 to the given date (proleptic Gregorian calendar).
#[cfg(test)]
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The calendar date and time (year, month, day, hour, minute, second) of `secs`.
fn civil_from_unix(secs: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day, rem / 3600, (rem % 3600) / 60, rem % 60)
}

/// One TLV: tag, DER length, content.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// `OBJECT IDENTIFIER` from its arcs.
fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut content = Vec::new();
    let mut subs = vec![arcs[0] * 40 + arcs.get(1).copied().unwrap_or(0)];
    subs.extend(arcs.iter().skip(2).copied());
    for sub in subs {
        let mut groups = vec![(sub & 0x7f) as u8];
        let mut rest = sub >> 7;
        while rest > 0 {
            groups.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        groups.reverse();
        content.extend(groups);
    }
    tlv(0x06, &content)
}

/// A positive `INTEGER` from big-endian bytes: leading zeros dropped, and a zero
/// octet added when the high bit is set.
fn positive_integer(bytes: &[u8]) -> Vec<u8> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len().saturating_sub(1));
    let trimmed = bytes.get(start..).unwrap_or(&[0]);
    let mut content = Vec::new();
    if trimmed.first().is_some_and(|b| b & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(trimmed);
    if content.is_empty() {
        content.push(0);
    }
    tlv(0x02, &content)
}

/// A `Time`: `UTCTime` through 2049, `GeneralizedTime` from 2050 (RFC 5280 §4.1.2.5).
fn time(unix: i64) -> Vec<u8> {
    let (year, month, day, hour, minute, second) = civil_from_unix(unix);
    if (1950..2050).contains(&year) {
        let text = alloc::format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            year % 100,
            month,
            day,
            hour,
            minute,
            second
        );
        tlv(0x17, text.as_bytes())
    } else {
        let text = alloc::format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            year,
            month,
            day,
            hour,
            minute,
            second
        );
        tlv(0x18, text.as_bytes())
    }
}

/// One attribute of a name: an OID and a UTF8String value.
#[derive(Clone, Debug)]
struct NameAttribute {
    oid: Vec<u64>,
    value: String,
}

/// A distinguished name: an ordered list of single-valued RDNs.
fn name(attributes: &[NameAttribute]) -> Vec<u8> {
    let rdns: Vec<Vec<u8>> = attributes
        .iter()
        .map(|attr| {
            let atv = seq(&[oid(&attr.oid), tlv(0x0c, attr.value.as_bytes())]);
            tlv(0x31, &atv)
        })
        .collect();
    seq(&rdns)
}

/// A DER `Extension` with the given OID, criticality, and value.
fn extension(arcs: &[u64], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut parts = vec![oid(arcs)];
    if critical {
        parts.push(tlv(0x01, &[0xff]));
    }
    parts.push(tlv(0x04, value));
    seq(&parts)
}

/// Builds a `Certificate`. Set the fields, then call [`CertificateBuilder::build`].
#[derive(Clone, Debug)]
pub struct CertificateBuilder {
    serial: Vec<u8>,
    signature_algorithm: Vec<u64>,
    signature_parameters: Option<Vec<u8>>,
    issuer: Vec<NameAttribute>,
    subject: Vec<NameAttribute>,
    not_before: i64,
    not_after: i64,
    public_key_algorithm: Vec<u64>,
    public_key_parameters: Option<Vec<u8>>,
    public_key: Vec<u8>,
    extensions: Vec<Vec<u8>>,
}

impl CertificateBuilder {
    /// Start a certificate with the given serial number (big-endian) and signature
    /// algorithm OID (for example `[1, 3, 101, 112]` for Ed25519).
    pub fn new(serial: &[u8], signature_algorithm: &[u64]) -> Self {
        CertificateBuilder {
            serial: serial.to_vec(),
            signature_algorithm: signature_algorithm.to_vec(),
            signature_parameters: None,
            issuer: Vec::new(),
            subject: Vec::new(),
            not_before: 0,
            not_after: 0,
            public_key_algorithm: Vec::new(),
            public_key_parameters: None,
            public_key: Vec::new(),
            extensions: Vec::new(),
        }
    }

    /// Set the signature algorithm parameters as a DER TLV (for example `05 00` for
    /// RSA's NULL). Leave unset when the algorithm has none.
    pub fn signature_parameters(mut self, der_tlv: &[u8]) -> Self {
        self.signature_parameters = Some(der_tlv.to_vec());
        self
    }

    /// Add an attribute to the issuer name, in order.
    pub fn issuer_attribute(mut self, oid: &[u64], value: &str) -> Self {
        self.issuer.push(NameAttribute { oid: oid.to_vec(), value: value.into() });
        self
    }

    /// Add an attribute to the subject name, in order.
    pub fn subject_attribute(mut self, oid: &[u64], value: &str) -> Self {
        self.subject.push(NameAttribute { oid: oid.to_vec(), value: value.into() });
        self
    }

    /// Set the validity window as Unix seconds, inclusive at both ends.
    pub fn validity(mut self, not_before: i64, not_after: i64) -> Self {
        self.not_before = not_before;
        self.not_after = not_after;
        self
    }

    /// Set the subject public key: its algorithm OID, optional parameters TLV, and
    /// the raw `subjectPublicKey` bytes (for example an uncompressed EC point).
    pub fn public_key(
        mut self,
        algorithm: &[u64],
        parameters_der_tlv: Option<&[u8]>,
        key_bytes: &[u8],
    ) -> Self {
        self.public_key_algorithm = algorithm.to_vec();
        self.public_key_parameters = parameters_der_tlv.map(|p| p.to_vec());
        self.public_key = key_bytes.to_vec();
        self
    }

    /// Add `basicConstraints`, critical, with the given CA flag and optional path length.
    pub fn basic_constraints(mut self, ca: bool, path_len: Option<u32>) -> Self {
        let mut parts = Vec::new();
        if ca {
            parts.push(tlv(0x01, &[0xff]));
        }
        if let Some(len) = path_len {
            parts.push(positive_integer(&len.to_be_bytes()));
        }
        let value = seq(&parts);
        self.extensions.push(extension(&[2, 5, 29, 19], true, &value));
        self
    }

    /// Add `keyUsage`, critical, from the bit values in [`usage`].
    pub fn key_usage(mut self, bits: u16) -> Self {
        // A named BIT STRING drops trailing zero bits, and bit 0 is the most
        // significant bit of the first octet.
        let value = match (0..16).rev().find(|&i| bits & (1 << i) != 0) {
            None => tlv(0x03, &[0x00]),
            Some(high) => {
                let byte_count = high / 8 + 1;
                let mut bytes = vec![0u8; byte_count];
                for bit in 0..=high {
                    if bits & (1 << bit) != 0 {
                        bytes[bit / 8] |= 0x80 >> (bit % 8);
                    }
                }
                let unused = (byte_count * 8 - (high + 1)) as u8;
                let mut content = vec![unused];
                content.extend(bytes);
                tlv(0x03, &content)
            }
        };
        self.extensions.push(extension(&[2, 5, 29, 15], true, &value));
        self
    }

    /// The DER `TBSCertificate` for these fields.
    pub fn tbs_der(&self) -> Vec<u8> {
        let version = tlv(0xa0, &tlv(0x02, &[0x02]));
        let algorithm = |arcs: &[u64], params: &Option<Vec<u8>>| {
            let mut parts = vec![oid(arcs)];
            if let Some(p) = params {
                parts.push(p.clone());
            }
            seq(&parts)
        };
        let validity = seq(&[time(self.not_before), time(self.not_after)]);
        let spki = seq(&[
            algorithm(&self.public_key_algorithm, &self.public_key_parameters),
            tlv(0x03, &[&[0u8][..], &self.public_key[..]].concat()),
        ]);
        let mut parts = vec![
            version,
            positive_integer(&self.serial),
            algorithm(&self.signature_algorithm, &self.signature_parameters),
            name(&self.issuer),
            validity,
            name(&self.subject),
            spki,
        ];
        if !self.extensions.is_empty() {
            parts.push(tlv(0xa3, &seq(&self.extensions)));
        }
        seq(&parts)
    }

    /// Build the certificate. `sign` receives the TBS bytes and returns the signature
    /// value, which is stored as a BIT STRING with no unused bits.
    pub fn build(&self, sign: impl FnOnce(&[u8]) -> Vec<u8>) -> Vec<u8> {
        let tbs = self.tbs_der();
        let signature = sign(&tbs);
        let mut sig_alg = vec![oid(&self.signature_algorithm)];
        if let Some(p) = &self.signature_parameters {
            sig_alg.push(p.clone());
        }
        let sig_value = tlv(0x03, &[&[0u8][..], &signature[..]].concat());
        seq(&[tbs, seq(&sig_alg), sig_value])
    }
}

/// Builds a PKCS#10 `CertificationRequest` (RFC 2986). The caller signs the
/// `CertificationRequestInfo`, as with certificates.
#[derive(Clone, Debug)]
pub struct CsrBuilder {
    subject: Vec<NameAttribute>,
    public_key_algorithm: Vec<u64>,
    public_key_parameters: Option<Vec<u8>>,
    public_key: Vec<u8>,
    signature_algorithm: Vec<u64>,
}

impl CsrBuilder {
    /// Start a request for the given signature algorithm and subject public key.
    pub fn new(
        signature_algorithm: &[u64],
        public_key_algorithm: &[u64],
        public_key_parameters_der_tlv: Option<&[u8]>,
        public_key: &[u8],
    ) -> Self {
        CsrBuilder {
            subject: Vec::new(),
            public_key_algorithm: public_key_algorithm.to_vec(),
            public_key_parameters: public_key_parameters_der_tlv.map(|p| p.to_vec()),
            public_key: public_key.to_vec(),
            signature_algorithm: signature_algorithm.to_vec(),
        }
    }

    /// Add an attribute to the subject name, in order.
    pub fn subject_attribute(mut self, oid: &[u64], value: &str) -> Self {
        self.subject.push(NameAttribute { oid: oid.to_vec(), value: value.into() });
        self
    }

    /// The DER `CertificationRequestInfo` (the bytes that are signed).
    pub fn info_der(&self) -> Vec<u8> {
        let mut spki_alg = vec![oid(&self.public_key_algorithm)];
        if let Some(p) = &self.public_key_parameters {
            spki_alg.push(p.clone());
        }
        let spki = seq(&[seq(&spki_alg), tlv(0x03, &[&[0u8][..], &self.public_key[..]].concat())]);
        seq(&[
            // version INTEGER 0
            tlv(0x02, &[0x00]),
            name(&self.subject),
            spki,
            // attributes [0] IMPLICIT SET OF Attribute, empty.
            tlv(0xa0, &[]),
        ])
    }

    /// Build the request. `sign` receives the `CertificationRequestInfo` bytes.
    pub fn build(&self, sign: impl FnOnce(&[u8]) -> Vec<u8>) -> Vec<u8> {
        let info = self.info_der();
        let signature = sign(&info);
        let sig_alg = seq(&[oid(&self.signature_algorithm)]);
        let sig_value = tlv(0x03, &[&[0u8][..], &signature[..]].concat());
        seq(&[info, sig_alg, sig_value])
    }
}

/// Builds a v2 `CertificateList` (a CRL, RFC 5280 §5.1) with revoked entries.
#[derive(Clone, Debug)]
pub struct CrlBuilder {
    signature_algorithm: Vec<u64>,
    issuer: Vec<NameAttribute>,
    this_update: i64,
    next_update: Option<i64>,
    revoked: Vec<(Vec<u8>, i64)>,
}

impl CrlBuilder {
    /// Start a CRL for the given signature algorithm, with `thisUpdate` as Unix seconds.
    pub fn new(signature_algorithm: &[u64], this_update: i64) -> Self {
        CrlBuilder {
            signature_algorithm: signature_algorithm.to_vec(),
            issuer: Vec::new(),
            this_update,
            next_update: None,
            revoked: Vec::new(),
        }
    }

    /// Add an attribute to the issuer name, in order.
    pub fn issuer_attribute(mut self, oid: &[u64], value: &str) -> Self {
        self.issuer.push(NameAttribute { oid: oid.to_vec(), value: value.into() });
        self
    }

    /// Set `nextUpdate` as Unix seconds.
    pub fn next_update(mut self, next_update: i64) -> Self {
        self.next_update = Some(next_update);
        self
    }

    /// Revoke the certificate with the given serial number (big-endian) at `when`.
    pub fn revoke(mut self, serial: &[u8], when: i64) -> Self {
        self.revoked.push((serial.to_vec(), when));
        self
    }

    /// The DER `TBSCertList` (the bytes that are signed).
    pub fn tbs_der(&self) -> Vec<u8> {
        let mut parts = vec![
            // version INTEGER v2 (1)
            tlv(0x02, &[0x01]),
            seq(&[oid(&self.signature_algorithm)]),
            name(&self.issuer),
            time(self.this_update),
        ];
        if let Some(next) = self.next_update {
            parts.push(time(next));
        }
        if !self.revoked.is_empty() {
            let entries: Vec<Vec<u8>> = self
                .revoked
                .iter()
                .map(|(serial, when)| seq(&[positive_integer(serial), time(*when)]))
                .collect();
            parts.push(seq(&entries));
        }
        seq(&parts)
    }

    /// Build the CRL. `sign` receives the `TBSCertList` bytes.
    pub fn build(&self, sign: impl FnOnce(&[u8]) -> Vec<u8>) -> Vec<u8> {
        let tbs = self.tbs_der();
        let signature = sign(&tbs);
        let sig_alg = seq(&[oid(&self.signature_algorithm)]);
        let sig_value = tlv(0x03, &[&[0u8][..], &signature[..]].concat());
        seq(&[tbs, sig_alg, sig_value])
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_round_trip() {
        for &secs in &[0i64, 951_782_400, 1_704_067_200, 1_792_972_800, 4_102_444_800, -86_400] {
            let (y, m, d, h, mi, s) = civil_from_unix(secs);
            assert_eq!(days_from_civil(y, m, d) * 86_400 + h * 3600 + mi * 60 + s, secs);
        }
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil_from_unix(951_782_400), (2000, 2, 29, 0, 0, 0));
    }

    #[test]
    fn time_uses_utctime_before_2050() {
        assert_eq!(time(1_704_067_200)[0], 0x17);
        assert_eq!(time(2_524_608_000)[0], 0x18);
    }

    #[test]
    fn long_lengths_are_encoded_minimally() {
        let v = tlv(0x04, &[0u8; 300]);
        assert_eq!(&v[..4], &[0x04, 0x82, 0x01, 0x2c]);
    }
}
