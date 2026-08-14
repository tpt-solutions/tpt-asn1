// SPDX-License-Identifier: MIT OR Apache-2.0

//! X.509v3 certificate extensions.
//!
//! Parsing is *fail-closed*: an unrecognized `critical` extension causes
//! `Extension::decode` (via [`Extensions::from_content`]) to return
//! [`Error::UnknownCriticalExtension`], matching RFC 5280 §4.2.

use alloc::vec::Vec;

use tpt_asn1_core::any::Any;
use tpt_asn1_core::decode::{read_sequence, Decode};
use tpt_asn1_core::error::{Error, Result};
use tpt_asn1_core::reader::Reader;
use tpt_asn1_core::tag::Tag;
use tpt_asn1_core::types::{BitString, Boolean, Integer, ObjectIdentifier, OctetString};

use crate::name::Name;
use crate::oid;

/// A single certificate extension: `SEQUENCE { extnID OID, critical BOOLEAN
/// DEFAULT FALSE, extnValue OCTET STRING }`.
///
/// `extn_value` holds the *inner* DER of the extension value (i.e. the content
/// of the `OCTET STRING`), ready to be decoded by the typed accessors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extension<'a> {
    /// The extension OID.
    pub extn_id: ObjectIdentifier<'a>,
    /// Whether the extension is marked critical.
    pub critical: bool,
    /// The DER-encoded extension value.
    pub extn_value: &'a [u8],
}

impl<'a> Extension<'a> {
    /// Returns `true` if this extension's OID equals `expected`.
    pub fn is(&self, expected: oid::Oid) -> bool {
        oid::oid_eq(&self.extn_id, expected)
    }

    /// Decode the extension value as `T`.
    pub fn decode_value<T: Decode<'a>>(&self) -> Result<T> {
        crate::decode::<T>(self.extn_value)
    }
}

/// The set of extensions carried by a `TBSCertificate`.
#[derive(Debug, PartialEq, Eq)]
pub struct Extensions<'a> {
    list: Vec<Extension<'a>>,
}

impl<'a> Extensions<'a> {
    /// An empty extension set.
    pub fn empty() -> Self {
        Extensions { list: Vec::new() }
    }

    /// Decode `Extensions` from the `SEQUENCE OF Extension` body (the content of
    /// the `extensions` context-[3] field). Critically-unknown extensions fail
    /// closed.
    pub fn from_content(content: &'a [u8], config: crate::reader::Config) -> Result<Self> {
        let mut r = Reader::new(content, config);
        let mut list = Vec::new();
        while !r.is_empty() {
            let ext = Extension::decode(&mut r)?;
            if ext.critical && !is_known_extension(&ext.extn_id) {
                return Err(Error::UnknownCriticalExtension);
            }
            list.push(ext);
        }
        Ok(Extensions { list })
    }

    /// Number of extensions.
    pub fn len(&self) -> usize {
        self.list.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Iterate the extensions.
    pub fn iter(&self) -> core::slice::Iter<'_, Extension<'a>> {
        self.list.iter()
    }

    /// Find the first extension with the given OID.
    pub fn find(&self, oid: oid::Oid) -> Option<&Extension<'a>> {
        self.list.iter().find(|e| e.is(oid))
    }

    /// Decode the [`BasicConstraints`] extension, if present.
    pub fn basic_constraints(&self) -> Result<Option<BasicConstraints>> {
        self.find(oid::ext::BASIC_CONSTRAINTS)
            .map(|e| e.decode_value())
            .transpose()
    }

    /// Decode the [`KeyUsage`] extension, if present.
    pub fn key_usage(&self) -> Result<Option<KeyUsage<'a>>> {
        self.find(oid::ext::KEY_USAGE)
            .map(|e| e.decode_value())
            .transpose()
    }

    /// Decode the [`ExtendedKeyUsage`] extension, if present.
    pub fn extended_key_usage(&self) -> Result<Option<ExtendedKeyUsage<'a>>> {
        self.find(oid::ext::EXT_KEY_USAGE)
            .map(|e| e.decode_value())
            .transpose()
    }

    /// Decode the [`SubjectAltName`], if present.
    pub fn subject_alt_name(&self) -> Result<Option<GeneralNames<'a>>> {
        self.find(oid::ext::SUBJECT_ALT_NAME)
            .map(|e| e.decode_value())
            .transpose()
    }

    /// Decode the [`IssuerAltName`], if present.
    pub fn issuer_alt_name(&self) -> Result<Option<GeneralNames<'a>>> {
        self.find(oid::ext::ISSUER_ALT_NAME)
            .map(|e| e.decode_value())
            .transpose()
    }

    /// Decode the [`SubjectKeyIdentifier`], if present.
    pub fn subject_key_identifier(&self) -> Result<Option<SubjectKeyIdentifier<'a>>> {
        self.find(oid::ext::SUBJECT_KEY_IDENTIFIER)
            .map(|e| e.decode_value())
            .transpose()
    }

    /// Decode the [`AuthorityKeyIdentifier`], if present.
    pub fn authority_key_identifier(&self) -> Result<Option<AuthorityKeyIdentifier<'a>>> {
        self.find(oid::ext::AUTHORITY_KEY_IDENTIFIER)
            .map(|e| e.decode_value())
            .transpose()
    }

    /// Decode the [`CrlDistributionPoints`], if present.
    pub fn crl_distribution_points(&self) -> Result<Option<CrlDistributionPoints<'a>>> {
        self.find(oid::ext::CRL_DISTRIBUTION_POINTS)
            .map(|e| e.decode_value())
            .transpose()
    }

    /// Decode the [`AuthorityInfoAccess`], if present.
    pub fn authority_info_access(&self) -> Result<Option<AuthorityInfoAccess<'a>>> {
        self.find(oid::ext::AUTHORITY_INFO_ACCESS)
            .map(|e| e.decode_value())
            .transpose()
    }

    /// Decode the [`CertificatePolicies`], if present.
    pub fn certificate_policies(&self) -> Result<Option<CertificatePolicies<'a>>> {
        self.find(oid::ext::CERTIFICATE_POLICIES)
            .map(|e| e.decode_value())
            .transpose()
    }

    /// Decode the [`NameConstraints`], if present.
    pub fn name_constraints(&self) -> Result<Option<NameConstraints<'a>>> {
        self.find(oid::ext::NAME_CONSTRAINTS)
            .map(|e| e.decode_value())
            .transpose()
    }

    /// Decode the [`PolicyConstraints`], if present.
    pub fn policy_constraints(&self) -> Result<Option<PolicyConstraints>> {
        self.find(oid::ext::POLICY_CONSTRAINTS)
            .map(|e| e.decode_value())
            .transpose()
    }

    /// Decode the [`InhibitAnyPolicy`], if present.
    pub fn inhibit_any_policy(&self) -> Result<Option<InhibitAnyPolicy>> {
        self.find(oid::ext::INHIBIT_ANY_POLICY)
            .map(|e| e.decode_value())
            .transpose()
    }
}

impl<'a> Decode<'a> for Extension<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let extn_id = ObjectIdentifier::decode(inner)?;
            // `critical` is DEFAULT FALSE and absent when false (DER).
            let (critical, extn_value_bytes) = if !inner.is_empty() {
                let any = Any::decode(inner)?;
                if any.tag.is_universal(Tag::BOOLEAN) {
                    let b = any.decode_as::<Boolean>()?.0;
                    let value_any = Any::decode(inner)?;
                    (b, value_any.decode_as::<OctetString>()?.0)
                } else {
                    (false, any.decode_as::<OctetString>()?.0)
                }
            } else {
                return Err(Error::TrailingData);
            };
            Ok(Extension { extn_id, critical, extn_value: extn_value_bytes })
        })
    }
}

/// Returns `true` if `oid` is a recognized extension (so a critical instance is
/// safe to process rather than reject).
pub fn is_known_extension(oid: &ObjectIdentifier<'_>) -> bool {
    oid::oid_in(
        oid,
        &[
            oid::ext::BASIC_CONSTRAINTS,
            oid::ext::KEY_USAGE,
            oid::ext::EXT_KEY_USAGE,
            oid::ext::SUBJECT_ALT_NAME,
            oid::ext::ISSUER_ALT_NAME,
            oid::ext::SUBJECT_KEY_IDENTIFIER,
            oid::ext::AUTHORITY_KEY_IDENTIFIER,
            oid::ext::CRL_DISTRIBUTION_POINTS,
            oid::ext::AUTHORITY_INFO_ACCESS,
            oid::ext::CERTIFICATE_POLICIES,
            oid::ext::POLICY_CONSTRAINTS,
            oid::ext::NAME_CONSTRAINTS,
            oid::ext::INHIBIT_ANY_POLICY,
            oid::ext::FRESHEST_CRL,
            oid::ext::CRL_NUMBER,
            oid::ext::DELTA_CRL_INDICATOR,
            oid::ext::ISSUING_DISTRIBUTION_POINT,
        ],
    )
}

// --- BasicConstraints -----------------------------------------------------

/// `BasicConstraints` — `SEQUENCE { cA BOOLEAN DEFAULT FALSE,
/// pathLenConstraint INTEGER (0..MAX) OPTIONAL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BasicConstraints {
    /// Whether the subject is a CA.
    pub ca: bool,
    /// Maximum number of non-self-issued intermediate certs that may follow.
    pub path_len_constraint: Option<u64>,
}

impl<'a> Decode<'a> for BasicConstraints {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let ca = if !inner.is_empty()
                && inner.peek_tag() == Ok(Tag::universal(Tag::BOOLEAN))
            {
                Boolean::decode(inner)?.0
            } else {
                false
            };
            let path_len_constraint = if !inner.is_empty() {
                Some(
                    Integer::decode(inner)?
                        .as_u64()
                        .ok_or(Error::Custom("pathLenConstraint too large"))?,
                )
            } else {
                None
            };
            Ok(BasicConstraints { ca, path_len_constraint })
        })
    }
}

// --- KeyUsage --------------------------------------------------------------

/// Key-usage bit positions (per RFC 5280 §4.2.1.3, bit 0 = most significant).
pub mod key_usage_bit {
    /// `digitalSignature` (bit 0).
    pub const DIGITAL_SIGNATURE: u8 = 0;
    /// `nonRepudiation` (bit 1).
    pub const NON_REPUDIATION: u8 = 1;
    /// `keyEncipherment` (bit 2).
    pub const KEY_ENCIPHERMENT: u8 = 2;
    /// `dataEncipherment` (bit 3).
    pub const DATA_ENCIPHERMENT: u8 = 3;
    /// `keyAgreement` (bit 4).
    pub const KEY_AGREEMENT: u8 = 4;
    /// `keyCertSign` (bit 5).
    pub const KEY_CERT_SIGN: u8 = 5;
    /// `cRLSign` (bit 6).
    pub const CRL_SIGN: u8 = 6;
    /// `encipherOnly` (bit 7).
    pub const ENCIPHER_ONLY: u8 = 7;
    /// `decipherOnly` (bit 8).
    pub const DECIPHER_ONLY: u8 = 8;
}

/// `KeyUsage` — a `BIT STRING`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyUsage<'a> {
    bits: BitString<'a>,
}

impl<'a> KeyUsage<'a> {
    /// The raw `BIT STRING`.
    pub fn as_bit_string(&self) -> BitString<'a> {
        self.bits
    }

    /// Returns `true` if `bit` (0 = most significant) is set.
    pub fn is_set(&self, bit: u8) -> bool {
        let byte = (bit / 8) as usize;
        let bit_in_byte = 7 - (bit % 8);
        match self.bits.data.get(byte) {
            Some(b) => (b & (1u8 << bit_in_byte)) != 0,
            None => false,
        }
    }
}

impl<'a> Decode<'a> for KeyUsage<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(KeyUsage { bits: BitString::decode(r)? })
    }
}

// --- ExtendedKeyUsage -----------------------------------------------------

/// `ExtendedKeyUsage` — `SEQUENCE OF KeyPurposeId`.
#[derive(Debug, PartialEq, Eq)]
pub struct ExtendedKeyUsage<'a> {
    /// The key-purpose OIDs.
    pub purposes: Vec<ObjectIdentifier<'a>>,
}

impl<'a> ExtendedKeyUsage<'a> {
    /// Returns `true` if the given purpose OID is present.
    pub fn contains(&self, purpose: oid::Oid) -> bool {
        self.purposes.iter().any(|p| oid::oid_eq(p, purpose))
    }

    /// Returns `true` if `id-kp-serverAuth` is present.
    pub fn allows_tls_server(&self) -> bool {
        self.contains(oid::eku::SERVER_AUTH)
    }
}

impl<'a> Decode<'a> for ExtendedKeyUsage<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let mut purposes = Vec::new();
            while !inner.is_empty() {
                purposes.push(ObjectIdentifier::decode(inner)?);
            }
            Ok(ExtendedKeyUsage { purposes })
        })
    }
}

// --- GeneralName / GeneralNames -------------------------------------------

/// A `GeneralName` (RFC 5280 §4.2.1.6). Only the commonly exercised members are
/// decoded into structured form; exotic members are retained as raw bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeneralName<'a> {
    /// `[0] EXPLICIT otherName` (type OID + value).
    OtherName {
        /// The other-name type OID.
        type_id: ObjectIdentifier<'a>,
        /// The (undecoded) value.
        value: Any<'a>,
    },
    /// `[1] rfc822Name` (email address).
    Rfc822Name(&'a [u8]),
    /// `[2] dNSName`.
    DnsName(&'a [u8]),
    /// `[4] EXPLICIT directoryName`.
    DirectoryName(Name<'a>),
    /// `[6] uniformResourceIdentifier`.
    Uri(&'a [u8]),
    /// `[7] iPAddress` (4 or 16 raw octets).
    IpAddress(&'a [u8]),
    /// `[8] registeredID`.
    RegisteredId(ObjectIdentifier<'a>),
    /// Any other GeneralName form, preserved verbatim.
    Other {
        /// The context tag number.
        tag_number: u32,
        /// The raw value bytes.
        bytes: &'a [u8],
    },
}

impl<'a> GeneralName<'a> {
    /// The DNS-name bytes, if this is a `dNSName`.
    pub fn dns(&self) -> Option<&'a [u8]> {
        match self {
            GeneralName::DnsName(b) => Some(b),
            _ => None,
        }
    }

    /// The URI bytes, if this is a `uniformResourceIdentifier`.
    pub fn uri(&self) -> Option<&'a [u8]> {
        match self {
            GeneralName::Uri(b) => Some(b),
            _ => None,
        }
    }
}

impl<'a> Decode<'a> for GeneralName<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let any = Any::decode(r)?;
        let t = any.tag;
        if t == Tag::context(true, 0) {
            let mut sub = Reader::new(any.value, *r.config());
            let (type_id, value) = read_sequence(&mut sub, |s| {
                let type_id = ObjectIdentifier::decode(s)?;
                let value = Any::decode(s)?;
                Ok((type_id, value))
            })?;
            Ok(GeneralName::OtherName { type_id, value })
        } else if t == Tag::context(false, 1) {
            Ok(GeneralName::Rfc822Name(any.value))
        } else if t == Tag::context(false, 2) {
            Ok(GeneralName::DnsName(any.value))
        } else if t == Tag::context(true, 4) {
            let mut sub = Reader::new(any.value, *r.config());
            let name = Name::decode(&mut sub)?;
            Ok(GeneralName::DirectoryName(name))
        } else if t == Tag::context(false, 6) {
            Ok(GeneralName::Uri(any.value))
        } else if t == Tag::context(false, 7) {
            Ok(GeneralName::IpAddress(any.value))
        } else if t == Tag::context(false, 8) {
            let mut sub = Reader::new(any.value, *r.config());
            Ok(GeneralName::RegisteredId(ObjectIdentifier::decode(&mut sub)?))
        } else {
            Ok(GeneralName::Other { tag_number: t.number, bytes: any.value })
        }
    }
}

/// `GeneralNames` — `SEQUENCE OF GeneralName`.
#[derive(Debug, PartialEq, Eq)]
pub struct GeneralNames<'a> {
    /// The names.
    pub names: Vec<GeneralName<'a>>,
}

impl<'a> GeneralNames<'a> {
    /// Iterate the names.
    pub fn iter(&self) -> core::slice::Iter<'_, GeneralName<'a>> {
        self.names.iter()
    }
}

impl<'a> Decode<'a> for GeneralNames<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let mut names = Vec::new();
            while !inner.is_empty() {
                names.push(GeneralName::decode(inner)?);
            }
            Ok(GeneralNames { names })
        })
    }
}

// --- SubjectKeyIdentifier / AuthorityKeyIdentifier -------------------------

/// `SubjectKeyIdentifier` — `OCTET STRING`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubjectKeyIdentifier<'a>(pub &'a [u8]);

impl<'a> SubjectKeyIdentifier<'a> {
    /// The key identifier bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

impl<'a> Decode<'a> for SubjectKeyIdentifier<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(SubjectKeyIdentifier(OctetString::decode(r)?.0))
    }
}

/// `AuthorityKeyIdentifier` — `SEQUENCE { keyIdentifier [0] IMPLICIT OCTET
/// STRING OPTIONAL, authorityCertIssuer [1] IMPLICIT GeneralNames OPTIONAL,
/// authorityCertSerialNumber [2] IMPLICIT INTEGER OPTIONAL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityKeyIdentifier<'a> {
    /// The key identifier (matches a `SubjectKeyIdentifier`), if present.
    pub key_identifier: Option<&'a [u8]>,
    /// The authority cert serial number, if present.
    pub authority_cert_serial: Option<Integer<'a>>,
}

impl<'a> Decode<'a> for AuthorityKeyIdentifier<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let mut key_identifier = None;
            let mut authority_cert_serial = None;
            while !inner.is_empty() {
                let any = Any::decode(inner)?;
                if any.tag == Tag::context(false, 0) {
                    key_identifier = Some(any.value);
                } else if any.tag == Tag::context(false, 2) {
                    let mut sub = Reader::new(any.value, *inner.config());
                    authority_cert_serial = Some(Integer::decode(&mut sub)?);
                }
                // authorityCertIssuer [1] is decoded but not retained here.
            }
            Ok(AuthorityKeyIdentifier { key_identifier, authority_cert_serial })
        })
    }
}

// --- CRLDistributionPoints ------------------------------------------------

/// `DistributionPoint` (subset: full-name distribution points).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistributionPoint<'a> {
    /// The `fullName` (if present).
    pub full_name: Option<GeneralNames<'a>>,
    /// The CRL issuer (if present).
    pub crl_issuer: Option<GeneralNames<'a>>,
}

impl<'a> DistributionPoint<'a> {
    /// The distribution-point URIs (from `fullName`), if any.
    pub fn uris(&self) -> impl Iterator<Item = &'a [u8]> {
        self.full_name
            .iter()
            .flat_map(|g| g.names.iter())
            .filter_map(|n| n.uri())
    }
}

/// `CRLDistributionPoints` — `SEQUENCE SIZE (1..MAX) OF DistributionPoint`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrlDistributionPoints<'a> {
    /// The distribution points.
    pub points: Vec<DistributionPoint<'a>>,
}

impl<'a> Decode<'a> for CrlDistributionPoints<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let mut points = Vec::new();
            while !inner.is_empty() {
                let dp_any = Any::decode(inner)?;
                let mut sub = Reader::new(dp_any.value, *r.config());
                let (full_name, crl_issuer) = read_sequence(&mut sub, |dp| {
                    let mut full_name = None;
                    let mut crl_issuer = None;
                    while !dp.is_empty() {
                        let field = Any::decode(dp)?;
                        if field.tag == Tag::context(true, 0) {
                            // [0] EXPLICIT DistributionPointName -> fullName [0]
                            let mut fn_sub = Reader::new(field.value, *dp.config());
                            let fn_any = Any::decode(&mut fn_sub)?;
                            if fn_any.tag == Tag::context(true, 0)
                                || fn_any.tag == Tag::context(false, 0)
                            {
                                let mut g = Reader::new(fn_any.value, *dp.config());
                                full_name = Some(GeneralNames::decode(&mut g)?);
                            }
                        } else if field.tag == Tag::context(true, 2) {
                            let mut g = Reader::new(field.value, *dp.config());
                            crl_issuer = Some(GeneralNames::decode(&mut g)?);
                        }
                    }
                    Ok((full_name, crl_issuer))
                })?;
                points.push(DistributionPoint { full_name, crl_issuer });
            }
            Ok(CrlDistributionPoints { points })
        })
    }
}

// --- AuthorityInfoAccess --------------------------------------------------

/// `AccessDescription` — `SEQUENCE { accessMethod OID, accessLocation GeneralName }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessDescription<'a> {
    /// The access method OID (e.g. OCSP or CA Issuers).
    pub access_method: ObjectIdentifier<'a>,
    /// The access location.
    pub access_location: GeneralName<'a>,
}

/// `AuthorityInfoAccess` — `SEQUENCE OF AccessDescription`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityInfoAccess<'a> {
    /// The descriptions.
    pub descriptions: Vec<AccessDescription<'a>>,
}

impl<'a> AuthorityInfoAccess<'a> {
    /// URIs whose access method is `id-ad-ocsp`.
    pub fn ocsp_uris(&self) -> impl Iterator<Item = &'a [u8]> {
        self.descriptions
            .iter()
            .filter(|d| oid::oid_eq(&d.access_method, oid::pkix::AD_OCSP))
            .filter_map(|d| d.access_location.uri())
    }

    /// URIs whose access method is `id-ad-caIssuers`.
    pub fn ca_issuers_uris(&self) -> impl Iterator<Item = &'a [u8]> {
        self.descriptions
            .iter()
            .filter(|d| oid::oid_eq(&d.access_method, oid::pkix::AD_CA_ISSUERS))
            .filter_map(|d| d.access_location.uri())
    }
}

impl<'a> Decode<'a> for AuthorityInfoAccess<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let mut descriptions = Vec::new();
            while !inner.is_empty() {
                let desc = read_sequence(inner, |d| {
                    let access_method = ObjectIdentifier::decode(d)?;
                    let access_location = GeneralName::decode(d)?;
                    Ok(AccessDescription { access_method, access_location })
                })?;
                descriptions.push(desc);
            }
            Ok(AuthorityInfoAccess { descriptions })
        })
    }
}

// --- CertificatePolicies --------------------------------------------------

/// `PolicyQualifierInfo` — `SEQUENCE { policyQualifierId OID, qualifier ANY }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyQualifierInfo<'a> {
    /// The qualifier OID.
    pub qualifier_id: ObjectIdentifier<'a>,
    /// The (undecoded) qualifier value.
    pub qualifier: Any<'a>,
}

/// `PolicyInformation` — `SEQUENCE { policyIdentifier OID, policyQualifiers
/// SEQUENCE OF PolicyQualifierInfo OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyInformation<'a> {
    /// The policy OID.
    pub policy_id: ObjectIdentifier<'a>,
    /// Any policy qualifiers.
    pub qualifiers: Vec<PolicyQualifierInfo<'a>>,
}

/// `CertificatePolicies` — `SEQUENCE OF PolicyInformation`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificatePolicies<'a> {
    /// The policies.
    pub policies: Vec<PolicyInformation<'a>>,
}

impl<'a> CertificatePolicies<'a> {
    /// Returns `true` if `anyPolicy` is asserted.
    pub fn has_any_policy(&self) -> bool {
        self.policies.iter().any(|p| oid::oid_eq(&p.policy_id, oid::pkix::ANY_POLICY))
    }
}

impl<'a> Decode<'a> for CertificatePolicies<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let mut policies = Vec::new();
            while !inner.is_empty() {
                let info = read_sequence(inner, |p| {
                    let policy_id = ObjectIdentifier::decode(p)?;
                    let mut qualifiers = Vec::new();
                    if !p.is_empty() {
                        read_sequence(p, |q| {
                            while !q.is_empty() {
                                let qinfo = read_sequence(q, |qi| {
                                    let qualifier_id = ObjectIdentifier::decode(qi)?;
                                    let qualifier = Any::decode(qi)?;
                                    Ok(PolicyQualifierInfo { qualifier_id, qualifier })
                                })?;
                                qualifiers.push(qinfo);
                            }
                            Ok(())
                        })?;
                    }
                    Ok(PolicyInformation { policy_id, qualifiers })
                })?;
                policies.push(info);
            }
            Ok(CertificatePolicies { policies })
        })
    }
}

// --- NameConstraints ------------------------------------------------------

/// `GeneralSubtree` — `SEQUENCE { base GeneralName, minimum [0] DEFAULT 0,
/// maximum [1] OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneralSubtree<'a> {
    /// The base name.
    pub base: GeneralName<'a>,
    /// The minimum base distance (default 0).
    pub minimum: u64,
    /// The maximum base distance, if present.
    pub maximum: Option<u64>,
}

/// `NameConstraints` — `SEQUENCE { permittedSubtrees [0] OPTIONAL,
/// excludedSubtrees [1] OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameConstraints<'a> {
    /// Permitted subtrees.
    pub permitted: Vec<GeneralSubtree<'a>>,
    /// Excluded subtrees.
    pub excluded: Vec<GeneralSubtree<'a>>,
}

impl<'a> Decode<'a> for NameConstraints<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let mut permitted = Vec::new();
            let mut excluded = Vec::new();
            while !inner.is_empty() {
                let field = Any::decode(inner)?;
                if field.tag == Tag::context(true, 0) {
                    permitted = decode_subtrees(field.value, *inner.config())?;
                } else if field.tag == Tag::context(true, 1) {
                    excluded = decode_subtrees(field.value, *inner.config())?;
                }
            }
            Ok(NameConstraints { permitted, excluded })
        })
    }
}

fn decode_subtrees<'a>(content: &'a [u8], config: crate::reader::Config) -> Result<Vec<GeneralSubtree<'a>>> {
    let mut r = Reader::new(content, config);
    let mut out = Vec::new();
    while !r.is_empty() {
        let st_any = Any::decode(&mut r)?;
        let mut sub = Reader::new(st_any.value, config);
        let subtree = read_sequence(&mut sub, |st| {
            let base = GeneralName::decode(st)?;
            let mut minimum = 0u64;
            let mut maximum = None;
            while !st.is_empty() {
                let f = Any::decode(st)?;
                if f.tag == Tag::context(false, 0) {
                    let mut mr = Reader::new(f.value, config);
                    minimum = Integer::decode(&mut mr)?
                        .as_u64()
                        .ok_or(Error::Custom("minimum too large"))?;
                } else if f.tag == Tag::context(false, 1) {
                    let mut mr = Reader::new(f.value, config);
                    maximum = Some(
                        Integer::decode(&mut mr)?
                            .as_u64()
                            .ok_or(Error::Custom("maximum too large"))?,
                    );
                }
            }
            Ok(GeneralSubtree { base, minimum, maximum })
        })?;
        out.push(subtree);
    }
    Ok(out)
}

// --- PolicyConstraints / InhibitAnyPolicy ----------------------------------

/// `PolicyConstraints` — `SEQUENCE { requireExplicitPolicy [0] OPTIONAL,
/// inhibitPolicyMapping [1] OPTIONAL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyConstraints {
    /// `requireExplicitPolicy` skip-certs, if present.
    pub require_explicit_policy: Option<u64>,
    /// `inhibitPolicyMapping` skip-certs, if present.
    pub inhibit_policy_mapping: Option<u64>,
}

impl<'a> Decode<'a> for PolicyConstraints {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        read_sequence(r, |inner| {
            let mut require_explicit_policy = None;
            let mut inhibit_policy_mapping = None;
            while !inner.is_empty() {
                let f = Any::decode(inner)?;
                let mut vr = Reader::new(f.value, *inner.config());
                let v = Integer::decode(&mut vr)?
                    .as_u64()
                    .ok_or(Error::Custom("policy constraint too large"))?;
                if f.tag == Tag::context(false, 0) {
                    require_explicit_policy = Some(v);
                } else if f.tag == Tag::context(false, 1) {
                    inhibit_policy_mapping = Some(v);
                }
            }
            Ok(PolicyConstraints { require_explicit_policy, inhibit_policy_mapping })
        })
    }
}

/// `InhibitAnyPolicy` — `INTEGER (0..MAX)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InhibitAnyPolicy {
    /// The skip-certs value.
    pub skip_certs: u64,
}

impl<'a> Decode<'a> for InhibitAnyPolicy {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(InhibitAnyPolicy {
            skip_certs: Integer::decode(r)?
                .as_u64()
                .ok_or(Error::Custom("inhibitAnyPolicy too large"))?,
        })
    }
}
