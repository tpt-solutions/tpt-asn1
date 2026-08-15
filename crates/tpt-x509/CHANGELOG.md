# Changelog

All notable changes to `tpt-x509` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0]

### Added
- `TBSCertificate` / `Certificate` decoding and `tbsCertificate` raw-DER access.
- `Name` / RDNSequence parsing with RFC 5280 7.1 normalization-aware matching.
- `AlgorithmIdentifier` and a PKIX OID registry (RSA, EC, Ed25519, SHA-2).
- `SubjectPublicKeyInfo` decoding per key algorithm.
- Validity window checks against a caller-supplied `UnixTime`.
- Typed extensions: `BasicConstraints`, `KeyUsage`, `ExtendedKeyUsage`,
  `SubjectAltName`/`IssuerAltName`, `SubjectKeyIdentifier`/
  `AuthorityKeyIdentifier`, `CRLDistributionPoints`, `AuthorityInfoAccess`,
  `CertificatePolicies`, `NameConstraints`, `PolicyConstraints`,
  `InhibitAnyPolicy`.
- Fail-closed unknown-critical-extension rejection.
- Pluggable `SignatureVerifier` backend trait (no C crypto dependencies).
- RFC 5280 6.1 path building and validation (signature, validity, basic
  constraints, key usage, policies, name constraints).
- `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`.
