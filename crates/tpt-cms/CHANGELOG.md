# Changelog

All notable changes to `tpt-cms` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0]

### Added
- `ContentInfo` / `SignedData` / `EnvelopedData` / `DigestedData` /
  `EncryptedData` parsing (RFC 5652).
- `SignerInfo` decoding with signed/unsigned attributes.
- `SignedData` signature verification reusing the `tpt-x509`
  `SignatureVerifier` backend (message-digest attribute check, canonical SET
  re-encoding).
- PKCS#7 (RFC 2315) legacy compatibility.
- `EnvelopedData` key-transport (RSA) and symmetric content decryption via a
  pluggable `EnvelopeBackend`.
- CRL/CMS certificate embedding helpers.
- `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`.
