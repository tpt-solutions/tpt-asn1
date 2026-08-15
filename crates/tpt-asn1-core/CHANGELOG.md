# Changelog

All notable changes to `tpt-asn1-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0]

### Added
- Zero-copy ASN.1 `Reader`/`Writer` over `&[u8]` with recursion-depth and
  element-size guards (DoS protection).
- DER/BER/CER parsing strictness selectable via `Config` (`EncodingRule`).
- `read_sequence` / `read_set` / `read_set_of` / `read_sequence_of` structured
  decode helpers and `retag_implicit` for IMPLICIT tagging.
- Core types: `Integer`, `BitString`, `OctetString`, `ObjectIdentifier`,
  `UtcTime`, `GeneralizedTime`, `DateTime`, and the universal string newtypes.
- `Tag`/`Class` model with short-form and high-tag-number encoding.
- `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`.
