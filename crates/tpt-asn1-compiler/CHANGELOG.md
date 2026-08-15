# Changelog

All notable changes to `tpt-asn1-compiler` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0]

### Added
- `.tpt-asn1` schema language: modules, `SEQUENCE`/`CHOICE`/`SET` types,
  IMPLICIT/EXPLICIT tagging, OPTIONAL/DEFAULT fields.
- Hand-written lexer and recursive-descent parser producing an `ast::Schema`.
- Code generator emitting Rust structs/enums with `Decode`/`Encode` impls
  targeting the `tpt-asn1-core` traits.
- `tpt-asn1-compiler` CLI: `schema.tpt-asn1 -o generated.rs`.
- Example schema (`examples/example.tpt-asn1`) and rustdoc syntax reference.
- `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`.
