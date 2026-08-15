# Changelog

All notable changes to `tpt-cli` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0]

### Added
- `tpt-asn1` CLI with `inspect` (structural tree / JSON / text dump of DER,
  BER/CER, and PEM) and `validate` (X.509 chain validation against supplied
  trust roots).
- `--fuzz` differential subcommand feeding input through the core decoder.
- Shell completion generation via `clap_complete`.
- `#![forbid(unsafe_code)]`.
