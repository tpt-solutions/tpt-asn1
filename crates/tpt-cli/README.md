# tpt-cli

[![crates.io](https://img.shields.io/crates/v/tpt-cli.svg)](https://crates.io/crates/tpt-cli)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

The command-line ASN.1 / X.509 / CMS toolkit — `tpt-asn1`. A `clap`-based binary
for inspecting, validating, and fuzzing ASN.1 structures, backed entirely by the
memory-safe [`tpt-asn1`](https://github.com/tpt-solutions/tpt-asn1) crates.

## Why

A drop-in, dependency-light companion to `openssl asn1parse` and
`openssl x509 -text` that is written in pure Rust with `#![forbid(unsafe_code)]`
— useful for triaging certificates and CMS blobs, diffing against OpenSSL, and
generating shell completions.

## Subcommands

| Command        | Status | Description                                                          |
| -------------- | ------ | -------------------------------------------------------------------- |
| `inspect`      | ✅     | Pretty-print DER/BER/CER (and PEM) as a tree or JSON, with PEM auto-detection. |
| `text`         | ✅     | Human-readable, `openssl x509 -text`-style cert dump (structural).   |
| `validate`     | ✅     | Structural X.509 chain inspection against supplied trust roots.       |
| `fuzz`         | ✅     | Differential fuzzer feeding inputs through the core decoder (and optionally OpenSSL). |
| `completions`  | ✅     | Generate shell completions (bash / zsh / fish / powershell).         |
| `req`          | ⏳     | CSR / self-signed cert generation — pending the crypto backend.       |

> `inspect`, `text`, and `fuzz` perform full typed decoding on the wire format.
> `validate` currently performs structural checks; full RFC 5280 §6.1 path
> validation is wired up in `tpt-x509` and will be integrated here.

## Installation

```sh
cargo install tpt-cli
```

Or build from the workspace:

```sh
cargo build -p tpt-cli --release
```

MSRV: **1.74.0**.

## Usage

```sh
# Inspect a DER or PEM file as an indented tree
tpt-asn1 inspect cert.der

# Emit JSON instead of text
tpt-asn1 inspect cert.pem --json

# Re-parse OCTET/BIT STRING contents as embedded DER
tpt-asn1 inspect blob.der --try-der --show-bytes --max-depth 32

# Human-readable cert dump
tpt-asn1 text cert.pem

# Structural chain inspection against trust roots
tpt-asn1 validate chain.pem --roots roots.pem

# Differential fuzz a directory of inputs against OpenSSL
tpt-asn1 fuzz ./corpus --require-openssl

# Generate completions
tpt-asn1 completions --shell zsh
```

### `inspect` options

- `--rule <der|ber|cer>` — encoding rule driving the parser (default `der`).
- `--json` — emit a JSON document instead of indented text.
- `--max-depth <n>` — max recursion depth before a constructed value is shown raw.
- `--try-der` — re-parse OCTET STRING / BIT STRING contents as embedded DER.
- `--show-bytes` — show full hex for primitive values instead of a preview.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

Copyright (c) TPT Solutions.
