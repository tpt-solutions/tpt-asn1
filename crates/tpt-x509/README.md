# tpt-x509

[![crates.io](https://img.shields.io/crates/v/tpt-x509.svg)](https://crates.io/crates/tpt-x509)
[![docs.rs](https://docs.rs/tpt-x509/badge.svg)](https://docs.rs/tpt-x509)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

X.509v3 certificate **parsing**, **validation**, and **RFC 5280 §6.1 chain
building** in pure Rust. `no_std` + `alloc`, `#![forbid(unsafe_code)]`, and
fail-closed on malformed input and unknown critical extensions.

Part of the [`tpt-asn1`](https://github.com/tpt-solutions/tpt-asn1) family,
built on top of [`tpt-asn1-core`](https://crates.io/crates/tpt-asn1-core).

## Why

X.509 is the backbone of TLS and code-signing PKI, yet most Rust tooling either
leans on OpenSSL or ships a partial parser. `tpt-x509` provides a complete,
auditable, `unsafe`-free decoder plus full path validation — and deliberately
delegates all cryptography to a caller-supplied backend, so the parsing crate
carries no C dependencies and no crypto primitives of its own.

## Features

- **`Certificate` / `TBSCertificate` decoding** with raw-DER access to
  `tbsCertificate` for signature verification.
- **`Name` / `RDNSequence`** parsing with RFC 5280 §7.1 normalization-aware
  matching for issuers and subjects.
- **Algorithm recognition** — `AlgorithmIdentifier` plus a PKIX OID registry
  (RSA, EC P-256/384/521, Ed25519, SHA-2, …).
- **`SubjectPublicKeyInfo`** decoding per key algorithm.
- **Validity checks** against a caller-supplied `UnixTime` (no clock in
  `no_std`).
- **Typed extensions** — `BasicConstraints`, `KeyUsage`, `ExtendedKeyUsage`,
  `SubjectAltName` / `IssuerAltName`, `SubjectKeyIdentifier` /
  `AuthorityKeyIdentifier`, `CRLDistributionPoints`, `AuthorityInfoAccess`,
  `CertificatePolicies`, `NameConstraints`, `PolicyConstraints`,
  `InhibitAnyPolicy`.
- **Fail-closed policy** — unknown critical extensions are rejected outright.
- **Pluggable crypto** — a `SignatureVerifier` backend trait keeps all
  signature math in the caller's chosen crate.
- **Path building & validation** — candidate-path construction plus RFC 5280
  §6.1 (signatures, validity, name chaining, basic constraints / path length,
  key usage, policies, name constraints).
- **Revocation parsing** — `CertificateList` (CRL) and OCSP request/response
  parsing and matching.
- **`#![forbid(unsafe_code)]`** and **`#![deny(missing_docs)]`**.

## Installation

```sh
cargo add tpt-x509
```

MSRV: **1.74.0**.

## Quick start

```rust
use tpt_asn1_core::decode;
use tpt_x509::{Certificate, UnixTime};

let der = std::fs::read("cert.der").unwrap();
let cert = decode::<Certificate>(&der).unwrap();

println!("issuer RDNs: {}", cert.issuer().rdns().len());
println!("subject RDNs: {}", cert.subject().rdns().len());
println!(
    "valid at 2024-01-01T00:00:00Z: {}",
    cert.is_valid_at(UnixTime::from_secs(1_704_067_200))
);
```

See a runnable version in [`examples/validate.rs`](examples/validate.rs).

## Cargo features

| Feature | Default | Description                                          |
| ------- | ------- | ---------------------------------------------------- |
| `std`   | yes     | Enables the standard library (implies `alloc`).      |
| `alloc` | yes     | Enables owned types: names, extensions, chain logic. |

The typed name/extension/chain/crl/ocsp modules are gated behind `alloc`.

## Documentation & examples

- rustdoc: <https://docs.rs/tpt-x509>
- Decode & inspect a cert: `cargo run -p tpt-x509 --example validate -- <cert.der>`

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md).

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
