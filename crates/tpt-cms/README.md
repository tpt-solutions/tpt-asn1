# tpt-cms

[![crates.io](https://img.shields.io/crates/v/tpt-cms.svg)](https://crates.io/crates/tpt-cms)
[![docs.rs](https://docs.rs/tpt-cms/badge.svg)](https://docs.rs/tpt-cms)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

Cryptographic Message Syntax — **PKCS#7 / CMS (RFC 5652)** — in pure Rust.
Zero-copy, `no_std` + `alloc` parsing and verification, `#![forbid(unsafe_code)]`,
and no C dependencies.

Part of the [`tpt-asn1`](https://github.com/tpt-solutions/tpt-asn1) family,
built on [`tpt-asn1-core`](https://crates.io/crates/tpt-asn1-core) and
[`tpt-x509`](https://crates.io/crates/tpt-x509).

## Why

CMS / PKCS#7 underpins S/MIME, firmware signing, and timestamping. `tpt-cms`
parses and verifies the full `ContentInfo` family without OpenSSL, reusing the
same pluggable `SignatureVerifier` backend as `tpt-x509` so cryptographic
primitive choices stay with the caller.

## Features

- **`ContentInfo` family** — `SignedData`, `EnvelopedData`, `DigestedData`,
  `EncryptedData` parsing (RFC 5652).
- **`SignerInfo`** decoding with signed / unsigned attributes.
- **Signature verification** over `SignedData`, reusing the `tpt-x509`
  `SignatureVerifier` backend (message-digest attribute check, canonical `SET`
  re-encoding).
- **PKCS#7 (RFC 2315) legacy compatibility** detection alongside CMS.
- **`EnvelopedData`** key-transport (RSA) and symmetric content decryption via a
  pluggable `EnvelopeBackend`.
- **Embedded certs / CRLs** — carry `tpt-x509` certificates and CRLs within
  `SignedData`.
- **`#![forbid(unsafe_code)]`** and **`#![deny(missing_docs)]`**.

## Installation

```sh
cargo add tpt-cms
```

MSRV: **1.74.0**.

## Quick start

```rust
use tpt_asn1_core::decode;
use tpt_cms::content_info::ContentInfo;
use tpt_cms::signed_data::SignedData;

let der = std::fs::read("message.der").unwrap();
let ci = decode::<ContentInfo>(&der).unwrap();
println!("content type OID: {:?}", ci.content_type.as_bytes());

let sd = ci.decode_content::<SignedData>().unwrap();
println!("signer infos: {}", sd.signer_infos.len());
```

See a runnable version in [`examples/verify.rs`](examples/verify.rs).

## Cargo features

| Feature | Default | Description                                     |
| ------- | ------- | ----------------------------------------------- |
| `std`   | yes     | Enables the standard library (implies `alloc`). |
| `alloc` | yes     | Enables owned types and CMS decoding/verification. |

## Documentation & examples

- rustdoc: <https://docs.rs/tpt-cms>
- Decode & inspect a CMS message: `cargo run -p tpt-cms --example verify -- <message.der>`

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
