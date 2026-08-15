# tpt-asn1-core

[![crates.io](https://img.shields.io/crates/v/tpt-asn1-core.svg)](https://crates.io/crates/tpt-asn1-core)
[![docs.rs](https://docs.rs/tpt-asn1-core/badge.svg)](https://docs.rs/tpt-asn1-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

A zero-copy, `no_std` + `no_alloc`-capable ASN.1 **DER / BER / CER**
tag-length-value (TLV) codec in pure Rust, with no C dependencies and a
fail-closed security posture.

This is the foundational crate of the `tpt-asn1` family. Higher-level crates
(`tpt-x509`, `tpt-cms`, `tpt-asn1-compiler`) build directly on the `Decode` /
`Encode` traits and the `Reader` / `Writer` primitives defined here.

## Why

ASN.1 parsers in C/C++ have a long history of memory-safety CVEs (OpenSSL,
among others). `tpt-asn1-core` is `#![forbid(unsafe_code)]` on the entire
parsing path and borrows directly from the input buffer (`&[u8]`) instead of
copying or allocating, so there is no allocator-driven attack surface and no
unsafe pointer arithmetic to get wrong.

## Features

- **Zero-copy by default** — parse tags, lengths, and values without allocating,
  borrowing straight from the input slice.
- **`no_std` / `no_alloc`** — runs on bare-metal and embedded targets; `alloc`
  is an optional feature for callers that want owned types.
- **Three encoding rules** — strict **DER**, lenient **BER**, and canonical
  **CER**, selectable per `Reader` via an `EncodingRule`.
- **Fail-closed parsing** — non-minimal (overlong) length encodings, indefinite
  lengths (in DER), and `SET OF` ordering violations are rejected immediately.
- **DoS defenses** — configurable recursion-depth guard for nested constructed
  types and an element-size guard that rejects length claims larger than the
  remaining buffer.
- **Universal, string, and time types** — `INTEGER`, `BIT STRING`, `OCTET
  STRING`, `OBJECT IDENTIFIER`, `RELATIVE-OID`, `ENUMERATED`, `BOOLEAN`, `NULL`,
  the universal string newtypes, `UTCTime`, `GeneralizedTime`, and structured
  `SEQUENCE` / `SET` / `SEQUENCE OF` / `SET OF` decoding.
- **Constant-time helpers** — shared primitives for safe byte comparison used by
  the higher-level crypto crates.
- **`#![forbid(unsafe_code)]`** and **`#![deny(missing_docs)]`** — fully
  documented, auditable, unsafe-free code.

## Installation

```sh
cargo add tpt-asn1-core
```

Minimum Supported Rust Version (MSRV): **1.74.0**.

## Quick start

Decode a single TLV, or a typed value, directly from a byte slice:

```rust
use tpt_asn1_core::{decode, tag::Class};

// Raw TLV view:
let der = [0x02, 0x01, 0x05]; // INTEGER 5
let (tag, len, value) = tpt_asn1_core::reader::read_tlv(&der).unwrap();
assert_eq!(tag.class, Class::Universal);
assert_eq!(tag.number, 2); // INTEGER
assert_eq!(value, &[0x05]);

// Typed decode (requires the `alloc` feature):
let n = tpt_asn1_core::types::Integer::decode(
    &mut tpt_asn1_core::reader::Reader::new(&der, tpt_asn1_core::reader::Config::der()),
).unwrap();
assert_eq!(n.as_slice(), &[0x05]);
```

Decode a whole document with strict DER, rejecting trailing bytes:

```rust
use tpt_asn1_core::decode;

let der = [/* …a DER-encoded document… */];
let doc: tpt_asn1_core::Any = decode(&der).unwrap();
```

See a runnable version in [`examples/decode.rs`](examples/decode.rs).

## Cargo features

| Feature   | Default | Description                                        |
| --------- | ------- | -------------------------------------------------- |
| `std`     | yes     | Enables the standard library (implies `alloc`).    |
| `alloc`   | yes     | Enables owned types and the `Decode`/`Encode` API. |

On `no_std` targets without an allocator, build with
`--no-default-features` to get the allocation-free decoding helpers.

## Documentation & examples

- Module-level rustdoc: <https://docs.rs/tpt-asn1-core>
- Decode a raw TLV: `cargo run -p tpt-asn1-core --example decode`

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
