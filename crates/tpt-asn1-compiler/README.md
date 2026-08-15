# tpt-asn1-compiler

[![crates.io](https://img.shields.io/crates/v/tpt-asn1-compiler.svg)](https://crates.io/crates/tpt-asn1-compiler)
[![docs.rs](https://docs.rs/tpt-asn1-compiler/badge.svg)](https://docs.rs/tpt-asn1-compiler)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

A **`no_std` + `alloc`** code generator that turns `.tpt-asn1` schema files into
Rust types implementing the `tpt-asn1-core` `Decode` / `Encode` traits. It ships
both a library (for `build.rs` integration) and a standalone CLI binary.

Part of the [`tpt-asn1`](https://github.com/tpt-solutions/tpt-asn1) family of
memory-safe ASN.1 tooling.

## Why

Hand-writing `Decode`/`Encode` impls for large ASN.1 modules (X.509, CMS, …) is
error-prone and boilerplate-heavy. The `.tpt-asn1` DSL lets you describe a module
once; `tpt-asn1-compiler` emits strongly typed, `no_std`-friendly Rust that
reuses the fail-closed `tpt-asn1-core` codec — no C dependencies, no `unsafe`.

## Features

- **`.tpt-asn1` DSL** — modules, `SEQUENCE` / `CHOICE` / `SET` types,
  IMPLICIT / EXPLICIT tagging, and `OPTIONAL` / `DEFAULT` fields.
- **Hand-written lexer & recursive-descent parser** — pure Rust, no generated
  parser tables, no external dependencies.
- **`Decode` / `Encode` emitter** — generates Rust `struct`s / `enum`s with
  trait impls targeting `tpt-asn1-core`.
- **`build.rs`-friendly** — `no_std` + `alloc` so it can run at compile time
  inside downstream build scripts.
- **Standalone CLI** — `tpt-asn1-compiler schema.tpt-asn1 -o generated.rs`.
- **`#![forbid(unsafe_code)]`** and **`#![deny(missing_docs)]`**.

## Installation

```sh
cargo add tpt-asn1-compiler --build
```

MSRV: **1.74.0**.

## Usage

### As a library in `build.rs`

Add to your `Cargo.toml`:

```toml
[build-dependencies]
tpt-asn1-compiler = "0.1"
```

`build.rs`:

```rust
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=schema.tpt-asn1");
    let src = fs::read_to_string("schema.tpt-asn1").unwrap();
    let code = tpt_asn1_compiler::generate(&src).unwrap();
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("schema.rs");
    fs::write(out, code).unwrap();
}
```

Then in `lib.rs`:

```rust
include!(concat!(env!("OUT_DIR"), "/schema.rs"));
```

### As a CLI

```sh
cargo install tpt-asn1-compiler
tpt-asn1-compiler schema.tpt-asn1 -o generated.rs
```

See [`examples/schema.tpt-asn1`](examples/schema.tpt-asn1) and
[`examples/build.rs`](examples/build.rs) for a working setup.

## DSL overview

```tpt-asn1
module BuildTest {
    SimpleSequence ::= SEQUENCE {
        id INTEGER,
        name UTF8String,
        flag BOOLEAN DEFAULT FALSE
    }

    SimpleChoice ::= CHOICE {
        intValue INTEGER,
        strValue IA5String
    }

    Container ::= SEQUENCE {
        seq SimpleSequence,
        choice SimpleChoice OPTIONAL,
        items SEQUENCE OF INTEGER
    }
}
```

A full syntax reference lives in the crate rustdoc.

## Cargo features

| Feature | Default | Description                                     |
| ------- | ------- | ----------------------------------------------- |
| `std`   | yes     | Enables the standard library (implies `alloc`). |
| `alloc` | yes     | Enables owned types used by the code generator. |

## Documentation & examples

- rustdoc: <https://docs.rs/tpt-asn1-compiler>
- Build-script integration: `cargo run -p tpt-asn1-compiler --example build`

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
