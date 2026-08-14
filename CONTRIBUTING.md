# Contributing to tpt-asn1

Thanks for your interest in contributing! This document describes how to get
started and the conventions we follow.

## Getting started

1. Fork and clone the repository.
2. Install the pinned toolchain: `rustup show` (reads `rust-toolchain.toml`).
3. Build and test: `cargo build --workspace` and `cargo test --workspace`.
4. Run the linters before opening a PR:
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo test --workspace`

## Code conventions

- **Edition 2021**, MSRV **1.74.0** (see `rust-toolchain.toml`).
- **No `unsafe` in the parsing path.** `tpt-asn1-core`, `tpt-x509`, and `tpt-cms`
  must compile with `#![forbid(unsafe_code)]`.
- Every source file must begin with the SPDX license header:
  ```rust
  // SPDX-License-Identifier: MIT OR Apache-2.0
  ```
- Document all public API items. We aim for `#![deny(missing_docs)]`.
- Prefer `#![no_std]` + `#[cfg(feature = "alloc")]` for the core/x509/cms crates.

## Commit / PR guidelines

- Keep commits focused and write descriptive messages.
- Add tests for new functionality, including malformed-input and edge cases.
- Fuzz targets are welcome under `fuzz/`; run `cargo +nightly fuzz run <target>`.

## Code of conduct

This project adheres to the [Code of Conduct](CODE_OF_CONDUCT.md). By
participating, you are expected to uphold it.

## Security

Found a vulnerability? **Do not open a public issue.** Follow the process in
[SECURITY.md](SECURITY.md).
