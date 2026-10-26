# tpt-asn1

[![CI](https://github.com/tpt-solutions/tpt-asn1/actions/workflows/ci.yml/badge.svg)](https://github.com/tpt-solutions/tpt-asn1/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

A memory-safe, zero-copy ASN.1 DER/BER/CER codec and X.509 / CMS (PKCS#7)
toolkit in pure Rust, with no C dependencies and no `unsafe` code.

> Not yet published to crates.io. Until it is, depend on it by git or path.

## Crates

| Crate               | What it does                                                          |
| ------------------- | --------------------------------------------------------------------- |
| `tpt-asn1-core`     | DER/BER/CER TLV codec, universal types, `Decode`/`Encode` traits. `no_std`. |
| `tpt-asn1-x509`     | X.509 certificates, CRLs, OCSP, extensions, RFC 5280 §6.1 path checks. `no_std` + `alloc`. |
| `tpt-asn1-cms`      | CMS / PKCS#7 `ContentInfo`, `SignedData`, `EnvelopedData`. `alloc`.   |
| `tpt-asn1-compiler` | `.tpt-asn1` schema DSL to Rust `Decode`/`Encode` code, for `build.rs`. |
| `tpt-asn1-cli`      | `tpt-asn1` binary: `inspect`, `validate`, `text`, `fuzz`, `completions`. |

## Feature matrix

| Area                         | Decode | Encode | Notes |
| ---------------------------- | :----: | :----: | ----- |
| DER/BER/CER TLVs, universal types | yes | yes (core) | Strict DER rules are enforced when the reader is in DER mode. |
| Certificates, TBSCertificate | yes    | no     | Typed extensions for the common RFC 5280 set. |
| CRL (`CertificateList`)      | yes    | no     | Delta CRLs and distribution-point scope are applied in path checks. |
| OCSP request and response    | yes    | no     | Parsing and CertID matching. Responses are not fetched or verified here. |
| RFC 5280 §6.1 path validation | yes   | n/a    | Needs a signature backend (see below). |
| CMS `SignedData`            | yes    | no     | `verify` checks the signature only; it does not establish trust. |
| CMS `EnvelopedData`         | yes    | no     | Decryption is delegated to an `EnvelopeBackend`. |
| Schema DSL codegen          | n/a    | n/a    | Its own grammar, not full ASN.1 modules yet. |
| PEM, PKCS#1/#8/#12 keys      | no     | no     | PEM is available in the CLI only. |

## Status

- **PKITS:** 246 of the 247 generated NIST PKITS subcases pass. The one open case is
  §4.4.19, documented in `todo.md`. The harness is a regression gate: it fails on any
  new failure and on any listed failure that starts passing.
- **Real-world certificates:** a vendored sample of 1,200 TLS leaf certificates is
  checked by a no-panic soak test on every run. An earlier 7,393-certificate run decoded with no panics; it predates the stricter string and time checks, so it should be re-run.
- **No signature backend is bundled.** `SignatureVerifier` (and `EnvelopeBackend`) are
  traits. The PKITS harness uses a test-only RSA and DSA implementation. Use a crate
  such as RustCrypto for production.
- **Not implemented:** certificate and CSR builders, trust-store loading, hostname
  checks, OCSP fetching and response-signature validation, RFC 3161 timestamps,
  PKCS#12, and a derive macro.

Security reports: see [SECURITY.md](SECURITY.md).

## Quick start

Decode a DER TLV with the core crate:

```rust
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_core::tag::Class;

let der = [0x02, 0x01, 0x05]; // INTEGER 5
let mut r = Reader::new(&der, Config::der());
let (tag, _len, value) = r.read_tlv().unwrap();
assert_eq!(tag.class, Class::Universal);
assert_eq!(tag.number, 2); // INTEGER
assert_eq!(value, &[0x05]);
```

Parse a certificate and check its validity period:

```rust
use tpt_asn1_core::decode;
use tpt_asn1_x509::{Certificate, UnixTime};

let der = std::fs::read("leaf.der")?;
let cert = decode::<Certificate>(&der)?;
let valid = cert.is_valid_at(UnixTime::from_secs(1_704_067_200));
```

More runnable examples:

- `cargo run -p tpt-asn1-x509 --example validate -- cert.der`
- `cargo run -p tpt-asn1-x509 --example crl_info -- list.crl`
- `cargo run -p tpt-asn1-x509 --example ocsp_info -- response.der`
- `cargo run -p tpt-asn1-cms --example verify -- message.der`

## Design

- **Zero-copy:** values borrow from the input slice. Parsing allocates only for
  collections (`alloc` feature).
- **Fail closed:** unknown critical extensions, non-canonical DER, malformed time
  and string values, and a malformed extension on a path certificate all return an
  error. They are not skipped.
- **Bounded work:** recursion depth, element size, and the path-search budget are
  capped.
- **No C, no `unsafe`:** every parsing crate has `#![forbid(unsafe_code)]`.

`spec.txt` is the design document, and `todo.md` tracks the roadmap and open items.

## Development

```sh
cargo xtask ci        # fmt, clippy -D warnings, and the test suite
cargo xtask pkits     # the PKITS regression gate
cargo xtask docs      # rustdoc, failing on warnings
cargo xtask deny      # licence, advisory, and source policy (needs cargo-deny)
```

The minimum supported Rust version is 1.81.0, the version pinned in `rust-toolchain.toml`.

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
