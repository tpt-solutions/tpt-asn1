# tpt-asn1

A memory-safe, **zero-copy** ASN.1 **DER/BER/CER** codec and X.509 / PKCS#7 (CMS)
Public Key Infrastructure toolkit written in pure Rust, with no C dependencies.

> Clean-room implementation. Memory safety without CVE-prone byte munging.

## Why

The internet's cryptographic foundation relies on ASN.1, a 1980s binary format
that has caused critical buffer-overflow CVEs in C/C++ parsers (e.g. OpenSSL).
`tpt-asn1` replaces fragile hand-rolled parsing with a strictly typed, fail-closed
Rust API that rejects malformed certificates at the boundary.

## Crates

| Crate                 | Description                                                        |
| --------------------- | ------------------------------------------------------------------ |
| `tpt-asn1-core`       | Low-level DER/BER/CER tag-length-value (TLV) codec (`no_std`).     |
| `tpt-asn1-compiler`   | Optional `.tpt-asn1` DSL → Rust code generator.                    |
| `tpt-x509`            | X.509v3 certificate parsing, validation, and chain building.       |
| `tpt-cms`             | Cryptographic Message Syntax (PKCS#7) signed/encrypted messages.   |
| `tpt-cli`             | Command-line toolkit (`inspect`, `validate`, …).                   |

## Design principles

- **Zero-copy by default** — parse tags and lengths without allocating, borrowing
  directly from the input buffer (`&[u8]`).
- **Fail-closed security** — malformed lengths, indefinite lengths (in DER), and
  non-canonical encodings are rejected immediately.
- **Type-safe cryptography** — extensions are strongly typed Rust types, not
  opaque byte blobs.
- **`#![forbid(unsafe_code)]`** on the core parsing path.
- **No C dependencies** — pure Rust, portable, auditable.

## Quick start

```rust
use tpt_asn1_core::{decode, Tag, tag::Class};

let der = [0x02, 0x01, 0x05]; // INTEGER 5
let (tag, len, value) = tpt_asn1_core::reader::read_tlv(&der).unwrap();
assert_eq!(tag.class, Class::Universal);
assert_eq!(tag.number, 2); // INTEGER
assert_eq!(value, &[0x05]);
```

See `spec.txt` for the full design document and `todo.md` for the phased roadmap.

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
