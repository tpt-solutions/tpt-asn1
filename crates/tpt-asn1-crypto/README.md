# tpt-asn1-crypto

A [RustCrypto](https://github.com/RustCrypto)-backed signature verifier for
[`tpt-asn1-x509`](../tpt-asn1-x509) and [`tpt-asn1-cms`](../tpt-asn1-cms).

The parsing crates do no cryptography. They call a `SignatureVerifier` supplied by
the caller. This crate provides one:

| Signature algorithm                       | Key                    |
| ----------------------------------------- | ---------------------- |
| RSA PKCS#1 v1.5 with SHA-1, SHA-256, SHA-384, SHA-512 | `rsaEncryption` |
| ECDSA with SHA-256 on P-256, SHA-384 on P-384 | `id-ecPublicKey`    |
| Ed25519 (strict verification)             | `id-Ed25519`           |

Anything else returns `VerifyError::UnsupportedAlgorithm`. A malformed or invalid
signature returns `Ok(false)`.

```rust
use tpt_asn1_crypto::RustCryptoVerifier;

let verifier = RustCryptoVerifier;
// Use `&verifier` as the `SignatureVerifier` in `PathConfig` or in CMS `verify`.
```

## Toolchain

This crate is **not** part of the main workspace. The RustCrypto crates need a newer
toolchain than the 1.81 minimum supported Rust version of the other crates, so it has
its own lockfile. Build and test it with:

```sh
cargo test --manifest-path crates/tpt-asn1-crypto/Cargo.toml
```

It is tested on current stable. It is not covered by the 1.81 MSRV job.

## Scope

- Verification only. Signing is out of scope.
- DSA and RSA-PSS are not supported yet.
- The verifier does not decide trust. Chain building and revocation are still the
  caller's responsibility, through `tpt-asn1-x509`.

## License

MIT OR Apache-2.0.
