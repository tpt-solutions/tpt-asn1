# tpt-asn1 — Project Roadmap

License: MIT OR Apache-2.0 · Copyright TPT Solutions
Release model: single v1.0 (phases below are tracking buckets, not separate published versions)

## Phase 1 — Project Foundation & Governance
- [x] Initialize git repo, `.gitignore`, top-level `README.md`
- [x] Create Cargo workspace (`Cargo.toml` with `[workspace]` members)
- [x] Add `LICENSE-MIT` and `LICENSE-APACHE` (copyright TPT Solutions)
- [x] Set `license = "MIT OR Apache-2.0"` in every crate's `Cargo.toml`
- [x] Add SPDX license header convention for source files
- [x] Write `CONTRIBUTING.md`
- [x] Write `SECURITY.md` (vulnerability disclosure process — important given crypto/PKI scope)
- [x] Write `CODE_OF_CONDUCT.md`
- [x] Decide Rust edition (2021) and MSRV; add `rust-toolchain.toml`
- [x] Add `rustfmt.toml` and `clippy.toml` (deny warnings)
- [x] Scaffold crate skeletons: `tpt-asn1-core`, `tpt-asn1-compiler`, `tpt-x509`, `tpt-cms`, `tpt-cli`
- [x] Set up GitHub Actions CI: build+test matrix (Linux/macOS/Windows × stable/beta/MSRV)
- [x] Add `no_std` target check to CI (e.g. `thumbv7em-none-eabi`) for `tpt-asn1-core`
- [ ] Reserve crates.io namespace for all five crate names (requires crates.io account — manual)
- [x] Add `cargo-deny`/`cargo-audit` CI job (license + advisory scanning)

## Phase 2 — `tpt-asn1-core`: DER/BER/CER TLV Codec (`no_std`, `no_alloc`, zero-copy)
- [x] Design `Tag` type: class (Universal/Application/Context/Private), primitive vs constructed, multi-byte high-tag-number form
- [x] Design `Length` decoding: short-form, long-form definite; reject overlong/non-minimal encodings in DER mode
- [x] Implement indefinite-length support for BER (with end-of-contents octets) and CER (always-indefinite constructed encoding)
- [x] Core zero-copy TLV reader: borrows value bytes as `&[u8]` from the input buffer
- [x] Bounded recursion depth guard for nested constructed types (configurable, sane default)
- [x] Max-element-size guard to reject oversized length claims against remaining buffer (OOM/DoS defense)
- [x] Encoding-rule-specific validation modes: strict DER, lenient BER, canonical CER (incl. CER's 1000-octet string fragmentation rule)
- [x] Universal type decoders: `BOOLEAN`, `INTEGER` (arbitrary precision via byte slice), `BIT STRING` (unused-bits handling), `OCTET STRING`, `NULL`, `OBJECT IDENTIFIER` (arc iterator, no alloc), `RELATIVE-OID`, `ENUMERATED`
- [x] String type decoders: `UTF8String`, `PrintableString`, `IA5String`, `TeletexString`, `BMPString`, `UniversalString`, etc.
- [x] Time type decoders: `UTCTime`, `GeneralizedTime` (with validation of date-time grammar)
- [x] Structured type decoders: `SEQUENCE`/`SEQUENCE OF`, `SET`/`SET OF` (incl. DER canonical sort-order validation for `SET OF`)
- [x] `Any`/deferred-decode wrapper for lazy typed decoding of nested content
- [x] Core `Decode`/`Encode` trait pair (foundational API other crates build on)
- [x] DER canonical encoder (writer into caller-provided buffer, no_alloc-friendly)
- [x] Constant-time byte comparison utility (shared primitive used later by x509/cms)
- [x] Hand-written DER/BER/CER test vectors covering edge cases (empty sequences, max nesting, boundary lengths, high tag numbers)
- [ ] Property-based round-trip tests (`encode(decode(x)) == x`) via `proptest` — deferred: pinned toolchain (1.81) cannot build `getrandom 0.4`; deterministic round-trip matrix in place instead
- [ ] `cargo-fuzz` target: arbitrary bytes must never panic (core parser) — pending Phase 7
- [x] `#![forbid(unsafe_code)]` on the core parsing path
- [ ] Rustdoc for all public API, module-level docs explaining the TLV model (set to `warn` pending Phase 8 promotion to `deny`)

## Phase 3 — `.tpt-asn1` DSL & `tpt-asn1-compiler` (built alongside core)
- [ ] Design DSL grammar: modules, `SEQUENCE`/`CHOICE`/`SET` types, IMPLICIT/EXPLICIT tagging, OPTIONAL/DEFAULT fields
- [ ] Decide DSL delivery form: standalone `.tpt-asn1` schema files + codegen binary (per spec's "compiler → Rust AST" framing)
- [ ] Hand-written lexer/parser for `.tpt-asn1` files (pure-Rust parser combinator, no C deps)
- [ ] AST representation of parsed schema (types, tags, constraints)
- [ ] Code generator: emit Rust structs/enums + `Decode`/`Encode` impls (targeting `tpt-asn1-core` traits)
- [ ] `build.rs` integration path for downstream crates to consume generated code
- [ ] Decide dogfooding scope: whether `tpt-x509`/`tpt-cms` hand-write structs against core traits initially, or generate from DSL from day one
- [ ] `tpt-asn1-compiler` CLI binary: `tpt-asn1-compiler schema.tpt-asn1 -o generated.rs`
- [ ] Round-trip dogfood test: define a known ASN.1 module in the DSL, compile it, confirm it parses real-world data correctly
- [ ] Example schema files + rustdoc for DSL syntax

## Phase 4 — `tpt-x509`: X.509v3 Parsing, Validation, Chain Building (`no_std` + `alloc`)
- [ ] `TBSCertificate` decode: version, serialNumber, signature AlgorithmIdentifier, issuer, validity, subject, SubjectPublicKeyInfo, extensions
- [ ] `Name`/RDNSequence parsing incl. multi-valued RDNs and string-type normalization for comparison (RFC 5280 §7.1)
- [ ] `AlgorithmIdentifier` + OID registry (RSA, ECDSA P-256/384/521, Ed25519, SHA-256/384/512, etc.)
- [ ] `SubjectPublicKeyInfo` decode per key algorithm (RSA, EC point, Ed25519 raw key)
- [ ] Validity period checks (`notBefore`/`notAfter`) against a caller-supplied current time (no clock in `no_std`)
- [ ] Generic `Extension` (oid, critical flag, raw value) framework
- [ ] Typed extension: `BasicConstraints` (CA flag, pathLenConstraint)
- [ ] Typed extension: `KeyUsage` (bitflags)
- [ ] Typed extension: `ExtendedKeyUsage`
- [ ] Typed extension: `SubjectAltName`/`IssuerAltName` (dNSName, iPAddress, rfc822Name, URI, otherName)
- [ ] Typed extension: `SubjectKeyIdentifier`/`AuthorityKeyIdentifier`
- [ ] Typed extension: `CRLDistributionPoints`
- [ ] Typed extension: `AuthorityInfoAccess` (OCSP, CA Issuers)
- [ ] Typed extension: `CertificatePolicies` (+ policy mapping, for PKITS policy tests)
- [ ] Typed extension: `NameConstraints` (permitted/excluded subtrees, for PKITS name-constraint tests)
- [ ] Typed extension: `PolicyConstraints`, `InhibitAnyPolicy`
- [ ] Unknown-critical-extension rejection policy (RFC 5280 fail-closed behavior)
- [ ] Pluggable signature-verification backend trait (delegates crypto math to a chosen backend crate; keeps `tpt-x509` itself free of C deps)
- [ ] Chain building: construct candidate paths from end-entity + intermediates + trust anchors; handle multiple issuers and self-signed detection
- [ ] Path validation algorithm (RFC 5280 §6.1): signature chain, validity, name chaining, basic-constraints path length, key usage enforcement, policy graph processing, name constraints
- [ ] Revocation checking scope decision: CRL (`CertificateList`) parsing + OCSP request/response parsing (parsing/matching only vs. also fetching — decide and scope explicitly)
- [ ] System/bundled trust root loading (for `tpt-asn1 validate --roots system`)
- [ ] Acquire NIST PKITS test vectors; build harness mapping PKITS test groups to test functions
- [ ] Wire PKITS harness into CI as an automated regression gate
- [ ] Acquire Cisco Umbrella Top 1M cert corpus; build no-panic soak test (scheduled/nightly CI job)
- [ ] Unit/integration tests per extension type

## Phase 5 — `tpt-cms`: Cryptographic Message Syntax / PKCS#7 (`no_std` + `alloc`)
- [ ] `ContentInfo`/`SignedData`/`EnvelopedData`/`DigestedData`/`EncryptedData` structures (RFC 5652)
- [ ] `SignerInfo` decode: signed/unsigned attributes, digest + signature algorithms
- [ ] Signature verification over `SignedData` (reuses crypto backend trait from `tpt-x509`)
- [ ] Embed `tpt-x509` certs/CRLs within `SignedData`
- [ ] PKCS#7 (RFC 2315) legacy compatibility detection/handling alongside CMS (RFC 5652)
- [ ] `EnvelopedData`: symmetric content decryption + RSA key transport / ECDH key agreement recipient info
- [ ] Decide scope for RFC 3161 timestamp tokens (optional/stretch — confirm in/out before Phase 5 starts)
- [ ] Test vectors: OpenSSL-generated `smime`/`cms` messages, cross-verified via external `openssl` CLI during test authoring only

## Phase 6 — `tpt-cli`: Command-Line Toolkit
- [x] `tpt-asn1 inspect <file>`: generic DER/BER/CER pretty-printer with PEM auto-detection (incl. `--json`, `--try-der`, `--show-bytes`, `--rule`, `--max-depth`)
- [x] `tpt-asn1 validate <chain.pem>`: structural certificate-chain inspection against `--roots <file>`; full RFC 5280 §6.1 path validation is deferred to `tpt-x509` (Phase 4, not yet integrated) — noted in output
- [x] `tpt-asn1 fuzz <inputs…>`: differential fuzzer diffing `tpt-asn1` against external `openssl asn1parse` (acceptance + element-count), walking files/dirs; warns if OpenSSL absent
- [ ] Byte-for-byte DER output parity test suite vs. OpenSSL (ties to acceptance criteria #4) — blocked on `tpt-asn1-core` DER re-encode round-trip; `fuzz` provides structural differential coverage in the meantime
- [ ] `openssl req`-equivalent: CSR / self-signed cert generation — blocked on pluggable crypto backend + `tpt-x509` (Phase 4/5); `req` subcommand prints a clear "not yet implemented" notice (exit 2)
- [x] `-text`-style human-readable cert dump (`tpt-asn1 text <cert>`); full typed field decoding (issuer/validity/extensions) deferred to `tpt-x509` (Phase 4) — noted in output
- [x] CLI argument parsing (clap, pinned to 4.5.x for the 1.81 MSRV), JSON output mode for scripting, sensible exit codes
- [x] End-to-end CLI snapshot tests (`crates/tpt-cli/tests/cli.rs`, 8 passing)
- [x] `--help` polish (clap derive) and shell completion generation (`completions --shell bash|zsh|fish|powershell`); man pages pending

### Phase 6 prerequisite fixes (unblocking the workspace)
- [x] Added `tpt-x509` / `tpt-cms` to `[workspace.dependencies]` (pre-existing manifest break stopped the whole workspace from loading)
- [x] Added `crates/tpt-x509/src/crypto.rs` stub implementing the pluggable `SignatureBackend` trait (Phase 4 item 75) referenced by `tpt-x509/src/lib.rs`
- [x] Removed pre-existing unused-import warnings in `tpt-asn1-core/src/decode.rs` that would fail CI's `-D warnings` gate

## Phase 7 — Security Hardening & Compliance Gates
- [ ] Enforce `#![forbid(unsafe_code)]` across all parsing crates via CI lint (acceptance criteria #3)
- [ ] Continuous `cargo-fuzz` targets for core, x509, and cms parsers
- [ ] Apply to OSS-Fuzz for ongoing fuzzing infrastructure
- [ ] Constant-time comparison audit across every signature/MAC/tag comparison site
- [ ] Formal gate: full NIST PKITS suite passing (acceptance criteria #1)
- [ ] Formal gate: 100% of Cisco Umbrella Top 1M parsed without panic (acceptance criteria #2)
- [ ] Formal gate: byte-for-byte DER parity vs. OpenSSL across differential suite (acceptance criteria #4)

## Phase 8 — Documentation & v1.0 Release
- [ ] Rustdoc coverage for all public APIs (`#![deny(missing_docs)]`)
- [ ] Architecture guide (README or mdBook): design principles, "why not OpenSSL", crate map
- [ ] Usage examples: parse a cert, validate a chain, verify a CMS signature, generate a CSR
- [ ] `CHANGELOG.md` per crate (Keep a Changelog format)
- [ ] crates.io metadata polish per crate (description, keywords, categories, repo link, readme)
- [ ] README badges: CI status, crates.io version, docs.rs, license
- [ ] Tag and publish v1.0 across all crates; GitHub Release notes mapping to acceptance criteria
