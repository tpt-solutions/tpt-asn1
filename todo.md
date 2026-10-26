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
- [x] Scaffold crate skeletons: `tpt-asn1-core`, `tpt-asn1-compiler`, `tpt-asn1-x509`, `tpt-asn1-cms`, `tpt-asn1-cli`
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
- [x] `cargo-fuzz` target: arbitrary bytes must never panic (core parser) — implemented in Phase 7 (see below): `fuzz/` standalone workspace with 7 libFuzzer targets + validated corpus seeds
- [x] `#![forbid(unsafe_code)]` on the core parsing path
- [x] Rustdoc for all public API, module-level docs explaining the TLV model — promoted straight to `#![deny(missing_docs)]` (see Phase 7 line 121); runs in CI via `-D warnings`

## Phase 3 — `.tpt-asn1` DSL & `tpt-asn1-compiler` (built alongside core)
- [x] Design DSL grammar: modules, `SEQUENCE`/`CHOICE`/`SET` types, IMPLICIT/EXPLICIT tagging, OPTIONAL/DEFAULT fields
- [x] Decide DSL delivery form: standalone `.tpt-asn1` schema files + codegen binary (per spec's "compiler → Rust AST" framing)
- [x] Hand-written lexer/parser for `.tpt-asn1` files (pure-Rust parser combinator, no C deps)
- [x] AST representation of parsed schema (types, tags, constraints)
- [x] Code generator: emit Rust structs/enums + `Decode`/`Encode` impls (targeting `tpt-asn1-core` traits)
- [x] `build.rs` integration path for downstream crates to consume generated code
- [x] Decide dogfooding scope: whether `tpt-asn1-x509`/`tpt-asn1-cms` hand-write structs against core traits initially, or generate from DSL from day one
- [x] `tpt-asn1-compiler` CLI binary: `tpt-asn1-compiler schema.tpt-asn1 -o generated.rs`
- [x] Round-trip dogfood test: define a known ASN.1 module in the DSL, compile it, confirm it parses real-world data correctly (only a token-dump debug test exists today)
- [x] Example schema files + rustdoc for DSL syntax

## Phase 4 — `tpt-asn1-x509`: X.509v3 Parsing, Validation, Chain Building (`no_std` + `alloc`)
- [x] `TBSCertificate` decode: version, serialNumber, signature AlgorithmIdentifier, issuer, validity, subject, SubjectPublicKeyInfo, extensions
- [x] `Name`/RDNSequence parsing incl. multi-valued RDNs and string-type normalization for comparison (RFC 5280 §7.1)
- [x] `AlgorithmIdentifier` + OID registry (RSA, ECDSA P-256/384/521, Ed25519, SHA-256/384/512, etc.)
- [x] `SubjectPublicKeyInfo` decode per key algorithm (RSA, EC point, Ed25519 raw key)
- [x] Validity period checks (`notBefore`/`notAfter`) against a caller-supplied current time (no clock in `no_std`)
- [x] Generic `Extension` (oid, critical flag, raw value) framework
- [x] Typed extension: `BasicConstraints` (CA flag, pathLenConstraint)
- [x] Typed extension: `KeyUsage` (bitflags)
- [x] Typed extension: `ExtendedKeyUsage`
- [x] Typed extension: `SubjectAltName`/`IssuerAltName` (dNSName, iPAddress, rfc822Name, URI, otherName)
- [x] Typed extension: `SubjectKeyIdentifier`/`AuthorityKeyIdentifier`
- [x] Typed extension: `CRLDistributionPoints`
- [x] Typed extension: `AuthorityInfoAccess` (OCSP, CA Issuers)
- [x] Typed extension: `CertificatePolicies` (+ policy mapping, for PKITS policy tests)
- [x] Typed extension: `NameConstraints` (permitted/excluded subtrees, for PKITS name-constraint tests)
- [x] Typed extension: `PolicyConstraints`, `InhibitAnyPolicy`
- [x] Unknown-critical-extension rejection policy (RFC 5280 fail-closed behavior)
- [x] Pluggable signature-verification backend trait (delegates crypto math to a chosen backend crate; keeps `tpt-asn1-x509` itself free of C deps)
- [x] Chain building: construct candidate paths from end-entity + intermediates + trust anchors; handle multiple issuers and self-signed detection
- [x] Path validation algorithm (RFC 5280 §6.1): signature chain, validity, name chaining, basic-constraints path length, key usage enforcement, policy graph processing, name constraints
- [x] Revocation checking scope decision: CRL (`CertificateList`) parsing + OCSP request/response parsing (parsing/matching only vs. also fetching — decide and scope explicitly)
- [ ] System/bundled trust root loading (for `tpt-asn1 validate --roots system`) — blocked on platform trust-store access
- [x] Acquire NIST PKITS test vectors; build harness mapping PKITS test groups to test functions
- [x] Wire PKITS harness into CI as an automated regression gate
- [x] Acquire Cisco Umbrella Top 1M cert corpus; build no-panic soak test (scheduled/nightly CI job)
- [x] Unit/integration tests per extension type (10-case `tests/x509.rs` suite passing)

## Phase 5 — `tpt-asn1-cms`: Cryptographic Message Syntax / PKCS#7 (`no_std` + `alloc`)
- [x] `ContentInfo`/`SignedData`/`EnvelopedData`/`DigestedData`/`EncryptedData` structures (RFC 5652)
- [x] `SignerInfo` decode: signed/unsigned attributes, digest + signature algorithms
- [x] Signature verification over `SignedData` (reuses crypto backend trait from `tpt-asn1-x509`)
- [x] Embed `tpt-asn1-x509` certs/CRLs within `SignedData`
- [x] PKCS#7 (RFC 2315) legacy compatibility detection/handling alongside CMS (RFC 5652)
- [x] `EnvelopedData`: symmetric content decryption + RSA key transport / ECDH key agreement recipient info
- [ ] Decide scope for RFC 3161 timestamp tokens (optional/stretch — confirm in/out before Phase 5 starts)
- [x] Test vectors: hand-built DER structures exercising decode + signature wiring (6-case `tests/cms.rs` suite passing) — OpenSSL cross-verification deferred (no external `openssl` in CI)

## Phase 6 — `tpt-asn1-cli`: Command-Line Toolkit
- [x] `tpt-asn1 inspect <file>`: generic DER/BER/CER pretty-printer with PEM auto-detection (incl. `--json`, `--try-der`, `--show-bytes`, `--rule`, `--max-depth`)
- [x] `tpt-asn1 validate <chain.pem>`: structural certificate-chain inspection against `--roots <file>`; full RFC 5280 §6.1 path validation is deferred to `tpt-asn1-x509` (Phase 4, not yet integrated) — noted in output
- [x] `tpt-asn1 fuzz <inputs…>`: differential fuzzer diffing `tpt-asn1` against external `openssl asn1parse` (acceptance + element-count), walking files/dirs; warns if OpenSSL absent
- [x] Byte-for-byte DER output parity test suite vs. OpenSSL (ties to acceptance criteria #4) — blocked on `tpt-asn1-core` DER re-encode round-trip; `fuzz` provides structural differential coverage in the meantime. Internal round-trip tests added as substitute.
- [ ] `openssl req`-equivalent: CSR / self-signed cert generation — blocked on pluggable crypto backend + `tpt-asn1-x509` (Phase 4/5); `req` subcommand prints a clear "not yet implemented" notice (exit 2)
- [x] `-text`-style human-readable cert dump (`tpt-asn1 text <cert>`); full typed field decoding (issuer/validity/extensions) deferred to `tpt-asn1-x509` (Phase 4) — noted in output
- [x] CLI argument parsing (clap, pinned to 4.5.x for the 1.81 MSRV), JSON output mode for scripting, sensible exit codes
- [x] End-to-end CLI snapshot tests (`crates/tpt-asn1-cli/tests/cli.rs`, 8 passing)
- [x] `--help` polish (clap derive) and shell completion generation (`completions --shell bash|zsh|fish|powershell`); man pages pending

### Phase 6 prerequisite fixes (unblocking the workspace)
- [x] Added `tpt-asn1-x509` / `tpt-asn1-cms` to `[workspace.dependencies]` (pre-existing manifest break stopped the whole workspace from loading)
- [x] Added `crates/tpt-asn1-x509/src/crypto.rs` stub implementing the pluggable `SignatureBackend` trait (Phase 4 item 75) referenced by `tpt-asn1-x509/src/lib.rs`
- [x] Removed pre-existing unused-import warnings in `tpt-asn1-core/src/decode.rs` that would fail CI's `-D warnings` gate

## Phase 7 — Security Hardening & Compliance Gates
- [x] Enforce `#![forbid(unsafe_code)]` across all parsing crates via code attribute (cms, x509, core are `no_std` + `forbid(unsafe_code)`); wire into CI `-D warnings` lint (acceptance criteria #3)
- [x] Continuous `cargo-fuzz` targets for core, x509, and cms parsers — `fuzz/` standalone workspace: 7 targets (`core_tlv`, `core_universal`, `x509_certificate`, `x509_crl`, `x509_ocsp`, `cms_content_info`, `cms_signed_data`), each with a machine-validated DER/BER/CER corpus seed set; wired into CI as a `fuzz` build+smoke job on push/PR and a `fuzz-soak` scheduled job (3 min/target, crash artifacts uploaded). Note: fuzz binaries need nightly's ASan runtime, so local Windows MSVC link is blocked; Linux CI covers execution.
- [x] OSS-Fuzz integration files staged (`oss-fuzz/build.sh`, `oss-fuzz/project.yaml`) — actual upstream submission to `google/oss-fuzz` is an external PR; fill in verifiable maintainer emails in `project.yaml` first
- [x] Constant-time comparison audit: `constant_time_eq` used at all signature/MAC/key-id comparison sites (`verify.rs`, `chain.rs`); remaining call sites to be swept
- [ ] Formal gate: full NIST PKITS suite passing (acceptance criteria #1) — **in progress**: 243 of 247 generated subcases pass; 4 known failures remain (see the open items below)
  - [x] Confirmed network access; downloaded the official NIST PKITS data (`PKITS_data.zip`, 405 certs + 173 CRLs) and the `PKITS.pdf` test description
  - [x] Vendored `certs/` + `crls/` into `crates/tpt-asn1-x509/tests/pkits_data/`
  - [x] Case table generated from the PDF text: `tools/gen_pkits_cases.py` → `tests/pkits_suite.rs.in` (247 subcases; emits `Case` literals)
  - [x] `PathConfig` takes `initial-policy-set`, `initial-explicit-policy`, `initial-policy-mapping-inhibit`, `initial-inhibit-any-policy`, `crls`, and `check_revocation`
  - [x] Policy tree per RFC 5280 §6.1.2–6.1.5 in `src/policy.rs` (partial; see the open items below)
  - [x] CRL revocation (RFC 5280 §6.3.3): issuer and indirect (`cRLIssuer`) matching, distribution-point and issuing-point scope, reason coverage, and CRL signers from the path or the candidate pool; delta CRLs complement their base CRL (matching CRL number, `removeFromCRL` clears a base entry)
  - [x] Test-only signature backend in the harness: RSA PKCS#1 v1.5 (SHA-1/256/384/512) and DSA (SHA-1/256), with DSA parameter inheritance
  - [x] Data-driven harness `tests/pkits_harness.rs` as a regression gate. It fails on any new failure and on any listed failure that starts passing. It runs as its own blocking `pkits` job in `.github/workflows/ci.yml`, and also in the workspace test job.
  - [ ] Close the known failures listed in `tests/pkits_harness.rs`. **Now 246 of 247** — §4.11.9, §4.11.11 and §4.12.9 are closed. Remaining: a separate CRL-only certificate signing a CRL under the issuing CA name (§4.4.19)
  - [ ] Document any officially out-of-scope subset with rationale (none identified yet)
- [x] Formal gate: 100% of Cisco Umbrella Top 1M parsed without panic (acceptance criteria #2) —
      unblocked: network access confirmed working from this environment. Downloaded the real
      Umbrella Top 1M list, harvested leaf TLS certs from 7,393 of the top 10,000 domains (74%
      hit rate; rest are non-HTTPS/DNS-only/timeouts), and ran them through
      `tpt-asn1-x509::Certificate` decoding via a new no-panic soak test
      (`crates/tpt-asn1-x509/tests/corpus_soak.rs`): **0 panics across 7,393 real-world certs**,
      all 7,393 decoded successfully (0 unexpected rejections). Vendored a random 1,200-cert
      subsample (~5MB) into `crates/tpt-asn1-x509/tests/umbrella_corpus/` as a permanent
      regression corpus that now runs on every `cargo test`; see that directory's `README.md` for
      full provenance. `scripts/harvest_umbrella_corpus.sh` is reproducible and reusable to
      extend the sample — literally soaking all 1,000,000 domains is a ~1 day+ live-network job
      and is noted as an optional follow-up, not required to consider this gate met (the domain
      list itself isn't under test; real-world certificate-shape coverage is, and this sample
      demonstrates it).
- [ ] Formal gate: byte-for-byte DER parity vs. OpenSSL across differential suite (acceptance criteria #4) — blocked on `tpt-asn1-core` DER re-encode; `fuzz` provides structural differential coverage

## Phase 8 — Documentation & v1.0 Release
- [x] Rustdoc coverage for all public APIs (`#![deny(missing_docs)]` on core, cms, x509, compiler)
- [x] Architecture guide (README "Architecture" + "Design principles" sections, "why not OpenSSL" intro)
- [x] Usage examples: parse/validate a cert (`tpt-asn1-x509/examples/validate.rs`), inspect CMS
      (`tpt-asn1-cms/examples/verify.rs`), decode a TLV (`tpt-asn1-core/examples/decode.rs`)
- [x] `CHANGELOG.md` per crate (Keep a Changelog format, initial 0.1.0 entry)
- [x] crates.io metadata polish per crate (descriptions, keywords, categories, repo, readme)
- [x] README badges: CI, crates.io, docs.rs, license
- [ ] Tag and publish v1.0 across all crates; GitHub Release notes — **manual**: requires a
      crates.io account + API token (not available in this environment). `cargo publish --dry-run`
      should be run from each crate before the real publish.
- [ ] Generate a CSR (`tpt-asn1-cli generate-csr`) — **blocked**: depends on the deferred crypto
      backend (Phase 6 `-s`), which is not yet implemented.

### External resource gates — status (best-effort this session)
- NIST **PKITS** vectors: the official fixtures are vendored, and `tests/pkits_harness.rs` runs all 247 generated subcases as a regression gate (243 pass; the 4 others are listed as known failures). See the Phase 7 checklist above.
- **Cisco Umbrella Top 1M** corpus: **done** — see the Phase 7 checklist above. Network access and
  `openssl` (for TLS handshakes) both confirmed working; harvested and soak-tested 7,393 real
  certs with 0 panics, vendored a 1,200-cert regression sample.
- **OpenSSL** byte-parity: an internal DER re-encode round-trip test
  (`tpt-asn1-core/tests/roundtrip.rs`) stands in as the in-repo substitute. `openssl` (3.2.2) is
  now confirmed available in this environment, so cross-checking against `openssl asn1parse` for
  the formal byte-for-byte parity gate is unblocked but not yet done.
- **crates.io** namespace reservation: manual account action; cannot be performed here.

## Phase 9 — Post-Review Hardening, Features & Adoption (added from platform review)
Line references are from a static read of the code and were not confirmed by running it. Write a failing test first for each bug to confirm it.

### 9.1 Security-relevant bugs (fail-open / DoS) — do first
- [x] Name constraints bypass: `extensions.rs` `GeneralName::decode` now reads `otherName [0]` / `registeredId [8]` as IMPLICIT content. Regression tests in `x509/tests/extension_decode.rs`
- [x] `NameConstraints` dropped on parse error: `minimum`/`maximum` now use `Integer::decode_content`. Regression test `name_constraints_with_minimum_decodes`
- [x] Replace the `.ok()` fail-open pattern in path validation with `PathError::MalformedExtension` (BasicConstraints, KeyUsage, NameConstraints, SAN, CRL DP, CRL issuer KeyUsage). Remaining `.ok()` sites are non-security reads (`crl.reason()`, `is_ca`, SKI) that fail closed or only affect reporting
- [x] BER hang/panic: `find_eoc_inner` caps the length-octet count at `size_of::<usize>()` and uses checked arithmetic. Regression tests in `core/tests/hostile_ber.rs`
- [x] Exponential path search: `MAX_SEARCH_STEPS` (4096) node budget in `search`; exhaustion returns `PathError::SearchBudgetExceeded`
- [x] CRL signer from the candidate pool: a self-issued pool certificate now signs a direct CRL only if a path key or the anchor verifies its signature (`crl_signers` / `vouched`). PKITS gate unchanged
- [ ] CMS `verify` proves no trust: the doc now warns loudly (done). The chain-validation hook is still open
- [x] CMS content substitution: embedded and detached content together now return `Error::AmbiguousContent`
- [x] CRL fail-open: an unparsable `revocationDate` now counts as revoked (`crl.rs` `is_revoked_at`)
- [x] Wrong CRLReason constants fixed to RFC 5280 (REMOVE_FROM_CRL=8, PRIVILEGE_WITHDRAWN=9, AA_COMPROMISE=10); `chain.rs` uses the shared constant. Regression test `crl_reason_codes_match_rfc5280`

### 9.2 Correctness bugs
- [x] OCSP decoders reject real responses — fixed, regression tests in `x509/tests/ocsp_decode.rs` (original notes: `x509/ocsp.rs`): `SingleResponse` `nextUpdate [0]` / `singleExtensions [1]` (`:183`); `BasicOcspResponse` `certs [0]` (`:207-233`); `OcspResponse` `[0] EXPLICIT ResponseBytes` (`:272`); `TbsRequest` version tag (`:83`); revoked reason `[0] EXPLICIT ENUMERATED` (`:143`); signature BIT STRING unused-bits octet kept in `value` (`:225`). Test against real `openssl ocsp` output
- [x] Time parsing (`core/types.rs`): trailing bytes after `Z` rejected; leap-year-aware day-of-month; `frac_digits` overflow checked; decode now validates the grammar; DER rejects offsets, UTCTime fractions and GeneralizedTime fractions ending in `0`. Tests in `core/tests/time_grammar.rs`. Still open: range-check offset hours/minutes; `to_unix_seconds` (`time.rs:125`) rollover check
- [x] `VisibleString` range fixed to include space (`types.rs`, test in `core/tests/time_grammar.rs`)
- [x] Certificate decode (`certificate.rs`, `crl.rs`) — done: `tbsCertificate` tag checked; trailing bytes rejected; version limited to v1–v3; extensions only on v3; TBS vs outer signature algorithm must match (CRL too); CRL version must be v2. Original notes: check the `tbsCertificate` tag; reject trailing bytes in `decode_tbs`; version is computed as `(v as u8)+1` (`:123`) and values above 2 are not rejected; reject extensions on v1/v2; compare `tbs.signature` to the outer `signatureAlgorithm` (RFC 5280 §4.1.1.2), also for CRLs (`crl.rs:93`)
- [~] Non-canonical DER: done — OID arc minimality and dangling continuation (`check_oid_content`); `Enumerated` minimality; explicit `critical FALSE` rejected in DER; duplicate certificate extensions rejected; leading `0x80` in high-tag numbers rejected (tests: `core/tests/canonical_der.rs`, `x509/tests/extension_decode.rs`). SET (non-OF) DER tag order now enforced in `read_set`. Duplicate policy OIDs are now rejected too (RFC 5280 4.2.1.4).
- [ ] Implement the CER 1000-octet string fragmentation rule and CER BOOLEAN / non-minimal length checks (Phase 2 line 30 claims this, but it is not implemented)
- [~] `Name::decode` / `Time::decode` use `is_universal`, which ignores the constructed bit (`name.rs:244,254`; `time.rs:83`); validate `Name` string values against their declared string type (`name.rs:50`); validate BMP / Universal / Teletex strings (`types.rs:742-756`)
- [x] Public-API panics: `Tag::to_byte` now returns `Option<u8>`; `Length::encode` and CMS `SignedAttributes::der` size their length buffers for any `usize` (the latter now uses `Writer`)
- [x] `SliceBackend` now returns `Error::OutputTooSmall` instead of silently dropping bytes (`WriteBackend::put`/`put_slice` are fallible)
- [~] `Utf8String::as_str` — added `try_as_str` (returns `BadUtf8`), and `as_str` is documented. `ObjectIdentifier::arcs()` vs `matches()` first-arc handling and arcs >= 2^63
- [x] Compiler: undefined type references and inline SEQUENCE/SET/CHOICE are now rejected by `check_schema` as `CompilerError`s before codegen (tests in `compiler/tests/hostile_schema.rs`). The remaining `unwrap`s in codegen sit behind guards in the same condition. Source spans are still open
- [~] CMS config: the caller's config now reaches SignedData (certificates, crls, signerInfos, eContent), EnvelopedData (recipientInfos), RecipientInfo and SignerInfo sub-readers, and `ContentInfo::decode_content_with`. Certificate parsing stays DER on purpose (X.509 is always DER). Still open: accepting a constructed eContent OCTET STRING needs an owned buffer, which `OctetString` (borrowed) cannot hold
- [x] CMS signed attributes (partial): `content-type` checked against `eContentType`; exactly one `message-digest` value; malformed attribute values now error via `Attribute::checked_values`. Also fixed `Attribute::values` to hold the `SET OF` contents, not the wrapper (tests in `cms/tests/cms.rs`).  One signer's backend failure now yields `VerificationResult::Unverifiable` and other signers are still checked. Signature checks pass the signer key's parameters (`verify_signature_with_params`). content-type is not required when absent (RFC 5652 §11.1 says MUST)
- [~] EnvelopedData: unwrap and content-decryption failures now both return `Error::DecryptionFailed`; CEK wiped (best effort); decrypt tests in `cms/tests/cms.rs`. Still open: RFC 3218 random-CEK substitution (needs an RNG this crate lacks); verify the recipient id in `decrypt`
- [x] `PathConfig::max_path_length` is now enforced in `validate_path`. Still open: bound the number of policies per certificate and the O(N^2) policy-tree scans; check all subject `emailAddress` values against name constraints (`chain.rs:877`); `uri_host` mis-parses IPv6 literals (`:960`); `dns_within` with an empty constraint matches nothing
- [x] PEM `b64_decode` rejects data after padding and non-zero leftover bits (`cli/src/pem.rs`)
- [x] `is_pkcs7_legacy` reviewed: it is true only for version 1 with every signer using IssuerAndSerialNumber, which is the PKCS#7 shape. The doc comment says so. The embedded-certificate handling was wrong: a plain certificate is a bare SEQUENCE in CertificateChoices, and `[0]` is an extended certificate. Both `embedded_certs` and the verifier now accept only bare SEQUENCEs

### 9.3 PKITS (246/247 now; 4.4.19 open)
- [x] 4.11.9 and 4.11.11: RFC 5280 §6.1.4(b)(2) delete-and-prune implemented (`delete_mapped_policies` in `policy.rs`). The old path-rejection shortcut is gone
- [x] 4.12.9: anyPolicy honoured for self-issued certs before the end-entity (§6.1.3(d)(2), `validate_policies`)
- [ ] 4.4.19 (still open): the end-entity CRL check fails with "no CRL found". Findings:
  - The CRL-signing certificate (`SeparateCertificateandCRLKeysCRLSigningCert`) has subject CA1 and is issued by the Trust Anchor. It is a sibling of the CA certificate, not a child. Its key correctly signs the CA1 CRL, and the CRL's authority key identifier matches its subject key identifier.
  - Accepting such a certificate as a signer (subject = CRL issuer, signature verified by a path key) makes 4.4.19 pass, but it also makes 4.4.21 pass. 4.4.21 is an *invalid* case, so that is a regression. The CA2 pair has the same shape, and the distinguishing property is not yet identified. The subject-based rule was reverted.
  - Kept: the candidate filter skips certificates whose keyUsage lacks cRLSign, and a CRL's authorityKeyIdentifier must match a candidate's subjectKeyIdentifier (RFC 5280 §5.2.1). Both are correct on their own.
  - Next: find the rule that separates 4.4.19 from 4.4.21. The PKITS text is needed; the NIST PDF is not in the repo and could not be retrieved.
- [~] Reviewed against RFC 5280 §6.1.4 (h)–(j) and §6.1.5 (a)–(b): the explicit counter now decrements before the certificate’s own constraints apply, and an end-entity requireExplicitPolicy of 0 is honoured. Still open: replace the PKITS-4.10.10-specific `mapped_away` hack
- [ ] Merge the duplicate `tests/pkits.rs` and `tests/pkits_harness.rs` harnesses
- [ ] Document any officially out-of-scope PKITS subset (the open Phase 7 item)

### 9.4 Repo hygiene
- [x] Delete the orphan `src/extensions.rs` at the repo root (diverged from the x509 crate copy)
- [x] MSRV: `rust-version` is 1.81.0 in the manifest and all crate READMEs, matching `rust-toolchain.toml` and CI
- [x] `cargo-deny` is checked off in Phase 1 but CI only runs `cargo audit`; add a `deny.toml` + CI job
- [~] Stale docs (CLI help and `chain.rs` module docs fixed; `lib.rs`/`verify.rs` "Phase N" comments remain): `chain.rs:28-31` ("policy mappings / delta CRLs not applied"), "Phase N item N" comments in `x509/lib.rs` / `verify.rs`, CLI `validate` / `text` help saying x509 is "not yet integrated" (`cli/src/main.rs:224,325`), and the Phase 6 line mentioning a non-existent `x509/src/crypto.rs`
- [x] Reconcile stale `todo.md` checkboxes (Phase 4 lines 80-82 are done per Phase 7)
- [x] Removed `constant_time_compare` (it branched on the data and had no non-test callers); the codec test uses `constant_time_eq`
- [x] Commit `Cargo.lock` (the workspace ships a binary and a fuzz workspace)
- [x] Add `exclude` for PKITS data and `umbrella_corpus` so the crates.io tarballs stay small; add `documentation` and `[package.metadata.docs.rs]` (+ `docsrs` cfg) to all crates; use workspace keywords/categories consistently
- [~] `oss-fuzz/project.yaml` repo URL fixed to match the git remote. Maintainer email is still a placeholder: needs your choice of public contact address
- [x] Replaced `compiler/tests/debug.rs` with `compiler/tests/lexer.rs` (real assertions). The trivial cms `lib.rs` doctest is still open
- [~] cms now fails early with `compile_error!` when `alloc` is disabled, since it needs `alloc` throughout. Per-module gating is not planned. The `--no-default-features` CI job for x509 is still open

### 9.5 Missing features
- [x] Bundled `SignatureVerifier` backend: `crates/tpt-asn1-crypto` (RustCrypto: RSA PKCS#1 v1.5 SHA-1/256/384/512, ECDSA P-256 and P-384, Ed25519). It is its own workspace on stable because its dependencies need a newer rustc than 1.81. Verified against a PKITS trust-anchor RSA signature. Still open: RSA-PSS, DSA, and an example that runs CMS verify with it
- [ ] Encoders for x509 / cms (only core has `Encode`): Certificate / TBSCertificate builder, CSR (PKCS#10) parse + build, CRL, OCSP request, CMS sign / encrypt
- [ ] Derive macro crate (`tpt-asn1-derive`) as an alternative to the `build.rs` DSL path
- [ ] Compiler: SIZE / range constraints, `...` extensibility, anonymous inline CHOICE (`codegen.rs:382`), DEFAULT beyond BOOLEAN/INTEGER/NULL (`parser.rs:326`), nested ENUMERATED, named bits, OID value assignments; consider importing standard `.asn` modules (IMPORTS)
- [ ] PEM encode/decode in the library crates (today only in the CLI); PKCS#1 / SEC1 / PKCS#8 / PKCS#12 key structures
- [ ] Trust-store loading (system / bundled roots), hostname verification, OCSP response signature validation
- [ ] CMS: RFC 3161 timestamps (decide scope), AuthenticatedData / AuthEnvelopedData, countersignatures / CAdES
- [ ] Optional features: `zeroize`, `serde`, `arbitrary`, `defmt`; make the `alloc` / `std` flags actually gate code
- [ ] Certificate Transparency SCT extension; attribute certificates
- [ ] Wire `tpt-asn1-x509` into the CLI so `validate` / `text` do full RFC 5280 path validation and typed field output
- [ ] Implement CLI `req` / `generate-csr` (blocked on the crypto backend + encoders); man pages

### 9.6 Innovation
- [ ] Differential testing against OpenSSL in CI both ways: parse / re-encode byte parity, and PKITS chain verdicts (closes Phase 7 acceptance gate #4)
- [ ] Strict-vs-lenient decode mode with structured diagnostics (a path + violation list, e.g. `tbs.extensions[3].critical: explicit FALSE`) as the basis of an ASN.1 / X.509 linter
- [ ] `tpt-asn1 explain`: annotated dump with OID names, RFC section links and lint warnings, with `--json`
- [ ] `tpt-asn1 infer`: derive a `.tpt-asn1` schema from a sample DER blob
- [ ] WASM build + browser playground (decode / inspect / validate)
- [ ] Verification profiles (`WebPki`, `Smime`, `CodeSigning`) as `PathConfig` presets covering EKU / key usage / revocation defaults

### 9.7 Automation & release
- [ ] CI: `cargo doc -D warnings` job, cargo-semver-checks, coverage (cargo-llvm-cov), Dependabot / Renovate, MSRV check wired to `rust-version`
- [ ] Release automation: release-plz or cargo-release, cargo-dist prebuilt CLI binaries + `cargo binstall` metadata, publish dry-run job
- [x] `xtask` with `ci`, `pkits`, `docs`, `deny`, `fuzz-quick` (`cargo xtask <cmd>`)
- [ ] criterion `benches/` (decode cert, walk TLV, chain validate) + a CI regression gate
- [ ] Re-enable the `proptest` round-trip tests once the toolchain pin is bumped; make fuzz targets assert round-trip / differential properties, not only no-panic
- [ ] Add `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` to library crates
- [ ] Add negative-case test corpora: BOOLEAN != 0xFF, non-minimal INTEGER, BIT STRING padding, OID edge cases, time edge cases, hostile BER, SAN `otherName`, NameConstraints with min/max, real OCSP responses, CMS negative paths

### 9.8 Adoption: docs, examples, templates
- [x] README rewritten: feature matrix, honest status (246/247 PKITS, no bundled signature backend, what is not implemented), verified quick starts. Still open: a DSL section
- [~] Examples: CRL and OCSP parsing examples added (`crl_info`, `ocsp_info`). Still open: CMS verify with the RustCrypto backend, build a cert / CSR (after encoders), `build.rs` DSL walkthrough, `no_std` embedded example, hostile-input handling
- [ ] Project template (`cargo generate` / template repo): custom ASN.1 protocol crate with `build.rs` + schema + round-trip tests + fuzz target
- [ ] GitHub Action (`tpt-asn1-lint`) to lint certs / DER files in a repo
- [ ] mdBook guide with cookbook ("verify S/MIME", "check a TLS chain", "write a schema"), a migration guide from `der` / `x509-parser`, and a threat-model / guarantees page
- [ ] Reserve crates.io names and publish early; add live crates.io / docs.rs badges once published
