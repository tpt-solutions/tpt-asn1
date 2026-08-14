# Security Policy

## Scope

`tpt-asn1` is a cryptographic PKI toolkit. A memory-safety bug or a parser
confusion vulnerability in the ASN.1 / X.509 / CMS layer can compromise the
security of any system that relies on it. We treat all parser and validation
issues as high priority.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report privately via one of:

- GitHub private vulnerability reporting (Preferred): use the
  *Security → Report a vulnerability* tab on the repository.
- Email: **security@tpt.example** (replace `example` with the real TLD once
  configured). Use our PGP key if available.

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce, including a minimal proof-of-concept input.
- Affected crate(s) and version(s).
- Any suggested mitigation.

## Disclosure process

1. We acknowledge receipt within **3 business days**.
2. We confirm the issue and determine severity within **10 business days**.
3. We develop and test a fix in a private branch.
4. We coordinate a release and public disclosure. We credit reporters unless
   they request anonymity.
5. CVEs are requested as appropriate.

## Hardening guarantees

- `#![forbid(unsafe_code)]` on the core parsing path (acceptance criterion #3).
- Bounded recursion depth and maximum element-size limits to mitigate
  stack-exhaustion and OOM DoS.
- Constant-time comparisons for signature / MAC / tag verification.
- Continuous fuzzing (see `todo.md`, Phase 7) including OSS-Fuzz.

Copyright (c) TPT Solutions.
