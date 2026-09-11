#!/bin/bash -eu
# SPDX-License-Identifier: MIT OR Apache-2.0

# OSS-Fuzz build script for tpt-asn1.
#
# Runs inside the OSS-Fuzz builder image (`$SRC` = checked-out repo, `$OUT` =
# directory that must receive the fuzz binaries, `$SANITIZER` = address/undefined/...).
# See: https://google.github.io/oss-fuzz/getting-started/new-project-guide/
#
# This mirrors the `fuzz` job in `.github/workflows/ci.yml`. Every cargo-fuzz
# target is built with the requested sanitizer and copied into `$OUT`.

cd "${SRC}"

# cargo-fuzz links against a sanitizer runtime that is only shipped with the
# nightly toolchain; the OSS-Fuzz Rust base image provides it.
rustup default nightly
rustup component add rust-src

cargo install cargo-fuzz --locked

cd fuzz

FUZZ_TARGETS=(core_tlv core_universal x509_certificate x509_crl x509_ocsp cms_content_info cms_signed_data)
for target in "${FUZZ_TARGETS[@]}"; do
    cargo fuzz build -O --sanitizer "${SANITIZER:-address}" --bin "${target}"
    cp "target/x86_64-unknown-linux-gnu/release/${target}" "${OUT}/${target}"
done