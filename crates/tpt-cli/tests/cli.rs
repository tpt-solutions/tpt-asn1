// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end CLI snapshot tests for `tpt-asn1`.

use std::io::Write;
use std::process::Command;

/// Path to the compiled `tpt-asn1` binary, provided by Cargo.
fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tpt-asn1"))
}

/// Write `bytes` to a uniquely-named temp file; returns its path.
fn write_temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("tpt-cli-test-{}-{}.bin", name, std::process::id()));
    let mut f = std::fs::File::create(&path).expect("create temp file");
    f.write_all(bytes).expect("write temp file");
    path
}

/// SEQUENCE { INTEGER 5, OCTET STRING aa bb }
const SAMPLE_DER: &[u8] = &[0x30, 0x07, 0x02, 0x01, 0x05, 0x04, 0x02, 0xaa, 0xbb];

/// X.509 `Certificate` shape: SEQUENCE { SEQUENCE, SEQUENCE, BIT STRING }
const CERT_DER: &[u8] = &[0x30, 0x07, 0x30, 0x00, 0x30, 0x00, 0x03, 0x01, 0x00];

#[test]
fn inspect_text_shows_structure() {
    let path = write_temp("inspect", SAMPLE_DER);
    let out = bin().arg("inspect").arg(&path).output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("SEQUENCE"), "expected SEQUENCE, got:\n{stdout}");
    assert!(stdout.contains("INTEGER"), "expected INTEGER, got:\n{stdout}");
    assert!(stdout.contains("OCTET STRING"), "expected OCTET STRING, got:\n{stdout}");
    std::fs::remove_file(&path).ok();
}

#[test]
fn inspect_json_contains_fields() {
    let path = write_temp("json", SAMPLE_DER);
    let out = bin().arg("inspect").arg(&path).arg("--json").output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("\"tag\":\"INTEGER\""), "json missing INTEGER tag:\n{stdout}");
    assert!(
        stdout.contains("\"summary\":\"5 (05)\""),
        "json missing INTEGER summary:\n{stdout}"
    );
    assert!(stdout.contains("\"tag\":\"SEQUENCE\""), "json missing SEQUENCE tag:\n{stdout}");
    std::fs::remove_file(&path).ok();
}

#[test]
fn inspect_pem_autodetect() {
    let der = SAMPLE_DER;
    let b64 = base64_encode(der);
    let pem = format!("-----BEGIN TESTDATA-----\n{b64}\n-----END TESTDATA-----\n");
    let mut path = std::env::temp_dir();
    path.push(format!("tpt-cli-test-pem-{}.pem", std::process::id()));
    std::fs::write(&path, pem).unwrap();
    let out = bin().arg("inspect").arg(&path).output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("SEQUENCE"), "PEM not decoded, got:\n{stdout}");
    std::fs::remove_file(&path).ok();
}

#[test]
fn inspect_try_der_unwraps_embedded() {
    // OCTET STRING wrapping INTEGER 7.
    let embedded = [0x04u8, 0x03, 0x02, 0x01, 0x07];
    let path = write_temp("tryder", &embedded);
    let out = bin()
        .arg("inspect")
        .arg(&path)
        .arg("--try-der")
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("embedded DER"),
        "expected embedded DER unwrap, got:\n{stdout}"
    );
    assert!(stdout.contains("INTEGER"), "embedded INTEGER not shown:\n{stdout}");
    std::fs::remove_file(&path).ok();
}

#[test]
fn validate_structural_cert() {
    let path = write_temp("validate", CERT_DER);
    let out = bin().arg("validate").arg(&path).output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("OK"), "expected OK, got:\n{stdout}");
    assert_eq!(out.status.code(), Some(0), "validate should exit 0");
    std::fs::remove_file(&path).ok();
}

#[test]
fn validate_rejects_non_cert() {
    // A bare INTEGER is not a Certificate.
    let path = write_temp("badcert", &[0x02, 0x01, 0x05]);
    let out = bin().arg("validate").arg(&path).output().unwrap();
    assert_ne!(out.status.code(), Some(0), "validate should fail on non-cert");
    std::fs::remove_file(&path).ok();
}

#[test]
fn fuzz_runs_without_panic() {
    let path = write_temp("fuzz", SAMPLE_DER);
    let out = bin().arg("fuzz").arg(&path).output().unwrap();
    let combined = String::from_utf8_lossy(&out.stdout);
    // Either OpenSSL is present (checks performed) or it is absent (warning).
    assert!(
        combined.contains("checked") || combined.contains("warning"),
        "unexpected fuzz output:\n{combined}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn completions_emits_script() {
    let out = bin().arg("completions").arg("--shell").arg("bash").output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("_tpt-asn1"), "completion script missing:\n{stdout}");
}

/// Minimal standard-base64 encoder (no padding needed for our short inputs).
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3f) as usize] as char);
        }
    }
    out
}
