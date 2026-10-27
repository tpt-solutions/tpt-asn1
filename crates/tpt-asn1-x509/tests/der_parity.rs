//! Byte-for-byte DER parity against OpenSSL (Phase 7 acceptance criteria #4).
//!
//! For each certificate in the vendored corpora this test:
//!
//! 1. re-encodes the DER with `tpt-asn1-core`'s generic TLV reader and writer
//!    (tag, length and content are re-emitted; nothing is interpreted), and
//! 2. runs the same bytes through `openssl x509 -inform DER -outform DER`, and
//! 3. asserts that the two outputs are identical.
//!
//! Both outputs equal the input for canonical DER, so a mismatch means one of
//! the two encoders produced something other than the input. Each mismatch is
//! reported with the first differing offset.
//!
//! The OpenSSL step needs an `openssl` binary on `PATH`. If none is found the
//! test prints a notice and returns without failing, so `cargo test` stays
//! green on machines without OpenSSL. CI should install it so the gate runs.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use tpt_asn1_core::length::Length;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_core::writer::{VecBackend, Writer};

/// Re-emit a DER byte string through the core TLV reader and writer.
fn reencode(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Writer::new_vec();
    let mut r = Reader::new(input, Config::der());
    while !r.is_empty() {
        encode_tlv(&mut r, &mut out)?;
    }
    Ok(out.into_vec())
}

/// Read one TLV from `r` and write it to `w`, recursing into constructed values.
fn encode_tlv(r: &mut Reader<'_>, w: &mut Writer<VecBackend>) -> Result<(), String> {
    let (tag, _len, value) = r.read_tlv().map_err(|e| format!("{e:?}"))?;
    if tag.constructed {
        let mut inner = Writer::new_vec();
        let mut ir = Reader::new(value, Config::der());
        while !ir.is_empty() {
            encode_tlv(&mut ir, &mut inner)?;
        }
        let bytes = inner.into_vec();
        w.write_tag(tag).map_err(|e| format!("{e:?}"))?;
        w.write_length(Length::Definite(bytes.len())).map_err(|e| format!("{e:?}"))?;
        w.write_bytes(&bytes).map_err(|e| format!("{e:?}"))?;
    } else {
        w.write_primitive(tag, value).map_err(|e| format!("{e:?}"))?;
    }
    Ok(())
}

/// Run `der` through `openssl x509` and return its DER output.
/// Returns `None` if `openssl` cannot be run or rejects the input.
///
/// Files are used instead of stdin pipes: the Windows build of OpenSSL
/// reports "Could not find certificate from <stdin>" for piped DER.
fn openssl_reencode(der: &[u8], scratch: &Path) -> Option<Vec<u8>> {
    let input = scratch.join("in.der");
    let output = scratch.join("out.der");
    fs::write(&input, der).ok()?;
    let status = Command::new("openssl")
        .args(["x509", "-inform", "DER", "-outform", "DER", "-in"])
        .arg(&input)
        .arg("-out")
        .arg(&output)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    if status.success() {
        fs::read(&output).ok()
    } else {
        None
    }
}

fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    a.iter()
        .zip(b.iter())
        .position(|(x, y)| x != y)
        .or_else(|| (a.len() != b.len()).then(|| a.len().min(b.len())))
}

fn der_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "der" || x == "crt"))
            .collect(),
        Err(_) => Vec::new(),
    };
    files.sort();
    files
}

/// Check one directory of DER certificates. Returns the number of files checked.
fn check_dir(dir: &Path) -> usize {
    let files = der_files(dir);
    let mut checked = 0usize;
    let mut identical_to_input = 0usize;
    let mut failures: Vec<String> = Vec::new();
    let scratch = std::env::temp_dir().join(format!(
        "tpt-asn1-der-parity-{}-{}",
        std::process::id(),
        dir.file_name().unwrap_or_default().to_string_lossy()
    ));
    fs::create_dir_all(&scratch).expect("create scratch dir");

    for path in &files {
        let input = fs::read(path).expect("read corpus file");
        let ours = match reencode(&input) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{}: core re-encode failed: {e}", path.display()));
                continue;
            }
        };
        let Some(theirs) = openssl_reencode(&input, &scratch) else {
            // OpenSSL rejected the input. Parity is undefined for it, so skip it.
            continue;
        };
        checked += 1;
        if ours == input {
            identical_to_input += 1;
        }
        if ours != theirs {
            let at = first_diff(&ours, &theirs).unwrap_or(0);
            failures.push(format!(
                "{}: differs at byte {at} (core {} bytes, openssl {} bytes)",
                path.display(),
                ours.len(),
                theirs.len()
            ));
        }
    }

    let _ = fs::remove_dir_all(&scratch);
    eprintln!(
        "{}: {} files, {} compared with OpenSSL, {} mismatches, core output == input for {}",
        dir.display(),
        files.len(),
        checked,
        failures.len(),
        identical_to_input
    );
    for f in failures.iter().take(20) {
        eprintln!("  {f}");
    }
    assert!(failures.is_empty(), "{} DER parity failures", failures.len());
    checked
}

fn have_openssl() -> bool {
    Command::new("openssl")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn umbrella_certs_match_openssl_der() {
    if !have_openssl() {
        eprintln!("openssl not found on PATH; skipping DER parity gate");
        return;
    }
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/umbrella_corpus");
    assert!(check_dir(&dir) > 0, "no certificates compared");
}

#[test]
fn pkits_certs_match_openssl_der() {
    if !have_openssl() {
        eprintln!("openssl not found on PATH; skipping DER parity gate");
        return;
    }
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pkits_data/certs");
    assert!(check_dir(&dir) > 0, "no certificates compared");
}
