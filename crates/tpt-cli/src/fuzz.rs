// SPDX-License-Identifier: MIT OR Apache-2.0

//! Differential fuzzer: compares `tpt-asn1`'s parser against OpenSSL's
//! `asn1parse` over a corpus of DER inputs, flagging any disagreement.

use std::path::{Path, PathBuf};

use tpt_asn1_core::reader::Config;

use crate::error::CliError;
use crate::inspect::{parse_tlvs, InspectOptions};

/// Options for the fuzzing run.
#[derive(Clone, Copy)]
pub struct FuzzOptions {
    /// Encoding-rule configuration for our own parser.
    pub config: Config,
    /// Optional: fail the run if OpenSSL is not available.
    pub require_openssl: bool,
}

/// A differential finding between our parser and OpenSSL.
struct Finding {
    path: PathBuf,
    detail: String,
}

/// Run the differential harness over `inputs` (files and/or directories).
///
/// Returns `Ok(false)` if any differential mismatch was found, `Ok(true)` if
/// everything agreed (or OpenSSL was unavailable and not required).
pub fn run(inputs: &[PathBuf], opts: FuzzOptions) -> Result<bool, CliError> {
    let mut files: Vec<PathBuf> = Vec::new();
    for p in inputs {
        collect_files(p, &mut files)?;
    }
    if files.is_empty() {
        return Err(CliError::msg("fuzz: no input files found"));
    }

    let openssl_present = openssl_available();
    if !openssl_present {
        if opts.require_openssl {
            return Err(CliError::msg("fuzz: OpenSSL (`openssl`) not found on PATH; --require-openssl set"));
        }
        eprintln!("tpt-asn1: warning: OpenSSL not found; comparing against our own parser only.");
    }

    let inspect_opts = InspectOptions {
        config: opts.config,
        max_depth: 64,
        try_der: true,
        show_bytes: false,
    };

    let mut findings: Vec<Finding> = Vec::new();
    let mut checked = 0usize;

    for path in &files {
        match std::fs::read(path) {
            Ok(bytes) => {
                // PEM inputs are normalized to their DER blocks for comparison.
                let der_blocks: Vec<Vec<u8>> = if crate::pem::detect_pem(&bytes) {
                    match crate::pem::decode_pem(&bytes) {
                        Ok(blocks) => blocks.into_iter().map(|b| b.der).collect(),
                        Err(e) => {
                            findings.push(Finding { path: path.clone(), detail: format!("pem decode: {e}") });
                            continue;
                        }
                    }
                } else {
                    vec![bytes.clone()]
                };

                for block in &der_blocks {
                    checked += 1;
                    let ours = parse_tlvs(block, &inspect_opts);
                    let ours_ok = ours.is_ok();
                    let ours_elems = ours.map(|n| count_nodes(&n)).unwrap_or(0);

                    if let Some(ossl) = openssl_check(block) {
                        if ossl.accepted != ours_ok {
                            findings.push(Finding {
                                path: path.clone(),
                                detail: format!(
                                    "acceptance mismatch: tpt-asn1={}, openssl={}",
                                    ours_ok, ossl.accepted
                                ),
                            });
                        } else if ossl.accepted && ossl.elems != ours_elems {
                            findings.push(Finding {
                                path: path.clone(),
                                detail: format!(
                                    "element count mismatch: tpt-asn1={}, openssl={}",
                                    ours_elems, ossl.elems
                                ),
                            });
                        }
                    }
                }
            }
            Err(e) => {
                findings.push(Finding { path: path.clone(), detail: format!("read: {e}") });
            }
        }
    }

    println!(
        "tpt-asn1 fuzz: checked {checked} DER inputs across {} files.",
        files.len()
    );
    if findings.is_empty() {
        println!("tpt-asn1 fuzz: no differential findings.");
        Ok(true)
    } else {
        println!("tpt-asn1 fuzz: {} differential finding(s):", findings.len());
        for f in &findings {
            println!("  {}: {}", f.path.display(), f.detail);
        }
        Ok(false)
    }
}

/// Recursively collect regular files under `path`.
fn collect_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<(), CliError> {
    let meta = std::fs::metadata(path)?;
    if meta.is_file() {
        out.push(path.to_path_buf());
    } else if meta.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(path)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        entries.sort();
        for e in entries {
            collect_files(&e, out)?;
        }
    }
    Ok(())
}

/// Total number of TLV nodes in a parsed tree.
fn count_nodes(nodes: &[crate::inspect::TlvNode]) -> usize {
    let mut total = 0;
    for n in nodes {
        total += 1 + count_nodes(&n.children);
    }
    total
}

/// Returns `true` if `openssl` can be invoked at all.
fn openssl_available() -> bool {
    std::process::Command::new("openssl")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

struct OpensslResult {
    accepted: bool,
    elems: usize,
}

/// Ask OpenSSL to parse a DER block via `asn1parse`; `None` if openssl missing.
fn openssl_check(der: &[u8]) -> Option<OpensslResult> {
    let tmp = match write_temp(der) {
        Ok(t) => t,
        Err(_) => return None,
    };
    let out = std::process::Command::new("openssl")
        .args(["asn1parse", "-inform", "DER", "-in"])
        .arg(&tmp)
        .output();
    let _ = std::fs::remove_file(&tmp);
    match out {
        Ok(o) => {
            let accepted = o.status.success();
            let elems = if accepted {
                count_openssl_elems(&o.stdout)
            } else {
                0
            };
            Some(OpensslResult { accepted, elems })
        }
        Err(_) => None,
    }
}

/// Count `asn1parse` element lines (lines like `    0:d=0 hl=2 l=3 cons: ...`).
fn count_openssl_elems(stdout: &[u8]) -> usize {
    let s = String::from_utf8_lossy(stdout);
    s.lines()
        .filter(|l| {
            let t = l.trim_start();
            let first = t.chars().next();
            first.map_or(false, |c| c.is_ascii_digit()) && l.contains(':')
        })
        .count()
}

/// Write `data` to a uniquely-named temp file, returning its path.
fn write_temp(data: &[u8]) -> Result<PathBuf, CliError> {
    let mut path = std::env::temp_dir();
    let name = format!("tpt-asn1-fuzz-{}.der", std::process::id());
    path.push(name);
    std::fs::write(&path, data)?;
    Ok(path)
}
