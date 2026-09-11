// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verifies the code generator actually emits compilable Rust: runs `rustc`
//! on freshly generated code, linked against the built `tpt-asn1-core`.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn generated_code_compiles() {
    let src = include_str!("../examples/example.tpt-asn1");
    let code = tpt_asn1_compiler::generate(src).expect("failed to generate code");

    let tmp = std::env::temp_dir().join(format!("tpt-asn1-gencheck-{}", std::process::id()));
    fs::create_dir_all(&tmp).unwrap();
    let source_path = tmp.join("generated.rs");
    fs::write(&source_path, &code).unwrap();

    let core_rlib = match find_core_rlib() {
        Some(path) => path,
        None => {
            ensure_core_built();
            find_core_rlib().expect("tpt_asn1_core rlib still missing after build")
        }
    };
    let out_path = tmp.join("generated.rlib");

    let status = Command::new("rustc")
        .args([
            "--edition",
            "2021",
            "--crate-type",
            "lib",
            "--crate-name",
            "tpt_gen_check",
            "--cap-lints",
            "warn",
        ])
        .arg("--extern")
        .arg(format!("tpt_asn1_core={}", core_rlib.display()))
        .arg(source_path)
        .arg("-o")
        .arg(out_path)
        .status()
        .expect("failed to spawn rustc; is it on PATH?");

    assert!(
        status.success(),
        "generated code failed to compile against tpt-asn1-core\n--- generated source ---\n{code}\n"
    );
}

/// Locate the compiled `tpt_asn1_core` rlib produced for the current profile by
/// searching the nearest `target/<profile>/deps` upward from this crate.
fn find_core_rlib() -> Option<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut dir = manifest.as_path();
    loop {
        let target = dir.join("target");
        if target.is_dir() {
            for profile in ["debug", "release"] {
                let deps = target.join(profile).join("deps");
                if deps.is_dir() {
                    if let Ok(entries) = fs::read_dir(&deps) {
                            for e in entries.flatten() {
                                let name = e.file_name().to_string_lossy().into_owned();
                                let is_core = name.starts_with("libtpt_asn1_core-")
                                    || name.starts_with("tpt_asn1_core-");
                                if is_core && name.ends_with(".rlib") {
                                    return Some(e.path());
                                }
                            }
                        }
                }
            }
        }
        match dir.parent() {
            Some(p) => dir = p,
            None => break,
        }
    }
    None
}

/// Build `tpt-asn1-core` so its rlib exists for the `rustc` check below; the
/// compiler crate itself has no dependency on core, so `-p tpt-asn1-compiler`
/// test invocations never produce the rlib on their own.
fn ensure_core_built() {
    let status = Command::new("cargo")
        .args(["build", "-p", "tpt-asn1-core", "--quiet"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("failed to spawn cargo");
    assert!(status.success(), "cargo build -p tpt-asn1-core failed");
}