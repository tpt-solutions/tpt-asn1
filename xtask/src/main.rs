// SPDX-License-Identifier: MIT OR Apache-2.0

//! Developer task runner. Run as `cargo xtask <command>` (see `.cargo/config.toml`).
//!
//! The commands mirror the CI jobs, so a contributor can check a change locally
//! with the same steps the pull-request pipeline runs.

use std::process::{exit, Command};

const USAGE: &str = "\
usage: cargo xtask <command>

commands:
  ci          fmt check, clippy (-D warnings), and the full test suite
  pkits       the NIST PKITS regression gate (tpt-asn1-x509 pkits_harness)
  docs        rustdoc for the workspace, failing on warnings
  deny        cargo-deny policy check (needs cargo-deny installed)
  fuzz-quick  build every fuzz target (needs nightly and cargo-fuzz)
";

fn main() {
    let command = std::env::args().nth(1).unwrap_or_default();
    let steps: Vec<Vec<&str>> = match command.as_str() {
        "ci" => vec![
            vec!["fmt", "--all", "--", "--check"],
            vec!["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"],
            vec!["test", "--workspace"],
        ],
        "pkits" => vec![vec!["test", "-p", "tpt-asn1-x509", "--test", "pkits_harness"]],
        "docs" => {
            run_with_env(&["doc", "--workspace", "--no-deps"], &[("RUSTDOCFLAGS", "-D warnings")]);
            return;
        }
        "deny" => {
            run_tool("cargo-deny", &["check"]);
            return;
        }
        "fuzz-quick" => {
            run_fuzz_quick();
            return;
        }
        "" | "help" | "--help" | "-h" => {
            print!("{USAGE}");
            return;
        }
        other => {
            eprintln!("xtask: unknown command `{other}`\n\n{USAGE}");
            exit(2);
        }
    };
    for step in steps {
        run("cargo", &step);
    }
    if command == "ci" {
        // The crypto crate is its own workspace with a stable toolchain file, so its
        // steps run from its directory for rustup to pick that toolchain.
        let dir = "crates/tpt-asn1-crypto";
        run_in(dir, "cargo", &["clippy", "--all-targets", "--", "-D", "warnings"]);
        run_in(dir, "cargo", &["test"]);
    }
}

/// Run a command from `dir`, so that directory's `rust-toolchain.toml` applies.
fn run_in(dir: &str, program: &str, args: &[&str]) {
    eprintln!("xtask: (in {dir}) {program} {}", args.join(" "));
    // `cargo xtask` sets RUSTUP_TOOLCHAIN for its children, which would override
    // the directory's own toolchain file. Clear it so that file applies.
    let status = Command::new(program)
        .args(args)
        .current_dir(dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .status()
        .unwrap_or_else(|e| {
            eprintln!("xtask: failed to start `{program}`: {e}");
            exit(1);
        });
    if !status.success() {
        exit(status.code().unwrap_or(1));
    }
}

fn run(program: &str, args: &[&str]) {
    eprintln!("xtask: {program} {}", args.join(" "));
    let status = Command::new(program).args(args).status().unwrap_or_else(|e| {
        eprintln!("xtask: failed to start `{program}`: {e}");
        exit(1);
    });
    if !status.success() {
        exit(status.code().unwrap_or(1));
    }
}

fn run_with_env(args: &[&str], env: &[(&str, &str)]) {
    eprintln!("xtask: cargo {} (env {:?})", args.join(" "), env);
    let mut cmd = Command::new("cargo");
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let status = cmd.status().unwrap_or_else(|e| {
        eprintln!("xtask: failed to start cargo: {e}");
        exit(1);
    });
    if !status.success() {
        exit(status.code().unwrap_or(1));
    }
}

fn run_tool(program: &str, args: &[&str]) {
    run(program, args);
}

/// The fuzz crate is a standalone workspace, so it is built from its own directory.
fn run_fuzz_quick() {
    eprintln!("xtask: building fuzz targets from ./fuzz (requires nightly and cargo-fuzz)");
    let status = Command::new("cargo")
        .args(["+nightly", "fuzz", "build"])
        .current_dir("fuzz")
        .status()
        .unwrap_or_else(|e| {
            eprintln!("xtask: failed to start cargo: {e}");
            exit(1);
        });
    if !status.success() {
        exit(status.code().unwrap_or(1));
    }
}
