// SPDX-License-Identifier: MIT OR Apache-2.0

//! Example `build.rs` showing how to use `tpt-asn1-compiler` to generate Rust code
//! from a `.tpt-asn1` schema at build time.
//!
//! Place this file in your crate's root (next to `Cargo.toml`) and add:
//! ```toml
//! [build-dependencies]
//! tpt-asn1-compiler = { path = "../tpt-asn1-compiler" }
//! ```
//!
//! Then in your `lib.rs`:
//! ```rust
//! include!(concat!(env!("OUT_DIR"), "/schema.rs"));
//! ```

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Tell cargo to re-run this build script if the schema file changes
    println!("cargo:rerun-if-changed=schema.tpt-asn1");

    // Read the schema file
    let schema_path = PathBuf::from("schema.tpt-asn1");
    let src = fs::read_to_string(&schema_path).expect("Failed to read schema.tpt-asn1");

    // Generate Rust code
    let code = tpt_asn1_compiler::generate(&src).expect("Failed to generate code from schema");

    // Write to OUT_DIR
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_path = out_dir.join("schema.rs");
    fs::write(&out_path, code).expect("Failed to write generated code");

    println!("cargo:warning=Generated schema.rs from schema.tpt-asn1");
}