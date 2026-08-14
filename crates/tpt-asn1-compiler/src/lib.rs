// SPDX-License-Identifier: MIT OR Apache-2.0

//! `tpt-asn1-compiler` — the `.tpt-asn1` DSL to Rust code generator.
//!
//! This crate provides a hand-written lexer/parser for the `.tpt-asn1` schema
//! language and a code generator that emits Rust types implementing the
//! `tpt-asn1-core` `Decode`/`Encode` traits. It is `no_std` + `alloc` so it can
//! run inside `build.rs` of downstream crates.
//!
//! Typical usage (in a downstream `build.rs`):
//!
//! ```ignore
//! fn main() {
//!     let src = std::fs::read_to_string("schema.tpt-asn1").unwrap();
//!     let code = tpt_asn1_compiler::generate(&src).unwrap();
//!     let out = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("schema.rs");
//!     std::fs::write(out, code).unwrap();
//! }
//! ```
//!
//! and in `lib.rs`:
//!
//! ```ignore
//! include!(concat!(env!("OUT_DIR"), "/schema.rs"));
//! ```

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod ast;
pub mod codegen;
pub mod error;
pub mod lexer;
pub mod parser;

pub use error::{CompilerError, Result};
pub use ast::Schema;

/// Parse `.tpt-asn1` source into a [`Schema`] AST.
pub fn parse(src: &str) -> core::result::Result<Schema, CompilerError> {
    let tokens = lexer::lex(src)?;
    parser::parse(&tokens)
}

/// Parse and generate Rust code for `.tpt-asn1` `src` in a single step.
pub fn generate(src: &str) -> core::result::Result<alloc::string::String, CompilerError> {
    let schema = parse(src)?;
    codegen::generate(&schema)
}
