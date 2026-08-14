// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compiler error types.

use alloc::string::String;

/// Errors produced while lexing, parsing, or generating code from a
/// `.tpt-asn1` schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompilerError {
    /// The lexer encountered an unexpected byte.
    LexError(String),
    /// The parser encountered an unexpected token or structure.
    ParseError(String),
    /// Code generation failed (e.g. an unresolved type reference).
    CodegenError(String),
}

impl CompilerError {
    /// Construct a lex error.
    pub fn lex(msg: impl Into<String>) -> Self {
        CompilerError::LexError(msg.into())
    }

    /// Construct a parse error.
    pub fn parse(msg: impl Into<String>) -> Self {
        CompilerError::ParseError(msg.into())
    }

    /// Construct a codegen error.
    pub fn codegen(msg: impl Into<String>) -> Self {
        CompilerError::CodegenError(msg.into())
    }
}

impl core::fmt::Display for CompilerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CompilerError::LexError(m) => write!(f, "lex error: {m}"),
            CompilerError::ParseError(m) => write!(f, "parse error: {m}"),
            CompilerError::CodegenError(m) => write!(f, "codegen error: {m}"),
        }
    }
}

/// Result alias used throughout the compiler.
pub type Result<T> = core::result::Result<T, CompilerError>;
