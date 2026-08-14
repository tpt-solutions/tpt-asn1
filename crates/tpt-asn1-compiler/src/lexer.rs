// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hand-written lexer for `.tpt-asn1` schema files (pure Rust, no C deps).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{CompilerError, Result};

/// A lexical token of the `.tpt-asn1` grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// An identifier or keyword (`INTEGER`, `SEQUENCE`, `module`, ...).
    Ident(String),
    /// An integer literal (also used for tag numbers and enum values).
    Int(i64),
    /// `:`
    Colon,
    /// `=`
    Equals,
    /// `{`
    LBrace,
    /// `}`
    RBrace,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `,`
    Comma,
    /// `;`
    Semi,
    /// End of input.
    Eof,
}

/// Tokenize `src` into a token stream.
pub fn lex(src: &str) -> Result<Vec<Token>> {
    let bytes = src.as_bytes();
    let mut i = 0usize;
    let mut toks = Vec::new();
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => {
                i += 1;
            }
            b':' => {
                toks.push(Token::Colon);
                i += 1;
            }
            b'=' => {
                toks.push(Token::Equals);
                i += 1;
            }
            b'{' => {
                toks.push(Token::LBrace);
                i += 1;
            }
            b'}' => {
                toks.push(Token::RBrace);
                i += 1;
            }
            b'(' => {
                toks.push(Token::LParen);
                i += 1;
            }
            b')' => {
                toks.push(Token::RParen);
                i += 1;
            }
            b'[' => {
                toks.push(Token::LBracket);
                i += 1;
            }
            b']' => {
                toks.push(Token::RBracket);
                i += 1;
            }
            b',' => {
                toks.push(Token::Comma);
                i += 1;
            }
            b';' => {
                toks.push(Token::Semi);
                i += 1;
            }
            b'-' => {
                if i + 1 < bytes.len() && (bytes[i + 1] == b'-' || bytes[i + 1] == b'/') {
                    // Line comment (`--` or `//`) to end of line.
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                } else if i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
                    i += 1;
                    let start = i;
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                    let s = core::str::from_utf8(&bytes[start..i])
                        .map_err(|_| CompilerError::lex("invalid integer"))?;
                    let v: i64 = s.parse().map_err(|_| CompilerError::lex("integer overflow"))?;
                    toks.push(Token::Int(-v));
                } else {
                    // Part of an identifier (e.g. `RELATIVE-OID`).
                    i = lex_ident(bytes, i, &mut toks)?;
                }
            }
            _ if c.is_ascii_alphabetic() || c == b'_' => {
                i = lex_ident(bytes, i, &mut toks)?;
            }
            _ if c.is_ascii_digit() => {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let s = core::str::from_utf8(&bytes[start..i]).unwrap();
                let v: i64 = s.parse().map_err(|_| CompilerError::lex("integer overflow"))?;
                toks.push(Token::Int(v));
            }
            _ => {
                return Err(CompilerError::lex(format!("unexpected byte 0x{:02x}", c)));
            }
        }
    }
    toks.push(Token::Eof);
    Ok(toks)
}

fn lex_ident(bytes: &[u8], mut i: usize, toks: &mut Vec<Token>) -> Result<usize> {
    let start = i;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' {
            i += 1;
        } else {
            break;
        }
    }
    let s = core::str::from_utf8(&bytes[start..i]).map_err(|_| CompilerError::lex("invalid identifier"))?;
    toks.push(Token::Ident(s.to_string()));
    Ok(i)
}
