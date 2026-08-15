// SPDX-License-Identifier: MIT OR Apache-2.0

//! Recursive-descent parser: tokens -> [`Schema`] AST.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::ast::*;
use crate::error::{CompilerError, Result};
use crate::lexer::Token;

/// Parse a token stream into a [`Schema`].
pub fn parse(tokens: &[Token]) -> Result<Schema> {
    let mut p = Parser { toks: tokens, pos: 0 };
    p.parse_schema()
}

struct Parser<'a> {
    toks: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> &Token {
        &self.toks[self.pos]
    }

    fn at_eof(&self) -> bool {
        matches!(self.peek(), Token::Eof)
    }

    fn next(&mut self) -> Token {
        let t = self.toks[self.pos].clone();
        if !matches!(t, Token::Eof) {
            self.pos += 1;
        }
        t
    }

    fn expect(&mut self, tok: Token) -> Result<()> {
        let got = self.peek().clone();
        if got == tok {
            self.pos += 1;
            Ok(())
        } else {
            Err(CompilerError::parse(format!(
                "expected {tok:?}, got {got:?} (token #{})",
                self.pos
            )))
        }
    }

    fn expect_ident(&mut self) -> Result<String> {
        match self.next() {
            Token::Ident(s) => Ok(s),
            other => Err(CompilerError::parse(format!(
                "expected identifier, got {other:?} (token #{})",
                self.pos
            ))),
        }
    }

    fn peek_is_ident(&self, s: &str) -> bool {
        matches!(self.peek(), Token::Ident(x) if x == s)
    }

    fn parse_int(&mut self) -> Result<i64> {
        match self.next() {
            Token::Int(n) => Ok(n),
            other => Err(CompilerError::parse(format!("expected integer, got {other:?}"))),
        }
    }

    fn parse_schema(&mut self) -> Result<Schema> {
        let mut types = Vec::new();
        let mut module = String::new();
        while !self.at_eof() {
            let kw = self.expect_ident()?;
            if kw != "module" {
                return Err(CompilerError::parse(format!("expected 'module', got '{kw}'")));
            }
            module = self.expect_ident()?;
            self.expect(Token::LBrace)?;
            while self.peek() != &Token::RBrace {
                let ta = self.parse_type_assignment()?;
                types.push(ta);
            }
            self.expect(Token::RBrace)?;
        }
        Ok(Schema { module, types })
    }

    fn parse_type_assignment(&mut self) -> Result<TypeAssignment> {
        let name = self.expect_ident()?;
        self.expect(Token::Colon)?;
        if matches!(self.peek(), Token::Colon) {
            self.next();
        }
        self.expect(Token::Equals)?;
        let def = self.parse_type_def()?;
        if self.peek() == &Token::Semi {
            self.next();
        }
        Ok(TypeAssignment { name, def })
    }

    fn parse_type_def(&mut self) -> Result<TypeDef> {
        let kw = self.expect_ident()?;
        match kw.as_str() {
            "ENUMERATED" => {
                let vars = self.parse_enum_variants()?;
                Ok(TypeDef::Enumerated(vars))
            }
            "SEQUENCE" => {
                if self.peek_is_ident("OF") {
                    self.next();
                    let inner = self.parse_base_type(true)?;
                    Ok(TypeDef::Alias(Type::SequenceOf(Box::new(inner))))
                } else {
                    let fields = self.parse_fields()?;
                    Ok(TypeDef::Sequence(fields))
                }
            }
            "SET" => {
                if self.peek_is_ident("OF") {
                    self.next();
                    let inner = self.parse_base_type(true)?;
                    Ok(TypeDef::Alias(Type::SetOf(Box::new(inner))))
                } else {
                    let fields = self.parse_fields()?;
                    Ok(TypeDef::Set(fields))
                }
            }
            "CHOICE" => {
                let fields = self.parse_fields()?;
                Ok(TypeDef::Choice(fields))
            }
            _ => {
                let ty = self.parse_base_type_inner(kw, true)?;
                Ok(TypeDef::Alias(ty))
            }
        }
    }

    /// Parse a type, having already consumed its leading identifier `kw`.
    fn parse_base_type_inner(&mut self, mut kw: String, allow_compound: bool) -> Result<Type> {
        if kw == "BIT" && self.peek_is_ident("STRING") {
            self.next();
            kw = "BIT STRING".to_string();
        } else if kw == "OBJECT" && self.peek_is_ident("IDENTIFIER") {
            self.next();
            kw = "OBJECT IDENTIFIER".to_string();
        } else if kw == "OCTET" && self.peek_is_ident("STRING") {
            self.next();
            kw = "OCTET STRING".to_string();
        }
        match kw.as_str() {
            "SEQUENCE" => {
                if self.peek_is_ident("OF") {
                    self.next();
                    let inner = self.parse_base_type(true)?;
                    Ok(Type::SequenceOf(Box::new(inner)))
                } else if allow_compound {
                    let fields = self.parse_fields()?;
                    Ok(Type::Sequence(fields))
                } else {
                    Err(CompilerError::parse(
                        "inline SEQUENCE must be a named type; define it at module level",
                    ))
                }
            }
            "SET" => {
                if self.peek_is_ident("OF") {
                    self.next();
                    let inner = self.parse_base_type(true)?;
                    Ok(Type::SetOf(Box::new(inner)))
                } else if allow_compound {
                    let fields = self.parse_fields()?;
                    Ok(Type::Set(fields))
                } else {
                    Err(CompilerError::parse(
                        "inline SET must be a named type; define it at module level",
                    ))
                }
            }
            "CHOICE" => {
                if allow_compound {
                    let fields = self.parse_fields()?;
                    Ok(Type::Choice(fields))
                } else {
                    Err(CompilerError::parse(
                        "inline CHOICE must be a named type; define it at module level",
                    ))
                }
            }
            "ENUMERATED" => Err(CompilerError::parse(
                "ENUMERATED must be a named type: `Name ::= ENUMERATED { ... }`",
            )),
            _ => match builtin_from_str(&kw) {
                Some(b) => Ok(Type::Builtin(b)),
                None => Ok(Type::Named(kw)),
            },
        }
    }

    /// Parse a base type, reading its leading identifier first.
    fn parse_base_type(&mut self, allow_compound: bool) -> Result<Type> {
        let kw = self.expect_ident()?;
        self.parse_base_type_inner(kw, allow_compound)
    }

    fn parse_fields(&mut self) -> Result<Vec<Field>> {
        self.expect(Token::LBrace)?;
        let mut fields = Vec::new();
        while self.peek() != &Token::RBrace {
            fields.push(self.parse_field()?);
            if self.peek() == &Token::Comma {
                self.next();
            }
        }
        self.expect(Token::RBrace)?;
        Ok(fields)
    }

    fn parse_field(&mut self) -> Result<Field> {
        let name = self.expect_ident()?;
        let tagging = self.parse_optional_tag()?;
        let ty = self.parse_base_type(false)?;
        let mut optional = false;
        let mut default = None;
        if self.peek_is_ident("OPTIONAL") {
            self.next();
            optional = true;
        }
        if self.peek_is_ident("DEFAULT") {
            self.next();
            default = Some(self.parse_default_value(&ty)?);
        }
        Ok(Field { name, ty, tagging, optional, default })
    }

    fn parse_optional_tag(&mut self) -> Result<Tagging> {
        if self.peek() != &Token::LBracket {
            return Ok(Tagging::None);
        }
        self.next(); // consume '['
        let class = if let Token::Ident(c) = self.peek() {
            match c.as_str() {
                "UNIVERSAL" => {
                    self.next();
                    TagClass::Universal
                }
                "APPLICATION" => {
                    self.next();
                    TagClass::Application
                }
                "PRIVATE" => {
                    self.next();
                    TagClass::Private
                }
                "CONTEXT" => {
                    self.next();
                    TagClass::Context
                }
                _ => TagClass::Context,
            }
        } else {
            TagClass::Context
        };
        let number = self.parse_int()?;
        self.expect(Token::RBracket)?;
        let mut explicit = true; // default tagging is EXPLICIT
        if let Token::Ident(k) = self.peek() {
            match k.as_str() {
                "IMPLICIT" => {
                    self.next();
                    explicit = false;
                }
                "EXPLICIT" => {
                    self.next();
                    explicit = true;
                }
                _ => {}
            }
        }
        Ok(Tagging::Tagged(TagSpec { class, number: number as u32, explicit }))
    }

    fn parse_enum_variants(&mut self) -> Result<Vec<EnumVariant>> {
        self.expect(Token::LBrace)?;
        let mut vars = Vec::new();
        while self.peek() != &Token::RBrace {
            let name = self.expect_ident()?;
            self.expect(Token::LParen)?;
            let number = self.parse_int()?;
            self.expect(Token::RParen)?;
            vars.push(EnumVariant { name, number });
            if self.peek() == &Token::Comma {
                self.next();
            }
        }
        self.expect(Token::RBrace)?;
        Ok(vars)
    }

    fn parse_default_value(&mut self, _ty: &Type) -> Result<DefaultValue> {
        match self.peek().clone() {
            Token::Ident(s) if s == "TRUE" => {
                self.next();
                Ok(DefaultValue::Boolean(true))
            }
            Token::Ident(s) if s == "FALSE" => {
                self.next();
                Ok(DefaultValue::Boolean(false))
            }
            Token::Ident(s) if s == "NULL" => {
                self.next();
                Ok(DefaultValue::Null)
            }
            Token::Int(n) => {
                self.next();
                Ok(DefaultValue::Integer(n))
            }
            other => Err(CompilerError::parse(format!(
                "unsupported DEFAULT value: {other:?}"
            ))),
        }
    }
}

fn builtin_from_str(s: &str) -> Option<Builtin> {
    Some(match s {
        "BOOLEAN" => Builtin::Boolean,
        "INTEGER" => Builtin::Integer,
        "BIT STRING" => Builtin::BitString,
        "OCTET STRING" => Builtin::OctetString,
        "NULL" => Builtin::Null,
        "OBJECT IDENTIFIER" => Builtin::ObjectIdentifier,
        "RELATIVE-OID" => Builtin::RelativeOid,
        "UTF8String" => Builtin::Utf8String,
        "NumericString" => Builtin::NumericString,
        "PrintableString" => Builtin::PrintableString,
        "TeletexString" => Builtin::TeletexString,
        "VideotexString" => Builtin::VideotexString,
        "IA5String" => Builtin::Ia5String,
        "UTCTime" => Builtin::UtcTime,
        "GeneralizedTime" => Builtin::GeneralizedTime,
        "GraphicString" => Builtin::GraphicString,
        "VisibleString" => Builtin::VisibleString,
        "GeneralString" => Builtin::GeneralString,
        "UniversalString" => Builtin::UniversalString,
        "CHARACTER STRING" => Builtin::CharacterString,
        "BMPString" => Builtin::BmpString,
        "ObjectDescriptor" => Builtin::ObjectDescriptor,
        _ => return None,
    })
}
