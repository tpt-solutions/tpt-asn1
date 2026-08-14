// SPDX-License-Identifier: MIT OR Apache-2.0

//! Abstract syntax tree for parsed `.tpt-asn1` schemas.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

/// A reference to a universal ASN.1 built-in type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Builtin {
    /// `BOOLEAN`
    Boolean,
    /// `INTEGER`
    Integer,
    /// `BIT STRING`
    BitString,
    /// `OCTET STRING`
    OctetString,
    /// `NULL`
    Null,
    /// `OBJECT IDENTIFIER`
    ObjectIdentifier,
    /// `RELATIVE-OID`
    RelativeOid,
    /// `UTF8String`
    Utf8String,
    /// `NumericString`
    NumericString,
    /// `PrintableString`
    PrintableString,
    /// `TeletexString`
    TeletexString,
    /// `VideotexString`
    VideotexString,
    /// `IA5String`
    Ia5String,
    /// `UTCTime`
    UtcTime,
    /// `GeneralizedTime`
    GeneralizedTime,
    /// `GraphicString`
    GraphicString,
    /// `VisibleString`
    VisibleString,
    /// `GeneralString`
    GeneralString,
    /// `UniversalString`
    UniversalString,
    /// `CHARACTER STRING`
    CharacterString,
    /// `BMPString`
    BmpString,
    /// `ObjectDescriptor`
    ObjectDescriptor,
}

/// ASN.1 tag class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagClass {
    /// `UNIVERSAL`
    Universal,
    /// `APPLICATION`
    Application,
    /// `CONTEXT` (default for bare `[n]`)
    Context,
    /// `PRIVATE`
    Private,
}

/// A tag applied to a field or CHOICE alternative.
#[derive(Debug, Clone, Copy)]
pub struct TagSpec {
    /// Tag class.
    pub class: TagClass,
    /// Tag number within the class.
    pub number: u32,
    /// `true` for EXPLICIT tagging, `false` for IMPLICIT.
    pub explicit: bool,
}

/// Whether and how a field/alternative is tagged.
#[derive(Debug, Clone, Copy)]
pub enum Tagging {
    /// No explicit tagging (uses the type's natural universal tag).
    None,
    /// Tagged with the given specification.
    Tagged(TagSpec),
}

/// A literal DEFAULT value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultValue {
    /// `TRUE` / `FALSE`
    Boolean(bool),
    /// An integer literal.
    Integer(i64),
    /// `NULL`
    Null,
}

/// A type expression.
#[derive(Debug, Clone)]
pub enum Type {
    /// Reference to a named type defined in the module.
    Named(String),
    /// A universal built-in type.
    Builtin(Builtin),
    /// Inline `SEQUENCE { ... }` (only produced by the parser for the rare
    /// anonymous case; the DSL otherwise requires named compounds).
    Sequence(Vec<Field>),
    /// Inline `SET { ... }`.
    Set(Vec<Field>),
    /// Inline `CHOICE { ... }`.
    Choice(Vec<Field>),
    /// `SEQUENCE OF <Type>`.
    SequenceOf(Box<Type>),
    /// `SET OF <Type>`.
    SetOf(Box<Type>),
}

/// A field of a `SEQUENCE`, `SET`, or `CHOICE`.
#[derive(Debug, Clone)]
pub struct Field {
    /// Field name (e.g. `commonName`).
    pub name: String,
    /// Field type.
    pub ty: Type,
    /// Tagging applied to this field.
    pub tagging: Tagging,
    /// `OPTIONAL` flag.
    pub optional: bool,
    /// `DEFAULT` value, if any.
    pub default: Option<DefaultValue>,
}

/// An `ENUMERATED` variant.
#[derive(Debug, Clone)]
pub struct EnumVariant {
    /// Variant identifier.
    pub name: String,
    /// Associated integer value.
    pub number: i64,
}

/// A top-level type definition body.
#[derive(Debug, Clone)]
pub enum TypeDef {
    /// `SEQUENCE { ... }`
    Sequence(Vec<Field>),
    /// `SET { ... }`
    Set(Vec<Field>),
    /// `CHOICE { ... }`
    Choice(Vec<Field>),
    /// `ENUMERATED { ... }`
    Enumerated(Vec<EnumVariant>),
    /// An alias to a built-in, named, or `OF` type.
    Alias(Type),
}

/// A `Name ::= <Type>` assignment.
#[derive(Debug, Clone)]
pub struct TypeAssignment {
    /// The defined type name.
    pub name: String,
    /// The definition body.
    pub def: TypeDef,
}

/// A parsed schema (one or more modules merged).
#[derive(Debug, Clone)]
pub struct Schema {
    /// The (last) module name encountered.
    pub module: String,
    /// All type assignments across the schema.
    pub types: Vec<TypeAssignment>,
}
