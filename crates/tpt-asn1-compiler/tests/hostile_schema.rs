//! Schemas with undefined or unsupported references must produce a
//! `CompilerError`, never a panic in codegen.

use tpt_asn1_compiler::generate;

#[test]
fn undefined_reference_in_sequence_of_is_an_error() {
    let src = "module M { A ::= SEQUENCE OF Missing }";
    assert!(generate(src).is_err());
}

#[test]
fn undefined_reference_in_nested_field_is_an_error() {
    let src = "module M { A ::= SEQUENCE { x SEQUENCE OF Missing } }";
    assert!(generate(src).is_err());
}

#[test]
fn undefined_reference_in_set_of_is_an_error() {
    let src = "module M { A ::= SET OF Missing }";
    assert!(generate(src).is_err());
}

#[test]
fn inline_compound_type_is_an_error_not_a_panic() {
    let src = "module M { A ::= SEQUENCE { inner SEQUENCE { x INTEGER } } }";
    assert!(generate(src).is_err());
}

#[test]
fn defined_reference_still_generates() {
    let src = "module M { B ::= INTEGER A ::= SEQUENCE OF B }";
    assert!(generate(src).is_ok());
}
