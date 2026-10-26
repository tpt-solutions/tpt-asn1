//! Lexer tests: the example schema tokenizes, and an invalid byte is rejected.

use tpt_asn1_compiler::lexer::lex;

#[test]
fn example_schema_tokenizes() {
    let src = include_str!("../examples/example.tpt-asn1");
    let tokens = lex(src).expect("example schema must lex");
    assert!(tokens.len() > 100, "expected a full schema, got {} tokens", tokens.len());
}

#[test]
fn empty_input_produces_no_error() {
    assert!(lex("").is_ok());
}

#[test]
fn unexpected_byte_is_a_lex_error() {
    // A bare `@` is not part of the DSL.
    assert!(lex("module M { @ }").is_err());
}
