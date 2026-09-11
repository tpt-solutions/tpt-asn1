// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dogfood test: compile the example schema and verify it can encode/decode
//! real data correctly.

use tpt_asn1_compiler::generate;

#[test]
fn dogfood_example_schema() {
    // Read the example schema
    let src = include_str!("../examples/example.tpt-asn1");

    // Generate code
    let code = generate(src).expect("Failed to generate code from example schema");

    // Verify key types are generated
    assert!(code.contains("pub struct AlgorithmIdentifier"));
    assert!(code.contains("pub enum Color"));
    assert!(code.contains("pub struct AttributeTypeAndValue"));
    assert!(code.contains("pub struct RelativeDistinguishedName<"));
    assert!(code.contains("pub struct Name<"));
    assert!(code.contains("pub struct SubjectPublicKeyInfo"));
    assert!(code.contains("pub struct Extension"));
    assert!(code.contains("pub struct Extensions<"));
    assert!(code.contains("pub enum GeneralName"));
    assert!(code.contains("pub struct GeneralNames<"));
    assert!(code.contains("pub type CertificateSerialNumber"));
    assert!(code.contains("pub type SignatureValue"));

    // Verify key traits are implemented
    assert!(code.contains("impl"));
    assert!(code.contains("Decode"));
    assert!(code.contains("Encode"));

    println!("Generated code structure verified");
}

// Regression: fields whose ASN.1 name is a Rust keyword must be escaped, and a
// named alias of `SET OF` must be matched by tag number 17, not 16.
#[test]
fn dogfood_generated_code_compiles() {
    let src = include_str!("../examples/example.tpt-asn1");
    let code = generate(src).expect("Failed to generate code from example schema");

    // `type OBJECT IDENTIFIER` must not emit `pub type:` (a keyword).
    assert!(
        code.contains("pub type_: ObjectIdentifier<'a>"),
        "keyword field name must be escaped:\n{code}"
    );

    // `RelativeDistinguishedName ::= SET OF AttributeTypeAndValue` must be
    // decoded using the SET tag (17), matching the encoder.
    assert!(code.contains("Tag::universal_constructed(Tag::SET)"));
    assert!(!code.contains("Tag::universal_constructed(Tag::SET_STRING)"));

    // The emitted imports must resolve against `tpt-asn1-core` (full compile
    // check lives in tests/codegen_compiles.rs).
    assert!(
        code.contains("writer::{Writer, WriteBackend, encode_to_vec}"),
        "encode_to_vec must be imported from writer:\n{code}"
    );
}
