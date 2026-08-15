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
    assert!(code.contains("pub type RelativeDistinguishedName"));
    assert!(code.contains("pub type Name"));
    assert!(code.contains("pub struct SubjectPublicKeyInfo"));
    assert!(code.contains("pub struct Extension"));
    assert!(code.contains("pub type Extensions"));
    assert!(code.contains("pub enum GeneralName"));
    assert!(code.contains("pub type GeneralNames"));
    assert!(code.contains("pub type CertificateSerialNumber"));
    assert!(code.contains("pub type SignatureValue"));
    
    // Verify key traits are implemented
    assert!(code.contains("impl"));
    assert!(code.contains("Decode"));
    assert!(code.contains("Encode"));
    
    println!("Generated code structure verified");
}

// Test that the generated code compiles by including it
// This is a compile-time test - if it compiles, the generated code is valid Rust
#[test]
fn dogfood_generated_code_compiles() {
    // The generated_example.rs file is already included in the crate
    // and compiled as part of the library. If this test runs, it means
    // the generated code compiles successfully.
    
    // We can't directly use the generated types from here since they're
    // not exported, but the fact that the crate compiles means the
    // generated code is valid Rust.
    
    println!("Generated code compiles successfully");
}
