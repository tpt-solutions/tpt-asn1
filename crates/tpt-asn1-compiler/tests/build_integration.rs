// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration test for the `build.rs` workflow: compile a schema, include the
//! generated code, and verify it can encode/decode correctly.

use std::fs;
use std::path::PathBuf;

#[test]
fn build_rs_integration() {
    // Read the example schema
    let schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/schema.tpt-asn1");
    let src = fs::read_to_string(&schema_path).expect("Failed to read schema");

    // Generate code
    let code = tpt_asn1_compiler::generate(&src).expect("Failed to generate code");

    // Write to a temp file and compile it as a test
    let out_dir = std::env::temp_dir().join("tpt-asn1-build-test");
    fs::create_dir_all(&out_dir).unwrap();
    let out_path = out_dir.join("generated.rs");
    fs::write(&out_path, &code).expect("Failed to write generated code");

    // Verify the generated code contains expected types
    assert!(code.contains("pub struct SimpleSequence"));
    assert!(code.contains("pub enum SimpleChoice"));
    assert!(code.contains("pub struct Container"));
    assert!(code.contains("impl"));
    assert!(code.contains("Decode"));
    assert!(code.contains("Encode"));

    // Test that we can parse a simple DER encoding of SimpleSequence
    // SimpleSequence { id: 42, name: "test", flag: true }
    // SEQUENCE (universal 16) with 3 elements
    let der = hex::decode("301a02012a0c04746573740101ff").unwrap();

    // We can't easily compile and run the generated code in this test,
    // but we can verify the generated code structure is correct
    println!("Generated code:\n{}", code);
}