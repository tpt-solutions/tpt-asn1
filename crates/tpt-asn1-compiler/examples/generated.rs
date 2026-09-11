// SPDX-License-Identifier: MIT OR Apache-2.0

//! Live demo of the `.tpt-asn1` DSL: this binary *is* the code emitted by
//! `tpt-asn1-compiler` (see `example.tpt-asn1` -> `gen/generated_example.rs`)
//! and round-trips real DER through it. Cargo builds every example in CI, so
//! the generator's output is kept honest; `tests/codegen_compiles.rs` re-checks
//! it from a fresh generation.

#[path = "gen/generated_example.rs"]
mod generated;

use generated::*;
use tpt_asn1_core::decode;
use tpt_asn1_core::types::{BitString, Ia5String, Null, ObjectIdentifier};
use tpt_asn1_core::writer::encode_to_vec;

fn main() {
    // AlgorithmIdentifier { algorithm = sha256WithRSAEncryption, parameters = NULL }.
    let sha256_rsa = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    let ai_der = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    ];

    let ai = decode::<AlgorithmIdentifier>(&ai_der).expect("decode AlgorithmIdentifier");
    assert_eq!(ai.algorithm.0, &sha256_rsa[..]);
    assert_eq!(ai.parameters, Some(Null));
    assert_eq!(encode_to_vec(&ai).unwrap(), ai_der, "AlgorithmIdentifier round-trip");

    // Color is a bare ENUMERATED and needs no lifetime.
    let color_der = [0x0a, 0x01, 0x01];
    assert_eq!(decode::<Color>(&color_der).expect("decode Color"), Color::Green);
    assert_eq!(encode_to_vec(&Color::Green).unwrap(), color_der, "Color round-trip");

    // SubjectPublicKeyInfo exercises tagging: [0] IMPLICIT DEFAULT, a BIT STRING,
    // and the optional [1] EXPLICIT OCTET STRING.
    let spki = SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            algorithm: ObjectIdentifier(&sha256_rsa),
            parameters: None,
        },
        subject_public_key: BitString { unused_bits: 0, data: &[0xaa] },
        critical_flag: None,
        custom_data: Some(tpt_asn1_core::types::OctetString(b"tagged")),
        extensions: Vec::new(),
    };
    let spki_der = encode_to_vec(&spki).expect("encode SubjectPublicKeyInfo");
    let back: SubjectPublicKeyInfo = decode(&spki_der).expect("decode SubjectPublicKeyInfo");
    assert_eq!(back, spki, "SubjectPublicKeyInfo round-trip");

    // CHOICE: dNSName is [0] IMPLICIT IA5String.
    let gn = GeneralName::DNSName(Ia5String(b"example.com"));
    let gn_der = encode_to_vec(&gn).expect("encode GeneralName");
    let back_gn: GeneralName = decode(&gn_der).expect("decode GeneralName");
    assert_eq!(back_gn, gn, "GeneralName CHOICE round-trip");

    println!("generated code round-trips DER correctly");
}