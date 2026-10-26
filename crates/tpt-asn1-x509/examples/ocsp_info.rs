//! Decode a DER-encoded OCSP response and print each single response's status.
//!
//! Parsing only: the responder signature is not checked here.
//!
//! Run with: `cargo run -p tpt-asn1-x509 --example ocsp_info -- <response.der>`

use tpt_asn1_core::decode;
use tpt_asn1_x509::ocsp::{decode_basic_response, CertStatus, OcspResponse};

fn main() {
    let path = std::env::args().nth(1).expect("usage: ocsp_info <response.der>");
    let der = std::fs::read(&path).expect("read OCSP response file");
    let response = decode::<OcspResponse>(&der).expect("decode OCSPResponse");
    println!("responseStatus: {}", response.status);

    let Some(bytes) = response.response_bytes else {
        println!("no responseBytes (the responder returned an error status)");
        return;
    };
    let basic = decode_basic_response(bytes.response).expect("decode BasicOCSPResponse");
    for single in &basic.responses {
        let status = match single.cert_status {
            CertStatus::Good => "good".to_string(),
            CertStatus::Revoked { reason, .. } => format!("revoked (reason {reason:?})"),
            CertStatus::Unknown => "unknown".to_string(),
        };
        println!("single response: {status}");
    }
}
