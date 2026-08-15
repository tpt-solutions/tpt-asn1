//! Minimal example: decode an X.509 certificate from a file and inspect it.
//!
//! Run with: `cargo run -p tpt-x509 --example validate -- <cert.der>`

use tpt_asn1_core::decode;
use tpt_x509::{Certificate, UnixTime};

fn main() {
    let path = std::env::args().nth(1).expect("usage: validate <cert.der>");
    let der = std::fs::read(&path).expect("read certificate file");
    let cert = decode::<Certificate>(&der).expect("decode X.509 certificate");

    println!("issuer RDNs: {}", cert.issuer().rdns().len());
    println!("subject RDNs: {}", cert.subject().rdns().len());
    println!(
        "valid at 2024-01-01T00:00:00Z: {}",
        cert.is_valid_at(UnixTime::from_secs(1_704_067_200))
    );
}
