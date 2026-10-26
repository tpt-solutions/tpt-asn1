//! Decode a DER-encoded X.509 CRL and list its revoked entries.
//!
//! Parsing only: this does not verify the CRL signature. Pass the CRL to
//! `tpt_asn1_x509::chain::build_and_validate` with a signature backend for that.
//!
//! Run with: `cargo run -p tpt-asn1-x509 --example crl_info -- <list.crl>`

use tpt_asn1_core::decode;
use tpt_asn1_x509::crl::CertificateList;

fn main() {
    let path = std::env::args().nth(1).expect("usage: crl_info <list.crl>");
    let der = std::fs::read(&path).expect("read CRL file");
    let crl = decode::<CertificateList>(&der).expect("decode CRL");

    println!("issuer RDNs: {}", crl.issuer.rdns().len());
    println!("revoked entries: {}", crl.revoked.len());
    for entry in &crl.revoked {
        let serial: String =
            entry.serial_number_bytes().iter().map(|b| format!("{b:02x}")).collect();
        match entry.reason() {
            Some(code) => println!("  serial {serial}: reason code {code}"),
            None => println!("  serial {serial}: no reason given"),
        }
    }
}
