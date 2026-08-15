//! Minimal example: decode a CMS `ContentInfo` and inspect its `SignedData`.
//!
//! Run with: `cargo run -p tpt-cms --example verify -- <message.der>`

use tpt_asn1_core::decode;
use tpt_cms::content_info::ContentInfo;
use tpt_cms::signed_data::SignedData;

fn main() {
    let path = std::env::args().nth(1).expect("usage: inspect <message.der>");
    let der = std::fs::read(&path).expect("read CMS message file");
    let ci = decode::<ContentInfo>(&der).expect("decode ContentInfo");
    println!("content type OID: {:?}", ci.content_type.as_bytes());

    let sd = ci
        .decode_content::<SignedData>()
        .expect("decode SignedData");
    println!("signer infos: {}", sd.signer_infos.len());
    println!("embedded content present: {}", sd.content_bytes().is_some());
}
