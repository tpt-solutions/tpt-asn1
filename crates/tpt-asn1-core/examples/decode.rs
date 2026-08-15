//! Minimal example: decode a single ASN.1 TLV.
//!
//! Run with: `cargo run -p tpt-asn1-core --example decode`

use tpt_asn1_core::reader::read_tlv;
use tpt_asn1_core::tag::Class;

fn main() {
    let der = [0x02, 0x01, 0x05]; // INTEGER 5
    let (tag, len, value) = read_tlv(&der).expect("decode TLV");
    assert_eq!(tag.class, Class::Universal);
    assert_eq!(tag.number, 2); // INTEGER
    assert_eq!(value, &[0x05]);
    println!("tag={:?} len={:?} value={:?}", tag, len, value);
}
