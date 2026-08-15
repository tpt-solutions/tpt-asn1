//! Internal DER re-encode round-trip checks — a stand-in for the OpenSSL
//! byte-for-byte parity gate (which requires an external `openssl` binary not
//! present here). These confirm that encode -> decode -> encode is byte-stable
//! for canonical DER, which is the property parity testing relies on.

use tpt_asn1_core::decode;
use tpt_asn1_core::types::{Integer, OctetString};
use tpt_asn1_core::writer::encode_to_vec;

#[test]
fn primitive_der_roundtrip_is_stable() {
    let i = encode_to_vec(&Integer(&[0x01, 0x00])).unwrap();
    assert_eq!(decode::<Integer>(&i).unwrap().as_bytes(), &[0x01, 0x00]);
    let re = encode_to_vec(&decode::<Integer>(&i).unwrap()).unwrap();
    assert_eq!(i, re);

    let o = encode_to_vec(&OctetString(b"hello")).unwrap();
    assert_eq!(decode::<OctetString>(&o).unwrap().as_bytes(), b"hello");
    let re2 = encode_to_vec(&decode::<OctetString>(&o).unwrap()).unwrap();
    assert_eq!(o, re2);
}
