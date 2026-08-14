// SPDX-License-Identifier: MIT OR Apache-2.0

use tpt_asn1_core::decode::{read_sequence, read_set_of, Decode};
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_core::tag::Tag;
use tpt_asn1_core::types::*;
use tpt_asn1_core::util::{constant_time_compare, constant_time_eq};
use tpt_asn1_core::writer::encode_to_vec;
use tpt_asn1_core::*;

#[test]
fn boolean_roundtrip() {
    let enc = encode_to_vec(&Boolean(true)).unwrap();
    assert_eq!(enc, &[0x01, 0x01, 0xFF]);
    let dec = decode::<Boolean>(&enc).unwrap();
    assert!(dec.value());

    let enc = encode_to_vec(&Boolean(false)).unwrap();
    assert_eq!(enc, &[0x01, 0x01, 0x00]);
    assert!(!decode::<Boolean>(&enc).unwrap().value());
}

#[test]
fn integer_values() {
    let d = decode::<Integer>(&[0x02, 0x01, 0x05]).unwrap();
    assert_eq!(d.as_i64(), Some(5));
    assert_eq!(d.as_u64(), Some(5));

    let d = decode::<Integer>(&[0x02, 0x01, 0xFF]).unwrap();
    assert_eq!(d.as_i64(), Some(-1));

    let d = decode::<Integer>(&[0x02, 0x02, 0x01, 0x00]).unwrap();
    assert_eq!(d.as_i64(), Some(256));

    // Non-minimal INTEGER rejected in DER.
    assert!(decode::<Integer>(&[0x02, 0x02, 0x00, 0x05]).is_err());
}

#[test]
fn bitstring() {
    let d = decode::<BitString>(&[0x03, 0x02, 0x00, 0xA0]).unwrap();
    assert_eq!(d.unused_bits, 0);
    assert_eq!(d.data, &[0xA0]);
    assert_eq!(d.bit_len(), 8);

    // Unused bits set with stray low bits must fail.
    assert!(decode::<BitString>(&[0x03, 0x02, 0x03, 0xA1]).is_err());
}

#[test]
fn octetstring_roundtrip() {
    let input = [0x04, 0x03, b'a', b'b', b'c'];
    let d = decode::<OctetString>(&input).unwrap();
    assert_eq!(d.as_bytes(), b"abc");
    let enc = encode_to_vec(&OctetString(b"abc")).unwrap();
    assert_eq!(enc, input);
}

#[test]
fn null_roundtrip() {
    let enc = encode_to_vec(&Null).unwrap();
    assert_eq!(enc, &[0x05, 0x00]);
    decode::<Null>(&enc).unwrap();
}

#[test]
fn object_identifier() {
    let d = decode::<ObjectIdentifier>(&[0x06, 0x03, 0x55, 0x1D, 0x11]).unwrap();
    assert!(d.matches(&[2, 5, 29, 17]));
    assert!(!d.matches(&[2, 5, 29, 18]));
    let arcs: Vec<u64> = d.arcs().collect();
    assert_eq!(arcs, vec![85, 29, 17]);
}

#[test]
fn sequence_decode() {
    let bytes = [0x30, 0x03, 0x02, 0x01, 0x05];
    let mut r = Reader::new(&bytes, Config::der());
    let val = read_sequence(&mut r, Integer::decode).unwrap();
    assert_eq!(val.as_i64(), Some(5));
}

#[test]
fn indefinite_length_ber() {
    let bytes = [0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00];
    let mut r = Reader::new(&bytes, Config::ber());
    let val = read_sequence(&mut r, Integer::decode).unwrap();
    assert_eq!(val.as_i64(), Some(5));

    // DER must reject indefinite length.
    let mut r = Reader::new(&bytes, Config::der());
    assert!(read_sequence(&mut r, Integer::decode).is_err());
}

#[test]
fn der_rejects_nonminimal_length() {
    // Long-form length for a 1-byte value (0x81 0x01) is non-minimal.
    let bytes = [0x02, 0x81, 0x01, 0x05];
    assert!(decode::<Integer>(&bytes).is_err());
}

#[test]
fn high_tag_number() {
    // Universal tag number 31 (primitive): 0x1F, 0x1F, then length 0.
    let bytes = [0x1F, 0x1F, 0x00];
    let (tag, _len, _value) = reader::read_tlv(&bytes).unwrap();
    assert_eq!(tag.number, 31);
    assert_eq!(tag.class, Class::Universal);
    assert!(!tag.constructed);
}

#[test]
fn context_tag() {
    let t = Tag::context(true, 0);
    let bytes = [0xA0, 0x00];
    let (tag, _len, _v) = reader::read_tlv(&bytes).unwrap();
    assert_eq!(tag, t);
}

#[test]
fn recursion_guard() {
    fn nest(depth: usize) -> Vec<u8> {
        if depth == 0 {
            vec![0x05, 0x00]
        } else {
            let inner = nest(depth - 1);
            let mut b = vec![0x30, inner.len() as u8];
            b.extend(inner);
            b
        }
    }
    fn decode_seq(r: &mut Reader) -> tpt_asn1_core::error::Result<()> {
        read_sequence(r, |inner| decode_seq(inner))
    }

    let bytes = nest(30);
    let mut cfg = Config::der();
    cfg.max_recursion = 8;
    assert!(decode_seq(&mut Reader::new(&bytes, cfg)).is_err());
}

#[test]
fn element_size_guard() {
    let bytes = [0x02, 0xFF, 0xFF, 0xFF, 0xFF];
    let mut cfg = Config::der();
    cfg.max_element_size = 4;
    let mut r = Reader::new(&bytes, cfg);
    assert!(Reader::read_tlv(&mut r).is_err());
}

#[test]
fn set_of_canonical_order() {
    // Two INTEGERs in ascending encoded order: 1 then 2.
    let ok = [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
    let mut r = Reader::new(&ok, Config::der());
    let v = read_set_of::<Integer>(&mut r).unwrap();
    assert_eq!(v.len(), 2);

    // Reversed order is not canonical under DER.
    let bad = [0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01];
    let mut r = Reader::new(&bad, Config::der());
    assert!(read_set_of::<Integer>(&mut r).is_err());
}

#[test]
fn time_parsing() {
    let d = decode::<UtcTime>(&[
        0x17, 0x0D, b'2', b'6', b'0', b'8', b'1', b'4', b'1', b'2', b'0', b'0', b'0', b'0', b'Z',
    ])
    .unwrap();
    let t = d.parse().unwrap();
    assert_eq!(t.year, 2026);
    assert_eq!(t.month, 8);
    assert_eq!(t.day, 14);
    assert_eq!(t.hour, 12);
    assert_eq!(t.tz_offset_minutes, None);

    let d = decode::<GeneralizedTime>(&[
        0x18, 0x0F, b'2', b'0', b'2', b'6', b'0', b'8', b'1', b'4', b'1', b'2', b'0', b'0', b'0',
        b'0', b'Z',
    ])
    .unwrap();
    let t = d.parse().unwrap();
    assert_eq!(t.year, 2026);
}

#[test]
fn utf8_string() {
    let enc = encode_to_vec(&Utf8String("héllo".as_bytes())).unwrap();
    let d = decode::<Utf8String>(&enc).unwrap();
    assert_eq!(d.as_str(), "héllo");
}

#[test]
fn constant_time() {
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd"));
    assert!(!constant_time_eq(b"abc", b"abcd"));
    assert_eq!(constant_time_compare(b"abc", b"abd"), core::cmp::Ordering::Less);
    assert_eq!(constant_time_compare(b"abc", b"abc"), core::cmp::Ordering::Equal);
}

#[test]
fn any_deferred() {
    let bytes = [0x02, 0x01, 0x07];
    let a = decode::<Any>(&bytes).unwrap();
    let i = a.decode_as::<Integer>().unwrap();
    assert_eq!(i.as_i64(), Some(7));
}

#[test]
fn integer_roundtrip_matrix() {
    fn int_bytes(v: i64) -> Vec<u8> {
        if v == 0 {
            return vec![0];
        }
        let mut bytes = v.to_be_bytes().to_vec();
        while bytes.len() > 1 {
            let (a, b) = (bytes[0], bytes[1]);
            if (a == 0x00 && (b & 0x80) == 0) || (a == 0xFF && (b & 0x80) != 0) {
                bytes.remove(0);
            } else {
                break;
            }
        }
        bytes
    }
    for v in [-128i64, -1, 0, 1, 127, 128, 255, 256, 65535, 65536, i64::MAX, i64::MIN] {
        let bytes = int_bytes(v);
        let enc = encode_to_vec(&Integer(&bytes)).unwrap();
        let dec = decode::<Integer>(&enc).unwrap();
        assert_eq!(dec.as_i64(), Some(v), "value {v} round-trip");
    }
}
