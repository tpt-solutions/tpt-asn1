//! Internal DER re-encode round-trip checks — a stand-in for the OpenSSL
//! byte-for-byte parity gate (which requires an external `openssl` binary not
//! present here). These confirm that encode -> decode -> encode is byte-stable
//! for canonical DER, which is the property parity testing relies on.

use tpt_asn1_core::{decode, Decode, Encode};
use tpt_asn1_core::types::{
    Integer, OctetString, Boolean, BitString, Null, ObjectIdentifier, Utf8String,
    PrintableString, Ia5String, UtcTime, GeneralizedTime, BmpString,
};
use tpt_asn1_core::writer::encode_to_vec;
use tpt_asn1_core::reader::{Reader, Config};
use tpt_asn1_core::decode::{read_sequence, read_set};
use tpt_asn1_core::writer::Writer;
use tpt_asn1_core::tag::Tag;

#[test]
fn primitive_der_roundtrip_is_stable() {
    // INTEGER
    let i = encode_to_vec(&Integer(&[0x01, 0x00])).unwrap();
    assert_eq!(decode::<Integer>(&i).unwrap().as_bytes(), &[0x01, 0x00]);
    let re = encode_to_vec(&decode::<Integer>(&i).unwrap()).unwrap();
    assert_eq!(i, re);

    // OCTET STRING
    let o = encode_to_vec(&OctetString(b"hello")).unwrap();
    assert_eq!(decode::<OctetString>(&o).unwrap().as_bytes(), b"hello");
    let re2 = encode_to_vec(&decode::<OctetString>(&o).unwrap()).unwrap();
    assert_eq!(o, re2);

    // BOOLEAN
    let b = encode_to_vec(&Boolean(true)).unwrap();
    assert_eq!(decode::<Boolean>(&b).unwrap().0, true);
    let re3 = encode_to_vec(&decode::<Boolean>(&b).unwrap()).unwrap();
    assert_eq!(b, re3);

    let b_false = encode_to_vec(&Boolean(false)).unwrap();
    assert_eq!(decode::<Boolean>(&b_false).unwrap().0, false);
    let re4 = encode_to_vec(&decode::<Boolean>(&b_false).unwrap()).unwrap();
    assert_eq!(b_false, re4);

    // BIT STRING
    let bs = encode_to_vec(&BitString { unused_bits: 0, data: &[0x01, 0x02, 0x03] }).unwrap();
    let decoded_bs = decode::<BitString>(&bs).unwrap();
    assert_eq!(decoded_bs.data, &[0x01, 0x02, 0x03]);
    assert_eq!(decoded_bs.unused_bits, 0);
    let re5 = encode_to_vec(&decoded_bs).unwrap();
    assert_eq!(bs, re5);

    // NULL
    let n = encode_to_vec(&Null).unwrap();
    let _ = decode::<Null>(&n).unwrap();
    let re6 = encode_to_vec(&decode::<Null>(&n).unwrap()).unwrap();
    assert_eq!(n, re6);

    // OBJECT IDENTIFIER
    let oid_bytes = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]; // 1.2.840.113549.1.1.11
    let oid = encode_to_vec(&ObjectIdentifier(oid_bytes)).unwrap();
    let decoded_oid = decode::<ObjectIdentifier>(&oid).unwrap();
    assert_eq!(decoded_oid.0, oid_bytes);
    let re7 = encode_to_vec(&decoded_oid).unwrap();
    assert_eq!(oid, re7);

    // UTF8String
    let utf8 = encode_to_vec(&Utf8String(b"hello world")).unwrap();
    let decoded_utf8 = decode::<Utf8String>(&utf8).unwrap();
    assert_eq!(decoded_utf8.0, b"hello world");
    let re8 = encode_to_vec(&decoded_utf8).unwrap();
    assert_eq!(utf8, re8);

    // PrintableString
    let ps = encode_to_vec(&PrintableString(b"HelloWorld123")).unwrap();
    let decoded_ps = decode::<PrintableString>(&ps).unwrap();
    assert_eq!(decoded_ps.0, b"HelloWorld123");
    let re9 = encode_to_vec(&decoded_ps).unwrap();
    assert_eq!(ps, re9);

    // IA5String
    let ia5 = encode_to_vec(&Ia5String(b"test@example.com")).unwrap();
    let decoded_ia5 = decode::<Ia5String>(&ia5).unwrap();
    assert_eq!(decoded_ia5.0, b"test@example.com");
    let re10 = encode_to_vec(&decoded_ia5).unwrap();
    assert_eq!(ia5, re10);

    // UTCTime
    let utc = encode_to_vec(&UtcTime(b"241231235959Z")).unwrap();
    let decoded_utc = decode::<UtcTime>(&utc).unwrap();
    assert_eq!(decoded_utc.0, b"241231235959Z");
    let re11 = encode_to_vec(&decoded_utc).unwrap();
    assert_eq!(utc, re11);

    // GeneralizedTime
    let gt = encode_to_vec(&GeneralizedTime(b"20241231235959Z")).unwrap();
    let decoded_gt = decode::<GeneralizedTime>(&gt).unwrap();
    assert_eq!(decoded_gt.0, b"20241231235959Z");
    let re12 = encode_to_vec(&decoded_gt).unwrap();
    assert_eq!(gt, re12);

    // BMPString - uses UCS-2 encoding (2 bytes per char)
    let bmp_input = &[0x00, 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74]; // "test" in UCS-2
    let bmp = encode_to_vec(&BmpString(bmp_input)).unwrap();
    let decoded_bmp = decode::<BmpString>(&bmp).unwrap();
    assert_eq!(decoded_bmp.0, bmp_input);
    let re13 = encode_to_vec(&decoded_bmp).unwrap();
    assert_eq!(bmp, re13);
}

#[test]
fn constructed_der_roundtrip_is_stable() {
    // Test SEQUENCE round-trip
    let mut writer = Writer::new_vec();
    writer.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
        Integer(&[0x01]).encode(w).unwrap();
        OctetString(b"test").encode(w).unwrap();
        Boolean(true).encode(w).unwrap();
        Ok(())
    }).unwrap();
    let seq_bytes = writer.into_vec();

    let mut reader = Reader::new(&seq_bytes, Config::der());
    let decoded_seq = read_sequence(&mut reader, |r| {
        let i = Integer::decode(r)?;
        let o = OctetString::decode(r)?;
        let b = Boolean::decode(r)?;
        Ok((i, o, b))
    }).unwrap();

    let mut writer2 = Writer::new_vec();
    writer2.nested(Tag::universal_constructed(Tag::SEQUENCE), |w| {
        decoded_seq.0.encode(w).unwrap();
        decoded_seq.1.encode(w).unwrap();
        decoded_seq.2.encode(w).unwrap();
        Ok(())
    }).unwrap();
    let re_seq = writer2.into_vec();
    assert_eq!(seq_bytes, re_seq);

    // Test SET round-trip (order should be preserved in DER)
    let mut writer3 = Writer::new_vec();
    writer3.nested(Tag::universal_constructed(Tag::SET), |w| {
        Integer(&[0x01]).encode(w).unwrap();
        Integer(&[0x02]).encode(w).unwrap();
        Integer(&[0x03]).encode(w).unwrap();
        Ok(())
    }).unwrap();
    let set_bytes = writer3.into_vec();

    let mut reader2 = Reader::new(&set_bytes, Config::der());
    let decoded_set = read_set(&mut reader2, |r| {
        let i1 = Integer::decode(r)?;
        let i2 = Integer::decode(r)?;
        let i3 = Integer::decode(r)?;
        Ok((i1, i2, i3))
    }).unwrap();

    let mut writer4 = Writer::new_vec();
    writer4.nested(Tag::universal_constructed(Tag::SET), |w| {
        decoded_set.0.encode(w).unwrap();
        decoded_set.1.encode(w).unwrap();
        decoded_set.2.encode(w).unwrap();
        Ok(())
    }).unwrap();
    let re_set = writer4.into_vec();
    assert_eq!(set_bytes, re_set);
}
