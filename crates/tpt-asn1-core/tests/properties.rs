//! Property-style tests with a deterministic generator. They stand in for
//! `proptest`, which the pinned 1.81 toolchain cannot build. Each property runs
//! over many generated values, and every failure reports the seed that produced it.

use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_core::types::{Integer, ObjectIdentifier, Utf8String};
use tpt_asn1_core::util::encode_signed_integer;
use tpt_asn1_core::writer::encode_to_vec;

/// xorshift64*: small, deterministic, and good enough to explore input shapes.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

const CASES: usize = 4000;

#[test]
fn signed_integers_round_trip_through_der() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for case in 0..CASES {
        // Mix small values, boundary values, and random 64-bit values.
        let value = match case % 3 {
            0 => (rng.next() % 512) as i64 - 256,
            1 => [i64::MIN, i64::MAX, -1, 0, 127, 128, -128, -129][case % 8],
            _ => rng.next() as i64,
        };
        let mut buf = [0u8; 9];
        let n = encode_signed_integer(value, &mut buf);
        let encoded = encode_to_vec(&Integer(&buf[..n])).expect("encodes");
        let decoded = Integer::decode(&mut Reader::new(&encoded, Config::der())).expect("decodes");
        assert_eq!(decoded.as_i64(), Some(value), "value {value} case {case}");
        // The minimal form is what DER requires, so re-encoding is byte-identical.
        let again = encode_to_vec(&decoded).expect("re-encodes");
        assert_eq!(again, encoded, "value {value} case {case}");
    }
}

#[test]
fn object_identifiers_round_trip_through_arcs() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for case in 0..CASES {
        // A valid OID: first arc 0-2, second arc below 40 unless the first is 2.
        let first = rng.next() % 3;
        let second = if first < 2 { rng.next() % 40 } else { rng.next() % 1000 };
        let mut arcs = vec![first, second];
        for _ in 0..(rng.next() % 6) {
            arcs.push(rng.next() % (1 << (rng.next() % 40)));
        }
        let content = encode_arcs(&arcs);
        let oid = ObjectIdentifier(&content);
        let back: Vec<u64> = oid.arcs().collect();
        assert_eq!(back, arcs, "case {case}");
        assert!(oid.matches(&arcs), "case {case}");
        // Encoding the decoded OID again gives the same bytes.
        assert_eq!(encode_arcs(&back), content, "case {case}");
    }
}

/// Base-128 encode an OID from its arcs (X.690 §8.19), for test inputs.
fn encode_arcs(arcs: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut subs = Vec::new();
    subs.push(arcs[0] * 40 + arcs[1]);
    subs.extend_from_slice(&arcs[2..]);
    for sub in subs {
        let mut groups = vec![(sub & 0x7f) as u8];
        let mut rest = sub >> 7;
        while rest > 0 {
            groups.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        groups.reverse();
        out.extend(groups);
    }
    out
}

#[test]
fn utf8_strings_round_trip_and_invalid_bytes_are_rejected() {
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    for case in 0..CASES {
        // Random bytes: valid UTF-8 must decode and round-trip; anything else must fail.
        let len = (rng.next() % 12) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let is_utf8 = core::str::from_utf8(&bytes).is_ok();
        let encoded = encode_tlv(0x0c, &bytes);
        let result = tpt_asn1_core::decode::<Utf8String>(&encoded);
        assert_eq!(result.is_ok(), is_utf8, "case {case}: {bytes:02x?}");
        if let Ok(value) = result {
            assert_eq!(value.as_bytes(), bytes.as_slice());
        }
    }
}

fn encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else {
        out.push(0x81);
        out.push(content.len() as u8);
    }
    out.extend_from_slice(content);
    out
}
