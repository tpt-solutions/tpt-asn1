// SPDX-License-Identifier: MIT OR Apache-2.0

//! Throughput of the TLV reader on a small DER structure.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_core::types::Integer;

fn bench_read_integer(c: &mut Criterion) {
    let der = [0x02, 0x04, 0x01, 0x02, 0x03, 0x04];
    c.bench_function("read_tlv integer", |b| {
        b.iter(|| {
            let mut r = Reader::new(black_box(&der), Config::der());
            let _ = r.read_tlv().unwrap();
        })
    });
    c.bench_function("decode Integer", |b| {
        b.iter(|| {
            let mut r = Reader::new(black_box(&der), Config::der());
            let _ = Integer::decode(&mut r).unwrap();
        })
    });
}

criterion_group!(benches, bench_read_integer);
criterion_main!(benches);
