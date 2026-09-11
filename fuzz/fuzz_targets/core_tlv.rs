// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz target: raw TLV grammar under every encoding rule.
//!
//! Walks arbitrary bytes as a stream of TLVs — exercising tag decoding
//! (incl. the multi-byte high-tag-number form), length decoding (short /
//! long / indefinite), the end-of-contents scanner, and the recursion / size
//! guards — under DER, BER, and CER. The invariant under test is: arbitrary
//! bytes must never cause a panic, OOM, or stack overflow.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_asn1_core::reader::{Config, EncodingRule, Reader};

fn walk(data: &[u8], config: Config, depth: usize) {
    if depth > config.max_recursion {
        return;
    }
    let mut reader = Reader::new(data, config);
    while !reader.is_empty() {
        let Ok((tag, _length, value)) = reader.read_tlv() else { return };
        if tag.constructed {
            walk(value, config, depth + 1);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    for (name, config) in [
        ("der", Config::der()),
        ("ber", Config::ber()),
        ("cer", Config::cer()),
    ] {
        walk(data, config, 0);
        // The step above drives the grammar; the label exists so libFuzzer's
        // feature suppression keeps the three rules from collapsing coverage.
        let _ = name.len();
    }
    // Explicitly exercise the standalone single-TLV entry point too.
    for rule in [EncodingRule::Der, EncodingRule::Ber, EncodingRule::Cer] {
        let config = Config { rule, max_recursion: 32, max_element_size: 64 * 1024 * 1024 };
        let mut reader = Reader::new(data, config);
        let _ = reader.read_tlv();
    }
});