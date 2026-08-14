// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared cryptographic-safety primitives.

/// Compare two byte slices in constant time.
///
/// Returns `true` if the slices are equal in length and content. The runtime
/// does not branch on or short-circuit from the content, mitigating timing
/// side channels for signature / MAC / tag comparisons.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Encode `value` as a minimal big-endian two's-complement ASN.1 `INTEGER`
/// content into `out`, returning the number of bytes written (1..=9).
///
/// The result is the canonical (DER) minimal encoding used for `INTEGER` and
/// `ENUMERATED` values.
pub fn encode_signed_integer(value: i64, out: &mut [u8; 9]) -> usize {
    // Build little-endian with possible leading sign byte, then reverse.
    let mut buf = [0u8; 9];
    let mut i = 0usize;
    let mut v = value;
    loop {
        buf[i] = (v & 0xff) as u8;
        i += 1;
        v >>= 8;
        let top = buf[i - 1];
        // Stop once the remaining bits are pure sign extension.
        if (v == 0 && (top & 0x80) == 0) || (v == -1 && (top & 0x80) != 0) {
            break;
        }
        if i == 9 {
            break;
        }
    }
    for k in 0..i {
        out[k] = buf[i - 1 - k];
    }
    i
}

/// Compare two byte slices, returning `Ordering::Equal` only when they are
/// byte-for-byte equal, in constant time.
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    if a.len() != b.len() {
        return if a.len() < b.len() {
            core::cmp::Ordering::Less
        } else {
            core::cmp::Ordering::Greater
        };
    }
    let mut diff: u8 = 0;
    let mut first_diff: i32 = -1;
    for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
        let neq = (x ^ y) as i32;
        // Record the index of the first differing byte without branching on it.
        if first_diff < 0 && neq != 0 {
            first_diff = i as i32;
        }
        diff |= neq as u8;
    }
    if diff == 0 {
        core::cmp::Ordering::Equal
    } else if first_diff >= 0 && (a[first_diff as usize] < b[first_diff as usize]) {
        core::cmp::Ordering::Less
    } else {
        core::cmp::Ordering::Greater
    }
}
