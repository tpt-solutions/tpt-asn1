// SPDX-License-Identifier: MIT OR Apache-2.0

//! Universal ASN.1 type decoders and encoders.
//!
//! Decoders borrow from the input wherever possible (e.g. `OctetString` holds a
//! `&[u8]`), keeping parsing allocation-free.

use crate::decode::{read_primitive, Decode, Encode};
use crate::error::{Error, Result};
use crate::reader::Reader;
use crate::tag::Tag;
use crate::writer::{WriteBackend, Writer};

/// ASN.1 `BOOLEAN`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Boolean(pub bool);

impl Boolean {
    /// The underlying boolean value.
    pub fn value(&self) -> bool {
        self.0
    }

    /// Decode from already-consumed-tag content bytes.
    pub fn decode_content(r: &mut Reader<'_>) -> Result<Self> {
        let bytes = r.read_remaining()?;
        Boolean::from_bytes(bytes, r.config().rule)
    }

    fn from_bytes(bytes: &[u8], rule: crate::reader::EncodingRule) -> Result<Self> {
        if bytes.len() != 1 {
            return Err(Error::MalformedBoolean);
        }
        let b = bytes[0];
        match b {
            0x00 => Ok(Boolean(false)),
            v if rule == crate::EncodingRule::Der => {
                if v == 0xFF {
                    Ok(Boolean(true))
                } else {
                    Err(Error::MalformedBoolean)
                }
            }
            _ => Ok(Boolean(true)),
        }
    }
}

impl<'a> Decode<'a> for Boolean {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let bytes = read_primitive(r, Tag::universal(Tag::BOOLEAN))?;
        Boolean::from_bytes(bytes, r.config().rule)
    }
}

impl Encode for Boolean {
    fn encode<W: WriteBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        w.write_primitive(Tag::universal(Tag::BOOLEAN), &[if self.0 { 0xFF } else { 0x00 }])
    }
}

/// ASN.1 `INTEGER`, stored as its raw big-endian byte encoding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Integer<'a>(pub &'a [u8]);

impl<'a> Integer<'a> {
    /// The raw encoding bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Interpret as `i64`, if it fits and is minimally encoded (DER).
    pub fn as_i64(&self) -> Option<i64> {
        if self.0.len() > 8 || self.0.is_empty() {
            return None;
        }
        let mut v: i64 = (self.0[0] as i8) as i64;
        for b in &self.0[1..] {
            v = (v << 8) | *b as i64;
        }
        Some(v)
    }

    /// Interpret as `u64`, if it is non-negative and fits.
    pub fn as_u64(&self) -> Option<u64> {
        if self.0.len() > 8 || self.0.is_empty() {
            return None;
        }
        if self.0[0] & 0x80 != 0 {
            return None;
        }
        let mut v: u64 = self.0[0] as u64;
        for b in &self.0[1..] {
            v = (v << 8) | *b as u64;
        }
        Some(v)
    }
}

impl<'a> Integer<'a> {
    /// Decode from already-consumed-tag content bytes.
    pub fn decode_content(r: &mut Reader<'a>) -> Result<Self> {
        let bytes = r.read_remaining()?;
        Integer::from_bytes(bytes, r.config().rule)
    }

    fn from_bytes(bytes: &'a [u8], rule: crate::reader::EncodingRule) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::Custom("INTEGER must have at least one byte"));
        }
        if rule != crate::EncodingRule::Ber {
            // Reject non-minimal encodings: no redundant leading sign byte.
            if bytes.len() >= 2
                && ((bytes[0] == 0x00 && (bytes[1] & 0x80) == 0)
                    || (bytes[0] == 0xFF && (bytes[1] & 0x80) != 0))
            {
                return Err(Error::IntegerNotMinimal);
            }
        }
        Ok(Integer(bytes))
    }
}

impl<'a> Decode<'a> for Integer<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let bytes = read_primitive(r, Tag::universal(Tag::INTEGER))?;
        Integer::from_bytes(bytes, r.config().rule)
    }
}

impl Encode for Integer<'_> {
    fn encode<W: WriteBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        w.write_primitive(Tag::universal(Tag::INTEGER), self.0)
    }
}

/// ASN.1 `ENUMERATED`, stored as its raw big-endian byte encoding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Enumerated<'a>(pub &'a [u8]);

impl<'a> Enumerated<'a> {
    /// The raw encoding bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Interpret as `i64`, if it fits.
    pub fn as_i64(&self) -> Option<i64> {
        Integer(self.0).as_i64()
    }

    /// Decode from already-consumed-tag content bytes.
    pub fn decode_content(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Enumerated(r.read_remaining()?))
    }
}

impl<'a> Decode<'a> for Enumerated<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let bytes = read_primitive(r, Tag::universal(Tag::ENUMERATED))?;
        Ok(Enumerated(bytes))
    }
}

impl Encode for Enumerated<'_> {
    fn encode<W: WriteBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        w.write_primitive(Tag::universal(Tag::ENUMERATED), self.0)
    }
}

/// ASN.1 `BIT STRING`: unused-bits count plus the (borrowed) data octets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BitString<'a> {
    /// Number of unused bits in the final octet (0..=7).
    pub unused_bits: u8,
    /// The data octets.
    pub data: &'a [u8],
}

impl<'a> BitString<'a> {
    /// The usable bits across all octets.
    pub fn bit_len(&self) -> usize {
        self.data.len() * 8 - self.unused_bits as usize
    }
}

impl<'a> BitString<'a> {
    /// Decode from already-consumed-tag content bytes.
    pub fn decode_content(r: &mut Reader<'a>) -> Result<Self> {
        let bytes = r.read_remaining()?;
        BitString::from_bytes(bytes)
    }

    fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::BadBitString);
        }
        let unused_bits = bytes[0];
        if unused_bits > 7 {
            return Err(Error::BadBitString);
        }
        let data = &bytes[1..];
        if !data.is_empty() && unused_bits != 0 {
            let last = data[data.len() - 1];
            if last & ((1u8 << unused_bits) - 1) != 0 {
                return Err(Error::BadBitString);
            }
        }
        Ok(BitString { unused_bits, data })
    }
}

impl<'a> Decode<'a> for BitString<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let bytes = read_primitive(r, Tag::universal(Tag::BIT_STRING))?;
        BitString::from_bytes(bytes)
    }
}

impl Encode for BitString<'_> {
    fn encode<W: WriteBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        w.write_tag(Tag::universal(Tag::BIT_STRING))?;
        w.write_length(crate::length::Length::Definite(1 + self.data.len()))?;
        w.write_u8(self.unused_bits)?;
        w.write_bytes(self.data)
    }
}

/// ASN.1 `OCTET STRING`, borrowing its bytes from the input.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OctetString<'a>(pub &'a [u8]);

impl<'a> OctetString<'a> {
    /// The contained bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

impl<'a> OctetString<'a> {
    /// Decode from already-consumed-tag content bytes.
    pub fn decode_content(r: &mut Reader<'a>) -> Result<Self> {
        Ok(OctetString(r.read_remaining()?))
    }
}

impl<'a> Decode<'a> for OctetString<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let bytes = read_primitive(r, Tag::universal(Tag::OCTET_STRING))?;
        Ok(OctetString(bytes))
    }
}

impl Encode for OctetString<'_> {
    fn encode<W: WriteBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        w.write_primitive(Tag::universal(Tag::OCTET_STRING), self.0)
    }
}

/// ASN.1 `NULL`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Null;

impl Null {
    /// Decode from already-consumed-tag content bytes.
    pub fn decode_content(r: &mut Reader<'_>) -> Result<Self> {
        if !r.read_remaining()?.is_empty() {
            return Err(Error::Custom("NULL must have zero length"));
        }
        Ok(Null)
    }
}

impl<'a> Decode<'a> for Null {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let bytes = read_primitive(r, Tag::universal(Tag::NULL))?;
        if !bytes.is_empty() {
            return Err(Error::Custom("NULL must have zero length"));
        }
        Ok(Null)
    }
}

impl Encode for Null {
    fn encode<W: WriteBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        w.write_primitive(Tag::universal(Tag::NULL), &[])
    }
}

/// ASN.1 `OBJECT IDENTIFIER`, stored as its raw subidentifier byte encoding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ObjectIdentifier<'a>(pub &'a [u8]);

impl<'a> ObjectIdentifier<'a> {
    /// Iterate the on-wire base-128 subidentifiers.
    pub fn arcs(&self) -> OidIter<'a> {
        OidIter { remaining: self.0 }
    }

    /// The raw object-identifier subidentifier bytes (the value content).
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Returns `true` if this OID's components equal `expected`, splitting the
    /// combined first subidentifier into arcs 0 and 1 per X.660.
    pub fn matches(&self, expected: &[u64]) -> bool {
        let bytes = self.0;
        let mut pos = 0;
        let mut combined: u64 = 0;
        let mut got = false;
        while pos < bytes.len() {
            let b = bytes[pos];
            pos += 1;
            combined = (combined << 7) | (b & 0x7f) as u64;
            if b & 0x80 == 0 {
                got = true;
                break;
            }
        }
        if !got {
            return false;
        }
        let a0 = if combined < 40 {
            0
        } else if combined < 80 {
            1
        } else {
            2
        };
        let a1 = combined - a0 * 40;
        if expected.first() != Some(&a0) || expected.get(1) != Some(&a1) {
            return false;
        }
        let mut idx = 2;
        let mut value: u64 = 0;
        while pos < bytes.len() {
            let b = bytes[pos];
            pos += 1;
            value = (value << 7) | (b & 0x7f) as u64;
            if b & 0x80 == 0 {
                if idx >= expected.len() || expected[idx] != value {
                    return false;
                }
                idx += 1;
                value = 0;
            }
        }
        idx == expected.len()
    }
}

/// Iterator over an OID's base-128 subidentifiers.
#[derive(Clone)]
pub struct OidIter<'a> {
    remaining: &'a [u8],
}

impl<'a> Iterator for OidIter<'a> {
    type Item = u64;
    fn next(&mut self) -> Option<u64> {
        if self.remaining.is_empty() {
            return None;
        }
        let mut value: u64 = 0;
        loop {
            let b = self.remaining[0];
            self.remaining = &self.remaining[1..];
            value = (value << 7) | (b & 0x7f) as u64;
            if b & 0x80 == 0 {
                return Some(value);
            }
            if self.remaining.is_empty() {
                return None;
            }
        }
    }
}

impl<'a> ObjectIdentifier<'a> {
    /// Decode from already-consumed-tag content bytes.
    pub fn decode_content(r: &mut Reader<'a>) -> Result<Self> {
        let bytes = r.read_remaining()?;
        if bytes.is_empty() {
            return Err(Error::BadObjectIdentifier);
        }
        if bytes[0] == 0x80 {
            return Err(Error::BadObjectIdentifier);
        }
        Ok(ObjectIdentifier(bytes))
    }
}

impl<'a> Decode<'a> for ObjectIdentifier<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let bytes = read_primitive(r, Tag::universal(Tag::OBJECT_IDENTIFIER))?;
        if bytes.is_empty() {
            return Err(Error::BadObjectIdentifier);
        }
        // Every subidentifier except the first must use a leading 0x80 byte if
        // it would otherwise be empty (value 0 is fine otherwise). Light check:
        // ensure the first subidentifier does not start with 0x80 (empty arc).
        if bytes[0] == 0x80 {
            return Err(Error::BadObjectIdentifier);
        }
        Ok(ObjectIdentifier(bytes))
    }
}

impl Encode for ObjectIdentifier<'_> {
    fn encode<W: WriteBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        w.write_primitive(Tag::universal(Tag::OBJECT_IDENTIFIER), self.0)
    }
}

/// ASN.1 `RELATIVE-OID`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RelativeOid<'a>(pub &'a [u8]);

impl<'a> RelativeOid<'a> {
    /// Decode from already-consumed-tag content bytes.
    pub fn decode_content(r: &mut Reader<'a>) -> Result<Self> {
        let bytes = r.read_remaining()?;
        if bytes.is_empty() {
            return Err(Error::BadObjectIdentifier);
        }
        Ok(RelativeOid(bytes))
    }
}

impl<'a> Decode<'a> for RelativeOid<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let bytes = read_primitive(r, Tag::universal(Tag::RELATIVE_OID))?;
        if bytes.is_empty() {
            return Err(Error::BadObjectIdentifier);
        }
        Ok(RelativeOid(bytes))
    }
}

impl Encode for RelativeOid<'_> {
    fn encode<W: WriteBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        w.write_primitive(Tag::universal(Tag::RELATIVE_OID), self.0)
    }
}

/// A parsed date-time value (no timezone conversion performed).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DateTime {
    /// Full year (e.g. 2026).
    pub year: u16,
    /// Month 1..=12.
    pub month: u8,
    /// Day 1..=31.
    pub day: u8,
    /// Hour 0..=23.
    pub hour: u8,
    /// Minute 0..=59.
    pub minute: u8,
    /// Second 0..=59 (60 reserved for leap seconds, not accepted).
    pub second: u8,
    /// Number of fractional-second digits (0 = none).
    pub frac_digits: u8,
    /// Timezone: `None` for UTC ('Z'), or an offset in minutes (east positive).
    pub tz_offset_minutes: Option<i32>,
}

/// ASN.1 `UTCTime`, stored as its raw bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UtcTime<'a>(pub &'a [u8]);

impl<'a> UtcTime<'a> {
    /// Parse the time value.
    pub fn parse(&self) -> Result<DateTime> {
        parse_time(self.0, true)
    }
}

impl<'a> UtcTime<'a> {
    /// Decode from already-consumed-tag content bytes.
    pub fn decode_content(r: &mut Reader<'a>) -> Result<Self> {
        Ok(UtcTime(r.read_remaining()?))
    }
}

impl<'a> Decode<'a> for UtcTime<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let bytes = read_primitive(r, Tag::universal(Tag::UTC_TIME))?;
        Ok(UtcTime(bytes))
    }
}

impl Encode for UtcTime<'_> {
    fn encode<W: WriteBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        w.write_primitive(Tag::universal(Tag::UTC_TIME), self.0)
    }
}

/// ASN.1 `GeneralizedTime`, stored as its raw bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GeneralizedTime<'a>(pub &'a [u8]);

impl<'a> GeneralizedTime<'a> {
    /// Parse the time value.
    pub fn parse(&self) -> Result<DateTime> {
        parse_time(self.0, false)
    }
}

impl<'a> GeneralizedTime<'a> {
    /// Decode from already-consumed-tag content bytes.
    pub fn decode_content(r: &mut Reader<'a>) -> Result<Self> {
        Ok(GeneralizedTime(r.read_remaining()?))
    }
}

impl<'a> Decode<'a> for GeneralizedTime<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let bytes = read_primitive(r, Tag::universal(Tag::GENERALIZED_TIME))?;
        Ok(GeneralizedTime(bytes))
    }
}

impl Encode for GeneralizedTime<'_> {
    fn encode<W: WriteBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        w.write_primitive(Tag::universal(Tag::GENERALIZED_TIME), self.0)
    }
}

fn peek(b: &[u8], i: usize) -> Option<u8> {
    b.get(i).copied()
}

fn take_digits(b: &[u8], i: &mut usize, n: usize) -> Result<u32> {
    let mut v = 0u32;
    for _ in 0..n {
        match peek(b, *i) {
            Some(c) if c.is_ascii_digit() => {
                v = v * 10 + (c - b'0') as u32;
                *i += 1;
            }
            _ => return Err(Error::BadTime),
        }
    }
    Ok(v)
}

fn parse_time(bytes: &[u8], is_utc: bool) -> Result<DateTime> {
    let s = core::str::from_utf8(bytes).map_err(|_| Error::BadTime)?;
    let b = s.as_bytes();
    let mut i = 0usize;

    let year = if is_utc {
        let yy = take_digits(b, &mut i, 2)? as u16;
        if yy >= 50 {
            1900 + yy
        } else {
            2000 + yy
        }
    } else {
        take_digits(b, &mut i, 4)? as u16
    };
    let month = take_digits(b, &mut i, 2)? as u8;
    let day = take_digits(b, &mut i, 2)? as u8;
    let hour = take_digits(b, &mut i, 2)? as u8;
    let minute = take_digits(b, &mut i, 2)? as u8;
    let second = take_digits(b, &mut i, 2)? as u8;
    if month == 0 || month > 12 || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 59 {
        return Err(Error::BadTime);
    }

    let mut frac_digits = 0u8;
    if peek(b, i) == Some(b'.') {
        i += 1;
        while peek(b, i) == Some(b'0')
            || peek(b, i) == Some(b'1')
            || peek(b, i) == Some(b'2')
            || peek(b, i) == Some(b'3')
            || peek(b, i) == Some(b'4')
            || peek(b, i) == Some(b'5')
            || peek(b, i) == Some(b'6')
            || peek(b, i) == Some(b'7')
            || peek(b, i) == Some(b'8')
            || peek(b, i) == Some(b'9')
        {
            frac_digits += 1;
            i += 1;
        }
        if frac_digits == 0 {
            return Err(Error::BadTime);
        }
    }

    let tz = match peek(b, i) {
        None => return Err(Error::BadTime),
        Some(b'Z') => None,
        Some(b'+') | Some(b'-') => {
            let sign = if peek(b, i) == Some(b'+') { 1 } else { -1 };
            i += 1;
            let oh = take_digits(b, &mut i, 2)? as i32;
            let om = take_digits(b, &mut i, 2)? as i32;
            if i != b.len() {
                return Err(Error::BadTime);
            }
            Some(sign * (oh * 60 + om))
        }
        _ => return Err(Error::BadTime),
    };

    Ok(DateTime { year, month, day, hour, minute, second, frac_digits, tz_offset_minutes: tz })
}

// --- String types --------------------------------------------------------

fn validate_utf8(b: &[u8]) -> Result<()> {
    core::str::from_utf8(b).map(|_| ()).map_err(|_| Error::BadUtf8)
}

fn is_in_set(b: &[u8], allowed: &[u8]) -> bool {
    b.iter().all(|c| allowed.contains(c))
}

fn validate_printable(b: &[u8]) -> Result<()> {
    const P: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?";
    if is_in_set(b, P) {
        Ok(())
    } else {
        Err(Error::BadStringType)
    }
}

fn validate_ia5(b: &[u8]) -> Result<()> {
    if b.iter().all(|c| *c < 0x80) {
        Ok(())
    } else {
        Err(Error::BadStringType)
    }
}

fn validate_numeric(b: &[u8]) -> Result<()> {
    const N: &[u8] = b"0123456789 ";
    if is_in_set(b, N) {
        Ok(())
    } else {
        Err(Error::BadStringType)
    }
}

fn validate_visible(b: &[u8]) -> Result<()> {
    // VisibleString: printable ASCII excluding space (0x21..=0x7E).
    if b.iter().all(|c| (0x21..=0x7e).contains(c)) {
        Ok(())
    } else {
        Err(Error::BadStringType)
    }
}

macro_rules! string_newtype {
    ($name:ident, $tag:expr, $validate:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub struct $name<'a>(pub &'a [u8]);

        impl<'a> $name<'a> {
            /// The raw string bytes.
            pub fn as_bytes(&self) -> &'a [u8] {
                self.0
            }

            /// Decode from already-consumed-tag content bytes.
            pub fn decode_content(r: &mut Reader<'a>) -> Result<Self> {
                let b = r.read_remaining()?;
                ($validate)(b)?;
                Ok($name(b))
            }
        }

        impl<'a> Decode<'a> for $name<'a> {
            fn decode(r: &mut Reader<'a>) -> Result<Self> {
                let bytes = read_primitive(r, Tag::universal($tag))?;
                ($validate)(bytes)?;
                Ok($name(bytes))
            }
        }

        impl Encode for $name<'_> {
            fn encode<W: WriteBackend>(&self, w: &mut Writer<W>) -> Result<()> {
                w.write_primitive(Tag::universal($tag), self.0)
            }
        }
    };
}

string_newtype!(Utf8String, Tag::UTF8_STRING, validate_utf8, "ASN.1 `UTF8String`.");
impl<'a> Utf8String<'a> {
    /// Interpret as `str` (validated as UTF-8 on decode).
    pub fn as_str(&self) -> &'a str {
        core::str::from_utf8(self.0).unwrap_or("")
    }
}

string_newtype!(
    PrintableString,
    Tag::PRINTABLE_STRING,
    validate_printable,
    "ASN.1 `PrintableString`."
);
string_newtype!(Ia5String, Tag::IA5_STRING, validate_ia5, "ASN.1 `IA5String`.");
string_newtype!(NumericString, Tag::NUMERIC_STRING, validate_numeric, "ASN.1 `NumericString`.");
string_newtype!(
    VisibleString,
    Tag::VISIBLE_STRING,
    validate_visible,
    "ASN.1 `VisibleString` (ISO646)."
);
string_newtype!(
    TeletexString,
    Tag::TELETEX_STRING,
    |_| Ok(()),
    "ASN.1 `TeletexString` / `T61String`."
);
string_newtype!(VideotexString, Tag::VIDEOTEX_STRING, |_| Ok(()), "ASN.1 `VideotexString`.");
string_newtype!(GraphicString, Tag::GRAPHIC_STRING, |_| Ok(()), "ASN.1 `GraphicString`.");
string_newtype!(GeneralString, Tag::GENERAL_STRING, |_| Ok(()), "ASN.1 `GeneralString`.");
string_newtype!(
    UniversalString,
    Tag::UNIVERSAL_STRING,
    |_| Ok(()),
    "ASN.1 `UniversalString` (UCS-4)."
);
string_newtype!(CharacterString, Tag::CHARACTER_STRING, |_| Ok(()), "ASN.1 `CHARACTER STRING`.");
string_newtype!(BmpString, Tag::BMP_STRING, |_| Ok(()), "ASN.1 `BMPString` (UCS-2).");
string_newtype!(ObjectDescriptor, Tag::OBJECT_DESCRIPTOR, |_| Ok(()), "ASN.1 `ObjectDescriptor`.");
