// SPDX-License-Identifier: MIT OR Apache-2.0

//! ASN.1 [`Tag`] and [`Class`] types.

use crate::error::{Error, Result};
use crate::reader::Reader;
use crate::writer::{WriteBackend, Writer};

/// ASN.1 tag class.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Class {
    /// The ASN.1 universal (built-in) tag space.
    Universal = 0,
    /// Application-specific tags.
    Application = 1,
    /// Context-specific tags (e.g. IMPLICIT/EXPLICIT fields).
    Context = 2,
    /// Private-use tags.
    Private = 3,
}

impl Class {
    /// Recover a `Class` from its two-bit encoding.
    pub fn from_bits(bits: u8) -> Option<Class> {
        match bits {
            0 => Some(Class::Universal),
            1 => Some(Class::Application),
            2 => Some(Class::Context),
            3 => Some(Class::Private),
            _ => None,
        }
    }

    /// The two-bit encoding of this class.
    pub fn to_bits(self) -> u8 {
        self as u8
    }
}

/// An ASN.1 tag: class + primitive/constructed flag + tag number.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct Tag {
    /// Tag class.
    pub class: Class,
    /// Whether the value is constructed (vs. primitive).
    pub constructed: bool,
    /// The tag number within its class.
    pub number: u32,
}

impl Tag {
    /// Universal tag numbers for the ASN.1 built-in types.
    pub const BOOLEAN: u32 = 1;
    /// INTEGER.
    pub const INTEGER: u32 = 2;
    /// BIT STRING.
    pub const BIT_STRING: u32 = 3;
    /// OCTET STRING.
    pub const OCTET_STRING: u32 = 4;
    /// NULL.
    pub const NULL: u32 = 5;
    /// OBJECT IDENTIFIER.
    pub const OBJECT_IDENTIFIER: u32 = 6;
    /// OBJECT DESCRIPTOR.
    pub const OBJECT_DESCRIPTOR: u32 = 7;
    /// EXTERNAL.
    pub const EXTERNAL: u32 = 8;
    /// REAL.
    pub const REAL: u32 = 9;
    /// ENUMERATED.
    pub const ENUMERATED: u32 = 10;
    /// EMBEDDED PDV.
    pub const EMBEDDED_PDV: u32 = 11;
    /// UTF8String.
    pub const UTF8_STRING: u32 = 12;
    /// RELATIVE-OID.
    pub const RELATIVE_OID: u32 = 13;
    /// SEQUENCE / SEQUENCE OF.
    pub const SEQUENCE: u32 = 16;
    /// SET / SET OF.
    pub const SET: u32 = 17;
    /// NumericString.
    pub const NUMERIC_STRING: u32 = 18;
    /// PrintableString.
    pub const PRINTABLE_STRING: u32 = 19;
    /// TeletexString / T61String.
    pub const TELETEX_STRING: u32 = 20;
    /// VideotexString.
    pub const VIDEOTEX_STRING: u32 = 21;
    /// IA5String.
    pub const IA5_STRING: u32 = 22;
    /// UTCTime.
    pub const UTC_TIME: u32 = 23;
    /// GeneralizedTime.
    pub const GENERALIZED_TIME: u32 = 24;
    /// GraphicString.
    pub const GRAPHIC_STRING: u32 = 25;
    /// VisibleString / ISO646String.
    pub const VISIBLE_STRING: u32 = 26;
    /// GeneralString.
    pub const GENERAL_STRING: u32 = 27;
    /// UniversalString.
    pub const UNIVERSAL_STRING: u32 = 28;
    /// CHARACTER STRING.
    pub const CHARACTER_STRING: u32 = 29;
    /// BMPString.
    pub const BMP_STRING: u32 = 30;

    /// Construct a tag.
    pub const fn new(class: Class, constructed: bool, number: u32) -> Self {
        Tag { class, constructed, number }
    }

    /// Construct a universal tag.
    pub const fn universal(number: u32) -> Self {
        Tag::new(Class::Universal, false, number)
    }

    /// Construct a universal *constructed* tag (e.g. SEQUENCE / SET).
    pub const fn universal_constructed(number: u32) -> Self {
        Tag::new(Class::Universal, true, number)
    }

    /// Construct a context-specific tag.
    pub const fn context(constructed: bool, number: u32) -> Self {
        Tag::new(Class::Context, constructed, number)
    }

    /// Returns `true` if this is the universal tag `number`.
    pub fn is_universal(self, number: u32) -> bool {
        self.class == Class::Universal && self.number == number
    }

    /// The first tag byte (short form). Panics in const-eval if `number >= 31`
    /// because the high-tag-number form requires multiple bytes.
    pub fn to_byte(self) -> u8 {
        if self.number >= 31 {
            panic!("tag number >= 31 requires high-tag-number form; use encode()");
        }
        (self.class.to_bits() << 6)
            | if self.constructed { 0x20 } else { 0x00 }
            | (self.number as u8 & 0x1f)
    }

    /// Encode the tag into `w`. Supports the multi-byte high-tag-number form.
    pub fn encode<B: WriteBackend>(&self, w: &mut Writer<B>) -> Result<()> {
        let first = (self.class.to_bits() << 6) | if self.constructed { 0x20 } else { 0x00 };
        if self.number < 31 {
            w.write_u8(first | (self.number as u8 & 0x1f))
        } else {
            w.write_u8(first | 0x1f)?;
            encode_high_tag_number(self.number, w)
        }
    }

    /// Decode a tag from `r`.
    pub fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let first = r.read_u8()?;
        let class = Class::from_bits(first >> 6).ok_or(Error::InvalidTag)?;
        let constructed = (first & 0x20) != 0;
        let low = first & 0x1f;
        let number = if low < 31 { low as u32 } else { decode_high_tag_number(r)? };
        Ok(Tag { class, constructed, number })
    }
}

fn encode_high_tag_number<B: WriteBackend>(mut number: u32, w: &mut Writer<B>) -> Result<()> {
    let mut buf = [0u8; 5];
    let mut i = buf.len();
    buf[i - 1] = (number & 0x7f) as u8;
    number >>= 7;
    while number > 0 {
        i -= 1;
        buf[i - 1] = 0x80 | (number & 0x7f) as u8;
        number >>= 7;
    }
    w.write_bytes(&buf[i - 1..])
}

fn decode_high_tag_number(r: &mut Reader<'_>) -> Result<u32> {
    let mut number: u32 = 0;
    let mut shifted = false;
    loop {
        let b = r.read_u8()?;
        if number > (u32::MAX >> 7) {
            return Err(Error::UnsupportedTagNumber(u32::MAX));
        }
        number = (number << 7) | (b & 0x7f) as u32;
        if b & 0x80 == 0 {
            break;
        }
        shifted = true;
    }
    if number < 31 && shifted {
        return Err(Error::InvalidTag);
    }
    Ok(number)
}
