// SPDX-License-Identifier: MIT OR Apache-2.0

//! X.509 `Time` and `Validity` handling, including conversion to a comparable
//! Unix-epoch integer so that `no_std` callers (which have no clock) can supply
//! a current time as a simple `i64`.

use tpt_asn1_core::any::Any;
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::error::{Error, Result};
use tpt_asn1_core::reader::Reader;
use tpt_asn1_core::tag::Tag;
use tpt_asn1_core::types::{DateTime, GeneralizedTime, UtcTime};

/// A point in time expressed as seconds since the Unix epoch (1970-01-01T00:00:00Z).
///
/// RFC 5280 `validity` checks take a `UnixTime` supplied by the caller; this
/// keeps the crate `no_std` and free of any wall-clock dependency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixTime(pub i64);

impl UnixTime {
    /// Construct from a Unix-epoch second count.
    pub fn from_secs(secs: i64) -> Self {
        UnixTime(secs)
    }

    /// The underlying second count.
    pub fn as_secs(&self) -> i64 {
        self.0
    }
}

/// An X.509 `Time` — `CHOICE { utcTime UTCTime, generalTime GeneralizedTime }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Time<'a> {
    inner: TimeInner<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TimeInner<'a> {
    Utc(UtcTime<'a>),
    General(GeneralizedTime<'a>),
}

impl<'a> Time<'a> {
    /// The raw `UTCTime` bytes, if this is a `UTCTime`.
    pub fn as_utc_bytes(&self) -> Option<&'a [u8]> {
        match self.inner {
            TimeInner::Utc(u) => Some(u.0),
            _ => None,
        }
    }

    /// The raw `GeneralizedTime` bytes, if this is a `GeneralizedTime`.
    pub fn as_general_bytes(&self) -> Option<&'a [u8]> {
        match self.inner {
            TimeInner::General(g) => Some(g.0),
            _ => None,
        }
    }

    /// Parse this `Time` to a [`DateTime`].
    pub fn parse(&self) -> Result<DateTime> {
        match self.inner {
            TimeInner::Utc(u) => u.parse(),
            TimeInner::General(g) => g.parse(),
        }
    }

    /// Convert this `Time` to a [`UnixTime`] (seconds since the epoch).
    ///
    /// Fractional seconds are truncated; timezone offsets are applied so the
    /// result is always UTC. Leap seconds are not represented.
    pub fn to_unix(self) -> Result<UnixTime> {
        let dt = self.parse()?;
        to_unix_seconds(&dt).map(UnixTime)
    }
}

impl<'a> Decode<'a> for Time<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let any = Any::decode(r)?;
        if any.tag.is_universal(Tag::UTC_TIME) {
            Ok(Time { inner: TimeInner::Utc(UtcTime(any.value)) })
        } else if any.tag.is_universal(Tag::GENERALIZED_TIME) {
            Ok(Time { inner: TimeInner::General(GeneralizedTime(any.value)) })
        } else {
            Err(Error::UnexpectedTag {
                expected: Tag::universal(Tag::UTC_TIME),
                actual: any.tag,
            })
        }
    }
}

/// An X.509 `Validity` — `SEQUENCE { notBefore Time, notAfter Time }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validity<'a> {
    /// The time before which the certificate is not valid.
    pub not_before: Time<'a>,
    /// The time after which the certificate is not valid.
    pub not_after: Time<'a>,
}

impl<'a> Validity<'a> {
    /// Returns `true` if `now` lies within `[notBefore, notAfter]`.
    pub fn contains(&self, now: UnixTime) -> bool {
        match (self.not_before.to_unix(), self.not_after.to_unix()) {
            (Ok(nb), Ok(na)) => nb <= now && now <= na,
            _ => false,
        }
    }
}

impl<'a> Decode<'a> for Validity<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        tpt_asn1_core::decode::read_sequence(r, |inner| {
            let not_before = Time::decode(inner)?;
            let not_after = Time::decode(inner)?;
            Ok(Validity { not_before, not_after })
        })
    }
}

/// Convert a [`DateTime`] (already validated) to Unix-epoch seconds using
/// Howard Hinnant's `days_from_civil` civil-date algorithm, which is exact for
/// any valid Gregorian date.
fn to_unix_seconds(dt: &DateTime) -> Result<i64> {
    // Howard Hinnant's `days_from_civil`: the months January and February are
    // counted as the final months (11 and 12) of the *previous* year, so the
    // year is decremented when `month <= 2`.
    let y = dt.year as i64 - if dt.month <= 2 { 1 } else { 0 };
    let m = dt.month as i64;
    let d = dt.day as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146097 + doe - 719468;

    let secs = days * 86_400
        + (dt.hour as i64) * 3600
        + (dt.minute as i64) * 60
        + (dt.second as i64);

    let offset = dt.tz_offset_minutes.unwrap_or(0) as i64 * 60;
    secs.checked_sub(offset).ok_or(Error::BadTime)
}
