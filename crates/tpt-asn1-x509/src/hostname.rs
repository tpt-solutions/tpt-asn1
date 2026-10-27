// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hostname verification for server certificates (RFC 9525, which updates
//! RFC 6125).
//!
//! Only the subjectAltName is consulted. RFC 9525 §3 forbids falling back to the
//! subject Common Name, so a certificate without a matching SAN is rejected.
//! DNS matching is case-insensitive and ignores one trailing dot. A wildcard is
//! allowed only as the whole leftmost label, matches exactly one label, and must
//! be followed by at least two labels. This crate has no public-suffix list, so
//! a wildcard such as `*.co.uk` is accepted; callers that need that check must
//! apply it themselves.

use alloc::vec::Vec;
use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::str::FromStr;

use crate::certificate::Certificate;
use crate::extensions::GeneralName;
use tpt_asn1_core::error::Error;

/// Why a certificate does not identify a host.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HostnameError {
    /// The host is empty.
    EmptyHost,
    /// No subjectAltName entry matches the host.
    NoMatch,
    /// The subjectAltName extension could not be decoded.
    MalformedExtension(Error),
}

impl fmt::Display for HostnameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostnameError::EmptyHost => f.write_str("host is empty"),
            HostnameError::NoMatch => f.write_str("no subjectAltName matches the host"),
            HostnameError::MalformedExtension(e) => {
                write!(f, "malformed subjectAltName: {e}")
            }
        }
    }
}

/// Check that `cert` identifies `host`.
///
/// `host` is a DNS name, or an IPv4 or IPv6 address (IPv6 may be bracketed). An
/// address matches only an `iPAddress` entry with the same octets. A name matches
/// a `dNSName` entry.
pub fn verify_hostname(cert: &Certificate<'_>, host: &str) -> Result<(), HostnameError> {
    let host = host.strip_suffix('.').unwrap_or(host);
    let host = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(inner) => inner,
        None => host,
    };
    if host.is_empty() {
        return Err(HostnameError::EmptyHost);
    }
    let san = cert.tbs.extensions.subject_alt_name().map_err(HostnameError::MalformedExtension)?;
    let names = || san.iter().flat_map(|s| s.names.iter());

    let matched = match parse_ip(host) {
        Some(octets) => {
            names().any(|n| matches!(n, GeneralName::IpAddress(a) if *a == &octets[..]))
        }
        None => {
            let host = host.as_bytes();
            names().any(|n| matches!(n, GeneralName::DnsName(p) if dns_match(p, host)))
        }
    };
    if matched {
        Ok(())
    } else {
        Err(HostnameError::NoMatch)
    }
}

/// The octets of an IPv4 or IPv6 literal, or `None` if `host` is not one.
fn parse_ip(host: &str) -> Option<Vec<u8>> {
    if let Ok(v4) = Ipv4Addr::from_str(host) {
        return Some(v4.octets().to_vec());
    }
    Ipv6Addr::from_str(host).ok().map(|v6| v6.octets().to_vec())
}

/// Match one `dNSName` pattern against a host name, both as raw bytes.
fn dns_match(pattern: &[u8], host: &[u8]) -> bool {
    let pattern = pattern.strip_suffix(b".").unwrap_or(pattern);
    if pattern.is_empty() || host.is_empty() || host.contains(&b'*') {
        return false;
    }
    match pattern.strip_prefix(b"*.") {
        // The wildcard covers exactly one label, and the rest of the pattern
        // must hold at least two labels.
        Some(rest) => {
            if !rest.contains(&b'.') {
                return false;
            }
            match host.iter().position(|&b| b == b'.') {
                Some(dot) if dot > 0 => host[dot + 1..].eq_ignore_ascii_case(rest),
                _ => false,
            }
        }
        None => !pattern.contains(&b'*') && host.eq_ignore_ascii_case(pattern),
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::{dns_match, parse_ip, verify_hostname, HostnameError};
    use crate::certificate::Certificate;
    use tpt_asn1_core::decode::Decode;
    use tpt_asn1_core::reader::{Config, Reader};

    #[test]
    fn exact_names_match_case_insensitively() {
        assert!(dns_match(b"example.com", b"EXAMPLE.com"));
        assert!(dns_match(b"example.com.", b"example.com"));
        assert!(!dns_match(b"example.com", b"www.example.com"));
        assert!(!dns_match(b"example.com", b"example.co"));
    }

    #[test]
    fn wildcard_covers_exactly_one_label() {
        assert!(dns_match(b"*.example.com", b"www.example.com"));
        assert!(!dns_match(b"*.example.com", b"example.com"));
        assert!(!dns_match(b"*.example.com", b"a.b.example.com"));
        assert!(!dns_match(b"*.example.com", b".example.com"));
    }

    #[test]
    fn wildcard_must_be_leftmost_and_leave_two_labels() {
        assert!(!dns_match(b"*", b"localhost"));
        assert!(!dns_match(b"*.com", b"example.com"));
        assert!(!dns_match(b"w*.example.com", b"www.example.com"));
        assert!(!dns_match(b"www.*.com", b"www.example.com"));
        assert!(!dns_match(b"*.example.com", b"*.example.com"));
    }

    #[test]
    fn ip_literals_are_parsed() {
        assert_eq!(parse_ip("192.0.2.1"), Some(alloc::vec![192, 0, 2, 1]));
        assert_eq!(parse_ip("2001:db8::1").map(|v| v.len()), Some(16));
        assert_eq!(parse_ip("example.com"), None);
        assert_eq!(parse_ip("256.0.0.1"), None);
    }

    #[test]
    fn corpus_certificate_matches_its_own_san_only() {
        let der: &[u8] =
            include_bytes!("../tests/umbrella_corpus/1.courier-push-apple.com.akadns.net_.der");
        let Ok(cert) = Certificate::decode(&mut Reader::new(der, Config::der())) else {
            panic!("fixture must decode");
        };
        let Ok(Some(san)) = cert.tbs.extensions.subject_alt_name() else {
            panic!("fixture has a SAN");
        };
        let mut checked = 0;
        for name in &san.names {
            if let crate::extensions::GeneralName::DnsName(d) = name {
                let Ok(d) = core::str::from_utf8(d) else { continue };
                if d.contains('*') {
                    continue;
                }
                assert_eq!(verify_hostname(&cert, d), Ok(()));
                checked += 1;
            }
        }
        assert!(checked > 0, "fixture should carry a concrete DNS SAN");
        assert_eq!(verify_hostname(&cert, "nonexistent.invalid"), Err(HostnameError::NoMatch));
        assert_eq!(verify_hostname(&cert, ""), Err(HostnameError::EmptyHost));
    }
}
