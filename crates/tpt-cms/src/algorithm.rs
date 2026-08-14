// SPDX-License-Identifier: MIT OR Apache-2.0

//! `AlgorithmIdentifier` — `SEQUENCE { algorithm OID, parameters ANY OPTIONAL }`.

use tpt_asn1_core::any::Any;
use tpt_asn1_core::decode::{Decode, read_sequence};
use tpt_asn1_core::reader::Reader;
use tpt_asn1_core::types::ObjectIdentifier;

/// An `AlgorithmIdentifier` as used throughout CMS and X.509.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AlgorithmIdentifier<'a> {
    /// The algorithm OID (raw on-wire bytes).
    pub algorithm: ObjectIdentifier<'a>,
    /// Optional parameters (the `ANY DEFINED BY algorithm` value), borrowed.
    pub parameters: Option<Any<'a>>,
}

impl<'a> AlgorithmIdentifier<'a> {
    /// The raw algorithm OID bytes.
    pub fn algorithm_bytes(&self) -> &'a [u8] {
        self.algorithm.0
    }
}

impl<'a> Decode<'a> for AlgorithmIdentifier<'a> {
    fn decode(r: &mut Reader<'a>) -> tpt_asn1_core::error::Result<Self> {
        read_sequence(r, |inner| {
            let algorithm = ObjectIdentifier::decode(inner)?;
            let parameters = if inner.is_empty() {
                None
            } else {
                Some(Any::decode(inner)?)
            };
            Ok(AlgorithmIdentifier { algorithm, parameters })
        })
    }
}
