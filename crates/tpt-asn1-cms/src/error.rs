// SPDX-License-Identifier: MIT OR Apache-2.0

//! CMS-specific error type.
//!
//! Wraps the lower-level codec [`Error`](tpt_asn1_core::error::Error) and adds
//! failures specific to Cryptographic Message Syntax processing (unknown content
//! types, unsupported versions/algorithms, signature mismatches).

use tpt_asn1_core::error::Error as CoreError;

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced while parsing or verifying CMS/PKCS#7 messages.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// An error from the underlying ASN.1 codec.
    Asn1(CoreError),
    /// The top-level content type was not a recognised CMS/PKCS#7 type.
    UnsupportedContentType,
    /// A structure carried a version number this implementation cannot handle.
    UnsupportedVersion,
    /// An algorithm OID was not recognised or is not supported here.
    UnsupportedAlgorithm,
    /// A `SignerInfo` was missing the `signedAttrs` required to verify it.
    MissingSignedAttributes,
    /// The encapsulated content required to verify a signature was absent
    /// (detached signature with no external content supplied).
    MissingContent,
    /// The `message-digest` signed attribute did not match the computed digest.
    MessageDigestMismatch,
    /// The cryptographic backend reported an invalid signature.
    VerificationFailed,
    /// The wire structure was not arranged as RFC 5652 / RFC 2315 require.
    UnexpectedStructure,
}

impl From<CoreError> for Error {
    fn from(e: CoreError) -> Self {
        Error::Asn1(e)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Asn1(e) => write!(f, "ASN.1 error: {e}"),
            Error::UnsupportedContentType => f.write_str("unsupported CMS content type"),
            Error::UnsupportedVersion => f.write_str("unsupported CMS version"),
            Error::UnsupportedAlgorithm => f.write_str("unsupported algorithm"),
            Error::MissingSignedAttributes => f.write_str("signer info is missing signedAttrs"),
            Error::MissingContent => f.write_str("encapsulated content is required but absent"),
            Error::MessageDigestMismatch => f.write_str("message-digest attribute mismatch"),
            Error::VerificationFailed => f.write_str("signature verification failed"),
            Error::UnexpectedStructure => f.write_str("unexpected CMS structure"),
        }
    }
}

impl core::error::Error for Error {}

impl From<Error> for tpt_asn1_core::error::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Asn1(c) => c,
            _ => tpt_asn1_core::error::Error::Custom("cms processing error"),
        }
    }
}
