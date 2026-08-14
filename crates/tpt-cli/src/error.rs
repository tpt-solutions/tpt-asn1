// SPDX-License-Identifier: MIT OR Apache-2.0

//! CLI error type.

use tpt_asn1_core::error::Error as CoreError;

/// Errors surfaced by the CLI.
#[derive(Debug)]
pub enum CliError {
    /// I/O failure (reading files, spawning subprocesses, etc.).
    Io(std::io::Error),
    /// A DER/BER/CER parsing failure from `tpt-asn1-core`.
    Core(CoreError),
    /// PEM framing or base64 decoding failure.
    Pem(String),
    /// A general, user-facing error message.
    Msg(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Io(e) => write!(f, "i/o error: {e}"),
            CliError::Core(e) => write!(f, "parse error: {e}"),
            CliError::Pem(e) => write!(f, "pem error: {e}"),
            CliError::Msg(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for CliError {}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Io(e)
    }
}

impl From<CoreError> for CliError {
    fn from(e: CoreError) -> Self {
        CliError::Core(e)
    }
}

impl CliError {
    /// Build a [`CliError::Msg`] from anything string-like.
    pub fn msg<D: std::fmt::Display>(d: D) -> Self {
        CliError::Msg(d.to_string())
    }
}
