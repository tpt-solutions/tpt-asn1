// SPDX-License-Identifier: MIT OR Apache-2.0

//! `tpt-asn1` — command-line ASN.1 / X.509 / CMS toolkit.
//!
//! Phase 6 of `todo.md`. Implements a `clap`-based CLI with:
//!
//! - `inspect` — generic DER/BER/CER pretty-printer with PEM auto-detection
//!   (fully implemented on `tpt-asn1-core`).
//! - `fuzz` — differential fuzzer against OpenSSL's `asn1parse`.
//! - `validate` / `text` — structural certificate inspection; full RFC 5280
//!   §6.1 path validation depends on the (not-yet-integrated) `tpt-x509` crate.
//! - `req` — CSR / self-signed generation; depends on the crypto backend and
//!   `tpt-x509` (Phase 4), not yet available.
//! - `completions` — shell completion generation.

#![forbid(unsafe_code)]

mod error;
mod fuzz;
mod inspect;
mod pem;

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use tpt_asn1_core::reader::Config;

use error::CliError;

/// Memory-safe ASN.1 / X.509 / CMS toolkit.
#[derive(Parser)]
#[command(name = "tpt-asn1", version, about = "Memory-safe ASN.1 / X.509 / CMS toolkit")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect and pretty-print ASN.1 (DER/BER/CER) with PEM auto-detection.
    Inspect(InspectArgs),
    /// Validate a certificate chain against trust roots.
    Validate(ValidateArgs),
    /// Print a human-readable, `openssl x509 -text`-style dump of a cert.
    Text(TextArgs),
    /// Differential fuzzer against OpenSSL's `asn1parse`.
    Fuzz(FuzzArgs),
    /// Generate a CSR / self-signed certificate (`openssl req` equivalent).
    Req(ReqArgs),
    /// Generate shell completions.
    Completions(CompletionsArgs),
}

/// Encoding rule selector.
#[derive(Copy, Clone, ValueEnum)]
enum Rule {
    Der,
    Ber,
    Cer,
}

impl Rule {
    fn config(self) -> Config {
        match self {
            Rule::Der => Config::der(),
            Rule::Ber => Config::ber(),
            Rule::Cer => Config::cer(),
        }
    }
}

fn rule_name(r: Rule) -> &'static str {
    match r {
        Rule::Der => "der",
        Rule::Ber => "ber",
        Rule::Cer => "cer",
    }
}

#[derive(Parser)]
struct InspectArgs {
    /// ASN.1 file to inspect (DER or PEM).
    file: PathBuf,
    /// Encoding rule used to drive the parser.
    #[arg(long, value_enum, default_value_t = Rule::Der)]
    rule: Rule,
    /// Emit a JSON document instead of indented text.
    #[arg(long)]
    json: bool,
    /// Maximum recursion depth before a constructed value is shown raw.
    #[arg(long, default_value_t = 64)]
    max_depth: usize,
    /// Attempt to re-parse OCTET STRING / BIT STRING contents as embedded DER.
    #[arg(long = "try-der")]
    try_der: bool,
    /// Show full hex for primitive values instead of a truncated preview.
    #[arg(long)]
    show_bytes: bool,
}

#[derive(Parser)]
struct ValidateArgs {
    /// Certificate chain file (PEM or DER).
    chain: PathBuf,
    /// Optional trust-anchor file (PEM or DER).
    #[arg(long)]
    roots: Option<PathBuf>,
}

#[derive(Parser)]
struct TextArgs {
    /// Certificate file (PEM or DER).
    cert: PathBuf,
    /// Encoding rule used to drive the parser.
    #[arg(long, value_enum, default_value_t = Rule::Der)]
    rule: Rule,
    /// Emit a JSON document instead of indented text.
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct FuzzArgs {
    /// Input files or directories of DER/PEM inputs.
    inputs: Vec<PathBuf>,
    /// Encoding rule used to drive our parser.
    #[arg(long, value_enum, default_value_t = Rule::Der)]
    rule: Rule,
    /// Fail the run if OpenSSL (`openssl`) is not available on PATH.
    #[arg(long)]
    require_openssl: bool,
}

#[derive(Parser)]
struct ReqArgs {
    /// Output file for the generated certificate or CSR.
    out: PathBuf,
}

#[derive(Parser)]
struct CompletionsArgs {
    /// Shell to generate completions for.
    #[arg(long, value_enum, default_value_t = ShellArg::Bash)]
    shell: ShellArg,
}

#[derive(Copy, Clone, ValueEnum)]
enum ShellArg {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

impl From<ShellArg> for clap_complete::Shell {
    fn from(s: ShellArg) -> Self {
        match s {
            ShellArg::Bash => clap_complete::Shell::Bash,
            ShellArg::Zsh => clap_complete::Shell::Zsh,
            ShellArg::Fish => clap_complete::Shell::Fish,
            ShellArg::Powershell => clap_complete::Shell::PowerShell,
        }
    }
}

fn main() {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("tpt-asn1: {e}");
            std::process::exit(1);
        }
    }
}

/// Run the selected subcommand, returning the process exit code.
fn run(cli: Cli) -> Result<i32, CliError> {
    match cli.command {
        Command::Inspect(a) => cmd_inspect(a),
        Command::Validate(a) => cmd_validate(a),
        Command::Text(a) => cmd_text(a),
        Command::Fuzz(a) => cmd_fuzz(a),
        Command::Req(a) => cmd_req(a),
        Command::Completions(a) => cmd_completions(a),
    }
}

/// Load a file, returning its DER blocks (PEM-decoded if applicable).
fn load_blocks(path: &PathBuf) -> Result<Vec<(String, Vec<u8>)>, CliError> {
    let bytes = std::fs::read(path)?;
    if pem::detect_pem(&bytes) {
        let blocks = pem::decode_pem(&bytes).map_err(CliError::Pem)?;
        Ok(blocks.into_iter().map(|b| (b.label, b.der)).collect())
    } else {
        Ok(vec![("DER".to_string(), bytes)])
    }
}

fn cmd_inspect(a: InspectArgs) -> Result<i32, CliError> {
    let blocks = load_blocks(&a.file)?;
    let opts = inspect::InspectOptions {
        config: a.rule.config(),
        max_depth: a.max_depth,
        try_der: a.try_der,
        show_bytes: a.show_bytes,
    };
    for (label, der) in &blocks {
        let nodes = inspect::parse_tlvs(der, &opts)?;
        if a.json {
            println!("{}", inspect::to_json(&nodes, Some(label), rule_name(a.rule)));
        } else {
            inspect::print_text(&nodes, if blocks.len() > 1 { Some(label) } else { None });
        }
    }
    Ok(0)
}

/// Structural certificate validation (no RFC 5280 path semantics yet).
fn cmd_validate(a: ValidateArgs) -> Result<i32, CliError> {
    if a.roots.is_some() {
        eprintln!(
            "tpt-asn1: note: --roots is accepted but trust-anchor path validation\n\
             \x20        requires the tpt-x509 crate (Phase 4), not yet integrated.\n\
             \x20        Performing structural certificate checks only."
        );
    }
    let blocks = load_blocks(&a.chain)?;
    let opts = inspect::InspectOptions {
        config: Config::der(),
        max_depth: 128,
        try_der: true,
        show_bytes: false,
    };
    let mut failed = 0;
    for (i, (label, der)) in blocks.iter().enumerate() {
        match inspect::parse_tlvs(der, &opts) {
            Ok(nodes) => {
                let cert = match nodes.first() {
                    Some(n) => n,
                    None => {
                        eprintln!("cert #{i} ({label}): empty input");
                        failed += 1;
                        continue;
                    }
                };
                match check_certificate_structure(cert) {
                    Ok(msg) => println!("cert #{i} ({label}): OK — {msg}"),
                    Err(e) => {
                        eprintln!("cert #{i} ({label}): structural error — {e}");
                        failed += 1;
                    }
                }
            }
            Err(e) => {
                eprintln!("cert #{i} ({label}): parse error — {e}");
                failed += 1;
            }
        }
    }
    if failed == 0 {
        println!(
            "tpt-asn1: all {} certificate(s) parsed structurally. \
             Full chain/path validation pending tpt-x509 (Phase 4).",
            blocks.len()
        );
        Ok(0)
    } else {
        eprintln!("tpt-asn1: {failed} certificate(s) failed structural checks.");
        Ok(1)
    }
}

/// Verify a top-level node looks like an X.509 `Certificate`.
fn check_certificate_structure(cert: &inspect::TlvNode) -> Result<String, CliError> {
    use tpt_asn1_core::tag::Tag;
    if !(cert.constructed && cert.class == 0 && cert.number == Tag::SEQUENCE) {
        return Err(CliError::msg("top-level element is not a SEQUENCE (expected Certificate)"));
    }
    if cert.children.len() != 3 {
        return Err(CliError::msg(format!(
            "Certificate SEQUENCE must have 3 fields, found {}",
            cert.children.len()
        )));
    }
    let tbs = &cert.children[0];
    let sig_alg = &cert.children[1];
    let sig_val = &cert.children[2];
    if !(tbs.constructed && tbs.number == Tag::SEQUENCE) {
        return Err(CliError::msg("field 1 (tbsCertificate) is not a SEQUENCE"));
    }
    if !(sig_alg.constructed && sig_alg.number == Tag::SEQUENCE) {
        return Err(CliError::msg("field 2 (signatureAlgorithm) is not a SEQUENCE"));
    }
    if sig_val.number != Tag::BIT_STRING {
        return Err(CliError::msg("field 3 (signatureValue) is not a BIT STRING"));
    }
    let tbs_fields = tbs.children.len();
    Ok(format!(
        "X.509 Certificate, tbsCertificate has {tbs_fields} field(s), signature algorithm present"
    ))
}

fn cmd_text(a: TextArgs) -> Result<i32, CliError> {
    let blocks = load_blocks(&a.cert)?;
    if blocks.len() != 1 {
        return Err(CliError::msg("text: expected exactly one certificate in the input"));
    }
    let (label, der) = &blocks[0];
    let opts = inspect::InspectOptions {
        config: a.rule.config(),
        max_depth: 256,
        try_der: true,
        show_bytes: false,
    };
    let nodes = inspect::parse_tlvs(der, &opts)?;
    println!("Certificate ({label}):");
    if a.json {
        println!("{}", inspect::to_json(&nodes, Some(label), rule_name(a.rule)));
    } else {
        inspect::print_text(&nodes, None);
    }
    eprintln!(
        "tpt-asn1: note: typed field decoding (issuer, validity, extensions, …)\n\
         \x20        requires the tpt-x509 crate (Phase 4), not yet integrated."
    );
    Ok(0)
}

fn cmd_fuzz(a: FuzzArgs) -> Result<i32, CliError> {
    if a.inputs.is_empty() {
        return Err(CliError::msg("fuzz: at least one input file or directory is required"));
    }
    let all_ok = fuzz::run(
        &a.inputs,
        fuzz::FuzzOptions {
            config: a.rule.config(),
            require_openssl: a.require_openssl,
        },
    )?;
    Ok(if all_ok { 0 } else { 1 })
}

fn cmd_req(_a: ReqArgs) -> Result<i32, CliError> {
    eprintln!(
        "tpt-asn1: `req` (CSR / self-signed cert generation) is not yet implemented.\n\
         \x20        It requires a pluggable crypto backend and the tpt-x509 crate\n\
         \x20        (Phases 4-5), which are not yet integrated."
    );
    Ok(2)
}

fn cmd_completions(a: CompletionsArgs) -> Result<i32, CliError> {
    let mut cmd = Cli::command();
    let shell: clap_complete::Shell = a.shell.into();
    clap_complete::generate(shell, &mut cmd, "tpt-asn1", &mut std::io::stdout());
    Ok(0)
}
