// SPDX-License-Identifier: MIT OR Apache-2.0

//! Recursive ASN.1 structural inspector: TLV tree, text printer, and JSON.

use std::fmt::Write as _;
use std::io::IsTerminal;

use tpt_asn1_core::error::Error as CoreError;
use tpt_asn1_core::length::Length;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_core::tag::{Class, Tag};
use tpt_asn1_core::types::{GeneralizedTime, Integer, UtcTime};

/// Options controlling how [`parse_tlvs`] walks and renders a value.
#[derive(Clone, Copy)]
pub struct InspectOptions {
    /// Encoding-rule configuration handed to the core reader.
    pub config: Config,
    /// Maximum recursion depth before a constructed value is shown raw.
    pub max_depth: usize,
    /// Attempt to re-parse OCTET STRING / BIT STRING contents as embedded DER.
    pub try_der: bool,
    /// Show full hex for primitive values instead of a truncated preview.
    pub show_bytes: bool,
}

/// A single ASN.1 TLV node in the inspection tree.
#[derive(Debug, Clone)]
pub struct TlvNode {
    /// Absolute byte offset of this TLV's tag within the top-level buffer.
    pub offset: usize,
    /// Total encoded length of this TLV (tag + length + value).
    pub tlv_len: usize,
    /// Tag class index (0=Universal, 1=Application, 2=Context, 3=Private).
    pub class: u8,
    /// Whether the tag is constructed.
    pub constructed: bool,
    /// Tag number within its class.
    pub number: u32,
    /// Human-readable tag label (e.g. `INTEGER`, `[CONTEXT 0]`).
    pub tag_label: String,
    /// A short, human-readable summary of the value.
    pub summary: String,
    /// Child nodes for constructed values (and embedded DER when `--try-der`).
    pub children: Vec<TlvNode>,
}

/// Parse every top-level TLV in `input`, returning the document's node tree.
pub fn parse_tlvs(input: &[u8], opts: &InspectOptions) -> Result<Vec<TlvNode>, CoreError> {
    parse_tlvs_at(input, opts, 0)
}

fn parse_tlvs_at(input: &[u8], opts: &InspectOptions, depth: usize) -> Result<Vec<TlvNode>, CoreError> {
    let mut r = Reader::new(input, opts.config);
    let mut out = Vec::new();
    while !r.is_empty() {
        out.push(parse_one(&mut r, opts, depth)?);
    }
    Ok(out)
}

fn parse_one(r: &mut Reader<'_>, opts: &InspectOptions, depth: usize) -> Result<TlvNode, CoreError> {
    let start = r.position();
    let (tag, length, value) = r.read_tlv()?;
    let end = r.position();

    let mut node = TlvNode {
        offset: start,
        tlv_len: end - start,
        class: tag.class as u8,
        constructed: tag.constructed,
        number: tag.number,
        tag_label: tag_label(&tag),
        summary: String::new(),
        children: Vec::new(),
    };

    if tag.constructed && depth < opts.max_depth {
        match parse_tlvs_at(value, opts, depth + 1) {
            Ok(children) => {
                node.children = children;
                node.summary = format!("{} element(s)", node.children.len());
            }
            Err(_) => {
                node.summary = format!("(unparseable constructed) {}", hex_preview(value, opts.show_bytes));
            }
        }
    } else {
        node.summary = summarize(&tag, &length, value, opts);
        if opts.try_der {
            if tag.is_universal(Tag::OCTET_STRING) {
                if let Some(ch) = try_embedded(value, opts, depth) {
                    node.children = ch;
                    node.summary = format!("octet string, embedded DER ({} elem)", node.children.len());
                }
            } else if tag.is_universal(Tag::BIT_STRING) && !value.is_empty() && value[0] == 0 {
                if let Some(ch) = try_embedded(&value[1..], opts, depth) {
                    node.children = ch;
                    node.summary = format!("bit string, embedded DER ({} elem)", node.children.len());
                }
            }
        }
    }
    Ok(node)
}

/// Attempt to interpret `bytes` as DER; returns the parsed subtree on success.
fn try_embedded(bytes: &[u8], opts: &InspectOptions, depth: usize) -> Option<Vec<TlvNode>> {
    if bytes.is_empty() {
        return None;
    }
    // A plausible DER tag byte must have a valid class (top two bits) and, for
    // the universal class, a known tag number range.
    let first = bytes[0];
    let class = first >> 6;
    if class > 3 {
        return None;
    }
    match parse_tlvs_at(bytes, opts, depth + 1) {
        Ok(nodes) if !nodes.is_empty() => Some(nodes),
        _ => None,
    }
}

/// Human-readable label for a tag.
fn tag_label(tag: &Tag) -> String {
    if tag.class == Class::Universal {
        let name = match tag.number {
            1 => "BOOLEAN",
            2 => "INTEGER",
            3 => "BIT STRING",
            4 => "OCTET STRING",
            5 => "NULL",
            6 => "OBJECT IDENTIFIER",
            7 => "OBJECT DESCRIPTOR",
            8 => "EXTERNAL",
            9 => "REAL",
            10 => "ENUMERATED",
            11 => "EMBEDDED PDV",
            12 => "UTF8String",
            13 => "RELATIVE-OID",
            16 => "SEQUENCE",
            17 => "SET",
            18 => "NumericString",
            19 => "PrintableString",
            20 => "TeletexString",
            21 => "VideotexString",
            22 => "IA5String",
            23 => "UTCTime",
            24 => "GeneralizedTime",
            25 => "GraphicString",
            26 => "VisibleString",
            27 => "GeneralString",
            28 => "UniversalString",
            29 => "CHARACTER STRING",
            30 => "BMPString",
            n => return format!("UNIVERSAL {n}"),
        };
        name.to_string()
    } else {
        let c = match tag.class {
            Class::Application => "APPLICATION",
            Class::Context => "CONTEXT",
            Class::Private => "PRIVATE",
            Class::Universal => unreachable!(),
        };
        if tag.constructed {
            format!("[{c} {number} constructed]", number = tag.number)
        } else {
            format!("[{c} {number}]", number = tag.number)
        }
    }
}

/// Produce a short value summary for a primitive TLV.
fn summarize(tag: &Tag, _len: &Length, value: &[u8], opts: &InspectOptions) -> String {
    let u = tag.class == Class::Universal;
    let n = tag.number;

    if u && n == Tag::BOOLEAN {
        if value.len() == 1 {
            return (value[0] != 0).to_string();
        }
        return format!("(bad) {}", hex_preview(value, opts.show_bytes));
    }
    if u && (n == Tag::INTEGER || n == Tag::ENUMERATED) {
        if let Some(v) = Integer(value).as_i64() {
            return format!("{v} ({})", hex_preview(value, opts.show_bytes));
        }
        return hex_preview(value, opts.show_bytes);
    }
    if u && n == Tag::BIT_STRING {
        if value.is_empty() {
            return "(empty)".to_string();
        }
        return format!("unused {} bits: {}", value[0], hex_preview(&value[1..], opts.show_bytes));
    }
    if u && n == Tag::NULL {
        return "NULL".to_string();
    }
    if u && n == Tag::OBJECT_IDENTIFIER {
        return oid_string(value, false);
    }
    if u && n == Tag::RELATIVE_OID {
        return oid_string(value, true);
    }
    if u
        && (n == Tag::UTF8_STRING
            || n == Tag::PRINTABLE_STRING
            || n == Tag::IA5_STRING
            || n == Tag::VISIBLE_STRING
            || n == Tag::NUMERIC_STRING)
    {
        if let Ok(s) = std::str::from_utf8(value) {
            return format!("{:?}", s);
        }
        return hex_preview(value, opts.show_bytes);
    }
    if u && n == Tag::UTC_TIME {
        if let Ok(dt) = UtcTime(value).parse() {
            return format!("{} (UTCTime)", format_datetime(&dt));
        }
        return hex_preview(value, opts.show_bytes);
    }
    if u && n == Tag::GENERALIZED_TIME {
        if let Ok(dt) = GeneralizedTime(value).parse() {
            return format!("{} (GeneralizedTime)", format_datetime(&dt));
        }
        return hex_preview(value, opts.show_bytes);
    }
    hex_preview(value, opts.show_bytes)
}

/// Render a parsed [`tpt_asn1_core::types::DateTime`] as an ISO-ish string.
fn format_datetime(dt: &tpt_asn1_core::types::DateTime) -> String {
    let tz = match dt.tz_offset_minutes {
        None => "Z".to_string(),
        Some(m) => {
            let sign = if m < 0 { '-' } else { '+' };
            let am = m.abs();
            format!("{sign}{:02}:{:02}", am / 60, am % 60)
        }
    };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{tz}",
        dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second
    )
}

/// Decode an OBJECT IDENTIFIER's subidentifiers into dotted notation.
fn oid_string(bytes: &[u8], relative: bool) -> String {
    let arcs: Vec<u64> = {
        let mut out = Vec::new();
        let mut cur: u64 = 0;
        for &b in bytes {
            cur = (cur << 7) | (b & 0x7f) as u64;
            if b & 0x80 == 0 {
                out.push(cur);
                cur = 0;
            }
        }
        out
    };
    if relative {
        arcs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(".")
    } else {
        match arcs.split_first() {
            Some((&first, rest)) => {
                let a0 = if first < 40 { 0 } else if first < 80 { 1 } else { 2 };
                let a1 = first - a0 * 40;
                let mut s = format!("{a0}.{a1}");
                for a in rest {
                    let _ = write!(s, ".{a}");
                }
                s
            }
            None => String::new(),
        }
    }
}

/// Hex preview: full spaced hex when `full`, else a truncated form for long values.
fn hex_preview(bytes: &[u8], full: bool) -> String {
    const LIMIT: usize = 32;
    if bytes.is_empty() {
        return "(empty)".to_string();
    }
    if full || bytes.len() <= LIMIT {
        bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
    } else {
        let head: String = bytes[..LIMIT].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
        format!("{head} … ({} bytes)", bytes.len())
    }
}

fn is_color() -> bool {
    std::io::stdout().is_terminal()
}

fn colorize(s: &str, code: &str) -> String {
    format!("\x1b[{code}m{s}\x1b[0m")
}

/// Print a parsed document as indented, human-readable text.
pub fn print_text(nodes: &[TlvNode], block_label: Option<&str>) {
    let color = is_color();
    if let Some(label) = block_label {
        println!("# {label}");
    }
    let mut out = String::new();
    for n in nodes {
        print_node(n, 0, color, &mut out);
    }
    print!("{out}");
}

fn print_node(n: &TlvNode, depth: usize, color: bool, out: &mut String) {
    let indent = "  ".repeat(depth);
    let label = if color {
        colorize(&n.tag_label, "36")
    } else {
        n.tag_label.clone()
    };
    let _ = writeln!(
        out,
        "{indent}{offset}: {label}  {summary}  [{begin}..{end}]",
        offset = n.offset,
        summary = n.summary,
        begin = n.offset,
        end = n.offset + n.tlv_len,
    );
    for c in &n.children {
        print_node(c, depth + 1, color, out);
    }
}

/// Serialize a parsed document as JSON.
pub fn to_json(nodes: &[TlvNode], block_label: Option<&str>, rule: &str) -> String {
    let mut out = String::new();
    out.push_str("{\"tool\":\"tpt-asn1\",\"rule\":");
    json_str(rule, &mut out);
    out.push_str(",\"block\":");
    json_str(block_label.unwrap_or(""), &mut out);
    out.push_str(",\"elements\":[");
    for (i, n) in nodes.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        append_json(n, &mut out);
    }
    out.push_str("]}");
    out
}

fn append_json(n: &TlvNode, out: &mut String) {
    out.push_str("{\"offset\":");
    out.push_str(&n.offset.to_string());
    out.push_str(",\"length\":");
    out.push_str(&n.tlv_len.to_string());
    out.push_str(",\"class\":");
    out.push_str(&n.class.to_string());
    out.push_str(",\"constructed\":");
    out.push_str(if n.constructed { "true" } else { "false" });
    out.push_str(",\"tag_number\":");
    out.push_str(&n.number.to_string());
    out.push_str(",\"tag\":");
    json_str(&n.tag_label, out);
    out.push_str(",\"summary\":");
    json_str(&n.summary, out);
    out.push_str(",\"children\":[");
    for (i, c) in n.children.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        append_json(c, out);
    }
    out.push_str("]}");
}

/// Append `s` to `out` as a JSON-escaped string literal.
fn json_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
