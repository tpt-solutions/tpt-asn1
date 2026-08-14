// SPDX-License-Identifier: MIT OR Apache-2.0

//! `tpt-asn1-compiler` command-line frontend.
//!
//! Usage:
//! ```text
//! tpt-asn1-compiler <schema.tpt-asn1> [-o <output.rs>]
//! ```

use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: tpt-asn1-compiler <schema.tpt-asn1> [-o <output.rs>]");
        process::exit(2);
    }

    let input = &args[1];
    let mut output: Option<String> = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                if i + 1 >= args.len() {
                    eprintln!("error: -o requires an output path");
                    process::exit(2);
                }
                output = Some(args[i + 1].clone());
                i += 2;
            }
            "-h" | "--help" => {
                println!("usage: tpt-asn1-compiler <schema.tpt-asn1> [-o <output.rs>]");
                return;
            }
            other => {
                eprintln!("error: unknown argument `{other}`");
                process::exit(2);
            }
        }
    }

    let src = match fs::read_to_string(input) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read `{input}`: {e}");
            process::exit(1);
        }
    };

    let code = match tpt_asn1_compiler::generate(&src) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    match output {
        Some(path) => {
            if let Err(e) = fs::write(&path, code) {
                eprintln!("error: cannot write `{path}`: {e}");
                process::exit(1);
            }
            eprintln!("wrote {path}");
        }
        None => {
            print!("{code}");
        }
    }
}
