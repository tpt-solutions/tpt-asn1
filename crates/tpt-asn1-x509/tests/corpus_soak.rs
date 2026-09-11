//! No-panic soak test (Phase 7 acceptance criteria #2): decode every DER file
//! in a corpus directory and assert that `Certificate` decoding never panics.
//!
//! A malformed/rejected certificate is an expected `Err(..)` and does not fail
//! this test — only a panic (caught via `catch_unwind`) or a hang does. The
//! corpus itself is not vendored into the repo (real-world leaf certs harvested
//! from live hosts, not fixed test data); point `TPT_CORPUS_DIR` at a directory
//! of `.der`/`.crt`/`.pem`-as-DER files to run it. Without that env var, or with
//! an empty/missing directory, the test is a no-op so `cargo test` stays green
//! without the corpus present.

use std::fs;
use std::panic;
use std::path::PathBuf;

use tpt_asn1_core::decode;
use tpt_asn1_x509::Certificate;

#[test]
fn corpus_soak_no_panic() {
    let dir = match std::env::var("TPT_CORPUS_DIR") {
        Ok(d) => PathBuf::from(d),
        Err(_) => {
            eprintln!("TPT_CORPUS_DIR not set; skipping corpus soak test");
            return;
        }
    };

    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(err) => {
            eprintln!("cannot read TPT_CORPUS_DIR {dir:?}: {err}; skipping");
            return;
        }
    };

    let mut total = 0usize;
    let mut ok = 0usize;
    let mut rejected = 0usize;
    let mut panics: Vec<String> = Vec::new();

    // Silence the default panic hook's stderr spam; we still catch and report.
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if bytes.is_empty() {
            continue;
        }
        total += 1;

        let result = panic::catch_unwind(|| decode::<Certificate<'_>>(&bytes));
        match result {
            Ok(Ok(_)) => ok += 1,
            Ok(Err(_)) => rejected += 1,
            Err(payload) => {
                let msg = payload
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "<non-string panic payload>".to_string());
                panics.push(format!("{}: {}", path.display(), msg));
            }
        }
    }

    panic::set_hook(default_hook);

    eprintln!(
        "corpus soak: {total} files, {ok} decoded, {rejected} rejected (Err), {} panicked",
        panics.len()
    );

    assert!(
        panics.is_empty(),
        "decoder panicked on {} of {total} corpus files:\n{}",
        panics.len(),
        panics.join("\n")
    );
}
