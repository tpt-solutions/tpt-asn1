// Temporary debug helper (not a real test).
use tpt_asn1_compiler::lexer::lex;

#[test]
fn dump_tokens() {
    let src = include_str!("../examples/example.tpt-asn1");
    let toks = lex(src).unwrap();
    for (i, t) in toks.iter().enumerate() {
        if (115..=135).contains(&i) {
            println!("{i}: {t:?}");
        }
    }
    println!("total tokens: {}", toks.len());
}
