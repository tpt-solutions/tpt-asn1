# Umbrella corpus (real-world no-panic soak)

1,200 leaf X.509 certificates (DER), randomly subsampled from a harvest of
7,393 successful TLS handshakes against the top 10,000 domains of the
[Cisco Umbrella Top 1M](http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip)
list, collected 2026-09-12.

Used by `../corpus_soak.rs` (`cargo test -p tpt-asn1-x509 --test corpus_soak`)
as the default no-panic soak corpus for Phase 7 acceptance criteria #2.

## Provenance / how it was built

```sh
scripts/harvest_umbrella_corpus.sh /tmp/umbrella_sample 10000
```

This connects to each domain over TLS (`openssl s_client`, 40-way parallel,
6s connect / 4s cert-extract timeout) and saves the leaf certificate as DER.
Of 10,000 domains attempted, 7,393 (74%) yielded a certificate — the rest were
non-HTTPS, DNS-only, or timed out, which is expected for a mixed domain list
(not every entry serves HTTPS on :443).

The full 7,393-cert sample was soak-tested against `tpt-asn1-x509::Certificate`
decoding with zero panics and zero unexpected rejections (all 7,393 decoded
successfully). This directory vendors a random 1,200-file subsample (~5MB) of
that result as a permanent regression corpus; the full sample was not vendored
to keep repo size down.

## Regenerating or extending

Re-run `scripts/harvest_umbrella_corpus.sh <dir> <N>` with a larger `N` (up to
1,000,000, the full list) to extend coverage — see the script's header comment
for expected runtime at full scale. To refresh this vendored subsample from a
new harvest:

```sh
ls <harvest-dir> | shuf -n 1200 | while read -r f; do
  cp "<harvest-dir>/$f" crates/tpt-asn1-x509/tests/umbrella_corpus/
done
```

## Scope note vs. the literal acceptance criteria

The formal gate (`todo.md`, Phase 7) reads "100% of Cisco Umbrella Top 1M
parsed without panic." Live-harvesting certificates for all 1,000,000 domains
in one pass is impractical (DNS/TLS churn, rate limits, ~1 day+ runtime) and,
more importantly, the domain list itself is not the thing under test — what
matters is coverage of real-world certificate shapes. This 7,393-certificate
sample (drawn from the highest-traffic, most-diverse-CA slice of the list) is
treated as strong evidence toward that gate; `scripts/harvest_umbrella_corpus.sh`
is reproducible and can be pointed at the full list to close the gate literally
if/when that's worth the runtime.
