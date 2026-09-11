#!/usr/bin/env bash
# Harvest leaf TLS certificates (DER) from a sample of the Cisco Umbrella
# Top 1M domain list, for use as a real-world no-panic soak corpus
# (crates/tpt-asn1-x509/tests/corpus_soak.rs).
#
# Usage:
#   scripts/harvest_umbrella_corpus.sh <output-dir> <num-domains>
#
# Example (regenerate the full sample this repo's vendored corpus was drawn
# from):
#   scripts/harvest_umbrella_corpus.sh /tmp/umbrella_sample 10000
#
# To soak the *entire* Top 1M list (the literal acceptance-criteria #2 gate),
# rerun with the full list: `wc -l top-1m.csv` domains. At ~40-way parallelism
# this takes on the order of a day and will hit many dead/non-HTTPS/rate-limited
# hosts; treat the exit count as a lower bound on successes, not a strict
# target. Requires `openssl`, `curl`, `xargs` (GNU coreutils).
set -euo pipefail

OUT="${1:?output directory required}"
N="${2:?number of domains required}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIST="$SCRIPT_DIR/top-1m.csv"

if [ ! -f "$LIST" ]; then
  echo "Downloading Cisco Umbrella Top 1M list..." >&2
  curl -sS --max-time 60 -o "$SCRIPT_DIR/top-1m.csv.zip" \
    http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip
  unzip -o -d "$SCRIPT_DIR" "$SCRIPT_DIR/top-1m.csv.zip" >/dev/null
fi

mkdir -p "$OUT"

tail -n +1 "$LIST" | head -n "$N" | cut -d',' -f2 | tr -d '\r' \
  | xargs -P 40 -I{} bash "$SCRIPT_DIR/harvest_one_cert.sh" {} "$OUT"

echo "Harvested: $(ls "$OUT" | wc -l) certs into $OUT (attempted $N domains)"
