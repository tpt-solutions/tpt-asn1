#!/usr/bin/env bash
# Fetch one domain's leaf TLS certificate as DER. Used by
# harvest_umbrella_corpus.sh via `xargs -P` (kept as a separate file so the
# command is portable to xargs implementations that can't run exported shell
# functions in parallel workers).
set -u
domain="$1"
out="$2"
safe=$(echo "$domain" | tr -c 'A-Za-z0-9._-' '_')
dest="$out/${safe}.der"
[ -f "$dest" ] && exit 0
timeout 6 openssl s_client -connect "${domain}:443" -servername "${domain}" </dev/null 2>/dev/null \
  | timeout 4 openssl x509 -outform der -out "$dest" 2>/dev/null
if [ ! -s "$dest" ]; then
  rm -f "$dest"
fi
