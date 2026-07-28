#!/bin/sh
set -eu

certificate="${1:-mitmproxy-ca-cert.pem}"
if [ ! -f "$certificate" ]; then
  echo "Usage: $0 path/to/mitmproxy-ca-cert.pem [expected-sha256-fingerprint]" >&2
  exit 2
fi
fingerprint="$(openssl x509 -in "$certificate" -outform DER | openssl dgst -sha256 -r | awk '{print $1}')"
printf 'SHA-256: %s\n' "$fingerprint"
if [ "${2:-}" ]; then
  expected="$(printf '%s' "$2" | tr -d ' :')"
  [ "$fingerprint" = "$expected" ] || { echo "Fingerprint mismatch" >&2; exit 1; }
  echo "Fingerprint verified."
fi
