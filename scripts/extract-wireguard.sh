#!/bin/sh
set -eu

target="${1:-device.conf}"
case "$target" in
  /*|*/*) : ;;
  *) target="$(pwd)/$target" ;;
esac

if [ -e "$target" ]; then
  echo "Refusing to overwrite $target" >&2
  exit 1
fi
umask 077
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT INT TERM
docker compose cp capture:/home/mitmproxy/.mitmproxy/wireguard.conf "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$target"

private_key="$(awk -F ' *= *' '$1 ~ /^PrivateKey$/ {print $2; exit}' "$target")"
if [ -z "$private_key" ]; then
  echo "No client PrivateKey found; inspect the generated profile." >&2
  exit 1
fi
if command -v wg >/dev/null 2>&1; then
  public_key="$(printf '%s\n' "$private_key" | wg pubkey)"
  printf 'Client profile: %s\nPeer public key: %s\n' "$target" "$public_key"
else
  printf 'Client profile: %s\nInstall wireguard-tools to derive the peer public key.\n' "$target"
fi
