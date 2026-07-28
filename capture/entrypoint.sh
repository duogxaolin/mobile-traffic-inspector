#!/bin/sh
set -eu

public_ca_dir="${PUBLIC_CA_ROOT:-/var/lib/traffic-inspector/public-ca}"
state_dir="${MITMPROXY_STATE:-/home/mitmproxy/.mitmproxy}"
mkdir -p "$public_ca_dir"

"$@" &
proxy_pid=$!

trap 'kill -TERM "$proxy_pid" 2>/dev/null || true; wait "$proxy_pid"; exit 0' INT TERM

publish_ca() {
  certificate="$state_dir/mitmproxy-ca-cert.pem"
  if [ -r "$certificate" ]; then
    cp "$certificate" "$public_ca_dir/mitmproxy-ca-cert.pem"
    cp "$certificate" "$public_ca_dir/mitmproxy-ca-cert.cer"
    chmod 0644 "$public_ca_dir/mitmproxy-ca-cert.pem" "$public_ca_dir/mitmproxy-ca-cert.cer"
    return 0
  fi
  return 1
}

while kill -0 "$proxy_pid" 2>/dev/null; do
  publish_ca || true
  sleep 2
done

wait "$proxy_pid"
