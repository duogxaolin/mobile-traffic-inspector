# Operations runbook

## First boot checklist

1. Confirm DNS resolves to the VPS and that the firewall permits only TCP/443 and UDP/51820. Do not publish port 8000, 5432 or a regular HTTP proxy port.
2. Run `./scripts/generate-secrets.sh` once. The script refuses to overwrite existing secrets. It writes local Docker Compose secret files as read-only/readable (`0644`) so non-root containers can read them. Save the generated bootstrap password in a password manager, then remove it from shell history.
3. Run `docker compose config -q` and `docker compose up -d --build`. Wait for all health checks to be healthy.
4. Visit `https://SITE_ADDRESS/healthz` and sign in to the panel. Confirm **System / Audit** can read disk free space.
5. Extract a WireGuard client profile with `./scripts/extract-wireguard.sh` and verify the public CA fingerprint before installing it.

## Client profile and CA verification

`extract-wireguard.sh` copies only the generated client profile to a local file with mode 0600 and prints the derived public key. It never prints the private key. A profile is a bearer credential; delete it after importing or store it in an encrypted secrets manager.

`verify-ca.sh` computes the SHA-256 fingerprint of the public certificate and compares it to an operator-provided value. The panel link serves `mitmproxy-ca-cert.pem` only. At startup, `capture` copies that public certificate into a separate read-only web volume; the CA private key and WireGuard server state remain in the capture-only Docker volume and are never part of the web build.

## Capture behavior and limits

The addon sends a `headers` event before a `complete` or `error` event. A bounded queue protects forwarding when PostgreSQL/API is slow; failed events are written to a spool and replayed at-least-once after recovery, with removal only after successful acknowledgement. The ingest endpoint is idempotent for replayed flow and message events. The capture heartbeat reports current spooled/dropped counts to the panel. A flow can therefore be `loading`, `complete`, `error`, `truncated` (preview only), `not-captured` (pinning/protocol), or `disconnected` (panel WebSocket). Pause stops recording and discards capture data while forwarding packets normally.

Retention and quota remain unlimited when their settings are `0`. A nonzero retention period deletes expired sessions and their encrypted payload files. A nonzero quota prunes the oldest prior sessions after a completed flow; it deliberately does not delete the session currently completing, so a single active session can briefly exceed the quota.

Raw body files use AES-GCM records under the body volume. The API decrypts records as a streaming response; it does not load an entire body to reveal or download it. The browser preview is capped by `PREVIEW_BYTES`, and a raw reveal expires after 60 seconds. Redaction covers Authorization/Proxy-Authorization/Cookie/Set-Cookie/API keys/tokens/passwords/OTP/secrets in headers, query fields and structured text. Binary previews are replaced with an explicit redacted marker until re-authentication.

## Backup and restore

Stop API writes before a consistent backup:

```sh
docker compose stop capture api
docker compose exec -T postgres pg_dump -U traffic_inspector traffic_inspector > backup.sql
docker run --rm -v mobile-traffic-inspector_body_data:/data -v "$PWD":/backup alpine \
  tar czf /backup/body-data.tgz -C /data .
docker compose start api capture
```

Keep `secrets/application_key.txt`, `body-data.tgz` and `backup.sql` under separate encrypted storage. Restore the database and body volume before starting the API. If the application key is lost, encrypted body data cannot be recovered; metadata remains present but raw fields cannot be decrypted.

## Rotation and teardown

To rotate an admin password, change it through a future password-management endpoint or rotate the `admin_password` secret and recreate the database only when a migration plan is in place. To revoke a device, use the Devices screen/API, disable its WireGuard tunnel, and remove its CA profile. To fully tear down, export the backups you intend to keep, run `docker compose down`, and remove named volumes only after confirming the retention decision. Never run `docker compose down -v` as a routine troubleshooting step.

## Troubleshooting

* `capture` unhealthy: inspect `docker compose logs capture`; confirm the WireGuard UDP port is free and that `wireguard.conf` appears in the mitmproxy state volume. A revoked device is blocked from capture forwarding within the control poll interval, but an already issued WireGuard key remains valid until the capture state is rotated/recreated and replacement profiles are distributed.
* `caddy` cannot bind `0.0.0.0:443`: another host process or container already owns the public HTTPS port. Run `ss -ltnp 'sport = :443'` and `docker ps --format 'table {{.Names}}\t{{.Ports}}' | grep ':443'` to identify it. Free TCP/443 for the default deployment; using an existing reverse proxy requires a separate TLS/websocket/CA-download design.
* `volume-init` failed: inspect `docker compose logs volume-init`. It is the one-shot root-owned setup job that applies ownership to named volumes before the non-root API, capture and web services start.
* TLS error/pinning: verify the device trusts the public CA and that the app is a debug build. Pinning and app-layer encryption are intentionally not bypassed.
* `spooledEvents` grows: inspect the API/Postgres health and free disk. Capture keeps forwarding traffic while it spools bounded metadata; replay/cleanup is an operator action.
* No flows: confirm WireGuard is active, the app is using the tunnel, and the app did not opt out with its own VPN/QUIC stack. Only traffic arriving through the enrolled tunnel can be observed.
