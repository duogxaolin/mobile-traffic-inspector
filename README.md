# Mobile Traffic Inspector

Mobile Traffic Inspector is a self-hosted, single-admin operations panel for inspecting traffic from **authorized** iOS and Android debug devices. Devices join a private WireGuard tunnel; mitmproxy terminates the tunnel and streams encrypted capture metadata/body chunks to a FastAPI + PostgreSQL backend. The React panel shows a live master/detail view and keeps raw captures until an administrator explicitly deletes them.

This project is for app owners, QA teams and security testers. Do not capture traffic from devices, accounts or people without permission. Captured bodies can contain passwords, tokens and personal data.

## What it captures

Every flow arriving through the WireGuard listener is considered in scope; there is no domain allowlist. The capture addon records HTTP/1.1, HTTP/2, HTTP/3 where mitmproxy supports it, WebSocket messages, and metadata for unsupported TCP/UDP connections. Request and response headers preserve duplicate ordering. Bodies are encrypted chunk-by-chunk and written to a shared volume while traffic continues, so an API outage or a multi-gigabyte upload does not create an unbounded RAM buffer. A bounded ingest queue spools metadata to disk when the API is unavailable.

HTTPS content is visible only when the app trusts the test CA. Certificate pinning, application-layer encryption, unsupported protocols and traffic that bypasses the tunnel are reported as metadata/error rather than bypassed.

## Quick start on a VPS

Prerequisites: a Linux VPS with Docker Engine + Compose v2, a DNS A/AAAA record for the host, ports TCP/443 and UDP/51820 available, and `openssl`, `wg` and `curl` for setup. Put the repository in a directory with a filesystem quota and encrypted VPS disk.

```sh
cp .env.example .env
# Edit SITE_ADDRESS and ACME_EMAIL; keep the remaining defaults unless needed.
./scripts/generate-secrets.sh
chmod 600 .env secrets/*.txt
docker compose config -q
docker compose up -d --build
docker compose ps
```

Caddy obtains a certificate using TLS-ALPN on port 443. Open `https://$SITE_ADDRESS/` and sign in as `admin` with the bootstrap password printed by `generate-secrets.sh`. The panel is the only HTTP API client; PostgreSQL and the ingest API have no host ports.

The default mode has no automatic retention deletion and no application-level body quota. Set `RETENTION_DAYS` or `STORAGE_QUOTA_BYTES` in `.env` when an operator quota is desired. `PREVIEW_BYTES` only limits what the panel loads into a preview; it never truncates the encrypted stored body.

## Enroll a device and trust the CA

Generate one WireGuard client profile from the running capture container. The profile contains a private key: keep it on the device and delete any workstation copy after import.

```sh
./scripts/extract-wireguard.sh ./device.conf
```

Import `device.conf` into WireGuard on the authorized device and activate it. Register the derived peer public key in **Devices / Setup** (or through the authenticated `POST /api/devices` endpoint). Revoke the record before deleting or replacing a device.

Download only the public proxy CA from the panel or:

```sh
curl --fail --proto '=https' --tlsv1.2 -o mitmproxy-ca-cert.pem \
  "https://$SITE_ADDRESS/setup/mitmproxy-ca-cert.pem"
sha256sum mitmproxy-ca-cert.pem
```

The fingerprint shown by `./scripts/verify-ca.sh` must match the value you communicate out-of-band to the tester. Never copy `mitmproxy-ca.pem` (the CA private key) out of the VPS. On Android, install the CA only on the test device and use a debug Network Security Configuration that trusts user certificates; release apps commonly ignore user CAs. On iOS, install the profile and enable it under **Settings → General → About → Certificate Trust Settings**. App traffic must still use the device tunnel; apps that pin the server certificate will fail or show `not-captured` rather than being bypassed.

## Panel workflow

* **Live Capture** lists every enrolled-device flow, with method/host/status/content type filters, pause/resume recording (network forwarding continues), and a realtime WebSocket stream.
* The detail view has Request, Response, Timing and WebSocket tabs. Sensitive headers, query values and parsed JSON/form/text body values are redacted by default. A recent admin password re-authentication grants a 60-second reveal token; each reveal/raw export is written to the audit trail. Redacted export is the default.
* **Sessions** lists retained captures and requires confirmation in the API before deletion. **System / Audit** reports body volume, disk free space, spooled/dropped ingest events and sensitive actions.

## Operations and security

The capture addon resolves every destination again at connect time and rejects loopback, RFC1918/RFC4193/link-local, multicast, shared, cloud metadata and other non-global addresses. This prevents the VPS from becoming an open proxy or an SSRF route. `SAFE_DESTINATION_OVERRIDES` is an explicit administrator escape hatch and should remain empty. Panel cookies are Secure, HttpOnly/SameSite and CSRF-protected; admin passwords use Argon2id. Containers drop capabilities where compatible, run without a Docker socket, and expose only TCP/443 and UDP/51820.

Back up PostgreSQL and the encrypted body volume together with the application key. Losing the application key makes existing encrypted bodies unrecoverable. Treat backups as raw sensitive data. Rotate/revoke the admin account and WireGuard peer when a workstation is lost.

For teardown and CA removal, disable the device tunnel, revoke/delete its device record, remove the CA profile from every test device, run `docker compose down`, and retain or remove named volumes according to your backup policy. See [docs/operations.md](docs/operations.md) for recovery, verification and troubleshooting.
