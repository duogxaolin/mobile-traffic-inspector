#!/bin/sh
set -eu

umask 077
mkdir -p secrets

write_secret() {
  name="$1"
  value="$2"
  target="secrets/${name}.txt"
  if [ -e "$target" ]; then
    echo "Refusing to overwrite $target" >&2
    exit 1
  fi
  printf '%s' "$value" > "$target"
  # Docker Compose mounts local file-backed secrets with host file permissions.
  # Services run as non-root users, so the files must be readable inside those
  # containers while remaining write-protected on the host.
  chmod 644 "$target"
}

db_password="$(openssl rand -hex 36)"
write_secret postgres_password "$db_password"
write_secret database_url "postgresql+asyncpg://traffic_inspector:${db_password}@postgres:5432/traffic_inspector"
write_secret application_key "$(openssl rand -base64 32 | tr -d '\n')"
write_secret session_secret "$(openssl rand -base64 48 | tr -d '\n')"
write_secret ingest_token "$(openssl rand -hex 32)"

admin_password="$(openssl rand -base64 24 | tr -d '\n')"
write_secret admin_password "$admin_password"

echo "Secrets created with mode 0644 for non-root Docker services. Store this bootstrap password now:"
printf '%s\n' "$admin_password"
