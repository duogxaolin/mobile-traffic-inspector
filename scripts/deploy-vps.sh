#!/usr/bin/env bash
set -Eeuo pipefail

: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${VPS_APP_DIR:?VPS_APP_DIR is required}"
: "${APP_URL:?APP_URL is required}"

if [[ ! "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "GITHUB_SHA must be a full lowercase commit SHA" >&2
  exit 2
fi

if [[ "$VPS_APP_DIR" != /* ]]; then
  echo "VPS_APP_DIR must be an absolute path" >&2
  exit 2
fi

if [[ "$APP_URL" != https://* ]]; then
  echo "APP_URL must use HTTPS" >&2
  exit 2
fi

cd "$VPS_APP_DIR"

if [[ ! -d .git ]]; then
  echo "VPS_APP_DIR is not a git worktree" >&2
  exit 2
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Refusing deployment: VPS worktree has local changes" >&2
  exit 2
fi

exec 9>"$(git rev-parse --git-dir)/mobile-traffic-inspector.deploy.lock"
if ! flock -n 9; then
  echo "Another deployment already holds the VPS lock" >&2
  exit 3
fi

previous_revision="$(git rev-parse HEAD)"
git_dir="$(git rev-parse --git-dir)"
target_revision=""
deployment_started=false

rollback() {
  local exit_code=$?
  if [[ "$deployment_started" == true && -n "$target_revision" ]]; then
    echo "Deployment failed; attempting rollback to $previous_revision" >&2
    docker compose logs --tail=100 || true
    git checkout --detach "$previous_revision" || true
    docker compose up -d --build --remove-orphans --wait --wait-timeout 180 || true
  fi
  exit "$exit_code"
}
trap rollback ERR

git fetch --prune origin main
target_revision="$(git rev-parse "$GITHUB_SHA^{commit}")"
main_revision="$(git rev-parse origin/main)"
if [[ "$target_revision" != "$main_revision" ]]; then
  echo "Refusing deployment: requested SHA is not the current origin/main revision" >&2
  exit 4
fi

deployment_started=true
printf '%s\n' "$previous_revision" > "$git_dir/mobile-traffic-inspector.previous-revision"
git checkout --detach "$target_revision"

docker compose config -q
docker compose up -d --build --remove-orphans --wait --wait-timeout 180

docker compose exec -T api python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=10).read()'
docker compose exec -T caddy wget -qO- http://127.0.0.1:2018/healthz
curl --fail --show-error --silent --proto '=https' --tlsv1.2 --connect-timeout 15 "$APP_URL/healthz" >/dev/null

echo "Deployment complete at revision $target_revision"
