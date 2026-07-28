#!/bin/sh
set -eu

if git ls-files | grep -E '(^|/)(secrets|data)/|\.env$' >/dev/null 2>&1; then
  echo "Tracked secret/data path detected" >&2
  exit 1
fi

if git grep -nEI '(BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|gh[opsu]_[A-Za-z0-9]{20,}|postgresql[^ ]*://[^:]+:[^@]+@)' -- ':!scripts/validate-no-secrets.sh' ':!.env.example'; then
  echo "Possible committed secret detected" >&2
  exit 1
fi

echo "No tracked secret material detected."

