#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"

if [[ -f "$ROOT/.run/caddy.pid" ]] && kill -0 "$(cat "$ROOT/.run/caddy.pid")" 2>/dev/null; then
  echo "https://md.openclaw.ngotrung.app"
  exit 0
fi

LOG="$ROOT/.run/tunnel.log"
if [[ ! -f "$LOG" ]]; then
  echo "url not ready"
  exit 1
fi
url="$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$LOG" | tail -n 1 || true)"
if [[ -z "$url" ]]; then
  echo "url not ready"
  exit 1
fi
echo "$url"
