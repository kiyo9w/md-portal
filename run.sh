#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$ROOT/.run"
mkdir -p "$LOG_DIR"

PORT="${PORT:-18901}"
HOST="${HOST:-127.0.0.1}"
ENV_FILE="${ENV_FILE:-$ROOT/.env}"
PASSWORD_FILE="${PASSWORD_FILE:-$ROOT/../.secrets/md_portal_password.txt}"
MD_PORTAL_PASSWORD="${MD_PORTAL_PASSWORD:-}"
PRIVATE_LINK_SECRET="${PRIVATE_LINK_SECRET:-}"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

if [[ -z "$MD_PORTAL_PASSWORD" ]] && [[ -f "$PASSWORD_FILE" ]]; then
  MD_PORTAL_PASSWORD="$(cat "$PASSWORD_FILE")"
fi

if [[ -z "$PRIVATE_LINK_SECRET" ]]; then
  PRIVATE_LINK_SECRET="$MD_PORTAL_PASSWORD"
fi

if [[ -f "$LOG_DIR/server.pid" ]] && kill -0 "$(cat "$LOG_DIR/server.pid")" 2>/dev/null; then
  echo "server already running pid=$(cat "$LOG_DIR/server.pid")"
else
  cd "$ROOT"
  nohup env PORT="$PORT" HOST="$HOST" MD_PORTAL_PASSWORD="$MD_PORTAL_PASSWORD" PRIVATE_LINK_SECRET="$PRIVATE_LINK_SECRET" node server.js > "$LOG_DIR/server.log" 2>&1 &
  echo $! > "$LOG_DIR/server.pid"
  echo "server started pid=$(cat "$LOG_DIR/server.pid")"
fi

if [[ -f "$LOG_DIR/caddy.pid" ]] && kill -0 "$(cat "$LOG_DIR/caddy.pid")" 2>/dev/null; then
  echo "caddy already running pid=$(cat "$LOG_DIR/caddy.pid")"
else
  cd "$ROOT"
  nohup /home/node/.openclaw/workspace/bin/caddy run --config "$ROOT/Caddyfile" --adapter caddyfile > "$LOG_DIR/caddy.log" 2>&1 &
  echo $! > "$LOG_DIR/caddy.pid"
  echo "caddy started pid=$(cat "$LOG_DIR/caddy.pid")"
fi

echo "logs: $LOG_DIR/server.log and $LOG_DIR/caddy.log"
