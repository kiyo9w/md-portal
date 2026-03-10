#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
NOTES="$ROOT/notes"
ENV_FILE="${ENV_FILE:-$ROOT/.env}"
PASSWORD_FILE="${PASSWORD_FILE:-$ROOT/../.secrets/md_portal_password.txt}"
mkdir -p "$NOTES"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

if [[ -z "${MD_PORTAL_PASSWORD:-}" ]] && [[ -f "$PASSWORD_FILE" ]]; then
  MD_PORTAL_PASSWORD="$(cat "$PASSWORD_FILE")"
fi

if [[ -z "${PRIVATE_LINK_SECRET:-}" ]]; then
  PRIVATE_LINK_SECRET="${MD_PORTAL_PASSWORD:-}"
fi

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <markdown-file>"
  exit 1
fi

src="$1"
if [[ ! -f "$src" ]]; then
  echo "file not found: $src"
  exit 1
fi

base="$(basename "$src")"
stamp="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
out="${stamp}-${base}"
cp "$src" "$NOTES/$out"

url="$("$ROOT/url.sh" 2>/dev/null || true)"
scope="${PUBLISH_SCOPE:-private}"
if [[ -n "$url" ]]; then
  if [[ "$scope" == "private" ]]; then
    if [[ -n "${PRIVATE_LINK_SECRET:-}" ]]; then
      token="$(PRIVATE_LINK_SECRET="$PRIVATE_LINK_SECRET" NOTE_NAME="$out" python3 -c "import hashlib,hmac,os; s=os.environ.get('PRIVATE_LINK_SECRET',''); n=os.environ.get('NOTE_NAME',''); print(hmac.new(s.encode(), n.encode(), hashlib.sha256).hexdigest()[:24])")"
      echo "$url/private/?note=$out&token=$token"
    else
      echo "$url/private/?note=$out"
    fi
  else
    echo "$url/?note=$out"
  fi
else
  echo "published: $NOTES/$out"
fi
