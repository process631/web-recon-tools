#!/usr/bin/env bash
set -euo pipefail

# Passive recon for authorized lab targets only.
# Usage: ./passive_recon.sh "http://target/login"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <url>"
  exit 1
fi

URL="$1"
TS="$(date +%Y%m%d_%H%M%S)"
OUTDIR="passive_recon_${TS}"
mkdir -p "$OUTDIR"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1"
    exit 1
  fi
}

require_cmd curl
require_cmd awk
require_cmd sed
require_cmd tee
require_cmd grep
require_cmd sort

if ! [[ "$URL" =~ ^http://|^https:// ]]; then
  echo "Invalid URL. Include scheme (http:// or https://)."
  exit 1
fi

HOST="$(printf '%s\n' "$URL" | sed -E 's#^[a-zA-Z]+://##' | cut -d'/' -f1 | cut -d':' -f1)"
PORT="$(printf '%s\n' "$URL" | sed -nE 's#^[a-zA-Z]+://[^:/]+:([0-9]+).*#\1#p')"
SCHEME="$(printf '%s\n' "$URL" | cut -d':' -f1)"

{
  echo "=== Passive Recon Report ==="
  echo "Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "Input URL: $URL"
  echo "Scheme: $SCHEME"
  echo "Host: $HOST"
  echo "Explicit Port: ${PORT:-none (default for scheme)}"
  echo
  echo "NOTE: For authorized lab targets only."
} | tee "$OUTDIR/00_summary.txt"

# DNS / registrar style metadata (passive-ish)
if command -v dig >/dev/null 2>&1; then
  {
    echo "=== dig A/AAAA/CNAME/NS/MX ==="
    dig +short A "$HOST"
    dig +short AAAA "$HOST"
    dig +short CNAME "$HOST"
    dig +short NS "$HOST"
    dig +short MX "$HOST"
  } > "$OUTDIR/10_dns.txt" 2>&1 || true
fi

if command -v whois >/dev/null 2>&1; then
  whois "$HOST" > "$OUTDIR/11_whois.txt" 2>&1 || true
fi

# HTTP page/headers collection without credential attempts
curl -sS -D "$OUTDIR/20_headers.txt" -o "$OUTDIR/21_body.html" "$URL"

# Security header snapshot (best-effort)
{
  echo "=== Security Headers (from response) ==="
  grep -Ei '^(Strict-Transport-Security:|Content-Security-Policy:|X-Frame-Options:|X-Content-Type-Options:|Referrer-Policy:|Permissions-Policy:|Cross-Origin-Opener-Policy:|Cross-Origin-Embedder-Policy:|Cross-Origin-Resource-Policy:)' "$OUTDIR/20_headers.txt" || true
  echo
  echo "=== Cookies Set (names) ==="
  awk -F'[;=]' '/^Set-Cookie:/ {print $2}' "$OUTDIR/20_headers.txt" | awk 'NF{print}' | sort -u || true
} > "$OUTDIR/23_security_headers.txt"

# Optional modern HTTP probe (tech detection, favicon hash, JARM, etc.)
if command -v httpx >/dev/null 2>&1; then
  httpx -silent -no-color -fr -status-code -title -server -tech-detect -location -favicon -jarm -ct -cl "$URL" \
    > "$OUTDIR/24_httpx_probe.txt" 2>&1 || true
else
  echo "httpx not installed; skipping httpx probe." > "$OUTDIR/24_httpx_probe.txt"
fi

# Quick extraction of useful passive artifacts
{
  echo "=== Title ==="
  awk 'BEGIN{IGNORECASE=1} /<title>/{print; exit}' "$OUTDIR/21_body.html"
  echo
  echo "=== Form Actions ==="
  grep -Eio '<form[^>]*action="[^"]*"' "$OUTDIR/21_body.html" || true
  echo
  echo "=== Hidden Token-Like Inputs (names) ==="
  grep -Eio '<input[^>]*type=["'\'']hidden["'\''][^>]*name=["'\''][^"'\'']*?(csrf|token|authenticity|_csrf|verification)[^"'\'']*["'\''][^>]*>' "$OUTDIR/21_body.html" \
    || true
  echo
  echo "=== Script Sources ==="
  grep -Eio '<script[^>]*src="[^"]*"' "$OUTDIR/21_body.html" || true
  echo
  echo "=== Potential Tech Headers ==="
  grep -Ei '^(Server:|X-Powered-By:|Set-Cookie:|Location:)' "$OUTDIR/20_headers.txt" || true
} > "$OUTDIR/22_passive_artifacts.txt"

echo "Passive recon complete. Output folder: $OUTDIR"
