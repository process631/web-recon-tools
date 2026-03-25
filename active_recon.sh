#!/usr/bin/env bash
set -euo pipefail

# Active recon for authorized lab targets only.
# Usage: ./active_recon.sh "http://target/login"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <url>"
  exit 1
fi

URL="$1"
TS="$(date +%Y%m%d_%H%M%S)"
OUTDIR="active_recon_${TS}"
mkdir -p "$OUTDIR"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1"
    exit 1
  fi
}

require_cmd curl
require_cmd nmap
require_cmd sed
require_cmd tee

if ! [[ "$URL" =~ ^http://|^https:// ]]; then
  echo "Invalid URL. Include scheme (http:// or https://)."
  exit 1
fi

HOSTPORT="$(printf '%s\n' "$URL" | sed -E 's#^[a-zA-Z]+://##' | cut -d'/' -f1)"
HOST="$(printf '%s\n' "$HOSTPORT" | cut -d':' -f1)"
PORT="$(printf '%s\n' "$HOSTPORT" | sed -nE 's#^[^:]+:([0-9]+)$#\1#p')"
SCHEME="$(printf '%s\n' "$URL" | cut -d':' -f1)"

if [[ -z "${PORT}" ]]; then
  if [[ "$SCHEME" == "https" ]]; then
    PORT="443"
  else
    PORT="80"
  fi
fi

{
  echo "=== Active Recon Report ==="
  echo "Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "Input URL: $URL"
  echo "Host: $HOST"
  echo "Port: $PORT"
  echo
  echo "NOTE: For authorized coursework targets only."
  echo "NOTE: This script performs direct probing and scanning."
} | tee "$OUTDIR/00_summary.txt"

# Lightweight connectivity and response checks
curl -sS -I "$URL" > "$OUTDIR/20_http_head.txt" 2>&1 || true
curl -sS -L -o /dev/null -w "final_url=%{url_effective}\nhttp_code=%{http_code}\nremote_ip=%{remote_ip}\nnum_redirects=%{num_redirects}\ntime_total=%{time_total}\n" "$URL" > "$OUTDIR/21_http_metrics.txt"

# Conservative nmap scans for class lab use
nmap -Pn -sS -T2 -p "$PORT" "$HOST" -oN "$OUTDIR/30_nmap_target_port.txt" >/dev/null
nmap -Pn -sV -T2 -p "$PORT" "$HOST" -oN "$OUTDIR/31_nmap_service_version.txt" >/dev/null
nmap -Pn -T2 --top-ports 100 "$HOST" -oN "$OUTDIR/32_nmap_top100.txt" >/dev/null

echo "Active recon complete. Output folder: $OUTDIR"
