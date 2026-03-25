#!/usr/bin/env bash
set -euo pipefail

# Active recon for authorized lab targets only.
# Usage: ./active_recon.sh "http://target/login" [--top-ports N]

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
require_cmd tr
require_cmd sort
require_cmd paste

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

TOP_PORTS=0
shift # consume URL; remaining args are optional flags
while [[ $# -gt 0 ]]; do
  case "$1" in
    --top-ports)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --top-ports"
        echo "Usage: $0 <url> [--top-ports N]"
        exit 1
      fi
      TOP_PORTS="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 <url> [--top-ports N]"
      exit 1
      ;;
  esac
done

WEB_PORTS="80,443,8080,8000,8888,8443,$PORT"
# Deduplicate + normalize to a comma list
WEB_PORTS="$(printf '%s\n' "$WEB_PORTS" | tr ',' '\n' | awk 'NF{print}' | sort -u | paste -sd, -)"

{
  echo "=== Active Recon Report ==="
  echo "Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "Input URL: $URL"
  echo "Host: $HOST"
  echo "Default Port: $PORT"
  echo "Web Ports Scan: $WEB_PORTS"
  echo
  echo "NOTE: For authorized lab targets only."
  echo "NOTE: This script performs direct probing and scanning."
} | tee "$OUTDIR/00_summary.txt"

# Lightweight connectivity and response checks
curl -sS -I "$URL" > "$OUTDIR/20_http_head.txt" 2>&1 || true
curl -sS -L -o /dev/null -w "final_url=%{url_effective}\nhttp_code=%{http_code}\nremote_ip=%{remote_ip}\nnum_redirects=%{num_redirects}\ntime_total=%{time_total}\n" "$URL" > "$OUTDIR/21_http_metrics.txt"

# Optional modern HTTP probe (tech detection, favicon hash, JARM, etc.)
if command -v httpx >/dev/null 2>&1; then
  httpx -silent -no-color -fr -status-code -title -server -tech-detect -location -favicon -jarm -ct -cl "$URL" \
    > "$OUTDIR/22_httpx_probe.txt" 2>&1 || true
else
  echo "httpx not installed; skipping httpx probe." > "$OUTDIR/22_httpx_probe.txt"
fi

# Conservative nmap scans (web ports only by default)
nmap -Pn -sS -T2 -p "$WEB_PORTS" "$HOST" -oN "$OUTDIR/30_nmap_web_ports.txt" >/dev/null
nmap -Pn -sV --version-light -T2 -p "$WEB_PORTS" "$HOST" -oN "$OUTDIR/31_nmap_web_service_version.txt" >/dev/null

if [[ "$TOP_PORTS" -gt 0 ]]; then
  nmap -Pn -T2 --top-ports "$TOP_PORTS" "$HOST" -oN "$OUTDIR/32_nmap_top_ports.txt" >/dev/null
fi

echo "Active recon complete. Output folder: $OUTDIR"
