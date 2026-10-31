#!/usr/bin/env bash
set -euo pipefail
umask 077

# Active recon for one host you are authorized to probe.
# Usage: ./active_recon.sh "http://scanme.nmap.org/" [--top-ports N]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 1
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

usage() {
  cat <<'EOF'
Usage: ./active_recon.sh <url> [--top-ports N]

Fetch HTTP metadata and run a conservative nmap scan of common web ports.
N is optional and must be an integer from 1 to 65535.

Examples:
  ./active_recon.sh "http://scanme.nmap.org/"
  ./active_recon.sh "http://127.0.0.1/" --top-ports 50

The URL must start with http:// or https://. Embedded credentials are rejected.
SYN scan (-sS) is used when the script runs as root; otherwise it uses a TCP
connect scan (-sT).
EOF
}

if [[ $# -ge 1 && ( "$1" == "-h" || "$1" == "--help" ) ]]; then
  usage
  exit 0
fi

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

URL="$1"
shift
TOP_PORTS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --top-ports)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --top-ports." >&2
        usage >&2
        exit 1
      fi
      if [[ ! "$2" =~ ^[1-9][0-9]*$ || ${#2} -gt 5 || "$2" -gt 65535 ]]; then
        echo "Invalid --top-ports value: use an integer from 1 to 65535." >&2
        exit 1
      fi
      TOP_PORTS="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

parse_http_url "$URL" || exit 1

require_cmd curl
require_cmd nmap
require_cmd tee
require_cmd tr
require_cmd sort
require_cmd paste
require_cmd grep
require_cmd mktemp

prepare_output_dir "active_recon"

WEB_PORTS="80,443,8080,8000,8888,8443,${PORT}"
WEB_PORTS="$(printf '%s\n' "$WEB_PORTS" | tr ',' '\n' | grep -E '^[0-9]+$' | sort -nu | paste -sd, -)"
if [[ ! "$WEB_PORTS" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
  echo "Internal error: refusing to scan an unexpected port list." >&2
  exit 1
fi

if [[ "$EUID" -eq 0 ]]; then
  NMAP_MODE=(-sS)
  NMAP_MODE_LABEL="SYN (-sS)"
else
  NMAP_MODE=(-sT)
  NMAP_MODE_LABEL="TCP connect (-sT)"
fi

NMAP_COMMON=(-Pn -T2)
if [[ "$IS_IPV6" -eq 1 ]]; then
  NMAP_COMMON+=(-6)
fi

{
  echo "=== Active Recon Report ==="
  echo "Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "Input URL: $URL"
  echo "Host: $HOST"
  echo "Default Port: $PORT"
  echo "Web Ports Scan: $WEB_PORTS"
  echo "Nmap mode: $NMAP_MODE_LABEL"
  if [[ "$TOP_PORTS" -gt 0 ]]; then
    echo "Top ports: $TOP_PORTS"
  fi
  echo
  echo "NOTE: For authorized targets only."
  echo "NOTE: This script performs direct probing and scanning."
} | tee "${OUTDIR}/00_summary.txt"

curl_http -sS -I -- "$URL" > "${OUTDIR}/20_http_head.txt" 2>&1 || true
curl_http -sS -L --max-redirs 10 -o /dev/null \
  -w "final_url=%{url_effective}\nhttp_code=%{http_code}\nremote_ip=%{remote_ip}\nnum_redirects=%{num_redirects}\ntime_total=%{time_total}\n" \
  -- "$URL" > "${OUTDIR}/21_http_metrics.txt" 2>&1 || true

run_httpx_probe "${OUTDIR}/22_httpx_probe.txt" "$URL"

nmap "${NMAP_COMMON[@]}" "${NMAP_MODE[@]}" -p "$WEB_PORTS" \
  -oN "${OUTDIR}/30_nmap_web_ports.txt" -- "$HOST" >/dev/null
nmap "${NMAP_COMMON[@]}" "${NMAP_MODE[@]}" -sV --version-light -p "$WEB_PORTS" \
  -oN "${OUTDIR}/31_nmap_web_service_version.txt" -- "$HOST" >/dev/null

if [[ "$TOP_PORTS" -gt 0 ]]; then
  nmap "${NMAP_COMMON[@]}" "${NMAP_MODE[@]}" --top-ports "$TOP_PORTS" \
    -oN "${OUTDIR}/32_nmap_top_ports.txt" -- "$HOST" >/dev/null
fi

echo "Active recon complete. Output folder: $OUTDIR"
