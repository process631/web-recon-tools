#!/usr/bin/env bash
set -euo pipefail
umask 077

# Low-impact recon for one URL you are authorized to request.
# Usage: ./passive_recon.sh "http://scanme.nmap.org/"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 1
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

usage() {
  cat <<'EOF'
Usage: ./passive_recon.sh <url>

Collect DNS and WHOIS metadata when those tools are installed, then request
the URL and extract headers, cookie names, and a few HTML artifacts.

Examples:
  ./passive_recon.sh "http://scanme.nmap.org/"
  ./passive_recon.sh "http://127.0.0.1:8080/"

The URL must start with http:// or https://. Embedded credentials are rejected.
This script contacts the host. It does not run a port scan.
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

if [[ $# -gt 1 ]]; then
  echo "Unexpected argument: $2" >&2
  usage >&2
  exit 1
fi

URL="$1"
parse_http_url "$URL" || exit 1

require_cmd curl
require_cmd awk
require_cmd tee
require_cmd grep
require_cmd sort
require_cmd mktemp

prepare_output_dir "passive_recon"

{
  echo "=== Passive Recon Report ==="
  echo "Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "Input URL: $URL"
  echo "Scheme: $SCHEME"
  echo "Host: $HOST"
  echo "Explicit Port: ${EXPLICIT_PORT:-none (default for scheme)}"
  echo
  echo "NOTE: For authorized targets only."
} | tee "${OUTDIR}/00_summary.txt"

if command -v dig >/dev/null 2>&1; then
  {
    echo "=== dig A/AAAA/CNAME/NS/MX ==="
    dig +time=2 +tries=1 +short A "$HOST" || true
    dig +time=2 +tries=1 +short AAAA "$HOST" || true
    dig +time=2 +tries=1 +short CNAME "$HOST" || true
    dig +time=2 +tries=1 +short NS "$HOST" || true
    dig +time=2 +tries=1 +short MX "$HOST" || true
  } > "${OUTDIR}/10_dns.txt" 2>&1 || true
fi

if command -v whois >/dev/null 2>&1; then
  run_with_timeout 20 whois "$HOST" > "${OUTDIR}/11_whois.txt" 2>&1 || true
fi

if ! curl_http -sS -D "${OUTDIR}/20_headers.txt" -o "${OUTDIR}/21_body.html" -- "$URL"; then
  echo "HTTP request failed. Partial output: $OUTDIR" >&2
  exit 1
fi

{
  echo "=== Security Headers (from response) ==="
  grep -Ei '^(Strict-Transport-Security:|Content-Security-Policy:|X-Frame-Options:|X-Content-Type-Options:|Referrer-Policy:|Permissions-Policy:|Cross-Origin-Opener-Policy:|Cross-Origin-Embedder-Policy:|Cross-Origin-Resource-Policy:)' \
    "${OUTDIR}/20_headers.txt" || true
  echo
  echo "=== Cookies Set (names) ==="
  awk '
    tolower($0) ~ /^set-cookie:/ {
      line = $0
      sub(/^[Ss][Ee][Tt]-[Cc][Oo][Oo][Kk][Ii][Ee]:[[:space:]]*/, "", line)
      split(line, parts, "=")
      name = parts[1]
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
      if (name != "") print name
    }
  ' "${OUTDIR}/20_headers.txt" | awk 'NF{print}' | sort -u || true
} > "${OUTDIR}/23_security_headers.txt"

run_httpx_probe "${OUTDIR}/24_httpx_probe.txt" "$URL"

{
  echo "=== Title ==="
  grep -i -m 1 '<title>' "${OUTDIR}/21_body.html" || true
  echo
  echo "=== Form Actions ==="
  grep -Eio '<form[^>]*action="[^"]*"' "${OUTDIR}/21_body.html" || true
  echo
  echo "=== Hidden Token-Like Inputs (names) ==="
  grep -Eio '<input[^>]*>' "${OUTDIR}/21_body.html" \
    | grep -Ei 'type=["'\'']hidden["'\'']' \
    | grep -Ei 'name=["'\''][^"'\'' ]*(csrf|token|authenticity|_csrf|verification)' \
    || true
  echo
  echo "=== Script Sources ==="
  grep -Eio '<script[^>]*src="[^"]*"' "${OUTDIR}/21_body.html" || true
  echo
  echo "=== Potential Tech Headers ==="
  grep -Ei '^(Server:|X-Powered-By:|Set-Cookie:|Location:)' "${OUTDIR}/20_headers.txt" || true
} > "${OUTDIR}/22_passive_artifacts.txt"

echo "Passive recon complete. Output folder: $OUTDIR"
