#!/usr/bin/env bash
# Shared helpers for the recon scripts. Source this file; do not execute it.

# Print an error and exit when a required command is missing.
require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

# Return 0 when $1 is a dotted IPv4 address with octets 0-255 and no leading zeros.
ipv4_ok() {
  local host="$1"
  local octet
  local o1 o2 o3 o4

  [[ "$host" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  o1="${BASH_REMATCH[1]}"
  o2="${BASH_REMATCH[2]}"
  o3="${BASH_REMATCH[3]}"
  o4="${BASH_REMATCH[4]}"
  for octet in "$o1" "$o2" "$o3" "$o4"; do
    if [[ ${#octet} -gt 1 && "$octet" == 0* ]]; then
      return 1
    fi
    if [[ "$octet" -gt 255 ]]; then
      return 1
    fi
  done
}

# Parse an http(s) URL into the globals SCHEME, HOST, EXPLICIT_PORT, PORT, and IS_IPV6.
# Rejects userinfo, control characters, and hosts that could be read as CLI flags.
parse_http_url() {
  local url="$1"
  local authority rest
  local rest_re='^[A-Za-z0-9._~:/?#@!&'"'"'()*+,;=%-]+$'

  SCHEME=""
  HOST=""
  EXPLICIT_PORT=""
  PORT=""
  IS_IPV6=0

  if [[ "$url" =~ [[:space:][:cntrl:]] ]]; then
    echo "Invalid URL: whitespace or control characters are not allowed." >&2
    return 1
  fi
  if [[ ${#url} -gt 2048 ]]; then
    echo "Invalid URL: must be 2048 characters or fewer." >&2
    return 1
  fi
  if [[ ! "$url" =~ ^(https?)://([^/?#]+)(.*)$ ]]; then
    echo "Invalid URL. Include scheme (http:// or https://)." >&2
    return 1
  fi

  SCHEME="${BASH_REMATCH[1]}"
  authority="${BASH_REMATCH[2]}"
  rest="${BASH_REMATCH[3]}"

  if [[ "$authority" == *@* ]]; then
    echo "Invalid URL: embedded credentials are not allowed." >&2
    return 1
  fi

  if [[ "$authority" =~ ^\[(.+)\]:([0-9]+)$ ]]; then
    HOST="${BASH_REMATCH[1]}"
    EXPLICIT_PORT="${BASH_REMATCH[2]}"
    IS_IPV6=1
  elif [[ "$authority" =~ ^\[(.+)\]$ ]]; then
    HOST="${BASH_REMATCH[1]}"
    IS_IPV6=1
  elif [[ "$authority" =~ ^([^:]+):([0-9]+)$ ]]; then
    HOST="${BASH_REMATCH[1]}"
    EXPLICIT_PORT="${BASH_REMATCH[2]}"
  elif [[ "$authority" =~ ^[^:]+$ ]]; then
    HOST="$authority"
  else
    echo "Invalid URL: host must be a hostname, IPv4 address, or bracketed IPv6 address." >&2
    return 1
  fi

  if [[ "$IS_IPV6" -eq 1 ]]; then
    if [[ "$HOST" != *:* || "$HOST" == *:::* || "$HOST" == *::*::* || "$HOST" == *[!0-9A-Fa-f:.]* ]]; then
      echo "Invalid URL: malformed IPv6 address." >&2
      return 1
    fi
  else
    if [[ -z "$HOST" || "$HOST" == -* || "$HOST" == .* || "$HOST" == *- || "$HOST" == *. || "$HOST" == *..* ]]; then
      echo "Invalid URL: malformed host." >&2
      return 1
    fi
    if [[ ! "$HOST" =~ ^[A-Za-z0-9._-]+$ ]]; then
      echo "Invalid URL: host contains unsupported characters." >&2
      return 1
    fi
    if [[ "$HOST" =~ ^[0-9.]+$ ]] && ! ipv4_ok "$HOST"; then
      echo "Invalid URL: malformed IPv4 address." >&2
      return 1
    fi
  fi

  if [[ -n "$EXPLICIT_PORT" ]]; then
    if [[ ! "$EXPLICIT_PORT" =~ ^[1-9][0-9]{0,4}$ ]] || [[ "$EXPLICIT_PORT" -gt 65535 ]]; then
      echo "Invalid URL: port must be an integer from 1 to 65535." >&2
      return 1
    fi
    # PORT is read by active_recon.sh.
    # shellcheck disable=SC2034
    PORT="$EXPLICIT_PORT"
  elif [[ "$SCHEME" == "https" ]]; then
    # shellcheck disable=SC2034
    PORT=443
  else
    # shellcheck disable=SC2034
    PORT=80
  fi

  if [[ -n "$rest" && ! "$rest" =~ $rest_re ]]; then
    echo "Invalid URL: path, query, or fragment contains unsupported characters." >&2
    return 1
  fi
}

# Create a private output directory in the current working directory.
# Sets the global OUTDIR. The suffix is random so a pre-created symlink cannot be reused.
prepare_output_dir() {
  local prefix="$1"
  local ts

  ts="$(date +%Y%m%d_%H%M%S)"
  OUTDIR="$(mktemp -d "./${prefix}_${ts}_XXXXXX")" || {
    echo "Could not create an output directory in the current working directory." >&2
    return 1
  }
  chmod 700 "$OUTDIR"
}

# curl locked to http and https, including redirects. -q ignores ~/.curlrc.
curl_http() {
  curl -q --proto '=http,https' --proto-redir '=http,https' --connect-timeout 15 --max-time 45 "$@"
}

# Run a command with a timeout when coreutils timeout is available.
run_with_timeout() {
  local seconds="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$seconds" "$@"
  else
    "$@"
  fi
}

# Optional ProjectDiscovery httpx probe. Other binaries named httpx are skipped.
run_httpx_probe() {
  local outfile="$1"
  local url="$2"
  local help

  if ! command -v httpx >/dev/null 2>&1; then
    echo "httpx not installed; skipping httpx probe." > "$outfile"
    return 0
  fi

  help="$(run_with_timeout 10 httpx -h 2>&1 || true)"
  if [[ "$help" != *tech-detect* ]]; then
    echo "httpx is installed but does not look like ProjectDiscovery httpx; skipping httpx probe." > "$outfile"
    return 0
  fi

  run_with_timeout 45 httpx -silent -no-color -fr -status-code -title -server -tech-detect -location -favicon -jarm -ct -cl "$url" \
    > "$outfile" 2>&1 || true
}
