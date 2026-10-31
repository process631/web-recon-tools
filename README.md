# Web Recon Tools

**Authorized use only.** Run these scripts against systems you own or have explicit permission to test. [scanme.nmap.org](https://nmap.org/book/man-examples.html) is a public host the Nmap project provides for scanner testing. `127.0.0.1` and `localhost` are for practice on your own machine. You are responsible for following the law and the rules of any network you use.

Small Bash helpers that collect web metadata and, in the active script, run a slow nmap check of common web ports. They do not brute-force logins, stuff credentials, or run exploit modules.

The passive script still contacts the target (DNS, WHOIS, and one HTTP request). It is low-impact. It is not an offline lookup.

## What it does

`passive_recon.sh` records DNS and WHOIS data when those tools are installed, downloads one URL, and pulls out security headers, cookie names, the page title, form actions, hidden token-like inputs, and script sources.

`active_recon.sh` records HTTP response metadata, then scans a fixed set of web ports with nmap at timing `-T2`. An optional `--top-ports` flag adds one wider port check. Service detection uses `--version-light`.

Both scripts can call [ProjectDiscovery httpx](https://github.com/projectdiscovery/httpx) when that binary is on `PATH`. The Python package named `httpx` is a different tool and is skipped.

## Features

- One URL in, one private output directory out
- DNS (`A`, `AAAA`, `CNAME`, `NS`, `MX`) and WHOIS when `dig` and `whois` are installed
- Security-header and cookie-name snapshot
- HTML artifact extraction (title, form actions, token-like hidden fields, script sources)
- Optional technology probe via ProjectDiscovery httpx
- Conservative nmap scan of ports `80`, `443`, `8080`, `8000`, `8888`, `8443`, plus the URL port
- Optional `--top-ports N` scan, with `N` limited to `1`–`65535`
- SYN scan (`-sS`) when run as root; TCP connect scan (`-sT`) otherwise

## Safety controls

- The URL must be `http://` or `https://`. Hostnames, IPv4, and bracketed IPv6 are accepted. Userinfo (`user:pass@host`), whitespace, and hosts that look like flags are rejected.
- `curl` is limited to HTTP and HTTPS, including redirects, ignores `~/.curlrc`, and gives up after 45 seconds.
- The host and port list passed to `nmap`, `dig`, and `whois` are validated before use. Values are passed as single quoted arguments.
- `--top-ports` accepts only an integer from 1 to 65535.
- Output directories are created with `mktemp` and mode `700`. Files inside them follow umask `077`.
- WHOIS and httpx are time-limited so a stalled lookup does not hang the script.

## Requirements

- Bash 3.2 or newer
- `curl` 7.73 or newer (needs `--proto-redir`)
- `mktemp`, `grep`, `awk`, `sort`, `tee` (standard on Linux and macOS)
- Active script also needs `nmap` and `paste`
- Optional: `dig` (package `dnsutils` / `bind`), `whois`, ProjectDiscovery `httpx`, and `timeout` from coreutils

## Install

```bash
git clone https://github.com/process631/web-recon-tools.git
cd web-recon-tools
chmod +x passive_recon.sh active_recon.sh
```

Debian or Ubuntu packages:

```bash
sudo apt install curl nmap dnsutils whois
```

macOS (Homebrew):

```bash
brew install nmap
```

`curl`, `whois`, and `dig` ship with macOS. ProjectDiscovery httpx is optional; install it from that project if you want the technology probe. Leave it off `PATH` and the scripts record that the probe was skipped.

## Usage

Passive collection against Nmap's scanner test host (it serves HTTP on port 80):

```bash
./passive_recon.sh "http://scanme.nmap.org/"
```

Active scan of your own machine:

```bash
./active_recon.sh "http://127.0.0.1/"
```

Active scan of the Nmap test host, plus the 50 most common ports:

```bash
./active_recon.sh "http://scanme.nmap.org/" --top-ports 50
```

Help:

```bash
./passive_recon.sh --help
./active_recon.sh --help
```

A root shell is required only for the SYN scan. Without root, the active script uses a TCP connect scan and says so in `00_summary.txt`.

## Output

Each run creates a new directory in the current working directory:

- `passive_recon_YYYYMMDD_HHMMSS_XXXXXX/`
- `active_recon_YYYYMMDD_HHMMSS_XXXXXX/`

The suffix comes from `mktemp`. These directories are gitignored. They can contain response bodies and scan results, so treat them as sensitive and delete them when you are done.

### Passive files

| File | Contents |
| --- | --- |
| `00_summary.txt` | Timestamp, URL, scheme, host, explicit port |
| `10_dns.txt` | DNS answers, when `dig` is installed |
| `11_whois.txt` | WHOIS text, when `whois` is installed |
| `20_headers.txt` | Response headers |
| `21_body.html` | Response body |
| `22_passive_artifacts.txt` | Title, forms, token-like hidden inputs, script sources, tech headers |
| `23_security_headers.txt` | Selected security headers and cookie names |
| `24_httpx_probe.txt` | ProjectDiscovery httpx output, or a skip message |

### Active files

| File | Contents |
| --- | --- |
| `00_summary.txt` | Timestamp, URL, host, ports, nmap mode |
| `20_http_head.txt` | `curl -I` output |
| `21_http_metrics.txt` | Final URL, status, remote IP, redirect count, total time |
| `22_httpx_probe.txt` | ProjectDiscovery httpx output, or a skip message |
| `30_nmap_web_ports.txt` | Port state for the web-port list |
| `31_nmap_web_service_version.txt` | Light service detection on those ports |
| `32_nmap_top_ports.txt` | Present only when `--top-ports` is set |

## Project structure

```
.
├── LICENSE
├── README.md
├── active_recon.sh    # HTTP metadata and conservative nmap
├── passive_recon.sh   # DNS, WHOIS, headers, and HTML artifacts
└── lib/
    └── common.sh      # URL checks, private output dirs, curl/httpx wrappers
```

## License

[MIT](LICENSE). Copyright (c) 2026 process631.
