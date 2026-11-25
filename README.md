# Web Recon Tools

Helper scripts for **passive and active reconnaissance on authorized lab targets only**. Do not run them against systems you do not have permission to test.

They collect basic host and HTTP information and write a timestamped report folder. There is no brute force, credential stuffing, or exploit functionality.

## Scripts

| Script | What it does |
|---|---|
| `passive_recon.sh` | Collects low-impact information from a URL: HTTP headers and body, a security-header snapshot, cookie names, and page artifacts (title, forms, script sources). Uses `dig` and `whois` if they are installed, and `httpx` only if it is installed. |
| `active_recon.sh` | Probes one target directly: HTTP head/metrics, optional `httpx`, and conservative `nmap` scans (`-T2`) of common web ports (`80,443,8080,8000,8888,8443` plus the URL's port). |

## Requirements

- bash, curl, and standard Unix tools (`awk`, `sed`, `grep`, `tee`, `sort`)
- `active_recon.sh` also needs `nmap`
- Optional: `dig`, `whois`, and `httpx` (skipped with a note in the report if they are missing)

## Usage

```bash
chmod +x passive_recon.sh active_recon.sh
./passive_recon.sh "http://target.example/login"
./active_recon.sh "http://target.example/login"
```

The URL must include `http://` or `https://`.

Optional, for a wider (still reconnaissance-only) port scan:

```bash
./active_recon.sh "http://target.example/login" --top-ports N
```

## Output

Each run creates a timestamped folder in the current directory:

- `passive_recon_YYYYMMDD_HHMMSS/`
- `active_recon_YYYYMMDD_HHMMSS/`

The folder includes a summary plus the collected headers, body, and scan output.

## License

No license file is included in this repository yet.
