# Web Recon Helper Scripts (Lab Use)

These scripts are intended for authorized lab targets only.

## Files

- `passive_recon.sh` - Collects passive/low-impact info from a provided URL
- `active_recon.sh` - Performs active probing and conservative scans against one target

## Usage

```bash
chmod +x passive_recon.sh active_recon.sh
./passive_recon.sh "http://target.example/login"
./active_recon.sh "http://target.example/login"
```

## Output

Each run creates a timestamped folder:

- `passive_recon_YYYYMMDD_HHMMSS/`
- `active_recon_YYYYMMDD_HHMMSS/`

## Notes

- No brute force, credential stuffing, or exploit modules are used.
- Passive script is header/body + DOM artifact parsing; it uses `httpx` only if installed.
- Active script uses `nmap` with conservative timing (`-T2`) and defaults to common web ports only.
- Optional: `./active_recon.sh "http://target.example/login" --top-ports N` for a wider port list (still a recon scan).
