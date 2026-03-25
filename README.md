# Web Recon Helper Scripts (Lab Use)

These scripts are intended for authorized course lab targets only.

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
- Active script uses `nmap` with conservative timing (`-T2`).
