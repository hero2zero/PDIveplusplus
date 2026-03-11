# PDIve++

PDIve++ is a CLI tool for authorized network reconnaissance and discovery workflows.
Current Version: v1.7.0

## Quick Start

1. Install dependencies and prerequisites: see `INSTALL.md`
2. Run a scan: see `USAGE.md`

## Core Docs

- Installation: `INSTALL.md`
- Usage and examples: `USAGE.md`
- Python dependencies: `requirements.txt`

## Example

```bash
python pdive++.py -t 127.0.0.1 --no-json
python pdive++.py -t 192.168.1.0/24 --masscan --all-ports
python pdive++.py -t 192.168.0.0/16 --masscan --masscan-timeout 600
python pdive++.py -t example.com --amass
python pdive++.py --resume ./pdive_output/scan_checkpoint.json
```

## Notes

- Use only on systems you are explicitly authorized to test.
- Scanning mode options (mutually exclusive):
  - `--nmap`: Detailed Nmap service enumeration after masscan
  - `--masscan`: Fast port scanning with basic service detection
  - `--amass`: Run only amass subdomain discovery
- Port scanning options:
  - `--all-ports`: Scan all ports 1-65535 (default: scan top 1000 ports only for faster results)
  - Works with both `--masscan` and `--nmap` modes
- Report format flags:
  - `--json-only`: JSON reports only
  - `--no-json`: disable JSON reports
- Report lookup controls:
  - `--dns-timeout <seconds>`: DNS lookup timeout (default: 5)
  - `--whois-timeout <seconds>`: WHOIS lookup timeout (default: 15)
  - `--no-whois`: disable WHOIS lookups in reports
- Resumable scans:
  - `--checkpoint-interval <seconds>`: autosave checkpoint interval (default: 30; 0 disables)
  - `--resume <checkpoint_json>`: resume a prior scan from a checkpoint file
- Timeout controls:
  - `--amass-timeout <seconds>`: timeout for amass run (default: 180)
  - `--masscan-timeout <seconds>`: timeout for masscan scans (default: 300)
    - User is prompted to extend timeout interactively if timeout is reached
