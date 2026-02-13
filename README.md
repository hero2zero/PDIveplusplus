# PDIve++

PDIve++ is a CLI tool for authorized network reconnaissance and discovery workflows.

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
python pdive++.py --resume ./pdive_output/scan_checkpoint.json
```

## Notes

- Use only on systems you are explicitly authorized to test.
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
- Amass:
  - `--amass-timeout <seconds>`: timeout for amass run (default: 180)
