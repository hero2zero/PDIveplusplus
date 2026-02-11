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
```

## Notes

- Use only on systems you are explicitly authorized to test.
- Report format flags:
  - `--json-only`: JSON reports only
  - `--no-json`: disable JSON reports
