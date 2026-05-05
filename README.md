# PDIve++

PDIve++ is a modular CLI tool for authorized network reconnaissance and discovery workflows.
Current Version: v1.7.6

## Project Overview

PDIve++ has been refactored into a modular Python package for better maintainability and extensibility. It orchestrates multiple discovery and scanning tools into a unified workflow.

### Features
- **Passive-Only Amass**: Amass runs with `-passive` enforced, relying entirely on OSINT data sources.
- **Concurrent Passive Discovery**: `amass`, `dnsdumpster`, and `crtsh` run in parallel across all targets.
- **Parallel Nmap Service Scanning**: Hosts are scanned concurrently rather than sequentially.
- **DNS Resolution Caching**: Hostnames resolved during target validation are reused across metadata lookup and masscan phases — no duplicate queries.
- **Targeted Passive Discovery**: Isolate specific OSINT tools with `--amass`, `--dnsdumpster`, or `--crtsh`.
- **Selective Scanning**: Skip the port scanning phase for pure discovery/OSINT workflows with `--no-scan`.
- **Modular Architecture**: Logic is separated into cohesive modules (`core`, `discovery`, `scanning`, `reporting`, `utils`).
- **Real-time WHOIS**: WHOIS lookups for primary targets are performed and displayed at the start of the scan.
- **Checkpoint Support**: Periodic checkpoints are saved during scanning and written on exit, enabling post-scan review of partial results.
- **Robust masscan Resiliency**: Automatic local IP detection and `--source-ip` / `--router-ip` retries.
- **Graceful Fallbacks**: Missing `nmap` or `masscan` binaries fall back to built-in scanning methods.
- **Type Safety**: Core modules include comprehensive type hints.

## Quick Start

1. Install dependencies and prerequisites: see `INSTALL.md`
2. Run a scan: see `USAGE.md`

## Project Structure

```text
PDIveplusplus/
├── lib/                    # Core package
│   ├── core.py             # Scan orchestration
│   ├── discovery.py        # Passive & active discovery
│   ├── scanning.py         # Port & service scanning
│   ├── reporting.py        # Report generation
│   └── utils.py            # Helpers & configuration
├── pdive++.py              # CLI entry point
├── INSTALL.md
├── USAGE.md
├── CHANGELOG.md
└── requirements.txt
```

## Setup and Execution

### Recommended Setup (Virtualenv)

```bash
# 1. Create and activate virtualenv
python3 -m venv venv
source venv/bin/activate           # Linux/macOS
# OR
.\venv\Scripts\Activate.ps1        # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the tool
python pdive++.py -t example.com
```

### Privileged Scans

Some modes (`masscan`, `nmap`) require elevated privileges. Always use the virtualenv's Python interpreter when using `sudo`:

```bash
sudo ./venv/bin/python pdive++.py -t 192.168.1.0/24
```

## Documentation

- **Installation**: `INSTALL.md`
- **Detailed Usage**: `USAGE.md`
- **Change History**: `CHANGELOG.md`

## Safety Warning

**PDIve++ is for authorized security testing only.** Users are responsible for ensuring they have explicit permission to scan target networks and domains.
