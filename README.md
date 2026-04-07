# PDIve++

PDIve++ is a modular CLI tool for authorized network reconnaissance and discovery workflows.
Current Version: v1.7.5 (Enhanced Passive Discovery)

## Project Overview

PDIve++ has been refactored into a modular Python package for better maintainability and extensibility. It orchestrates multiple discovery and scanning tools into a unified workflow.

### New Features & Improvements
- **Targeted Passive Discovery**: Isolate specific OSINT tools like `amass`, `dnsdumpster`, or `crtsh`.
- **Selective Scanning**: Skip the port scanning phase for pure discovery/OSINT workflows.
- **Modular Architecture**: Logic is now separated into cohesive modules (`core`, `discovery`, `scanning`, `reporting`, `utils`).
- **Real-time WHOIS**: WHOIS lookups for primary targets are now performed and displayed in real-time at the start of the scan.
- **Enhanced Error Handling**: 
  - Improved `masscan` reliability with automatic local IP detection and `--source-ip` retries.
  - Robust `nmap` binary detection with graceful fallback to basic service identification.
- **Type Safety**: Core modules now include comprehensive type hints.

## Quick Start

1. Install dependencies and prerequisites: see `INSTALL.md`
2. Run a scan: see `USAGE.md`

## Project Structure

```text
PDIveplusplus/
├── pdive/                  # Core package
│   ├── core.py             # Scan orchestration
│   ├── discovery.py        # Passive & active discovery
│   ├── scanning.py         # Port & service scanning
│   ├── reporting.py        # Report generation
│   └── utils.py            # Helpers & configuration
├── pdive++.py              # CLI entry point (wrapper)
├── pdive++_legacy.py       # Original monolithic script (deprecated)
├── GEMINI.md               # Development guidelines & roadmap
└── ...
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
- **Development**: `GEMINI.md`

## Safety Warning

**PDIve++ is for authorized security testing only.** Users are responsible for ensuring they have explicit permission to scan target networks and domains.
