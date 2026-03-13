# PDIve++

PDIve++ is a CLI tool for authorized network reconnaissance and discovery workflows.
Current Version: v1.7.4

## Quick Start

1. Install dependencies and prerequisites: see `INSTALL.md`
2. Run a scan: see `USAGE.md`

## Setup and Execution

### Correct Setup (Virtualenv Recommended)

```bash
# 1. Create virtualenv
python3 -m venv venv

# 2. Activate virtualenv
source venv/bin/activate           # Linux/macOS
# OR
.\venv\Scripts\Activate.ps1        # Windows PowerShell

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the tool (without sudo if possible)
python pdive++.py -t 192.168.1.0/24

# 5. If sudo is required (for raw sockets), use the virtualenv interpreter
sudo ./venv/bin/python pdive++.py -t 192.168.1.0/24     # Linux/macOS
```

### Common Pitfall: sudo with Wrong Python

**❌ WRONG - This bypasses your virtualenv:**
```bash
pip install python-whois          # Installs in venv
sudo python3 pdive++.py -t ...    # Uses system Python, not venv Python
# Result: "whois module not available" error
```

**✅ CORRECT - Use virtualenv interpreter with sudo:**
```bash
pip install python-whois          # Installs in venv
sudo ./venv/bin/python pdive++.py -t ...   # Uses venv Python
# Result: Works correctly
```

### Why This Happens

- `pip install` puts packages in your virtualenv (`./venv/lib/python3.x/site-packages/`)
- `sudo python3` uses the system Python interpreter (`/usr/bin/python3`)
- System Python cannot see virtualenv packages
- `apt install whois` installs the CLI tool, NOT the Python module `python-whois`

### Virtualenv Detection

The tool automatically detects and warns about virtualenv mismatches:
- Use `-v` flag to see which Python interpreter is active
- If running as root without a virtualenv, you'll get a warning if a local venv exists

## Core Docs

- Installation: `INSTALL.md`
- Usage and examples: `USAGE.md`
- Python dependencies: `requirements.txt`

## Example

```bash
python pdive++.py -t 127.0.0.1 --no-json
python pdive++.py -t 192.168.1.0/24 --masscan --all-ports
python pdive++.py -t 192.168.0.0/16 --masscan --masscan-timeout 600 -v
python pdive++.py -t example.com --ca-bundle /path/to/cert.pem
python pdive++.py -t internal.local -k
python pdive++.py --resume ./pdive_output/scan_checkpoint.json
```

## Notes

- Use only on systems you are explicitly authorized to test.
- Logging and Verbosity:
  - Default output uses standardized logging with timestamps.
  - `-v, --verbose`: Enable debug-level logging for detailed troubleshooting.
- SSL Configuration:
  - `--ca-bundle <path>`: Use a specific CA bundle for HTTP service checks.
  - `-k, --insecure`: Disable SSL verification for internal testing.
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
