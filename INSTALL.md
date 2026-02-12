# PDIve++ Install Guide

## 1. Prerequisites

- Python 3.9+ recommended
- `pip`
- Authorized test scope and permission

Optional external tools (recommended for full capability):
- `amass` (passive subdomain discovery)
- `masscan` (high-speed port scan)
- `nmap` binary (used by `python-nmap`)

## 2. Create/activate a virtual environment

### Windows (PowerShell)

```powershell
cd C:\Users\james.garcia\Tools\PDIve++
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Linux/macOS

```bash
cd /path/to/PDIve++
python3 -m venv .venv
source .venv/bin/activate
```

## 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

## 4. Verify optional binaries in PATH

```bash
amass -version
masscan --version
nmap --version
```

If a binary is missing, install it via your OS package manager or official release.

## 5. Run

```bash
python pdive++.py -t 127.0.0.1 --no-json
```

## 6. Resume (Optional)

If a scan is interrupted, resume from the last checkpoint:

```bash
python pdive++.py --resume ./pdive_output/scan_checkpoint.json
```

## Troubleshooting

- `requests module not available`: run `pip install -r requirements.txt`
- `nmap module not available`: install `python-nmap` and ensure `nmap` binary is installed
- `Masscan not found in PATH`: install `masscan` or let tool fall back to built-in scanner
- Windows (masscan): ensure `masscan.exe` is in `PATH` and run PowerShell as Administrator if raw socket scans fail
- Windows (nmap): install Nmap for Windows and ensure `nmap.exe` is in `PATH`
- On restricted environments, raw-socket scans may require elevated privileges or capabilities
