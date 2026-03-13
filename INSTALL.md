# PDIve++ Install Guide

Current Version: v1.7.4

## 1. Prerequisites

- Python 3.9+ recommended
- `pip`
- Authorized test scope and permission

Required/Optional external tools:
- `amass` (Highly Recommended: passive subdomain discovery)
- `masscan` (Optional: high-speed port scan)
- `nmap` binary (Optional: used by `python-nmap` for detailed service enumeration)

## 2. Installing Amass

`amass` is required for the passive discovery phase. If you see the error `[-] Amass not found in PATH`, follow these steps:

### Linux (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install amass
```

### Linux (Arch)
```bash
sudo pacman -S amass
```

### macOS (Homebrew)
```bash
brew install amass
```

### Using Go (Cross-Platform)
If you have Go installed:
```bash
go install -v github.com/owasp-amass/amass/v4/...@master
```
Ensure `~/go/bin` is in your `PATH`.

### Manual (Any OS)
1. Download the latest release from [OWASP Amass Releases](https://github.com/OWASP/Amass/releases).
2. Extract the archive.
3. Move the `amass` binary to a folder in your `PATH` (e.g., `/usr/local/bin` on Linux/macOS).

## 3. Create/activate a virtual environment

### Windows (PowerShell)

```powershell
cd /path/to/PDIveplusplus
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Linux/macOS

```bash
cd /path/to/PDIveplusplus
python3 -m venv .venv
source .venv/bin/activate
```

## 4. Install Python dependencies

```bash
pip install -r requirements.txt
```

## 5. Verify optional binaries in PATH

```bash
amass -version
masscan --version
nmap --version
```

If a binary is missing, install it via your OS package manager or the official repository.

## 6. Run

```bash
python pdive++.py -t 127.0.0.1 --no-json
```

## 7. Resume (Optional)

If a scan is interrupted, resume from the last checkpoint:

```bash
python pdive++.py --resume ./pdive_output/scan_checkpoint.json
```

## Troubleshooting

- `requests module not available`: run `pip install -r requirements.txt`
- `nmap module not available`: install `python-nmap` and ensure `nmap` binary is installed
- `Amass not found in PATH`: Follow the instructions in Section 2 above.
- `Masscan not found in PATH`: install `masscan` or let tool fall back to built-in scanner
- Windows (masscan): ensure `masscan.exe` is in `PATH` and run PowerShell as Administrator if raw socket scans fail
- Windows (nmap): install Nmap for Windows and ensure `nmap.exe` is in `PATH`
- On restricted environments, raw-socket scans may require elevated privileges or capabilities
