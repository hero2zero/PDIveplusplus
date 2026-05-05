# PDIve++ Install Guide

Current Version: v1.7.6

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

**IMPORTANT:** Always use a virtualenv to avoid dependency issues.

### Windows (PowerShell)

```powershell
cd /path/to/PDIveplusplus
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Linux/macOS

```bash
cd /path/to/PDIveplusplus
python3 -m venv venv
source venv/bin/activate
```

## 4. Install Python dependencies

```bash
pip install -r requirements.txt
```

**Note:** The `python-whois` package is NOT the same as the `whois` CLI tool from `apt`. Installing `apt install whois` does not provide the Python module.

## 5. Verify optional binaries in PATH

```bash
amass -version
masscan --version
nmap --version
```

If a binary is missing, install it via your OS package manager or the official repository.

## 6. Run

### Standard Execution (No sudo)

```bash
python pdive++.py -t 127.0.0.1
```

### Execution with sudo (If Required for Raw Sockets)

Some scanning modes (masscan, nmap) may require elevated privileges for raw socket access.

**❌ WRONG - Don't use system Python with sudo:**
```bash
sudo python3 pdive++.py -t 192.168.1.0/24
# This will cause "module not available" errors even if you installed them!
```

**✅ CORRECT - Use virtualenv Python with sudo:**
```bash
sudo ./venv/bin/python pdive++.py -t 192.168.1.0/24      # Linux/macOS
sudo .\venv\Scripts\python.exe pdive++.py -t 192.168.1.0/24   # Windows
```

**Why?**
- `sudo python3` uses the system Python interpreter (`/usr/bin/python3`)
- Your virtualenv packages are installed in `./venv/lib/python3.x/site-packages/`
- System Python cannot see virtualenv packages
- Solution: Use `sudo ./venv/bin/python` to preserve the virtualenv context

### Verification

Use verbose mode to see which Python interpreter is active:
```bash
python pdive++.py -t 127.0.0.1 -v --no-json
# Look for: "Python interpreter: /path/to/python"
```

## Troubleshooting

### Module Not Found Errors

**Problem: "whois module not available" even after `pip install python-whois`**

This usually means you're running with the wrong Python interpreter.

**Diagnosis:**
```bash
# Check which Python you're using
python pdive++.py -t 127.0.0.1 -v
# Look for: "Python interpreter: /path/to/python"
```

**Solution:**
- If you see `/usr/bin/python3` but have a virtualenv, you're using system Python
- Activate your virtualenv: `source venv/bin/activate`
- Or if using sudo: `sudo ./venv/bin/python pdive++.py -t ...`

**Common causes:**
- Running `sudo python3` instead of `sudo ./venv/bin/python`
- Not activating the virtualenv before running
- Installing with `pip` but running with `pip3` (different Python versions)

### Other Issues

- `requests module not available`: run `pip install -r requirements.txt` in your active virtualenv
- `nmap module not available`: install `python-nmap` and ensure `nmap` binary is installed
- `Amass not found in PATH`: Follow the instructions in Section 2 above.
- `Masscan not found in PATH`: install `masscan` or let tool fall back to built-in scanner
- Windows (masscan): ensure `masscan.exe` is in `PATH` and run PowerShell as Administrator if raw socket scans fail
- Windows (nmap): install Nmap for Windows and ensure `nmap.exe` is in `PATH`
- On restricted environments, raw-socket scans may require elevated privileges or capabilities

### Important Note

- `apt install whois` installs a CLI tool, NOT the Python module
- You need `pip install python-whois` for the Python import
- These are completely different packages!
