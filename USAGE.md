# PDIve++ Usage Guide

`pdive++.py` is a powerful reconnaissance tool for authorized security testing.
Current Version: v1.8.0

## Core Workflow

PDIve++ follows a structured reconnaissance lifecycle:
1. **Primary Target Analysis**: Real-time WHOIS lookup for initial targets.
2. **Discovery**: Active (ping/port) or Passive (Amass/DNS) subdomain/host enumeration. Passive providers run concurrently.
3. **Metadata Enrichment**: DNS and reverse-DNS resolution for all discovered hosts. IPs resolved during target validation are cached and reused here.
4. **Port Scanning** *(active mode only)*: Built-in TCP scanner runs against the top 1000 ports by default; use `-p/--ports` to target specific ports or `--all-ports` for the full range. Skipped in passive mode (the default).
5. **Service Enumeration** *(active mode only)*: Detailed identification via `nmap` (hosts scanned in parallel) or built-in methods. Skipped in passive mode.
6. **Unified Reporting**: Generation of JSON, CSV, and text reports.

> **Default behavior:** PDIve++ runs in **passive** mode by default. WHOIS, passive discovery (Amass / DNSDumpster / crt.sh), and DNS/rDNS metadata lookups all execute, but the port scan and nmap service enumeration phases are skipped. Pass `-m active` to enable them.

## Basic Syntax

```bash
python pdive++.py -t <target> [options]
python pdive++.py -f <targets_file> -v -k [options]
```

## Key Options

### General Selection
- `-t, --target`: Comma-separated list of IP addresses, CIDR ranges, or hostnames.
- `-f, --file`: Path to a file containing targets (one per line).
- `-o, --output`: Output directory (default: `pdive_output`).
- `-T, --threads`: Thread count for parallel tasks (default: 50).
- `-m, --mode`: Discovery mode (`active` or `passive`, default: `passive`). Passive mode skips the nmap port and service scan phases; pass `-m active` to enable them.

### Discovery & Scanning Features
- `--ping`: Enable ICMP-based host discovery.
- `-p, --ports`: Comma-separated ports or ranges to scan (e.g., `-p 80,443` or `-p 80,8000-9000`). Mutually exclusive with `--all-ports`.
- `--all-ports`: Scan the full TCP port range (1-65535) instead of the top 1000.
- `--amass`: Run Amass for passive subdomain discovery (switches mode to passive; warns if `--mode active` was set).
- `--dnsdumpster`: Run DNSDumpster for passive discovery (switches mode to passive; warns if `--mode active` was set).
- `--crtsh`: Run crt.sh for passive discovery (switches mode to passive; warns if `--mode active` was set).
- `--no-scan`: Skip the port scanning phase entirely.
- `-k, --insecure`: Disable SSL verification for service checks.
- `--ca-bundle`: Use a custom CA bundle for certificate verification.
- `-v, --verbose`: Enable debug-level logging.

### Control & Tuning
- `--amass-timeout`: Timeout for Amass subdomain discovery (default: 180s).
- `--dns-timeout`: Timeout for DNS/rDNS resolution (default: 5s).
- `--whois-timeout`: Timeout for WHOIS queries (default: 15s).
- `--no-whois`: Completely disable WHOIS lookups.

## Examples

### Rapid Host Discovery
```bash
# Active scan of a network range with the built-in port scanner and nmap service detection
python pdive++.py -t 192.168.1.0/24 -m active
```

### Targeted Port Scan
```bash
# Only check for HTTP/HTTPS on a network range
python pdive++.py -t 192.168.1.0/24 -m active -p 80,443
```

### Full Reconnaissance
```bash
# Passive discovery, WHOIS, and all-ports nmap scan for a domain
python pdive++.py -t example.com -m active --all-ports
```

### Default Passive Recon
```bash
# Passive default: WHOIS + Amass/DNSDumpster/crt.sh + DNS metadata, no port/service scans
python pdive++.py -t example.com
```

### Targeted Passive Discovery (OSINT Only)
```bash
# Run ONLY Amass discovery and WHOIS (skip port scanning)
python pdive++.py -t example.com --amass --no-scan
```

### Combined Passive Tools
```bash
# Run Amass and crt.sh discovery concurrently, then perform metadata lookup
python pdive++.py -t example.com --amass --crtsh --no-scan
```

### Advanced Troubleshooting
```bash
# Use custom certificates and verbose logging
python pdive++.py -t internal.local -k -v --ca-bundle ./internal-ca.pem
```

## Robust Scanning & Troubleshooting

### Targeted Discovery
Isolate specific passive discovery providers using `--amass`, `--dnsdumpster`, or `--crtsh`. When any of these flags are used, the tool switches to `passive` mode and only executes the selected providers. If you also pass `--mode active`, a warning is printed before the mode is overridden.

When `--mode passive` is used without specific tool flags, all three providers run.

### Concurrent Passive Discovery
All passive providers (`amass`, `dnsdumpster`, `crtsh`) are dispatched concurrently. For multiple domains, each provider/domain combination runs in its own thread up to the configured thread limit.

### Amass Passive Mode
Amass is always invoked with `-passive`, restricting it to OSINT data sources (certificate logs, APIs, DNS records) and preventing any active probing.

### Skipping Scans
PDIve++ runs in passive mode by default, which already skips the port scanning and nmap service enumeration phases. For an active scan that *also* skips port scanning (e.g. when you only want active host discovery), pass `--no-scan` alongside `-m active`.

### Real-time WHOIS
PDIve++ prints WHOIS results for primary targets immediately at the start of the scan, allowing you to verify domain ownership before the more time-consuming discovery phases begin.

### nmap Service Enumeration
When run with `-m active`, PDIve++ automatically performs a port scan and then runs `nmap -Pn -sV` for service enumeration — no extra flag is needed. This requires both the `python-nmap` Python module and the `nmap` binary in `PATH`. If either is missing, PDIve++ falls back to its built-in service identification and prints:

```
[-] Nmap module not available, using basic identification
```

To resolve: install both dependencies (see `INSTALL.md` Section 3), then re-run using the virtualenv interpreter. On Linux/macOS, `nmap` scanning requires `sudo` for raw socket access — use `sudo ./venv/bin/python pdive++.py` rather than `sudo python3`.

In passive mode (the default), the port scan and nmap service scan are not run at all, regardless of whether `nmap` is installed.

## Safety & Compliance

- **Authorization Prompt**: PDIve++ will always ask for confirmation that you are authorized to scan the targets.
- **Scope**: Ensure all targets (IPs and discovered subdomains) are within your authorized scope.
