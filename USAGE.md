# PDIve++ Usage Guide

`pdive++.py` is a powerful reconnaissance tool for authorized security testing.
Current Version: v1.10.0

## Core Workflow

PDIve++ follows a structured reconnaissance lifecycle:
1. **Primary Target Analysis**: Real-time WHOIS lookup for initial targets.
2. **Discovery**: By default a scan probes only the targets you supply. Subdomain enumeration (Amass / DNSDumpster / crt.sh) is opt-in via `-e/--enumerate` or a per-tool flag; when enabled, each selected provider is queried in turn. In active mode, ping/port host discovery probes the targets (and any enumerated subdomains). In passive mode, bare IP targets get a reverse-DNS (PTR) record as metadata only — no enumeration pivot (see *PTR Metadata for IP Targets* below).
3. **Metadata Enrichment**: DNS and reverse-DNS resolution for all targets and discovered hosts. IPs resolved during target validation are cached and reused here.
4. **Port Scanning** *(active mode only)*: Built-in TCP scanner runs against the top 1000 ports by default; use `-p/--ports` to target specific ports or `--all-ports` for the full range. Skipped in passive mode (the default).
5. **Service Enumeration** *(active mode only)*: Detailed identification via `nmap` (one host at a time) or built-in methods. Skipped in passive mode.
6. **Unified Reporting**: Generation of JSON, CSV, and text reports.

> **Default behavior:** PDIve++ runs in **passive** mode by default and scans **only the targets you supply**. WHOIS and DNS/rDNS metadata lookups execute, but subdomain enumeration is **off** unless you pass `-e/--enumerate` (or a per-tool flag), and the port scan / nmap service enumeration phases are skipped unless you pass `-m active`. For constrained workflows, use `--strict-passive` or `--strict-active`.

## Basic Syntax

```bash
python pdive++.py -t <target> [options]
python pdive++.py -f <targets_file> -v -k [options]
```

If you installed the package (`pip install .`), the `pdive` command is
equivalent to `python pdive++.py` and can be used anywhere:

```bash
pdive -t <target> [options]
```

## Key Options

### General Selection
- `-t, --target`: Comma-separated list of IP addresses, CIDR ranges, or hostnames.
- `-f, --file`: Path to a file containing targets (one per line).
- `-o, --output`: Output directory (default: `pdive_output`).
- `-T, --threads`: Thread count for parallel tasks (default: 50).
- `-m, --mode`: Discovery mode (`active` or `passive`, default: `passive`). Passive mode skips the nmap port and service scan phases; pass `-m active` to enable them.
- `--strict-passive`: Run passive-only discovery without WHOIS or Amass, and skip active scanning.
- `--strict-active`: Run active-only discovery/scanning against supplied targets; disables WHOIS and all passive discovery providers.

### Discovery & Scanning Features
- `--ping`: Enable ICMP-based host discovery.
- `-p, --ports`: Comma-separated ports or ranges to scan (e.g., `-p 80,443` or `-p 80,8000-9000`). Mutually exclusive with `--all-ports`.
- `--all-ports`: Scan the full TCP port range (1-65535) instead of the top 1000.
- `-e, --enumerate`: Enable subdomain enumeration via **all** passive providers (Amass, DNSDumpster, crt.sh). Off by default — without this (or a per-tool flag below), a scan probes only the supplied targets.
- `--amass`: Enable subdomain enumeration via Amass only.
- `--dnsdumpster`: Enable subdomain enumeration via DNSDumpster only.
- `--crtsh`: Enable subdomain enumeration via crt.sh only.
- `--no-amass`: Disable Amass (subtracts from `--enumerate`).
- `--no-dnsdumpster`: Disable DNSDumpster (subtracts from `--enumerate`).
- `--no-crtsh`: Disable crt.sh (subtracts from `--enumerate`).
- `--no-ptr`: Disable reverse-DNS (PTR) lookup of IP targets in passive mode.
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
# Subdomain enumeration, WHOIS, and all-ports nmap scan for a domain
python pdive++.py -t example.com -m active -e --all-ports
```

### Default Passive Recon
```bash
# Passive default: WHOIS + DNS metadata for the supplied target only (no enumeration, no port/service scans)
python pdive++.py -t example.com
```

### Passive Recon with Subdomain Enumeration
```bash
# Passive default plus all passive providers (Amass / DNSDumpster / crt.sh)
python pdive++.py -t example.com -e
```

### Strict Passive Recon
```bash
# Passive-only discovery without WHOIS, Amass, or active scanning
python pdive++.py -t example.com --strict-passive
```

### Strict Active Recon
```bash
# Active-only discovery/scanning against supplied targets; no WHOIS or passive providers
python pdive++.py -t example.com --strict-active
```

### Targeted Subdomain Enumeration (OSINT Only)
```bash
# Run ONLY Amass enumeration and WHOIS (skip port scanning)
python pdive++.py -t example.com --amass --no-scan
```

### Combined Passive Tools
```bash
# Run Amass and crt.sh enumeration, then perform metadata lookup
python pdive++.py -t example.com --amass --crtsh --no-scan
```

### Enumerate, Excluding a Specific Provider
```bash
# Enable all providers except Amass
python pdive++.py -t example.com -e --no-amass
```

### Passive Recon of an IP-Only Target List
```bash
# Scan each IP and record its PTR record as metadata (no enumeration)
python pdive++.py -f ip_targets.txt --strict-passive

# Same input, but skip the PTR lookup entirely
python pdive++.py -f ip_targets.txt --strict-passive --no-ptr
```

### Advanced Troubleshooting
```bash
# Use custom certificates and verbose logging
python pdive++.py -t internal.local -k -v --ca-bundle ./internal-ca.pem
```

## Robust Scanning & Troubleshooting

### Subdomain Enumeration (Opt-in)
Subdomain enumeration is **off by default** — a scan probes only the targets you supply, so a single IP or domain never fans out to other hosts. To enable it:

- `-e/--enumerate` turns on all three providers (Amass, DNSDumpster, crt.sh).
- `--amass`, `--dnsdumpster`, `--crtsh` each enable a single provider.
- Combine a per-tool flag with others to build any subset (e.g. `--amass --crtsh`).
- `--no-amass`, `--no-dnsdumpster`, `--no-crtsh` subtract a provider from `--enumerate` (e.g. `-e --no-amass` runs DNSDumpster and crt.sh only).

Enumeration is independent of `--mode`: it can run in passive mode (default) or alongside active host discovery and scanning (`-m active -e`).

### PTR Metadata for IP Targets
The passive providers take a domain as input, so a bare IP has nothing to enumerate. In passive mode PDIve++ reverse-DNS (PTR) resolves each IP target and records the PTR hostname as the IP's `reverse_dns` metadata.

PDIve++ does **not** pivot from the PTR to its registrable domain or enumerate that domain. Earlier versions did, which turned a single IP target into a full-domain subdomain enumeration that fanned out to many unrelated addresses; that behavior has been removed. A single IP target is scanned as a single IP.

The PTR lookup is on by default in passive mode (including `--strict-passive`) and is disabled with `--no-ptr`. It has no effect in active mode, where IP targets are probed directly.

### Strict Modes
`--strict-passive` forces passive mode, disables WHOIS, disables Amass, and skips active port/service scanning. DNSDumpster and crt.sh are not enabled by default (enumeration is opt-in), and PTR lookup of IP targets still runs (disable with `--no-ptr`).

`--strict-active` forces active mode, disables WHOIS, and disables all passive providers. Active host discovery and port/service scanning remain enabled unless `--no-scan` is also passed.

Strict mode conflicts are rejected early. For example, `--strict-active --amass`, `--strict-active --enumerate`, `--strict-passive --enumerate`, `--strict-active --mode passive`, and `--strict-passive --mode active` all fail with a parser error.

### Multithreading
The built-in TCP port scan parallelizes across ports, and active host discovery (ping/port probing) parallelizes across hosts, both using a thread pool sized by `-T/--threads`. The passive providers (`amass`, `dnsdumpster`, `crtsh`) and the nmap service scan currently run sequentially, so `--threads` does not affect them.

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
