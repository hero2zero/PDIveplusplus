# PDIve++ Usage Guide

`pdive++.py` is a powerful reconnaissance tool for authorized security testing.
Current Version: v1.7.6

## Core Workflow

PDIve++ follows a structured reconnaissance lifecycle:
1. **Primary Target Analysis**: Real-time WHOIS lookup for initial targets.
2. **Discovery**: Active (ping/port) or Passive (Amass/DNS) subdomain/host enumeration. Passive providers run concurrently.
3. **Metadata Enrichment**: DNS and reverse-DNS resolution for all discovered hosts. IPs resolved during target validation are cached and reused here.
4. **Fast Port Scanning**: High-speed discovery using `masscan` (optional).
5. **Service Enumeration**: Detailed identification via `nmap` (hosts scanned in parallel) or built-in methods (optional).
6. **Unified Reporting**: Generation of JSON, CSV, and text reports.

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
- `-m, --mode`: Discovery mode (`active` or `passive`, default: `active`).

### Discovery & Scanning Features
- `--ping`: Enable ICMP-based host discovery.
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
- `--masscan-timeout`: Timeout for port scanning (default: 300s).
- `--dns-timeout`: Timeout for DNS/rDNS resolution (default: 5s).
- `--whois-timeout`: Timeout for WHOIS queries (default: 15s).
- `--no-whois`: Completely disable WHOIS lookups.

## Examples

### Rapid Host Discovery
```bash
# Scan a network range using masscan and basic service detection
python pdive++.py -t 192.168.1.0/24
```

### Full Reconnaissance
```bash
# Passive discovery, WHOIS, and all-ports scan for a domain
python pdive++.py -t example.com -m passive --all-ports
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
For pure OSINT workflows, use the `--no-scan` flag. This will perform WHOIS, discovery, and DNS/rDNS metadata lookups, then immediately generate a report without attempting any connection to target ports.

### Real-time WHOIS
PDIve++ prints WHOIS results for primary targets immediately at the start of the scan, allowing you to verify domain ownership before the more time-consuming discovery phases begin.

### masscan Resiliency
`masscan` can be sensitive to network interfaces. PDIve++ includes:
- **Automatic IP Detection**: Finds the preferred source IP for outbound traffic.
- **Smart Retries**: Retries with `--source-ip` on interface detection failure, and with `--router-ip` on ARP timeout.

### nmap Fallback
Detailed service scanning via `nmap` is attempted if installed. If the binary is missing, PDIve++ falls back to its internal service identification methods.

## Safety & Compliance

- **Authorization Prompt**: PDIve++ will always ask for confirmation that you are authorized to scan the targets.
- **Scope**: Ensure all targets (IPs and discovered subdomains) are within your authorized scope.
