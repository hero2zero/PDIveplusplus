# PDIve++ Usage

`pdive++.py` is a CLI reconnaissance tool for authorized security testing.
Current Version: v1.7.2

## Basic Syntax

```bash
python pdive++.py -t <target> [options]
python pdive++.py -v -f <targets_file> [options]
```

## Targets

- Single host: `-t 10.0.0.5`
- CIDR range: `-t 192.168.1.0/24`
- Domain: `-t example.com`
- Multiple targets: `-t "192.168.1.10,example.com,10.0.0.0/24"`
- File input: `-f targets.txt` (one target per line, `#` allowed for comments)

## Key Options

### General Options

- `-o, --output <dir>`: Output directory (default: `pdive_output`)
- `-T, --threads <n>`: Thread count (1-1000, default: 50)
- `-m, --mode <active|passive>`: Discovery mode (default: `active`)
- `-v, --verbose`: Enable debug-level logging for troubleshooting
- `--ping`: Enable ICMP ping discovery
- `--all-ports`: Scan all ports 1-65535 (default: scan top 1000 ports only for faster results)

### Scanning Mode (Mutually Exclusive)

**IMPORTANT**: `--nmap`, `--masscan`, and `--amass` cannot be used together. Choose one:

- `--masscan`: Active mode only; skip passive discovery and run fast scan + basic service detection
  - Faster scanning with basic service identification
  - Good for quick reconnaissance
- `--nmap`: Active mode only; run detailed nmap service enumeration after masscan
  - Slower but more detailed service detection
  - Includes version detection and enhanced service identification
- `--amass`: Active mode only; run only amass subdomain discovery
  - Performs only passive subdomain enumeration
  - No port scanning or service detection
  - Fastest option for domain reconnaissance

### Report and Timeout Options

- `--amass-timeout <seconds>`: Timeout for amass run (1-3600, default: 180)
- `--masscan-timeout <seconds>`: Timeout for masscan scans (1-3600, default: 300)
  - User is prompted to extend timeout interactively if timeout is reached
  - Falls back to basic port scan if user declines or retry fails
- `--dns-timeout <seconds>`: DNS lookup timeout (1-60, default: 5)
- `--whois-timeout <seconds>`: WHOIS lookup timeout (1-300, default: 15)
- `--no-whois`: Disable WHOIS lookups in reports
- `--json-only`: Write JSON reports only (skip TXT/CSV)
- `--no-json`: Disable JSON report output

### Checkpoint and Resume Options

- `--checkpoint-interval <seconds>`: Autosave checkpoint interval (default: 30; 0 disables)
- `--resume <checkpoint_json>`: Resume a prior scan from a checkpoint JSON file

## Scan Mode Combinations

### Valid Combinations

```bash
# Default (no scanning flags)
python pdive++.py -t 192.168.1.0/24

# Masscan only (fast scan)
python pdive++.py -t 192.168.1.0/24 --masscan

# Nmap with masscan (detailed enumeration)
python pdive++.py -t 192.168.1.0/24 --nmap

# Amass only (subdomain discovery)
python pdive++.py -t example.com --amass

# With all-ports flag
python pdive++.py -t 192.168.1.0/24 --masscan --all-ports
python pdive++.py -t 192.168.1.0/24 --nmap --all-ports
```

### Invalid Combinations

```bash
# ERROR: Cannot use multiple scanning flags together
python pdive++.py -t 192.168.1.0/24 --nmap --masscan
python pdive++.py -t example.com --nmap --amass
python pdive++.py -t example.com --masscan --amass

# ERROR: Scanning flags not allowed in passive mode
python pdive++.py -t example.com -m passive --nmap
python pdive++.py -t example.com -m passive --masscan
python pdive++.py -t example.com -m passive --amass
```

## Report Output Controls

- Default: writes TXT + CSV + JSON
- `--json-only`: writes only JSON
- `--no-json`: writes TXT + CSV only
- `--json-only` and `--no-json` cannot be used together

## Resumable Scans

- Checkpoints are saved periodically to `scan_checkpoint.json` in the output directory.
- Use `--checkpoint-interval <seconds>` to control autosave frequency (0 disables).
- Resume with `--resume <checkpoint_json>` to continue from the last completed phase.

Example:

```bash
python pdive++.py --resume ./pdive_output/scan_checkpoint.json
```

## Mode Behavior

### Active Mode

Active mode performs network scanning and service enumeration. The scanning behavior depends on flags:

**Default (no flags)**:
1. Optional passive subdomain discovery (amass)
2. Host discovery (cross-platform ping optional + port fallback)
3. Fast port scan via masscan (fallback to built-in scanner if unavailable)
4. Basic service identification
5. Report generation

**With `--masscan` flag**:
1. Skips passive subdomain discovery
2. Host discovery
3. Fast port scan via masscan (top 1000 ports by default, all ports with `--all-ports`)
4. Basic service identification
5. Report generation

**With `--nmap` flag**:
1. Skips passive subdomain discovery
2. Host discovery
3. Fast port scan via masscan
4. Detailed Nmap service enumeration (version detection, enhanced identification)
5. Report generation

**With `--amass` flag**:
1. Amass subdomain discovery only
2. Host list display
3. Simple report generation
4. No port scanning or service detection

### Passive Mode

Passive mode performs reconnaissance without active scanning:

1. Passive subdomain discovery (amass)
2. Host list display
3. Passive reports

**Note**: `--nmap`, `--masscan`, and `--amass` flags are not allowed in passive mode (passive mode already performs amass scanning by default).

## Example Commands

### Basic Active Scans

```bash
# Default active scan (masscan with basic service detection)
python pdive++.py -t 192.168.1.0/24

# With ICMP ping discovery
python pdive++.py -t 10.0.0.1 --ping

# Using file input
python pdive++.py -f targets.txt -o ./scan_results
```

### Scanning Mode Examples

```bash
# Fast scan with masscan (basic service enumeration)
python pdive++.py -t 192.168.1.0/24 --masscan

# Detailed scan with nmap (enhanced service detection)
python pdive++.py -t 10.0.0.1 --nmap

# Amass subdomain discovery only
python pdive++.py -t example.com --amass

# Amass with custom timeout
python pdive++.py -t example.com --amass --amass-timeout 300

# Comprehensive port scanning (all 65535 ports)
python pdive++.py -t 10.0.0.1 --nmap --all-ports
python pdive++.py -t 192.168.1.0/24 --masscan --all-ports
```

### Passive Mode Examples

```bash
# Basic passive reconnaissance
python pdive++.py -t example.com -m passive

# Passive with extended amass timeout
python pdive++.py -t example.com -m passive --amass-timeout 300
```

### Report Configuration

```bash
# JSON output only
python pdive++.py -t testphp.vulnweb.com --json-only

# Skip JSON output
python pdive++.py -t testphp.vulnweb.com --no-json

# Skip WHOIS lookups
python pdive++.py -t example.com --no-whois

# Custom timeouts
python pdive++.py -t example.com --dns-timeout 3 --whois-timeout 10
```

### Performance Tuning

```bash
# Custom thread count
python pdive++.py -f targets.txt -T 100

# Custom checkpoint interval
python pdive++.py -t example.com --checkpoint-interval 15

# Extended masscan timeout for large networks
python pdive++.py -t 192.168.0.0/16 --masscan --masscan-timeout 600

# Comprehensive scan with extended timeout
python pdive++.py -t 10.0.0.0/8 --masscan --all-ports --masscan-timeout 1800
```

### Resume and Checkpoint

```bash
# Resume interrupted scan
python pdive++.py --resume ./scan_results/scan_checkpoint.json
```

## Interactive Timeout Extension

When masscan times out during a scan, PDIve++ will prompt you with an option to extend the timeout and retry:

```
[-] Masscan timeout after 300 seconds
Would you like to extend the timeout and retry? (y/N): y
Enter timeout extension in seconds (e.g., 300): 300
[*] Extending timeout by 300 seconds...
[*] Retrying masscan with 600 second timeout...
```

**Benefits:**
- No need to restart entire scan from scratch
- Flexibility to adjust timeout based on network conditions
- Automatic retry with extended timeout
- Falls back to basic port scan if declined or retry fails

**Usage Tips:**
- Start with default timeout (300s) for most networks
- Extend timeout for large networks or slow connections
- Use `--masscan-timeout` to set a higher initial timeout for known large scans
- Maximum extension value: 3600 seconds (1 hour)

## Safety

- The tool prompts for authorization before scanning.
- Run only against systems you are explicitly authorized to test.
