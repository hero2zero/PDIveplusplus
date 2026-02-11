# PDIve++ Usage

`pdive++.py` is a CLI reconnaissance tool for authorized security testing.

## Basic Syntax

```bash
python pdive++.py -t <target> [options]
python pdive++.py -f <targets_file> [options]
```

## Targets

- Single host: `-t 10.0.0.5`
- CIDR range: `-t 192.168.1.0/24`
- Domain: `-t example.com`
- Multiple targets: `-t "192.168.1.10,example.com,10.0.0.0/24"`
- File input: `-f targets.txt` (one target per line, `#` allowed for comments)

## Key Options

- `-o, --output <dir>`: Output directory (default: `pdive_output`)
- `-T, --threads <n>`: Thread count (1-1000, default: 50)
- `-m, --mode <active|passive>`: Discovery mode (default: `active`)
- `--ping`: Enable ICMP ping discovery
- `--masscan`: Active mode only; skip passive discovery and run fast scan + basic service detection
- `--nmap`: Active mode only; run detailed nmap service enumeration after masscan
- `--amass-timeout <seconds>`: Timeout for amass run (1-3600)
- `--dns-timeout <seconds>`: DNS lookup timeout (1-60, default: 5)
- `--whois-timeout <seconds>`: WHOIS lookup timeout (1-300, default: 15)
- `--no-whois`: Disable WHOIS lookups in reports
- `--checkpoint-interval <seconds>`: Autosave checkpoint interval (default: 30; 0 disables)
- `--resume <checkpoint_json>`: Resume a prior scan from a checkpoint JSON file
- `--json-only`: Write JSON reports only (skip TXT/CSV)
- `--no-json`: Disable JSON report output

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

1. Optional passive subdomain discovery (amass)
2. Host discovery (cross-platform ping optional + port fallback)
3. Fast port scan via masscan (fallback to built-in scanner if unavailable)
4. Service identification (basic or `--nmap` detailed)
5. Report generation

### Passive Mode

1. Passive discovery (amass)
2. Host list display
3. Passive reports

## Example Commands

```bash
python pdive++.py -t 192.168.1.0/24
python pdive++.py -t 10.0.0.1 --ping
python pdive++.py -t 10.0.0.1 --nmap
python pdive++.py -t example.com -m passive --amass-timeout 300
python pdive++.py -f targets.txt -o ./scan_results -T 100
python pdive++.py -t testphp.vulnweb.com --json-only
python pdive++.py -t testphp.vulnweb.com --no-json
python pdive++.py -t example.com --no-whois
python pdive++.py -t example.com --dns-timeout 3 --whois-timeout 10
python pdive++.py --resume ./scan_results/scan_checkpoint.json
python pdive++.py -t example.com --checkpoint-interval 15
```

## Safety

- The tool prompts for authorization before scanning.
- Run only against systems you are explicitly authorized to test.
