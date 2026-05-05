# Changelog

All notable changes to PDIve++ will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.6] - 2026-05-05

### Fixed
- **Checkpoint thread was never started**: `_checkpoint_worker` and supporting state were wired up in `__init__` but `run()` never started the thread. Periodic checkpointing now works correctly; a final checkpoint is written on scan completion or interruption via a `try/finally` guard.
- **Amass now enforces passive-only mode**: Added `-passive` flag to the `amass enum` command so it relies strictly on passive data sources and performs no active DNS resolution.
- **DNSDumpster subdomain extraction was producing malformed results**: The previous regex used capturing groups, causing `re.findall` to return group tuples rather than full match strings. Replaced with a non-capturing pattern; results are now correctly extracted.
- **`nmap_scan` shallow copy aliased input data**: `.copy()` on the results dict left inner port dicts shared between the copy and the original. Replaced with `copy.deepcopy`.
- **Temp file could leak on exception in `masscan_scan`**: Initialised `target_file_path = None` before the `with` block so the `finally` clause can safely guard the cleanup.
- **`validate_targets` swallowed unresolvable hosts silently**: Hosts that fail DNS resolution at validation time now print a yellow warning instead of disappearing without trace.
- **`enable_amass/dnsdumpster/crtsh` defaulted to `True` in active mode**: Flags now correctly default to `False` when `--mode active` is used and no specific passive-tool flags are passed.
- **Passive tool flags silently overrode `--mode active`**: Passing `--amass`, `--dnsdumpster`, or `--crtsh` alongside `--mode active` now prints an explicit warning before switching to passive discovery.
- **Bare `except:` clauses throughout**: All bare `except:` blocks replaced with `except ValueError:` or `except Exception:` to avoid swallowing `KeyboardInterrupt` and `SystemExit` (affected `resolve_domain_to_ip`, `reverse_dns_lookup`, `validate_targets`, `load_targets_from_file`, `check_sudo_venv_mismatch`).
- **`get_local_ip` socket could leak on exception**: Socket is now closed in a `finally` block.
- **`requests.Session` not closed in `dnsdumpster_discovery`**: Session is now used as a context manager.
- **Dead `json_only` / `no_json` fields removed from `ScannerConfig`**: These fields were never populated from CLI arguments and never read anywhere.

### Changed
- **Passive discovery providers now run concurrently**: `amass`, `dnsdumpster`, and `crtsh` are dispatched via `ThreadPoolExecutor` across all targets, reducing total passive discovery time proportionally to the number of providers and domains.
- **`nmap_scan` now scans hosts in parallel**: Each host gets its own `PortScanner` instance and runs concurrently, replacing the previous sequential per-host loop.
- **DNS resolution cached across phases**: `validate_targets` now returns resolved IPs alongside the validated target list. The cache is stored in `ScannerConfig.resolved_ips` and reused during the metadata lookup phase and `masscan_scan` hostname resolution, eliminating duplicate DNS queries.
- **`TOP_1000_PORTS` pre-parsed at module load**: `TOP_1000_PORTS_LIST` (a `List[int]`) is built once when `utils.py` is imported. `port_scan` uses it directly instead of re-parsing the string on every call.



### Added
- **Targeted Passive Discovery**: Added ability to select specific passive discovery providers.
  - `--amass`: Explicitly run Amass for passive discovery.
  - `--dnsdumpster`: Explicitly run DNSDumpster for passive discovery.
  - `--crtsh`: Explicitly run crt.sh for passive discovery.
- **Selective Scanning**: Added `--no-scan` flag to skip the port scanning phase entirely (useful for pure OSINT workflows).
- Using any specific passive tool flag now automatically switches the discovery mode to `passive`.

### Changed
- Refactored `ScannerConfig` and `Discovery` modules to support granular tool selection.
- Updated `PDIve.run()` to respect the new `enable_scan` configuration.

## [1.7.4] - 2026-03-13

### Changed
- **Enhanced Amass Installation Guidance**: Updated `INSTALL.md` with explicit instructions for installing `amass` via multiple methods (package managers, Go, and direct binary download).
- Synchronized version strings across all supporting documentation (`README.md`, `USAGE.md`, `INSTALL.md`).

## [1.7.3] - 2026-03-13

### Added
- **SSL Configuration Options**: Added CLI arguments to control SSL verification for HTTP-based service checks.
  - `--ca-bundle <PATH>`: Specify a custom CA bundle for SSL verification.
  - `-k, --insecure`: Disable SSL verification (useful for internal environments with self-signed certs).
- Configuration for SSL verification is now saved in checkpoints and honored during resumed scans.

## [1.7.2] - 2026-03-13

### Changed
- **Implemented Logging System**: Replaced most `print` statements with Python's `logging` module for better control over output.
- Added `-v/--verbose` flag to enable debug-level logging.
- Standardized log messages with timestamps and severity levels.

## [1.7.1] - 2026-03-13

### Changed
- **Refactored Metadata Gathering Lifecycle**: Moved DNS, reverse DNS, and WHOIS lookups earlier in the scan process to improve efficiency and reduce report generation time.
  - Added `perform_initial_lookups()` to gather WHOIS data for targets at the start of the scan.
  - Updated `host_discovery()` and `passive_discovery()` to perform DNS/rDNS lookups as hosts are identified.
  - Metadata is now stored directly in `self.results` and preserved across checkpoints.
  - `generate_report()` and `generate_passive_report()` now pull from pre-cached values instead of performing redundant lookups.

## [1.7.0] - 2026-03-11

### Added
- **New `--amass` scanning mode flag**: Run only amass subdomain discovery
  - Mutually exclusive with `--nmap` and `--masscan` flags
  - Active mode only (not compatible with passive mode)
  - Performs only passive subdomain enumeration without any port scanning
  - Displays discovered hosts and generates simple report
  - Fastest option for domain reconnaissance when only subdomain discovery is needed
- Added `amass_only` parameter to `run_scan()` method
- Added validation to prevent `--amass` flag use in passive mode
- Updated checkpoint/resume functionality to preserve `amass_only` setting

### Changed
- **Scanning mode options now three-way mutually exclusive**: `--nmap`, `--masscan`, and `--amass`
- Updated help text and examples to include `--amass` option
- Updated all documentation (README.md, USAGE.md) to reflect new scanning mode
- Console output now shows "Amass-Only Mode" when `--amass` flag is used

### Fixed
- **Amass output parsing now filters invalid entries**: Fixed issue where ASN numbers, CIDR ranges, and IP addresses were being incorrectly added to discovered hosts
  - Added `_is_valid_hostname()` validation method to filter amass output
  - Now properly validates hostnames before adding to results
  - Filters out ASN numbers (e.g., "11377", "15169")
  - Filters out CIDR ranges (e.g., "142.250.160.0/19", "2a01:111:4000::/36")
  - Filters out standalone IP addresses
  - Invalid entries no longer appear in CSV, TXT, or JSON output files
  - Console output shows count of filtered entries for transparency

### Technical Details
- Modified argument parser to include `--amass` in mutually exclusive `scan_group`
- Added `elif amass_only:` branch in `run_scan()` method for amass-only execution flow
- Updated resume data handling to include `amass_only` state
- Added example: `python pdive++.py -t example.com --amass`
- Added `_is_valid_hostname()` method with regex validation for hostname format
- Modified `amass_discovery()` to validate each parsed entry before adding to discovered_hosts
- Added filtered entry counter to track and report skipped invalid entries

## [1.6.0] - 2026-03-06

### Added
- **Interactive Masscan Timeout Extension**: When masscan times out, users are now prompted to extend the timeout and retry
  - User-friendly prompt asking if they want to extend the timeout
  - Input field for specifying extension duration (1-3600 seconds)
  - Automatic retry with extended timeout if user chooses to continue
  - Falls back to basic port scan if user declines or retry fails
- **New `--masscan-timeout` flag**: Configure masscan timeout duration (default: 300 seconds)
  - Allows values between 1-3600 seconds
  - Timeout can be extended interactively during scan if timeout occurs
  - Setting is preserved in checkpoint/resume functionality

### Changed
- **Default port scanning upgraded from ~50 common ports to top 1000 ports**
  - Masscan now scans top 1000 ports by default (based on nmap frequency ranking)
  - Basic port scanner fallback also uses top 1000 ports by default
  - Significantly improved coverage while maintaining reasonable scan times
  - Better detection of less common but important services
- Console messages updated to reflect "top 1000 ports" instead of "common ports"
- Help text and examples updated to clarify new default behavior

### Technical Details
- Added `TOP_1000_PORTS` constant with nmap's default port frequency list
- Added `masscan_timeout` parameter to `PDIve.__init__()` method
- Modified `masscan_scan()` to use configurable timeout instead of hardcoded 300 seconds
- Implemented interactive timeout extension with subprocess retry logic
- Updated `port_scan()` method to parse and use TOP_1000_PORTS for fallback scanning
- Checkpoint save/restore now includes `masscan_timeout` configuration
- Added validation for `--masscan-timeout` argument (1-3600 seconds range)

## [1.5.0] - 2026-03-06

### Added
- **New `--all-ports` flag**: Enables comprehensive port scanning of all 65,535 ports
  - Works with both `--masscan` and `--nmap` scanning modes
  - Also applies to fallback basic port scanning when masscan is unavailable
  - Default behavior (without flag) scans only common ports for faster results
- Console feedback to indicate when full port scan vs. common port scan is being performed
- Warning message when scanning all ports with basic scanner (due to longer scan time)

### Changed
- **Default port scanning behavior**: Now scans ~50 common ports by default instead of all 65,535 ports
  - Significantly improves scan speed for typical reconnaissance scenarios
  - Users can opt-in to comprehensive scanning with `--all-ports` flag
- Masscan port range selection:
  - Without `--all-ports`: Scans common ports only (21,22,23,25,53,80,443,3306,3389, etc.)
  - With `--all-ports`: Scans all ports 1-65535
- **Refactored `--nmap` and `--masscan` mutual exclusivity**: Now uses argparse's `mutually_exclusive_group`
  - Cleaner code structure with automatic validation
  - Clearer error messages from argparse
  - Help text explicitly shows `[--nmap | --masscan]` to indicate mutual exclusivity
- Updated all documentation (README.md, USAGE.md, INSTALL.md) to reflect new feature
- Updated version examples in help text to demonstrate `--all-ports` usage
- Checkpoint/resume functionality now preserves `all_ports` setting

### Fixed
- Removed redundant manual validation for `--nmap` and `--masscan` conflicts
- Streamlined argument parsing logic for better maintainability

### Technical Details
- Added `all_ports` parameter to `PDIve.__init__()` method
- Modified `masscan_scan()` method to respect `all_ports` setting
- Modified `port_scan()` method to support full port range when requested
- Updated checkpoint save/restore to include `all_ports` configuration
- Created `scan_group` as mutually exclusive group for scanning options
- Removed manual validation check (lines 1813-1816 in previous version)
- Version bumped from 1.4.5 to 1.5.0

## [1.4.5] - Previous Release

### Features
- Active and passive discovery modes
- Masscan integration for high-speed port scanning
- Nmap integration for detailed service enumeration
- Amass integration for passive subdomain discovery
- Multi-threaded scanning with configurable thread count
- Checkpoint and resume functionality for long-running scans
- Multiple report formats (TXT, CSV, JSON)
- WHOIS lookup integration with configurable timeouts
- DNS resolution with timeout controls
- Cross-platform support (Linux, macOS, Windows)
- ICMP ping discovery (optional)
- Comprehensive error handling and fallback mechanisms
- Authorization prompt before scanning

[1.7.6]: https://github.com/yourusername/PDIveplusplus/compare/v1.7.5...v1.7.6
[1.7.5]: https://github.com/yourusername/PDIveplusplus/compare/v1.7.4...v1.7.5
[1.7.4]: https://github.com/yourusername/PDIveplusplus/compare/v1.7.3...v1.7.4
[1.7.3]: https://github.com/yourusername/PDIveplusplus/compare/v1.7.2...v1.7.3
[1.7.2]: https://github.com/yourusername/PDIveplusplus/compare/v1.7.1...v1.7.2
[1.7.1]: https://github.com/yourusername/PDIveplusplus/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/yourusername/PDIveplusplus/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/yourusername/PDIveplusplus/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/yourusername/PDIveplusplus/compare/v1.4.5...v1.5.0
[1.4.5]: https://github.com/yourusername/PDIveplusplus/releases/tag/v1.4.5
