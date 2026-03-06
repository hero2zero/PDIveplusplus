# Changelog

All notable changes to PDIve++ will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.5.0]: https://github.com/yourusername/PDIveplusplus/compare/v1.4.5...v1.5.0
[1.4.5]: https://github.com/yourusername/PDIveplusplus/releases/tag/v1.4.5
