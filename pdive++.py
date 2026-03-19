#!/usr/bin/env python3
import argparse
import sys
import os
import logging
from pdive.utils import (
    VERSION, Fore, Style, ScannerConfig, logger,
    detect_virtualenv, check_sudo_venv_mismatch, 
    load_targets_from_file, validate_targets
)
from pdive.core import PDIve

def main():
    parser = argparse.ArgumentParser(description=f'PDIve++ v{VERSION} - Automated Network Reconnaissance')
    
    # Target selection
    target_group = parser.add_mutually_exclusive_group(required=False)
    target_group.add_argument('-t', '--target', help='Target IP, CIDR, or hostname (comma-separated for multiple)')
    target_group.add_argument('-f', '--file', help='File containing targets, one per line')
    
    parser.add_argument('-o', '--output', default='pdive_output', help='Output directory (default: pdive_output)')
    parser.add_argument('-T', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('-m', '--mode', choices=['active', 'passive'], default='active', help='Discovery mode (default: active)')
    
    parser.add_argument('--ping', action='store_true', help='Enable ICMP ping discovery')
    parser.add_argument('--all-ports', action='store_true', help='Scan all 65535 ports')
    parser.add_argument('--amass-timeout', type=int, default=180, help='Amass timeout in seconds')
    parser.add_argument('--masscan-timeout', type=int, default=300, help='Masscan timeout in seconds')
    parser.add_argument('--dns-timeout', type=int, default=5, help='DNS timeout in seconds')
    parser.add_argument('--whois-timeout', type=int, default=15, help='WHOIS timeout in seconds')
    parser.add_argument('--no-whois', action='store_true', help='Disable WHOIS lookups')
    parser.add_argument('--ca-bundle', help='Path to CA bundle')
    parser.add_argument('-k', '--insecure', action='store_true', help='Disable SSL verification')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--version', action='version', version=f'PDIve++ {VERSION}')

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    check_sudo_venv_mismatch()

    # Load targets
    targets = []
    if args.file:
        targets = load_targets_from_file(args.file)
    elif args.target:
        targets = [t.strip() for t in args.target.split(',') if t.strip()]
    
    if not targets:
        print(f"{Fore.RED}[-] Error: No targets specified{Style.RESET_ALL}")
        parser.print_help()
        sys.exit(1)

    targets = validate_targets(targets)
    if not targets:
        print(f"{Fore.RED}[-] Error: No valid targets found{Style.RESET_ALL}")
        sys.exit(1)

    print(f"{Fore.RED}WARNING: Authorized security testing only!{Style.RESET_ALL}")
    response = input(f"Do you have authorization to scan {len(targets)} targets? (y/N): ")
    if response.lower() != 'y':
        print("Aborted.")
        sys.exit(1)

    config = ScannerConfig(
        targets=targets,
        output_dir=args.output,
        threads=args.threads,
        discovery_mode=args.mode,
        enable_ping=args.ping,
        all_ports=args.all_ports,
        amass_timeout=args.amass_timeout,
        masscan_timeout=args.masscan_timeout,
        dns_timeout=args.dns_timeout,
        whois_timeout=args.whois_timeout,
        enable_whois=not args.no_whois,
        ca_bundle=args.ca_bundle,
        insecure=args.insecure
    )

    pdive = PDIve(config)
    pdive.run()

if __name__ == "__main__":
    main()
