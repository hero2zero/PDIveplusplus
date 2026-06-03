#!/usr/bin/env python3
import argparse
import sys
import os
import logging
from lib.utils import (
    VERSION, Fore, Style, BANNER, ScannerConfig, logger,
    detect_virtualenv, check_sudo_venv_mismatch,
    load_targets_from_file, validate_targets, parse_port_spec
)
from lib.core import PDIve

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description=f'PDIve++ v{VERSION} - Automated Network Reconnaissance')
    
    # Target selection
    target_group = parser.add_mutually_exclusive_group(required=False)
    target_group.add_argument('-t', '--target', help='Target IP, CIDR, or hostname (comma-separated for multiple)')
    target_group.add_argument('-f', '--file', help='File containing targets, one per line')
    
    parser.add_argument('-o', '--output', default='pdive_output', help='Output directory (default: pdive_output)')
    parser.add_argument('-T', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('-m', '--mode', choices=['active', 'passive'], default=None, help='Discovery mode (default: passive)')
    strict_group = parser.add_mutually_exclusive_group()
    strict_group.add_argument(
        '--strict-passive',
        action='store_true',
        help='Run passive-only discovery without WHOIS or Amass; skips active scanning'
    )
    strict_group.add_argument(
        '--strict-active',
        action='store_true',
        help='Run active-only discovery/scanning against supplied targets; disables WHOIS and passive discovery providers'
    )
    
    parser.add_argument('--ping', action='store_true', help='Enable ICMP ping discovery')

    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument('-p', '--ports', help='Comma-separated ports or ranges to scan (e.g., 80,443 or 8000-9000)')
    port_group.add_argument('--all-ports', action='store_true', help='Scan all 65535 ports')

    parser.add_argument('--amass', action='store_true', help='Run Amass discovery')
    parser.add_argument('--dnsdumpster', action='store_true', help='Run DNSDumpster discovery')
    parser.add_argument('--crtsh', action='store_true', help='Run crt.sh discovery')
    parser.add_argument('--no-amass', action='store_true', help='Disable Amass discovery')
    parser.add_argument('--no-dnsdumpster', action='store_true', help='Disable DNSDumpster discovery')
    parser.add_argument('--no-crtsh', action='store_true', help='Disable crt.sh discovery')
    parser.add_argument('--no-scan', action='store_true', help='Skip port scanning phase')
    parser.add_argument('--amass-timeout', type=int, default=180, help='Amass timeout in seconds')
    parser.add_argument('--dns-timeout', type=int, default=5, help='DNS timeout in seconds')
    parser.add_argument('--whois-timeout', type=int, default=15, help='WHOIS timeout in seconds')
    parser.add_argument('--no-whois', action='store_true', help='Disable WHOIS lookups')
    parser.add_argument('--ca-bundle', help='Path to CA bundle')
    parser.add_argument('-k', '--insecure', action='store_true', help='Disable SSL verification')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--version', action='version', version=f'PDIve++ {VERSION}')

    args = parser.parse_args()

    if args.amass and args.no_amass:
        parser.error("--amass and --no-amass cannot be used together")
    if args.dnsdumpster and args.no_dnsdumpster:
        parser.error("--dnsdumpster and --no-dnsdumpster cannot be used together")
    if args.crtsh and args.no_crtsh:
        parser.error("--crtsh and --no-crtsh cannot be used together")
    if args.strict_active and (args.amass or args.dnsdumpster or args.crtsh):
        parser.error("--strict-active cannot be combined with passive provider flags")
    if args.strict_passive and args.amass:
        parser.error("--strict-passive cannot be combined with --amass")
    if args.strict_active and args.mode == "passive":
        parser.error("--strict-active cannot be combined with --mode passive")
    if args.strict_passive and args.mode == "active":
        parser.error("--strict-passive cannot be combined with --mode active")

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

    targets, resolved_ips = validate_targets(targets)
    if not targets:
        print(f"{Fore.RED}[-] Error: No valid targets found{Style.RESET_ALL}")
        sys.exit(1)

    selected_ports = None
    if args.ports:
        try:
            selected_ports = parse_port_spec(args.ports)
        except ValueError as e:
            print(f"{Fore.RED}[-] Error: Invalid --ports value: {e}{Style.RESET_ALL}")
            sys.exit(1)
        if not selected_ports:
            print(f"{Fore.RED}[-] Error: --ports produced no valid ports{Style.RESET_ALL}")
            sys.exit(1)

    print(f"{Fore.RED}WARNING: Authorized security testing only!{Style.RESET_ALL}")
    response = input(f"Do you have authorization to scan {len(targets)} targets? (y/N): ")
    if response.lower() != 'y':
        print("Aborted.")
        sys.exit(1)

    # Handle passive discovery tool selection
    discovery_mode = args.mode or "passive"
    if args.amass or args.dnsdumpster or args.crtsh:
        if args.mode == "active":
            print(f"{Fore.YELLOW}[!] Passive tool flags override --mode active, switching to passive discovery{Style.RESET_ALL}")
        discovery_mode = "passive"
        enable_amass = args.amass
        enable_dnsdumpster = args.dnsdumpster
        enable_crtsh = args.crtsh
    else:
        # No specific tools selected; enable all passive tools by default.
        enable_amass = True
        enable_dnsdumpster = True
        enable_crtsh = True

    if args.no_amass:
        enable_amass = False
    if args.no_dnsdumpster:
        enable_dnsdumpster = False
    if args.no_crtsh:
        enable_crtsh = False

    enable_whois = not args.no_whois
    enable_scan = not args.no_scan

    if args.strict_passive:
        discovery_mode = "passive"
        enable_whois = False
        enable_amass = False
        enable_scan = False
    elif args.strict_active:
        discovery_mode = "active"
        enable_whois = False
        enable_amass = False
        enable_dnsdumpster = False
        enable_crtsh = False

    config = ScannerConfig(
        targets=targets,
        resolved_ips=resolved_ips,
        output_dir=args.output,
        threads=args.threads,
        discovery_mode=discovery_mode,
        enable_ping=args.ping,
        all_ports=args.all_ports,
        ports=selected_ports,
        amass_timeout=args.amass_timeout,
        dns_timeout=args.dns_timeout,
        whois_timeout=args.whois_timeout,
        enable_whois=enable_whois,
        enable_amass=enable_amass,
        enable_dnsdumpster=enable_dnsdumpster,
        enable_crtsh=enable_crtsh,
        enable_scan=enable_scan,
        ca_bundle=args.ca_bundle,
        insecure=args.insecure
    )

    pdive = PDIve(config)
    pdive.run()

if __name__ == "__main__":
    main()
