import ipaddress
import json
import threading
import time
from datetime import datetime
from typing import Any, Dict

from .discovery import Discovery
from .reporting import Reporter
from .scanning import Scanner
from .utils import HAS_WHOIS, VERSION, Fore, ScannerConfig, Style, resolve_domain_to_ip, reverse_dns_lookup


def _is_ip_literal(host: str) -> bool:
    """True if host is a bare IP address (not a hostname)."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def _is_multi_host_network(target: str) -> bool:
    """True if target is a CIDR/range covering more than one address.

    Single hosts (a bare IP, a /32, or a hostname) return False; an actual
    range like 10.0.0.0/24 returns True.
    """
    try:
        return ipaddress.ip_network(target, strict=False).num_addresses > 1
    except ValueError:
        return False

class PDIve:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.discovery = Discovery(config)
        self.scanner = Scanner(config)
        self.reporter = Reporter(config.output_dir)

        self.results = {
            "scan_info": {
                "targets": config.targets,
                "start_time": datetime.now().isoformat(),
                "scanner": f"PDIve++ v{VERSION}",
                "discovery_mode": config.discovery_mode
            },
            "hosts": {},
            "unresponsive_hosts": 0
        }

        self.scan_state: Dict[str, Any] = {
            "completed_phases": [],
            "live_hosts": []
        }

        self._checkpoint_lock = threading.Lock()
        self._checkpoint_stop_event = threading.Event()
        self._checkpoint_thread = None

    def _save_checkpoint(self):
        payload = {
            "version": 1,
            "saved_at": datetime.now().isoformat(),
            "scan_state": self.scan_state,
            "results": self.results
        }
        with self._checkpoint_lock:
            try:
                with open(self.config.checkpoint_path, 'w') as f:
                    json.dump(payload, f, indent=2, default=str)
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Failed to write checkpoint: {e}{Style.RESET_ALL}")

    def _checkpoint_worker(self):
        while not self._checkpoint_stop_event.is_set():
            time.sleep(self.config.checkpoint_interval)
            if self._checkpoint_stop_event.is_set(): break
            self._save_checkpoint()

    def _active_live_hosts(self):
        """Assemble the live-host list for active mode.

        Explicitly-supplied single-host targets (individual IPs / hostnames) are
        ALWAYS scanned — they are never dropped by the host-discovery liveness
        probe. Only multi-host CIDR ranges and enumerated subdomains are routed
        through host_discovery, which expands ranges and filters out hosts that
        do not answer the ping/port probe.
        """
        always_scan = []
        discovery_inputs = []
        for target in self.config.targets:
            if _is_multi_host_network(target):
                discovery_inputs.append(target)
            else:
                always_scan.append(target)

        if self.config.enable_amass or self.config.enable_dnsdumpster or self.config.enable_crtsh:
            discovered = self.discovery.passive_discovery()
            if discovered:
                print(f"{Fore.CYAN}[*] Passive enumeration discovered {len(discovered)} subdomain(s); including in active host discovery{Style.RESET_ALL}")
            discovery_inputs.extend(h for h in discovered if h not in discovery_inputs)

        live_hosts = list(always_scan)
        if discovery_inputs:
            discovery_results = self.discovery.host_discovery(discovery_inputs)
            live_hosts.extend(h for h in discovery_results["live_hosts"] if h not in live_hosts)
            self.results["unresponsive_hosts"] = discovery_results["unresponsive_count"]
        return live_hosts

    def run(self):
        """Execute the full scan workflow"""
        print(f"{Fore.CYAN}PDIve++ v{VERSION} starting...{Style.RESET_ALL}")

        # 1. WHOIS Lookups for primary targets (Real-time)
        if self.config.enable_whois and HAS_WHOIS:
            print(f"\n{Fore.YELLOW}[+] Performing WHOIS Lookups for targets...{Style.RESET_ALL}")
            if "whois" not in self.results:
                self.results["whois"] = {}

            for target in self.config.targets:
                # Basic validation: only WHOIS valid domains or IPs
                print(f"{Fore.CYAN}[*] WHOIS lookup for {target}...{Style.RESET_ALL}")
                whois_data = self.scanner.whois_lookup(target)

                if "error" not in whois_data:
                    self.results["whois"][target] = whois_data
                    # Real-time print of results
                    print(f"    {Fore.GREEN}Registrar: {whois_data.get('registrar', 'N/A')}{Style.RESET_ALL}")
                    print(f"    {Fore.GREEN}Organization: {whois_data.get('org', 'N/A')}{Style.RESET_ALL}")
                    print(f"    {Fore.GREEN}Country: {whois_data.get('country', 'N/A')}{Style.RESET_ALL}")
                    if whois_data.get('emails') and whois_data.get('emails') != 'N/A':
                        print(f"    {Fore.GREEN}Email: {whois_data.get('emails')}{Style.RESET_ALL}")
                else:
                    print(f"    {Fore.RED}[-] WHOIS failed: {whois_data['error']}{Style.RESET_ALL}")

        # 2. Discovery
        if self.config.discovery_mode == "passive":
            # Always scan the supplied targets themselves; enumeration only adds to them.
            live_hosts = list(self.config.targets)
            if self.config.enable_amass or self.config.enable_dnsdumpster or self.config.enable_crtsh:
                discovered = self.discovery.passive_discovery()
                if discovered:
                    print(f"{Fore.CYAN}[*] Passive enumeration discovered {len(discovered)} host(s){Style.RESET_ALL}")
                live_hosts.extend(h for h in discovered if h not in live_hosts)
            self.scan_state["live_hosts"] = live_hosts
        else:
            self.scan_state["live_hosts"] = self._active_live_hosts()

        # 3. Metadata Lookup (DNS/rDNS)
        print(f"\n{Fore.YELLOW}[+] Performing Metadata Lookups...{Style.RESET_ALL}")
        for host in self.scan_state["live_hosts"]:
            ip = resolve_domain_to_ip(host, self.config.dns_timeout)
            # PTR (reverse DNS) for IP targets is metadata only and can be disabled with --no-ptr.
            if ip != "N/A" and (self.config.enable_ptr or not _is_ip_literal(host)):
                rdns = reverse_dns_lookup(ip, self.config.dns_timeout)
            else:
                rdns = "N/A"
            self.results["hosts"][host] = {
                "status": "up",
                "ip_address": ip,
                "reverse_dns": rdns,
                "ports": {}
            }

        # 4. Scanning (active mode only — port and nmap service scans are skipped in passive mode)
        if self.config.discovery_mode != "active":
            print(f"\n{Fore.CYAN}[*] Passive mode: skipping port and nmap service scans (use -m active to enable).{Style.RESET_ALL}")
        elif self.config.enable_scan and self.scan_state["live_hosts"]:
            port_results = self.scanner.port_scan(self.scan_state["live_hosts"])

            # Enumerate services with nmap
            final_results = self.scanner.nmap_scan(port_results)

            # Update results
            for host, ports in final_results.items():
                if host in self.results["hosts"]:
                    self.results["hosts"][host]["ports"].update(ports)

        # 4. Reporting
        self.reporter.generate_report(self.results)
        print(f"\n{Fore.CYAN}[*] Scan completed successfully!{Style.RESET_ALL}")
