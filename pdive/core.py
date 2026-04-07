import os
import json
import threading
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

from .utils import (
    Fore, Style, VERSION, BANNER, ScannerConfig, HAS_WHOIS,
    resolve_domain_to_ip, reverse_dns_lookup
)
from .discovery import Discovery
from .scanning import Scanner
from .reporting import Reporter

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
        
        self.scan_state = {
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
            discovered = self.discovery.passive_discovery()
            self.scan_state["live_hosts"] = list(discovered)
        else:
            discovery_results = self.discovery.host_discovery()
            self.scan_state["live_hosts"] = discovery_results["live_hosts"]
            self.results["unresponsive_hosts"] = discovery_results["unresponsive_count"]

        # 3. Metadata Lookup (DNS/rDNS)
        print(f"\n{Fore.YELLOW}[+] Performing Metadata Lookups...{Style.RESET_ALL}")
        for host in self.scan_state["live_hosts"]:
            ip = resolve_domain_to_ip(host, self.config.dns_timeout)
            rdns = reverse_dns_lookup(ip, self.config.dns_timeout) if ip != "N/A" else "N/A"
            self.results["hosts"][host] = {
                "status": "up",
                "ip_address": ip,
                "reverse_dns": rdns,
                "ports": {}
            }

        # 4. Scanning
        if self.config.enable_scan and self.scan_state["live_hosts"]:
            # Try masscan first
            port_results = self.scanner.masscan_scan(self.scan_state["live_hosts"])
            
            # Enumerate services with nmap
            final_results = self.scanner.nmap_scan(port_results)
            
            # Update results
            for host, ports in final_results.items():
                if host in self.results["hosts"]:
                    self.results["hosts"][host]["ports"].update(ports)

        # 4. Reporting
        self.reporter.generate_report(self.results)
        print(f"\n{Fore.CYAN}[*] Scan completed successfully!{Style.RESET_ALL}")
