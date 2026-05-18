import os
import json
import csv
import threading
from datetime import datetime
from typing import Dict, Any

from .utils import Fore, Style, _show_progress_bar

class Reporter:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    @staticmethod
    def _whois_for_host(host: str, whois_map: Dict[str, Any]) -> Dict[str, str]:
        """Find WHOIS data for a host: exact match first, then apex/parent domain."""
        empty = {"registrar": "N/A", "org": "N/A", "country": "N/A", "emails": "N/A"}
        if not whois_map:
            return empty
        if host in whois_map and "error" not in whois_map[host]:
            return whois_map[host]
        for target, data in whois_map.items():
            if "error" in data:
                continue
            if host == target or host.endswith("." + target):
                return data
        return empty

    def generate_report(self, results: Dict[str, Any]):
        """Generate scan reports in various formats"""
        print(f"\n{Fore.YELLOW}[+] Generating Reports...{Style.RESET_ALL}")

        stop_event = threading.Event()
        progress_thread = threading.Thread(target=_show_progress_bar, args=(stop_event, "Generating reports"), daemon=True)
        progress_thread.start()

        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            discovery_mode = results.get("scan_info", {}).get("discovery_mode", "active")
            is_passive = discovery_mode == "passive"
            whois_map = results.get("whois", {})

            # Embed per-host WHOIS data into each host record so JSON output reflects it
            for host, data in results.get("hosts", {}).items():
                w = self._whois_for_host(host, whois_map)
                data["whois"] = {
                    "registrar": w.get("registrar", "N/A"),
                    "organization": w.get("org", "N/A"),
                    "country": w.get("country", "N/A"),
                    "email": w.get("emails", "N/A"),
                }

            # JSON Report
            json_path = os.path.join(self.output_dir, f"report_{timestamp}.json")
            with open(json_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n{Fore.GREEN}[+] JSON report saved to: {json_path}{Style.RESET_ALL}")

            # Text Summary
            txt_path = os.path.join(self.output_dir, f"report_{timestamp}.txt")
            with open(txt_path, 'w') as f:
                f.write(f"PDIve++ Scan Report\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 50 + "\n\n")

                for host, data in results.get("hosts", {}).items():
                    w = data.get("whois", {})
                    f.write(f"Host: {host} ({data.get('status', 'unknown')})\n")
                    f.write(f"IP: {data.get('ip_address', 'N/A')}\n")
                    f.write(f"Reverse DNS: {data.get('reverse_dns', 'N/A')}\n")
                    f.write(f"Registrar: {w.get('registrar', 'N/A')}\n")
                    f.write(f"Organization: {w.get('organization', 'N/A')}\n")
                    f.write(f"Country: {w.get('country', 'N/A')}\n")
                    f.write(f"Email: {w.get('email', 'N/A')}\n")

                    if not is_passive:
                        ports = data.get("ports", {})
                        if ports:
                            f.write("Open Ports:\n")
                            for port, port_data in ports.items():
                                f.write(f"  - {port}/tcp: {port_data.get('service', 'unknown')}\n")
                    f.write("-" * 30 + "\n")
            print(f"{Fore.GREEN}[+] Text report saved to: {txt_path}{Style.RESET_ALL}")

            # CSV Report
            csv_path = os.path.join(self.output_dir, f"report_{timestamp}.csv")
            with open(csv_path, 'w', newline='') as f:
                writer = csv.writer(f)

                if is_passive:
                    writer.writerow(['Host', 'IP_Address', 'Reverse_DNS',
                                     'Registrar', 'Organization', 'Country', 'Email'])
                    for host, data in results.get("hosts", {}).items():
                        w = data.get("whois", {})
                        writer.writerow([
                            host,
                            data.get("ip_address", "N/A"),
                            data.get("reverse_dns", "N/A"),
                            w.get("registrar", "N/A"),
                            w.get("organization", "N/A"),
                            w.get("country", "N/A"),
                            w.get("email", "N/A"),
                        ])
                else:
                    writer.writerow(['Host', 'IP_Address', 'Reverse_DNS', 'Port', 'Protocol',
                                     'State', 'Service',
                                     'Registrar', 'Organization', 'Country', 'Email'])
                    for host, data in results.get("hosts", {}).items():
                        ip_address = data.get("ip_address", "N/A")
                        reverse_dns = data.get("reverse_dns", "N/A")
                        w = data.get("whois", {})
                        whois_cols = [
                            w.get("registrar", "N/A"),
                            w.get("organization", "N/A"),
                            w.get("country", "N/A"),
                            w.get("email", "N/A"),
                        ]
                        ports = data.get("ports", {})

                        if ports:
                            for port, port_data in ports.items():
                                writer.writerow([
                                    host, ip_address, reverse_dns,
                                    port, 'tcp', 'open',
                                    port_data.get('service', 'unknown'),
                                    *whois_cols,
                                ])
                        else:
                            writer.writerow([host, ip_address, reverse_dns,
                                             '', '', 'up', 'no_open_ports',
                                             *whois_cols])
            print(f"{Fore.GREEN}[+] CSV report saved to: {csv_path}{Style.RESET_ALL}")

        finally:
            stop_event.set()
            progress_thread.join()
