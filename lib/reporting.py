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

    def generate_report(self, results: Dict[str, Any]):
        """Generate scan reports in various formats"""
        print(f"\n{Fore.YELLOW}[+] Generating Reports...{Style.RESET_ALL}")
        
        stop_event = threading.Event()
        progress_thread = threading.Thread(target=_show_progress_bar, args=(stop_event, "Generating reports"), daemon=True)
        progress_thread.start()

        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
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
                    f.write(f"Host: {host} ({data.get('status', 'unknown')})\n")
                    f.write(f"IP: {data.get('ip_address', 'N/A')}\n")
                    f.write(f"Reverse DNS: {data.get('reverse_dns', 'N/A')}\n")
                    
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
                writer.writerow(['Host', 'IP_Address', 'Reverse_DNS', 'Port', 'Protocol', 'State', 'Service'])
                
                for host, data in results.get("hosts", {}).items():
                    ip_address = data.get("ip_address", "N/A")
                    reverse_dns = data.get("reverse_dns", "N/A")
                    ports = data.get("ports", {})
                    
                    if ports:
                        for port, port_data in ports.items():
                            writer.writerow([
                                host,
                                ip_address,
                                reverse_dns,
                                port,
                                'tcp',
                                'open',
                                port_data.get('service', 'unknown')
                            ])
                    else:
                        writer.writerow([host, ip_address, reverse_dns, '', '', 'up', 'no_open_ports'])
            print(f"{Fore.GREEN}[+] CSV report saved to: {csv_path}{Style.RESET_ALL}")

        finally:
            stop_event.set()
            progress_thread.join()
