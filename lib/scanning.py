import os
import sys
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Union

from .utils import (
    Fore, Style, HAS_REQUESTS, HAS_NMAP, HAS_WHOIS, VERSION,
    ScannerConfig, TOP_1000_PORTS,
)

class Scanner:
    def __init__(self, config: ScannerConfig):
        self.config = config

    def port_scan(self, hosts: List[str]) -> Dict[str, Dict[str, Any]]:
        """Perform basic TCP port scanning"""
        print(f"\n{Fore.YELLOW}[+] Starting Port Scanning...{Style.RESET_ALL}")

        if self.config.ports:
            ports_to_scan = list(self.config.ports)
            print(f"{Fore.CYAN}[*] Scanning {len(ports_to_scan)} specified port(s): {','.join(str(p) for p in ports_to_scan)}{Style.RESET_ALL}")
        elif self.config.all_ports:
            ports_to_scan = list(range(1, 65536))
            print(f"{Fore.CYAN}[*] Scanning all 65535 ports{Style.RESET_ALL}")
        else:
            ports_to_scan = []
            for part in TOP_1000_PORTS.split(','):
                if '-' in part:
                    start, end = part.split('-')
                    ports_to_scan.extend(range(int(start), int(end) + 1))
                else:
                    ports_to_scan.append(int(part))
            print(f"{Fore.CYAN}[*] Scanning top 1000 ports{Style.RESET_ALL}")

        scan_results = {}

        def scan_port(host, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    return port
            except Exception:
                pass
            return None

        for host in hosts:
            print(f"\n{Fore.CYAN}[*] Scanning {host}...{Style.RESET_ALL}")
            open_ports = []
            with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                futures = [executor.submit(scan_port, host, port) for port in ports_to_scan]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        print(f"{Fore.GREEN}[+] Open port found: {host}:{result}{Style.RESET_ALL}")

            scan_results[host] = {str(port): {"state": "open", "service": ""} for port in open_ports}

        return scan_results

    def nmap_scan(self, scan_results: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Perform detailed Nmap scan for service enumeration"""
        if not HAS_NMAP:
            print(f"\n{Fore.RED}[-] Nmap module not available, using basic identification{Style.RESET_ALL}")
            return self._basic_service_enumeration(scan_results)

        import nmap
        import shutil
        if not shutil.which('nmap'):
            print(f"\n{Fore.RED}[-] Nmap binary not found in PATH, using basic identification{Style.RESET_ALL}")
            return self._basic_service_enumeration(scan_results)

        try:
            nm = nmap.PortScanner()
        except Exception as e:
            print(f"\n{Fore.RED}[-] Failed to initialize Nmap: {e}{Style.RESET_ALL}")
            return self._basic_service_enumeration(scan_results)
        
        updated_results = scan_results.copy()
        for host, ports in scan_results.items():
            if not ports: continue
            
            port_list = ','.join(ports.keys())
            print(f"{Fore.CYAN}[*] Nmap service scan on {host} ports: {port_list}{Style.RESET_ALL}")

            stop_progress = threading.Event()

            def _progress():
                sys.stdout.write(f"{Fore.CYAN}[*] Scanning")
                sys.stdout.flush()
                while not stop_progress.wait(2):
                    sys.stdout.write(".")
                    sys.stdout.flush()
                sys.stdout.write(f"{Style.RESET_ALL}\n")
                sys.stdout.flush()

            progress_thread = threading.Thread(target=_progress, daemon=True)
            progress_thread.start()

            scan_error = None
            try:
                nm.scan(hosts=host, ports=port_list, arguments="-Pn -sV")
            except Exception as e:
                scan_error = e
            finally:
                stop_progress.set()
                progress_thread.join()

            if scan_error:
                print(f"{Fore.RED}[-] Nmap scan failed for {host}: {scan_error}{Style.RESET_ALL}")
                continue

            for scanned_host in nm.all_hosts():
                for protocol in nm[scanned_host].all_protocols():
                    for port in nm[scanned_host][protocol].keys():
                        port_info = nm[scanned_host][protocol][port]
                        service = port_info.get('name', 'unknown')
                        product = port_info.get('product', '')
                        version = port_info.get('version', '')

                        details = f"{service}"
                        if product: details += f" ({product} {version})".strip()

                        if str(port) in updated_results[host]:
                            updated_results[host][str(port)]["service"] = details
                            print(f"{Fore.GREEN}[+] Nmap service: {host}:{port} -> {details}{Style.RESET_ALL}")
        
        return updated_results

    def _basic_service_enumeration(self, scan_results: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        updated_results = scan_results.copy()
        for host, ports in scan_results.items():
            for port in ports:
                service_info = self.enumerate_basic_service(host, port)
                updated_results[host][port]["service"] = service_info
                print(f"{Fore.GREEN}[+] Service identified: {host}:{port} -> {service_info}{Style.RESET_ALL}")
        return updated_results

    def enumerate_basic_service(self, host: str, port: Union[int, str]) -> str:
        service_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 443: "https", 3306: "mysql", 3389: "rdp", 8080: "http-proxy"
        }
        service = service_map.get(int(port), "unknown")
        
        if HAS_REQUESTS and service in ["http", "https", "http-alt", "https-alt"]:
            import requests
            protocol = "https" if "https" in service else "http"
            url = f"{protocol}://{host}:{port}"
            try:
                response = requests.get(url, timeout=5, verify=self.config.verify_ssl)
                server = response.headers.get('Server', 'Unknown')
                return f"{service} ({server})"
            except Exception:
                pass
        return service

    def whois_lookup(self, target: str) -> Dict[str, Any]:
        """Perform WHOIS lookup"""
        if not HAS_WHOIS:
            return {"error": "WHOIS module not available"}

        import whois
        try:
            # print(f"{Fore.CYAN}[*] WHOIS lookup for {target}...{Style.RESET_ALL}") # Moved to core for real-time control
            w = whois.whois(target)
            
            # Extract more comprehensive information if available
            def _clean(val):
                if isinstance(val, list):
                    return val[0] if val else "N/A"
                return val or "N/A"

            data = {
                "domain_name": _clean(getattr(w, 'domain_name', None)),
                "registrar": _clean(getattr(w, 'registrar', None)),
                "org": _clean(getattr(w, 'org', None)),
                "country": _clean(getattr(w, 'country', None)),
                "status": _clean(getattr(w, 'status', None)),
                "emails": _clean(getattr(w, 'emails', None)),
                "creation_date": _clean(getattr(w, 'creation_date', None)),
                "expiration_date": _clean(getattr(w, 'expiration_date', None))
            }
            return data
        except Exception as e:
            return {"error": str(e)}
