import os
import sys
import socket
import ipaddress
import threading
import subprocess
import shutil
import json
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Union

from .utils import (
    Fore, Style, HAS_REQUESTS, HAS_NMAP, HAS_WHOIS, VERSION, 
    ScannerConfig, TOP_1000_PORTS, _show_progress_bar
)

class Scanner:
    def __init__(self, config: ScannerConfig):
        self.config = config

    def port_scan(self, hosts: List[str]) -> Dict[str, Dict[str, Any]]:
        """Perform basic TCP port scanning"""
        print(f"\n{Fore.YELLOW}[+] Starting Port Scanning...{Style.RESET_ALL}")
        
        if self.config.all_ports:
            ports_to_scan = range(1, 65536)
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

    def masscan_scan(self, hosts: List[str]) -> Dict[str, Dict[str, Any]]:
        """Perform fast port scanning using masscan"""
        print(f"\n{Fore.YELLOW}[+] Starting Fast Port Scan (masscan)...{Style.RESET_ALL}")
        
        masscan_path = os.path.expanduser('~/go/bin/masscan')
        if not os.path.exists(masscan_path):
            masscan_path = shutil.which('masscan')

        if not masscan_path:
            print(f"{Fore.RED}[-] Masscan not found, falling back to basic port scan{Style.RESET_ALL}")
            return self.port_scan(hosts)

        # Basic privilege check
        is_root = False
        if hasattr(os, 'geteuid'):
            is_root = os.geteuid() == 0
        
        if not is_root and not sys.platform.startswith('win'):
            print(f"{Fore.YELLOW}[!] Not running as root - masscan requires sudo or capabilities{Style.RESET_ALL}")
            return self.port_scan(hosts)

        port_range = "1-65535" if self.config.all_ports else TOP_1000_PORTS
        
        resolved_hosts = []
        ip_to_hostname = {}
        for host in hosts:
            try:
                ipaddress.ip_address(host)
                resolved_hosts.append(host)
                ip_to_hostname[host] = host
            except ValueError:
                try:
                    ip = socket.gethostbyname(host)
                    resolved_hosts.append(ip)
                    ip_to_hostname[ip] = host
                except socket.gaierror:
                    continue

        if not resolved_hosts:
            return self.port_scan(hosts)

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as target_file:
            for ip in resolved_hosts:
                target_file.write(f"{ip}\n")
            target_file_path = target_file.name

        cmd = [
            masscan_path, '-iL', target_file_path, '-p', port_range,
            '--rate', '1000', '--output-format', 'list', '--output-filename', '-'
        ]
        if not is_root and not sys.platform.startswith('win'):
            cmd.insert(0, 'sudo')

        masscan_results = {}
        progress_stop = threading.Event()
        progress_thread = threading.Thread(target=_show_progress_bar, args=(progress_stop, "Masscan port scan in progress"), daemon=True)
        progress_thread.start()

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config.masscan_timeout)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip() and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == 'open' and parts[1] == 'tcp':
                            port, ip = parts[2], parts[3]
                            host = ip_to_hostname.get(ip, ip)
                            if host not in masscan_results:
                                masscan_results[host] = {}
                            masscan_results[host][port] = {"state": "open", "service": ""}
                            print(f"{Fore.GREEN}[+] Masscan found: {host}:{port}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Masscan failed, falling back to basic port scan{Style.RESET_ALL}")
                return self.port_scan(hosts)
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[-] Masscan timed out, falling back to basic port scan{Style.RESET_ALL}")
            return self.port_scan(hosts)
        finally:
            progress_stop.set()
            progress_thread.join()
            if os.path.exists(target_file_path):
                os.unlink(target_file_path)

        return masscan_results

    def nmap_scan(self, scan_results: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Perform detailed Nmap scan for service enumeration"""
        if not HAS_NMAP:
            print(f"\n{Fore.RED}[-] Nmap module not available, using basic identification{Style.RESET_ALL}")
            return self._basic_service_enumeration(scan_results)

        import nmap
        nm = nmap.PortScanner()
        
        updated_results = scan_results.copy()
        for host, ports in scan_results.items():
            if not ports: continue
            
            port_list = ','.join(ports.keys())
            print(f"{Fore.CYAN}[*] Nmap service scan on {host} ports: {port_list}{Style.RESET_ALL}")
            
            progress_stop = threading.Event()
            progress_thread = threading.Thread(target=_show_progress_bar, args=(progress_stop, f"Nmap scanning {host}"), daemon=True)
            progress_thread.start()

            try:
                nm.scan(hosts=host, ports=port_list, arguments="-Pn -sV")
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
            except Exception as e:
                print(f"{Fore.RED}[-] Nmap scan failed for {host}: {e}{Style.RESET_ALL}")
            finally:
                progress_stop.set()
                progress_thread.join()
        
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
            print(f"{Fore.CYAN}[*] WHOIS lookup for {target}...{Style.RESET_ALL}")
            w = whois.whois(target)
            data = {
                "registrar": getattr(w, 'registrar', "N/A"),
                "org": getattr(w, 'org', "N/A"),
                "country": getattr(w, 'country', "N/A"),
                "status": getattr(w, 'status', "N/A")
            }
            return data
        except Exception as e:
            return {"error": str(e)}
