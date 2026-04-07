import os
import sys
import socket
import ipaddress
import threading
import subprocess
import shutil
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Dict, Any, Optional

from .utils import (
    Fore, Style, HAS_REQUESTS, VERSION, ScannerConfig, 
    _show_progress, resolve_domain_to_ip, reverse_dns_lookup
)

class Discovery:
    def __init__(self, config: ScannerConfig):
        self.config = config

    def _is_valid_hostname(self, hostname: str) -> bool:
        """Validate if a string is a valid hostname/domain"""
        if not hostname or not hostname.strip():
            return False

        hostname = hostname.strip()

        if hostname.isdigit():
            return False
        if hostname.startswith('AS') and hostname[2:].isdigit():
            return False

        if '/' in hostname:
            return False

        try:
            ipaddress.ip_address(hostname)
            return False
        except ValueError:
            pass

        hostname_pattern = r'^(?=.*[a-zA-Z])(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if re.match(hostname_pattern, hostname):
            return True

        return False

    def extract_domain(self, target: str) -> Optional[str]:
        """Extract domain name from target"""
        try:
            ipaddress.ip_network(target, strict=False)
            return None
        except ValueError:
            return target.lower().strip()

    def host_discovery(self) -> Dict[str, Any]:
        """Perform host discovery using optional ping and port-based detection"""
        print(f"\n{Fore.YELLOW}[+] Starting Host Discovery...{Style.RESET_ALL}")

        all_hosts = []
        for target in self.config.targets:
            try:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts()) if network.num_addresses > 1 else [network.network_address]
            except ValueError:
                hosts = [target]
            all_hosts.extend([str(host) for host in hosts])

        all_hosts = list(set(all_hosts))
        live_hosts = set()
        ping_responsive = set()

        discovery_ports = [80, 443, 22, 21, 25, 53, 135, 139, 445]

        def ping_host(host):
            try:
                if sys.platform.startswith('win'):
                    ping_cmd = ['ping', '-n', '1', '-w', '2000', str(host)]
                elif sys.platform.startswith('linux'):
                    ping_cmd = ['ping', '-c', '1', '-W', '2', str(host)]
                else:
                    ping_cmd = ['ping', '-c', '1', str(host)]

                result = subprocess.run(
                    ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
                )
                if result.returncode == 0:
                    return str(host)
            except Exception:
                pass
            return None

        def port_discovery(host):
            for port in discovery_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    if result == 0:
                        return str(host)
                except Exception:
                    continue
            return None

        if self.config.enable_ping:
            print(f"{Fore.CYAN}[*] Phase 1: Ping discovery...{Style.RESET_ALL}")
            with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                futures = [executor.submit(ping_host, host) for host in all_hosts]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        live_hosts.add(result)
                        ping_responsive.add(result)
                        print(f"{Fore.GREEN}[+] Host discovered (ping): {result}{Style.RESET_ALL}")
            non_ping_hosts = [host for host in all_hosts if host not in ping_responsive]
        else:
            print(f"{Fore.CYAN}[*] Ping discovery disabled{Style.RESET_ALL}")
            non_ping_hosts = all_hosts

        if non_ping_hosts:
            phase_num = 2 if self.config.enable_ping else 1
            print(f"{Fore.CYAN}[*] Phase {phase_num}: Port-based discovery for {len(non_ping_hosts)} hosts...{Style.RESET_ALL}")
            with ThreadPoolExecutor(max_workers=min(self.config.threads, 20)) as executor:
                futures = [executor.submit(port_discovery, host) for host in non_ping_hosts]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        live_hosts.add(result)
                        print(f"{Fore.GREEN}[+] Host discovered (port): {result}{Style.RESET_ALL}")

        discovery_results = {
            "live_hosts": list(live_hosts),
            "ping_responsive_count": len(ping_responsive),
            "unresponsive_count": len(all_hosts) - len(live_hosts)
        }
        return discovery_results

    def passive_discovery(self) -> Set[str]:
        """Perform passive discovery using multiple providers"""
        print(f"\n{Fore.YELLOW}[+] Starting Passive Discovery...{Style.RESET_ALL}")
        discovered_hosts = set()

        for target in self.config.targets:
            domain = self.extract_domain(target)
            if not domain:
                continue

            print(f"{Fore.CYAN}[*] Performing passive discovery on domain: {domain}{Style.RESET_ALL}")
            
            # Provider: Amass
            if self.config.enable_amass:
                discovered_hosts.update(self.amass_discovery(domain))
            
            # Provider: DNSDumpster
            if self.config.enable_dnsdumpster:
                discovered_hosts.update(self.dnsdumpster_discovery(domain))
            
            # Provider: crt.sh
            if self.config.enable_crtsh:
                discovered_hosts.update(self.crtsh_discovery(domain))

        return discovered_hosts

    def amass_discovery(self, domain: str) -> Set[str]:
        """Use amass for passive subdomain enumeration"""
        discovered_hosts = set()
        print(f"{Fore.CYAN}[*] Running amass on {domain}...{Style.RESET_ALL}")

        amass_path = os.path.expanduser('~/go/bin/amass')
        if not os.path.exists(amass_path):
            amass_path = shutil.which('amass')

        if not amass_path:
            print(f"{Fore.RED}[-] Amass not found, skipping{Style.RESET_ALL}")
            return discovered_hosts

        cmd = [amass_path, 'enum', '-d', domain]
        progress_stop = threading.Event()
        timeout_msg = f"Amass scan in progress (timeout: {self.config.amass_timeout}s)" if self.config.amass_timeout else "Amass scan in progress"
        
        progress_thread = threading.Thread(target=_show_progress, args=(progress_stop, timeout_msg), daemon=True)
        progress_thread.start()

        stdout, stderr, returncode = "", "", 0
        try:
            if self.config.amass_timeout:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    stdout, stderr = process.communicate(timeout=self.config.amass_timeout)
                    returncode = process.returncode
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        stdout, stderr = process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        stdout, stderr = process.communicate(timeout=5)
                    returncode = -1
                    print(f"\n{Fore.YELLOW}[!] Amass timeout reached, processing partial results...{Style.RESET_ALL}")
            else:
                result = subprocess.run(cmd, capture_output=True, text=True)
                stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
        except Exception as e:
            print(f"{Fore.RED}[-] Amass execution error: {e}{Style.RESET_ALL}")
        finally:
            progress_stop.set()
            progress_thread.join()
            print()

        if stdout:
            for line in stdout.strip().split('\n'):
                if line.strip():
                    hostname = line.strip().split()[0]
                    if self._is_valid_hostname(hostname):
                        discovered_hosts.add(hostname)
                        print(f"{Fore.GREEN}[+] Amass discovered: {hostname}{Style.RESET_ALL}")

        return discovered_hosts

    def dnsdumpster_discovery(self, domain: str) -> Set[str]:
        """Use dnsdumpster.com API for passive DNS discovery"""
        discovered_hosts = set()
        if not HAS_REQUESTS:
            return discovered_hosts

        try:
            import requests
            print(f"{Fore.CYAN}[*] Querying dnsdumpster for {domain}...{Style.RESET_ALL}")
            session = requests.Session()
            headers = {'User-Agent': f'PDIve++/{VERSION}'}
            url = 'https://dnsdumpster.com/'
            page = session.get(url, headers=headers, timeout=15)
            
            csrf_token = None
            csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', page.text)
            if csrf_match:
                csrf_token = csrf_match.group(1)

            if not csrf_token:
                return discovered_hosts

            data = {'csrfmiddlewaretoken': csrf_token, 'targetip': domain, 'user': 'free'}
            headers.update({'Referer': url})
            response = session.post(url, data=data, headers=headers, timeout=30)

            if response.status_code == 200:
                subdomain_pattern = r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*' + re.escape(domain)
                matches = re.findall(subdomain_pattern, response.text)
                for match in matches:
                    subdomain = match[0] + domain if isinstance(match, tuple) and match[0] else (match if isinstance(match, str) else None)
                    if subdomain and subdomain != domain:
                        discovered_hosts.add(subdomain)
                        print(f"{Fore.GREEN}[+] DNSDumpster discovered: {subdomain}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] DNSDumpster error: {e}{Style.RESET_ALL}")

        return discovered_hosts

    def crtsh_discovery(self, domain: str) -> Set[str]:
        """Use crt.sh certificate transparency logs for subdomain discovery"""
        discovered_hosts = set()
        if not HAS_REQUESTS:
            return discovered_hosts

        try:
            import requests
            import json
            print(f"{Fore.CYAN}[*] Querying crt.sh for {domain}...{Style.RESET_ALL}")
            url = f'https://crt.sh/?q=%.{domain}&output=json'
            response = requests.get(url, timeout=30, headers={'User-Agent': f'PDIve++/{VERSION}'})

            if response.status_code == 200:
                data = response.json()
                for cert in data:
                    if 'name_value' in cert:
                        names = cert['name_value'].split('\n')
                        for name in names:
                            name = name.strip().lower()
                            if name and not name.startswith('*') and domain in name:
                                discovered_hosts.add(name)
                                print(f"{Fore.GREEN}[+] crt.sh discovered: {name}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] crt.sh error: {e}{Style.RESET_ALL}")

        return discovered_hosts
