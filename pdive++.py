#!/usr/bin/env python3
"""
PDIve - Automated Penetration Testing Discovery Tool
Dive deep into the network - A defensive security tool for authorized network reconnaissance and vulnerability assessment.
"""

import argparse
import csv
import ipaddress
import json
import os
import socket
import sys
import threading
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    from colorama import init, Fore, Back, Style
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    class MockColor:
        CYAN = YELLOW = GREEN = RED = ""
        RESET_ALL = ""
    Fore = Style = MockColor()

try:
    import requests
    import urllib3
    # Suppress SSL warnings for reconnaissance purposes
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("Note: requests module not available, HTTP-based service checks disabled")

try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False
    print("Note: nmap module not available, nmap scanning disabled")

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False
    print("Note: whois module not available, whois lookups disabled")

if HAS_COLORAMA:
    init(autoreset=True)

# Version constant
VERSION = "1.3.6"


class PDIve:
    def __init__(self, targets, output_dir="pdive_output", threads=50, discovery_mode="active", enable_ping=False, amass_timeout=180, json_only=False, no_json=False, dns_timeout=5, whois_timeout=15, enable_whois=True, checkpoint_interval=30, checkpoint_path=None):
        self.targets = targets if isinstance(targets, list) else [targets]
        self.output_dir = output_dir
        self.threads = threads
        self.discovery_mode = discovery_mode
        self.enable_ping = enable_ping
        self.amass_timeout = amass_timeout
        self.json_only = json_only
        self.no_json = no_json
        self.dns_timeout = dns_timeout
        self.whois_timeout = whois_timeout
        self.enable_whois = enable_whois
        self.checkpoint_interval = checkpoint_interval
        self.checkpoint_path = checkpoint_path or os.path.join(output_dir, "scan_checkpoint.json")
        self.scan_state = {
            "completed_phases": [],
            "amass_hosts": [],
            "live_hosts": []
        }
        self._checkpoint_lock = threading.Lock()
        self._checkpoint_stop_event = threading.Event()
        self._checkpoint_thread = None
        self.results = {
            "scan_info": {
                "targets": self.targets,
                "start_time": datetime.now().isoformat(),
                "scanner": f"PDIve v{VERSION}",
                "discovery_mode": self.discovery_mode
            },
            "hosts": {},
            "services": {},
            "summary": {},
            "unresponsive_hosts": 0
        }

        os.makedirs(output_dir, exist_ok=True)

    def _save_checkpoint(self):
        payload = {
            "version": 1,
            "saved_at": datetime.now().isoformat(),
            "config": {
                "targets": self.targets,
                "output_dir": self.output_dir,
                "threads": self.threads,
                "discovery_mode": self.discovery_mode,
                "enable_ping": self.enable_ping,
                "amass_timeout": self.amass_timeout,
                "json_only": self.json_only,
                "no_json": self.no_json,
                "dns_timeout": self.dns_timeout,
                "whois_timeout": self.whois_timeout,
                "enable_whois": self.enable_whois
            },
            "scan_state": self.scan_state,
            "results": self.results
        }
        with self._checkpoint_lock:
            try:
                with open(self.checkpoint_path, 'w') as f:
                    json.dump(payload, f, indent=2, default=str)
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Failed to write checkpoint: {e}{Style.RESET_ALL}")

    def _checkpoint_worker(self):
        while not self._checkpoint_stop_event.is_set():
            time.sleep(self.checkpoint_interval)
            if self._checkpoint_stop_event.is_set():
                break
            self._save_checkpoint()

    def _start_checkpointing(self):
        if self.checkpoint_interval <= 0:
            return
        self._checkpoint_stop_event.clear()
        self._checkpoint_thread = threading.Thread(target=self._checkpoint_worker, daemon=True)
        self._checkpoint_thread.start()

    def _stop_checkpointing(self):
        if self._checkpoint_thread:
            self._checkpoint_stop_event.set()
            self._checkpoint_thread.join(timeout=2)
            self._checkpoint_thread = None

    def _mark_phase_complete(self, phase):
        if phase not in self.scan_state["completed_phases"]:
            self.scan_state["completed_phases"].append(phase)
        self._save_checkpoint()

    def print_banner(self):
        targets_display = ', '.join(self.targets[:3])
        if len(self.targets) > 3:
            targets_display += f" ... (+{len(self.targets) - 3} more)"

        amass_timeout_display = f"{self.amass_timeout}s" if self.amass_timeout else "None"

        banner = f"""
{Fore.CYAN}
██████╗ ██████╗ ██╗██╗   ██╗███████╗
██╔══██╗██╔══██╗██║██║   ██║██╔════╝
██████╔╝██║  ██║██║██║   ██║█████╗
██╔═══╝ ██║  ██║██║╚██╗ ██╔╝██╔══╝
██║     ██████╔╝██║ ╚████╔╝ ███████╗
╚═╝     ╚═════╝ ╚═╝  ╚═══╝  ╚══════╝
{Style.RESET_ALL}
{Fore.YELLOW}Dive deep into the network{Style.RESET_ALL}
{Fore.RED}For authorized security testing only!{Style.RESET_ALL}

Targets ({len(self.targets)}): {Fore.GREEN}{targets_display}{Style.RESET_ALL}
Output Directory: {Fore.GREEN}{self.output_dir}{Style.RESET_ALL}
Threads: {Fore.GREEN}{self.threads}{Style.RESET_ALL}
Discovery Mode: {Fore.GREEN}{self.discovery_mode.upper()}{Style.RESET_ALL}
Ping Enabled: {Fore.GREEN}{'YES' if self.enable_ping else 'NO'}{Style.RESET_ALL}
Amass Timeout: {Fore.GREEN}{amass_timeout_display}{Style.RESET_ALL}
"""
        print(banner)

    def _show_progress(self, stop_event, message):
        """Display a progress indicator while a long-running task is executing"""
        spinner = ['|', '/', '-', '\\']
        idx = 0
        start_time = time.time()
        while not stop_event.is_set():
            elapsed = int(time.time() - start_time)
            time_str = f"{elapsed}s"
            print(f"\r{Fore.CYAN}[*] {message} {spinner[idx % len(spinner)]} ({time_str}){Style.RESET_ALL}", end='', flush=True)
            idx += 1
            time.sleep(0.2)

    def _show_progress_bar(self, stop_event, message):
        """Display a progress bar with arrow that crawls from left to right"""
        start_time = time.time()
        bar_width = 30

        while not stop_event.is_set():
            elapsed = time.time() - start_time
            # Estimate progress based on typical amass scan duration (assume ~60 seconds for estimation)
            # Progress moves continuously but slows down as it approaches 95%
            estimated_progress = min(95, (elapsed / 60.0) * 100)

            # Calculate the position of the arrow in the bar
            filled = int((estimated_progress / 100.0) * bar_width)

            # Create the progress bar with arrow
            if filled == 0:
                bar = '>' + ' ' * (bar_width - 1)
            elif filled >= bar_width:
                bar = '=' * bar_width
            else:
                bar = '=' * (filled - 1) + '>' + ' ' * (bar_width - filled)

            # Format elapsed time
            mins, secs = divmod(int(elapsed), 60)
            time_str = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"

            print(f"\r{Fore.CYAN}[*] {message} [{bar}] {estimated_progress:>5.1f}% ({time_str}){Style.RESET_ALL}",
                  end='', flush=True)
            time.sleep(0.3)

    def validate_targets(self):
        """Validate if all targets are valid IP addresses, network ranges, or hostnames"""
        valid_targets = []
        invalid_targets = []

        for target in self.targets:
            try:
                ipaddress.ip_network(target, strict=False)
                valid_targets.append(target)
            except ValueError:
                try:
                    socket.gethostbyname(target)
                    valid_targets.append(target)
                except socket.gaierror:
                    invalid_targets.append(target)

        if invalid_targets:
            print(f"{Fore.RED}[-] Invalid targets: {', '.join(invalid_targets)}{Style.RESET_ALL}")

        self.targets = valid_targets
        return len(valid_targets) > 0

    def host_discovery(self):
        """Perform host discovery using optional ping and port-based detection"""
        print(f"\n{Fore.YELLOW}[+] Starting Host Discovery...{Style.RESET_ALL}")

        all_hosts = []

        for target in self.targets:
            print(f"{Fore.CYAN}[*] Processing target: {target}{Style.RESET_ALL}")

            try:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts()) if network.num_addresses > 1 else [network.network_address]
            except ValueError:
                hosts = [target]

            all_hosts.extend([str(host) for host in hosts])

        all_hosts = list(set(all_hosts))
        live_hosts = set()
        ping_responsive = set()

        # Common ports for host discovery fallback
        discovery_ports = [80, 443, 22, 21, 25, 53, 135, 139, 445]

        def ping_host(host):
            try:
                import subprocess

                if sys.platform.startswith('win'):
                    ping_cmd = ['ping', '-n', '1', '-w', '2000', str(host)]
                elif sys.platform.startswith('linux'):
                    ping_cmd = ['ping', '-c', '1', '-W', '2', str(host)]
                else:
                    # macOS and other Unix variants
                    ping_cmd = ['ping', '-c', '1', str(host)]

                result = subprocess.run(
                    ping_cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5
                )
                if result.returncode == 0:
                    return str(host)
            except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
                pass
            return None

        def port_discovery(host):
            """Try to connect to common ports to detect live hosts"""
            for port in discovery_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    if result == 0:
                        return str(host)
                except (socket.error, socket.timeout, OSError):
                    continue
            return None

        # Phase 1: Ping discovery (only if enabled)
        if self.enable_ping:
            print(f"{Fore.CYAN}[*] Phase 1: Ping discovery...{Style.RESET_ALL}")
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(ping_host, host) for host in all_hosts]

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        live_hosts.add(result)
                        ping_responsive.add(result)
                        print(f"{Fore.GREEN}[+] Host discovered (ping): {result}{Style.RESET_ALL}")

            # For hosts that didn't respond to ping, try port-based discovery
            non_ping_hosts = [host for host in all_hosts if host not in ping_responsive]
        else:
            print(f"{Fore.CYAN}[*] Ping discovery disabled (use --ping to enable){Style.RESET_ALL}")
            # All hosts will be checked via port-based discovery
            non_ping_hosts = all_hosts

        # Phase 2: Port-based discovery
        if non_ping_hosts:
            phase_num = 2 if self.enable_ping else 1
            print(f"{Fore.CYAN}[*] Phase {phase_num}: Port-based discovery for {len(non_ping_hosts)} hosts...{Style.RESET_ALL}")
            with ThreadPoolExecutor(max_workers=min(self.threads, 20)) as executor:
                futures = [executor.submit(port_discovery, host) for host in non_ping_hosts]

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        live_hosts.add(result)
                        print(f"{Fore.GREEN}[+] Host discovered (port): {result}{Style.RESET_ALL}")

        live_hosts_list = list(live_hosts)
        unresponsive_count = len(all_hosts) - len(live_hosts_list)

        for host in live_hosts_list:
            if host not in self.results["hosts"]:
                self.results["hosts"][host] = {"status": "up", "ports": {}}
            else:
                self.results["hosts"][host]["status"] = "up"
                if "ports" not in self.results["hosts"][host]:
                    self.results["hosts"][host]["ports"] = {}
        self.results["unresponsive_hosts"] = unresponsive_count
        print(f"\n{Fore.CYAN}[*] Host discovery completed. Found {len(live_hosts_list)} live hosts from {len(all_hosts)} total hosts.{Style.RESET_ALL}")
        if self.enable_ping:
            print(f"{Fore.CYAN}[*] Ping responsive: {len(ping_responsive)}, Port responsive: {len(live_hosts_list) - len(ping_responsive)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}[*] All hosts discovered via port-based detection (ping disabled){Style.RESET_ALL}")

        return live_hosts_list

    def port_scan(self, hosts):
        """Perform port scanning on discovered hosts"""
        print(f"\n{Fore.YELLOW}[+] Starting Port Scanning...{Style.RESET_ALL}")

        common_ports = [
            # FTP, SSH, Telnet
            21, 22, 23,
            # SMTP, DNS
            25, 53,
            # HTTP/HTTPS
            80, 443, 8080, 8443, 8000, 8888, 9000, 9090,
            # Email
            110, 143, 993, 995, 587,
            # Windows
            135, 139, 445, 3389,
            # Remote access
            111, 1723, 5900, 5901,
            # Databases
            3306, 5432, 27017, 6379, 9200, 9300, 5984,
            # Web frameworks
            3000, 4000, 5000, 8000, 8081, 8082,
            # Other services
            1433, 2049, 2181, 2375, 5601, 6443, 7001, 8161, 8500, 9092, 11211
        ]

        def scan_port(host, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)  # Increased timeout for better detection
                result = sock.connect_ex((host, port))
                sock.close()

                if result == 0:
                    return port
            except (socket.error, socket.timeout, OSError):
                pass
            return None

        for host in hosts:
            print(f"\n{Fore.CYAN}[*] Scanning {host}...{Style.RESET_ALL}")
            open_ports = []

            # Ensure host is initialized in results
            if host not in self.results["hosts"]:
                self.results["hosts"][host] = {"status": "up", "ports": {}}

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(scan_port, host, port) for port in common_ports]

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        print(f"{Fore.GREEN}[+] Open port found: {host}:{result}{Style.RESET_ALL}")

            self.results["hosts"][host]["ports"] = {str(port): {"state": "open", "service": ""} for port in open_ports}

    def service_enumeration(self, hosts):
        """Perform service enumeration on open ports"""
        print(f"\n{Fore.YELLOW}[+] Starting Service Enumeration...{Style.RESET_ALL}")

        service_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
            443: "https", 445: "microsoft-ds", 587: "submission", 993: "imaps", 995: "pop3s",
            1433: "ms-sql-s", 1723: "pptp", 2049: "nfs", 2181: "zookeeper", 2375: "docker",
            3000: "node", 3306: "mysql", 3389: "rdp", 4000: "http-alt", 5000: "http-alt",
            5432: "postgresql", 5601: "kibana", 5900: "vnc", 5901: "vnc-1",
            5984: "couchdb", 6379: "redis", 6443: "kubernetes", 7001: "afs3-callback",
            8000: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8082: "http-alt",
            8161: "patrol-snmp", 8443: "https-alt", 8500: "consul", 8888: "http-alt",
            9000: "http-alt", 9090: "http-alt", 9092: "kafka", 9200: "elasticsearch",
            9300: "elasticsearch-transport", 11211: "memcached", 27017: "mongodb"
        }

        def enumerate_service(host, port):
            try:
                service = service_map.get(int(port), "unknown")

                if service in ["http", "https", "http-alt", "https-alt"] and HAS_REQUESTS:
                    protocol = "https" if service in ["https", "https-alt"] else "http"
                    # Only include port in URL if it's not the default for the protocol
                    default_port = "443" if protocol == "https" else "80"
                    if port == default_port:
                        url = f"{protocol}://{host}"
                    else:
                        url = f"{protocol}://{host}:{port}"

                    try:
                        # Suppress SSL warnings and disable SSL verification for reconnaissance
                        response = requests.get(url, timeout=5, verify=False,
                                              headers={'User-Agent': f'PDIve/{VERSION}'})
                        server_header = response.headers.get('Server', 'Unknown')
                        service_info = f"{service} ({server_header})"
                    except (requests.RequestException, ConnectionError, TimeoutError):
                        service_info = service
                else:
                    service_info = service

                return service_info
            except Exception as e:
                return "unknown"

        for host in hosts:
            if host in self.results["hosts"]:
                for port in self.results["hosts"][host]["ports"]:
                    service_info = enumerate_service(host, port)
                    self.results["hosts"][host]["ports"][port]["service"] = service_info
                    print(f"{Fore.GREEN}[+] Service identified: {host}:{port} -> {service_info}{Style.RESET_ALL}")

    def passive_discovery(self):
        """Perform passive discovery using amass only"""
        print(f"\n{Fore.YELLOW}[+] Starting Passive Discovery (amass only)...{Style.RESET_ALL}")

        discovered_hosts = set()

        for target in self.targets:
            # Extract domain from target
            domain = self.extract_domain(target)
            if not domain:
                continue

            print(f"{Fore.CYAN}[*] Performing passive discovery on domain: {domain}{Style.RESET_ALL}")

            # Use amass for passive discovery
            amass_hosts = self.amass_discovery(domain)
            discovered_hosts.update(amass_hosts)

        discovered_hosts_list = list(discovered_hosts)

        # Add discovered hosts to results
        self.results["hosts"] = {host: {"status": "discovered", "ports": {}} for host in discovered_hosts_list}

        print(f"\n{Fore.CYAN}[*] Passive discovery completed. Found {len(discovered_hosts_list)} hosts.{Style.RESET_ALL}")

        return discovered_hosts_list

    def extract_domain(self, target):
        """Extract domain name from target"""
        try:
            # If it's an IP or CIDR, skip
            ipaddress.ip_network(target, strict=False)
            return None
        except ValueError:
            # It's likely a domain name
            return target.lower().strip()

    def amass_discovery(self, domain):
        """Use amass for passive subdomain enumeration"""
        discovered_hosts = set()

        try:
            print(f"{Fore.CYAN}[*] Running amass on {domain}...{Style.RESET_ALL}")

            # Check if amass is available - try multiple methods
            import subprocess
            import shutil

            # Try Go-installed amass first (to avoid broken snap version), then check PATH
            amass_path = None
            go_amass_path = os.path.expanduser('~/go/bin/amass')
            if os.path.exists(go_amass_path):
                amass_path = go_amass_path
            else:
                # Try using shutil.which as fallback
                amass_path = shutil.which('amass')

            if not amass_path:
                # Fallback to 'which' command
                try:
                    result = subprocess.run(['which', 'amass'], capture_output=True, text=True)
                    if result.returncode != 0:
                        print(f"{Fore.RED}[-] Amass not found in PATH, skipping amass discovery{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}[*] Install amass from: https://github.com/OWASP/Amass{Style.RESET_ALL}")
                        return discovered_hosts
                    amass_path = result.stdout.strip()
                except FileNotFoundError:
                    print(f"{Fore.RED}[-] Amass not found, skipping amass discovery{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[*] Install amass from: https://github.com/OWASP/Amass{Style.RESET_ALL}")
                    return discovered_hosts

            # Run amass with specified options (passive mode is default in v4+)
            cmd = [amass_path, 'enum', '-d', domain]

            # Start progress indicator in a separate thread
            progress_stop = threading.Event()

            # Display timeout info if set
            if self.amass_timeout:
                timeout_msg = f"Amass scan in progress (timeout: {self.amass_timeout}s)"
            else:
                timeout_msg = "Amass scan in progress"

            progress_thread = threading.Thread(target=self._show_progress, args=(progress_stop, timeout_msg))
            progress_thread.daemon = True
            progress_thread.start()

            # Run amass with or without timeout
            try:
                if self.amass_timeout:
                    # Use Popen for better timeout handling with partial output
                    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    try:
                        stdout, stderr = process.communicate(timeout=self.amass_timeout)
                        returncode = process.returncode
                    except subprocess.TimeoutExpired:
                        # Timeout occurred - terminate process and get partial output
                        process.terminate()
                        try:
                            # Give it a moment to terminate gracefully
                            stdout, stderr = process.communicate(timeout=5)
                        except subprocess.TimeoutExpired:
                            # Force kill if it doesn't terminate
                            process.kill()
                            try:
                                stdout, stderr = process.communicate(timeout=5)
                            except subprocess.TimeoutExpired:
                                stdout, stderr = "", ""

                        returncode = -1  # Indicate timeout occurred
                        print(f"\n{Fore.YELLOW}[!] Amass timeout reached ({self.amass_timeout}s), processing partial results...{Style.RESET_ALL}")
                else:
                    # Run without timeout
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    stdout = result.stdout
                    stderr = result.stderr
                    returncode = result.returncode
            finally:
                # Always stop progress indicator, even if subprocess fails
                progress_stop.set()
                progress_thread.join()
                print()  # New line after progress indicator

            # Process output regardless of timeout
            if stdout and stdout.strip():
                output_lines = stdout.strip().split('\n')
                if output_lines and any(line.strip() for line in output_lines):
                    for line in output_lines:
                        if line.strip():
                            # Extract just the hostname from amass output
                            # Amass may output formats like: "hostname (FQDN) --> record_type --> ip (IPAddress)"
                            # We only want the hostname part
                            hostname = line.strip().split()[0]
                            discovered_hosts.add(hostname)
                            print(f"{Fore.GREEN}[+] Amass discovered: {hostname}{Style.RESET_ALL}")

                    if returncode == -1:
                        print(f"{Fore.GREEN}[+] Saved {len(discovered_hosts)} hosts discovered before timeout{Style.RESET_ALL}")
                else:
                    if returncode != -1:
                        print(f"{Fore.YELLOW}[*] Amass completed but found no subdomains for {domain}{Style.RESET_ALL}")
            else:
                if returncode != -1:
                    print(f"{Fore.YELLOW}[*] Amass completed but found no subdomains for {domain}{Style.RESET_ALL}")

            if returncode not in [0, -1]:
                error_msg = stderr.strip() if stderr else "Unknown error"
                print(f"{Fore.RED}[-] Amass failed (exit code {returncode}): {error_msg}{Style.RESET_ALL}")

                # If amass fails, provide helpful debugging info
                if "config" in error_msg.lower() or "permission" in error_msg.lower():
                    print(f"{Fore.YELLOW}[*] Amass may need configuration. Try running 'amass enum -d {domain} -passive' manually{Style.RESET_ALL}")
                elif not error_msg:
                    print(f"{Fore.YELLOW}[*] Amass failed silently. This may be due to missing configuration or network issues{Style.RESET_ALL}")

                print(f"{Fore.YELLOW}[*] Continuing with other passive discovery methods...{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[-] Amass error for {domain}: {e}{Style.RESET_ALL}")

        return discovered_hosts

    def dnsdumpster_discovery(self, domain):
        """Use dnsdumpster.com API for passive DNS discovery"""
        discovered_hosts = set()

        if not HAS_REQUESTS:
            print(f"{Fore.YELLOW}[*] requests module not available, skipping DNSDumpster discovery{Style.RESET_ALL}")
            return discovered_hosts

        try:
            print(f"{Fore.CYAN}[*] Querying dnsdumpster for {domain}...{Style.RESET_ALL}")

            import re

            # DNSDumpster requires a session and CSRF token
            session = requests.Session()

            # Set realistic headers to avoid blocking
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }

            # Get the page to extract CSRF token
            url = 'https://dnsdumpster.com/'
            page = session.get(url, headers=headers, timeout=15)

            if page.status_code != 200:
                print(f"{Fore.RED}[-] Failed to access dnsdumpster.com (status: {page.status_code}){Style.RESET_ALL}")
                return discovered_hosts

            # Try multiple CSRF token patterns
            csrf_patterns = [
                r'name="csrfmiddlewaretoken" value="([^"]+)"',
                r'csrfmiddlewaretoken["\s]*:["\s]*([^"]+)',
                r'csrf_token["\s]*:["\s]*([^"]+)',
                r'<input[^>]*name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']'
            ]

            csrf_token = None
            for pattern in csrf_patterns:
                matches = re.findall(pattern, page.text)
                if matches:
                    csrf_token = matches[0]
                    break

            if not csrf_token:
                print(f"{Fore.RED}[-] Could not extract CSRF token from dnsdumpster{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] This may be due to rate limiting or site changes{Style.RESET_ALL}")
                return discovered_hosts

            # Submit the form
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'targetip': domain,
                'user': 'free'
            }

            # Update headers for POST request
            headers.update({
                'Referer': url,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': 'https://dnsdumpster.com'
            })

            response = session.post(url, data=data, headers=headers, timeout=30)

            if response.status_code == 200:
                # Parse the response for subdomains
                subdomain_pattern = r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*' + re.escape(domain)
                matches = re.findall(subdomain_pattern, response.text)

                for match in matches:
                    if isinstance(match, tuple):
                        subdomain = match[0] + domain if match[0] else domain
                    else:
                        subdomain = match

                    if subdomain and subdomain != domain:
                        discovered_hosts.add(subdomain)
                        print(f"{Fore.GREEN}[+] DNSDumpster discovered: {subdomain}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] DNSDumpster request failed with status {response.status_code}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[-] DNSDumpster error for {domain}: {e}{Style.RESET_ALL}")

        return discovered_hosts

    def crtsh_discovery(self, domain):
        """Use crt.sh certificate transparency logs for subdomain discovery"""
        discovered_hosts = set()

        if not HAS_REQUESTS:
            print(f"{Fore.YELLOW}[*] requests module not available, skipping crt.sh discovery{Style.RESET_ALL}")
            return discovered_hosts

        try:
            print(f"{Fore.CYAN}[*] Querying crt.sh for {domain}...{Style.RESET_ALL}")

            import json

            # Query crt.sh API
            url = f'https://crt.sh/?q=%.{domain}&output=json'
            response = requests.get(url, timeout=30, headers={'User-Agent': f'PDIve/{VERSION}'})

            if response.status_code == 200:
                try:
                    data = response.json()

                    for cert in data:
                        if 'name_value' in cert:
                            # Certificate can contain multiple domains
                            names = cert['name_value'].split('\n')

                            for name in names:
                                name = name.strip().lower()

                                # Filter out wildcards and invalid entries
                                if name and not name.startswith('*') and domain in name:
                                    discovered_hosts.add(name)
                                    print(f"{Fore.GREEN}[+] crt.sh discovered: {name}{Style.RESET_ALL}")

                except json.JSONDecodeError:
                    print(f"{Fore.RED}[-] Failed to parse crt.sh JSON response{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] crt.sh request failed with status {response.status_code}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[-] crt.sh error for {domain}: {e}{Style.RESET_ALL}")

        return discovered_hosts

    def masscan_scan(self, hosts):
        """Perform fast port scanning using masscan"""
        print(f"\n{Fore.YELLOW}[+] Starting Fast Port Scan (masscan)...{Style.RESET_ALL}")

        if not hosts:
            print(f"{Fore.RED}[-] No hosts provided for masscan{Style.RESET_ALL}")
            return {}

        import subprocess
        import shutil
        import json

        # Check if masscan is available - try custom path first, then PATH
        masscan_path = None
        custom_masscan_path = os.path.expanduser('~/go/bin/masscan')
        if os.path.exists(custom_masscan_path):
            masscan_path = custom_masscan_path
        else:
            masscan_path = shutil.which('masscan')

        if not masscan_path:
            print(f"{Fore.RED}[-] Masscan not found in PATH, falling back to basic port scan{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Install masscan from: https://github.com/robertdavidgraham/masscan{Style.RESET_ALL}")
            if sys.platform.startswith('win'):
                print(f"{Fore.YELLOW}[*] On Windows, ensure masscan.exe is in PATH (run PowerShell as Administrator).{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[*] On Linux/macOS, install via your package manager or add the binary to PATH.{Style.RESET_ALL}")
            # Fallback to the original port_scan method
            self.port_scan(hosts)
            return {host: self.results["hosts"][host]["ports"] for host in hosts if host in self.results["hosts"]}

        # Check if we're already running as root or can run masscan
        # geteuid() is Unix-only, so we need platform checks
        is_root = False
        use_sudo = False

        print(f"{Fore.CYAN}[*] Checking masscan privileges...{Style.RESET_ALL}")

        if sys.platform.startswith('win'):
            print(f"{Fore.CYAN}[*] Windows detected: running masscan without sudo{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] If masscan fails, rerun PowerShell as Administrator.{Style.RESET_ALL}")
            use_sudo = False
        else:
            try:
                # Only available on Unix-like systems
                if hasattr(os, 'geteuid'):
                    is_root = os.geteuid() == 0
                    print(f"{Fore.CYAN}[*] Running as root: {is_root} (UID: {os.getuid()}, EUID: {os.geteuid()}){Style.RESET_ALL}")
                else:
                    # Other platforms - assume not root
                    print(f"{Fore.CYAN}[*] Platform does not support privilege detection, assuming non-root{Style.RESET_ALL}")
                    is_root = False
            except AttributeError:
                is_root = False

            # If we're already running as root, no need for sudo
            if is_root:
                print(f"{Fore.GREEN}[+] Running as root - no sudo needed{Style.RESET_ALL}")
                use_sudo = False
            else:
                print(f"{Fore.YELLOW}[!] Not running as root - masscan will need sudo or capabilities{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Please run with 'sudo python3 pdive.py' or set CAP_NET_RAW on masscan{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Falling back to basic port scan...{Style.RESET_ALL}")
                self.port_scan(hosts)
                return {host: self.results["hosts"][host]["ports"] for host in hosts if host in self.results["hosts"]}

        masscan_results = {}

        # Common ports to scan quickly
        port_range = "1-65535"

        try:
            # Create a temporary target file for masscan
            # Masscan requires IP addresses, so resolve hostnames first
            import tempfile
            resolved_hosts = []
            ip_to_hostname = {}  # Map IPs back to original hostnames

            print(f"{Fore.CYAN}[*] Resolving hostnames to IP addresses for masscan...{Style.RESET_ALL}")
            for host in hosts:
                try:
                    # Check if it's already an IP address
                    ipaddress.ip_address(host)
                    resolved_hosts.append(host)
                    ip_to_hostname[host] = host
                    print(f"{Fore.GREEN}[+] Using IP: {host}{Style.RESET_ALL}")
                except ValueError:
                    # It's a hostname, resolve it
                    try:
                        ip = socket.gethostbyname(host)
                        resolved_hosts.append(ip)
                        ip_to_hostname[ip] = host  # Remember the original hostname
                        print(f"{Fore.GREEN}[+] Resolved {host} -> {ip}{Style.RESET_ALL}")
                    except socket.gaierror:
                        print(f"{Fore.YELLOW}[!] Could not resolve {host}, skipping{Style.RESET_ALL}")

            if not resolved_hosts:
                print(f"{Fore.RED}[-] No valid IP addresses to scan{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Falling back to basic port scan...{Style.RESET_ALL}")
                self.port_scan(hosts)
                return {host: self.results["hosts"][host]["ports"] for host in hosts if host in self.results["hosts"]}

            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as target_file:
                for ip in resolved_hosts:
                    target_file.write(f"{ip}\n")
                target_file_path = target_file.name

            print(f"{Fore.CYAN}[*] Running masscan on {len(resolved_hosts)} IP addresses...{Style.RESET_ALL}")

            # Run masscan with output in list format (requires sudo for raw sockets)
            # Use sudo only if needed
            if use_sudo:
                cmd = [
                    'sudo', masscan_path,
                    '-iL', target_file_path,
                    '-p', port_range,
                    '-Pn',  # Skip ping check - scan all hosts regardless of ping response
                    '--rate', '1000',
                    '--output-format', 'list',
                    '--output-filename', '-'
                ]
            else:
                cmd = [
                    masscan_path,
                    '-iL', target_file_path,
                    '-p', port_range,
                    '-Pn',  # Skip ping check - scan all hosts regardless of ping response
                    '--rate', '1000',
                    '--output-format', 'list',
                    '--output-filename', '-'
                ]

            # Start progress indicator in a separate thread
            progress_stop = threading.Event()
            progress_thread = threading.Thread(target=self._show_progress_bar, args=(progress_stop, "Masscan port scan in progress"))
            progress_thread.daemon = True
            progress_thread.start()

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            finally:
                # Always stop progress indicator
                progress_stop.set()
                progress_thread.join()
                print()  # New line after progress indicator

            # Clean up temp file
            os.unlink(target_file_path)

            if result.returncode == 0:
                # Parse masscan output
                for line in result.stdout.strip().split('\n'):
                    if line.strip() and not line.startswith('#'):
                        # Masscan list format: "open tcp 80 1.2.3.4 1234567890"
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == 'open' and parts[1] == 'tcp':
                            port = parts[2]
                            ip = parts[3]

                            # Map IP back to original hostname if available
                            original_host = ip_to_hostname.get(ip, ip)

                            if original_host not in masscan_results:
                                masscan_results[original_host] = {}
                            masscan_results[original_host][port] = {"state": "open", "service": ""}

                            print(f"{Fore.GREEN}[+] Masscan found: {original_host}:{port}{Style.RESET_ALL}")

                print(f"\n{Fore.CYAN}[*] Masscan completed. Found ports on {len(masscan_results)} hosts.{Style.RESET_ALL}")

                # Update results with masscan findings
                for host in hosts:
                    if host not in self.results["hosts"]:
                        self.results["hosts"][host] = {"status": "up", "ports": {}}

                    if host in masscan_results:
                        self.results["hosts"][host]["ports"].update(masscan_results[host])

            else:
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                print(f"{Fore.RED}[-] Masscan failed (exit code {result.returncode}): {error_msg}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Falling back to basic port scan...{Style.RESET_ALL}")
                self.port_scan(hosts)
                return {host: self.results["hosts"][host]["ports"] for host in hosts if host in self.results["hosts"]}

        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[-] Masscan timeout{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Falling back to basic port scan...{Style.RESET_ALL}")
            self.port_scan(hosts)
            return {host: self.results["hosts"][host]["ports"] for host in hosts if host in self.results["hosts"]}
        except Exception as e:
            print(f"{Fore.RED}[-] Masscan error: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Falling back to basic port scan...{Style.RESET_ALL}")
            self.port_scan(hosts)
            return {host: self.results["hosts"][host]["ports"] for host in hosts if host in self.results["hosts"]}

        return masscan_results

    def nmap_scan(self, masscan_results):
        """Perform detailed Nmap scan on masscan results for service enumeration"""
        import shutil
        if not HAS_NMAP:
            print(f"\n{Fore.RED}[-] Nmap module not available, skipping detailed service enumeration{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Install python-nmap and ensure the nmap binary is installed.{Style.RESET_ALL}")
            self._basic_service_from_results(masscan_results)
            return

        nmap_path = shutil.which('nmap')
        if not nmap_path:
            print(f"\n{Fore.RED}[-] Nmap binary not found in PATH, skipping detailed service enumeration{Style.RESET_ALL}")
            if sys.platform.startswith('win'):
                print(f"{Fore.YELLOW}[*] Install Nmap for Windows and ensure nmap.exe is in PATH.{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[*] Install nmap via your package manager or add it to PATH.{Style.RESET_ALL}")
            self._basic_service_from_results(masscan_results)
            return

        if not masscan_results:
            print(f"\n{Fore.YELLOW}[*] No masscan results to enumerate with nmap{Style.RESET_ALL}")
            return

        print(f"\n{Fore.YELLOW}[+] Starting Detailed Service Enumeration (Nmap)...{Style.RESET_ALL}")

        nm = nmap.PortScanner()

        for host, ports in masscan_results.items():
            if not ports:
                continue

            try:
                # Create port list from masscan results
                port_list = ','.join(ports.keys())
                print(f"{Fore.CYAN}[*] Nmap service scan on {host} ports: {port_list}{Style.RESET_ALL}")

                # Start progress indicator in a separate thread
                progress_stop = threading.Event()
                progress_thread = threading.Thread(target=self._show_progress_bar, args=(progress_stop, f"Nmap service scan on {host}"))
                progress_thread.daemon = True
                progress_thread.start()

                try:
                    # Run nmap only on the ports that masscan found
                    nm.scan(hosts=host, ports=port_list, arguments="-Pn -sV --version-intensity 7")
                finally:
                    # Always stop progress indicator
                    progress_stop.set()
                    progress_thread.join()
                    print()  # New line after progress indicator

                for scanned_host in nm.all_hosts():
                    if scanned_host not in self.results["hosts"]:
                        self.results["hosts"][scanned_host] = {"status": "up", "ports": {}}

                    # Add OS detection results if available
                    if nm[scanned_host].get('osmatch'):
                        self.results["hosts"][scanned_host]["os"] = nm[scanned_host]['osmatch']

                    for protocol in nm[scanned_host].all_protocols():
                        nmap_ports = nm[scanned_host][protocol].keys()
                        for port in nmap_ports:
                            port_info = nm[scanned_host][protocol][port]
                            service_name = port_info.get('name', 'unknown')
                            service_version = port_info.get('version', '')
                            service_product = port_info.get('product', '')

                            # Build comprehensive service info
                            service_details = service_name
                            if service_product:
                                service_details += f" ({service_product}"
                                if service_version:
                                    service_details += f" {service_version}"
                                service_details += ")"
                            elif service_version:
                                service_details += f" {service_version}"

                            # Update the existing port info from masscan with detailed nmap results
                            if str(port) in self.results["hosts"][scanned_host]["ports"]:
                                self.results["hosts"][scanned_host]["ports"][str(port)]["service"] = service_details
                                self.results["hosts"][scanned_host]["ports"][str(port)]["state"] = port_info['state']
                            else:
                                # This shouldn't happen if masscan worked correctly, but add it anyway
                                self.results["hosts"][scanned_host]["ports"][str(port)] = {
                                    "state": port_info['state'],
                                    "service": service_details
                                }

                            print(f"{Fore.GREEN}[+] Nmap service: {scanned_host}:{port} -> {service_details}{Style.RESET_ALL}")

            except Exception as e:
                print(f"{Fore.RED}[-] Nmap scan failed for {host}: {e}{Style.RESET_ALL}")

    def _basic_service_from_results(self, masscan_results):
        """Fallback basic service enumeration when nmap is unavailable"""
        if not masscan_results:
            return
        if isinstance(masscan_results, list):
            # Resume path may provide only host list; derive ports from existing results
            derived = {}
            for host in masscan_results:
                if host in self.results["hosts"]:
                    derived[host] = self.results["hosts"][host].get("ports", {})
            masscan_results = derived
        print(f"{Fore.YELLOW}[*] Falling back to basic service identification...{Style.RESET_ALL}")
        for host, ports in masscan_results.items():
            if host not in self.results["hosts"]:
                self.results["hosts"][host] = {"status": "up", "ports": {}}
            for port in ports:
                if str(port) not in self.results["hosts"][host]["ports"]:
                    self.results["hosts"][host]["ports"][str(port)] = {"state": "open", "service": ""}
                service_info = self.enumerate_basic_service(host, port)
                self.results["hosts"][host]["ports"][str(port)]["service"] = service_info
                print(f"{Fore.GREEN}[+] Service identified: {host}:{port} -> {service_info}{Style.RESET_ALL}")

    def enumerate_basic_service(self, host, port):
        """Perform basic service enumeration without nmap"""
        service_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
            443: "https", 445: "microsoft-ds", 587: "submission", 993: "imaps", 995: "pop3s",
            1433: "ms-sql-s", 1723: "pptp", 2049: "nfs", 2181: "zookeeper", 2375: "docker",
            3000: "node", 3306: "mysql", 3389: "rdp", 4000: "http-alt", 5000: "http-alt",
            5432: "postgresql", 5601: "kibana", 5900: "vnc", 5901: "vnc-1",
            5984: "couchdb", 6379: "redis", 6443: "kubernetes", 7001: "afs3-callback",
            8000: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8082: "http-alt",
            8161: "patrol-snmp", 8443: "https-alt", 8500: "consul", 8888: "http-alt",
            9000: "http-alt", 9090: "http-alt", 9092: "kafka", 9200: "elasticsearch",
            9300: "elasticsearch-transport", 11211: "memcached", 27017: "mongodb"
        }

        try:
            service = service_map.get(int(port), "unknown")

            if service in ["http", "https", "http-alt", "https-alt"] and HAS_REQUESTS:
                protocol = "https" if service in ["https", "https-alt"] else "http"
                # Only include port in URL if it's not the default for the protocol
                default_port = "443" if protocol == "https" else "80"
                if port == default_port:
                    url = f"{protocol}://{host}"
                else:
                    url = f"{protocol}://{host}:{port}"

                try:
                    response = requests.get(url, timeout=5, verify=False,
                                          headers={'User-Agent': f'PDIve/{VERSION}'})
                    server_header = response.headers.get('Server', 'Unknown')
                    service_info = f"{service} ({server_header})"
                except (requests.RequestException, ConnectionError, TimeoutError):
                    service_info = service
            else:
                service_info = service

            return service_info
        except Exception as e:
            return "unknown"

    def resolve_domain_to_ip(self, hostname):
        """Resolve domain name to IP address"""
        try:
            # Check if the hostname is already an IP address
            ipaddress.ip_address(hostname)
            return hostname  # Already an IP address
        except ValueError:
            # It's a hostname, try to resolve it
            prev_timeout = socket.getdefaulttimeout()
            try:
                socket.setdefaulttimeout(self.dns_timeout)
                ip_address = socket.gethostbyname(hostname)
                return ip_address
            except (socket.gaierror, Exception):
                return "N/A"  # Resolution failed
            finally:
                socket.setdefaulttimeout(prev_timeout)

    def reverse_dns_lookup(self, ip_address):
        """Perform reverse DNS lookup on IP address"""
        try:
            # Validate that it's actually an IP address
            ipaddress.ip_address(ip_address)

            # Perform reverse DNS lookup
            prev_timeout = socket.getdefaulttimeout()
            try:
                socket.setdefaulttimeout(self.dns_timeout)
                hostname, _, _ = socket.gethostbyaddr(ip_address)
                return hostname
            except (socket.herror, socket.gaierror, ValueError, Exception):
                return "N/A"  # Reverse lookup failed or invalid IP
            finally:
                socket.setdefaulttimeout(prev_timeout)
        except ValueError:
            return "N/A"

    def whois_lookup(self, target):
        """Perform WHOIS lookup on domain or IP address"""
        if not HAS_WHOIS:
            return {"error": "WHOIS module not available"}

        try:
            print(f"{Fore.CYAN}[*] Performing WHOIS lookup for {target}...{Style.RESET_ALL}")

            result_holder = {}
            error_holder = {}

            def _run_whois():
                try:
                    w = whois.whois(target)
                    # Extract useful information
                    whois_data = {
                        "domain_name": w.domain_name if hasattr(w, 'domain_name') else "N/A",
                        "registrar": w.registrar if hasattr(w, 'registrar') else "N/A",
                        "creation_date": str(w.creation_date) if hasattr(w, 'creation_date') else "N/A",
                        "expiration_date": str(w.expiration_date) if hasattr(w, 'expiration_date') else "N/A",
                        "updated_date": str(w.updated_date) if hasattr(w, 'updated_date') else "N/A",
                        "name_servers": ', '.join(w.name_servers) if hasattr(w, 'name_servers') and w.name_servers else "N/A",
                        "status": ', '.join(w.status) if hasattr(w, 'status') and w.status else "N/A",
                        "emails": ', '.join(w.emails) if hasattr(w, 'emails') and w.emails else "N/A",
                        "org": w.org if hasattr(w, 'org') else "N/A",
                        "country": w.country if hasattr(w, 'country') else "N/A"
                    }

                    # Handle list values for domain_name
                    if isinstance(whois_data["domain_name"], list):
                        whois_data["domain_name"] = ', '.join(whois_data["domain_name"])

                    result_holder["data"] = whois_data
                except Exception as e:
                    error_holder["error"] = str(e)

            whois_thread = threading.Thread(target=_run_whois, daemon=True)
            whois_thread.start()
            whois_thread.join(self.whois_timeout)

            if whois_thread.is_alive():
                print(f"{Fore.YELLOW}[!] WHOIS lookup timed out for {target} after {self.whois_timeout}s{Style.RESET_ALL}")
                return {"error": f"WHOIS timeout after {self.whois_timeout}s"}

            if "error" in error_holder:
                print(f"{Fore.YELLOW}[!] WHOIS lookup failed for {target}: {error_holder['error']}{Style.RESET_ALL}")
                return {"error": error_holder["error"]}

            print(f"{Fore.GREEN}[+] WHOIS lookup completed for {target}{Style.RESET_ALL}")
            return result_holder.get("data", {"error": "WHOIS returned no data"})

        except Exception as e:
            print(f"{Fore.YELLOW}[!] WHOIS lookup failed for {target}: {e}{Style.RESET_ALL}")
            return {"error": str(e)}

    def generate_report(self):
        """Generate comprehensive scan reports in text and CSV format"""
        print(f"\n{Fore.YELLOW}[+] Generating Reports...{Style.RESET_ALL}")
        stop_event = threading.Event()
        progress_thread = threading.Thread(
            target=self._show_progress_bar,
            args=(stop_event, "Generating reports"),
            daemon=True
        )
        progress_thread.start()

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        end_time = datetime.now().isoformat()

        total_hosts = len(self.results["hosts"])
        total_ports = sum(len(host_data["ports"]) for host_data in self.results["hosts"].values())

        # DNS lookup caches to avoid redundant lookups
        dns_cache = {}  # hostname -> IP
        rdns_cache = {}  # IP -> reverse DNS

        # Perform WHOIS lookups for targets
        whois_results = {}
        if HAS_WHOIS and self.enable_whois:
            print(f"\n{Fore.YELLOW}[+] Performing WHOIS lookups for targets...{Style.RESET_ALL}")
            for target in self.targets:
                # Extract domain from target (skip IP ranges)
                domain = self.extract_domain(target)
                if domain and domain not in whois_results:
                    whois_results[target] = self.whois_lookup(target)
                elif not domain:
                    # For IP addresses or ranges, try to get the first host
                    try:
                        network = ipaddress.ip_network(target, strict=False)
                        if network.num_addresses == 1:
                            whois_results[target] = self.whois_lookup(str(network.network_address))
                    except:
                        pass

        # Extract the directory name to use as prefix
        dir_name = os.path.basename(self.output_dir)

        txt_file = None
        csv_file = None
        json_file = None

        # Generate detailed text report
        if not self.json_only:
            txt_file = os.path.join(self.output_dir, f"{dir_name}_report_{timestamp}.txt")
            with open(txt_file, 'w') as f:
                f.write("PDIVE DETAILED SCAN REPORT\n")
                f.write("=" * 60 + "\n\n")

                # Summary section
                f.write("SCAN SUMMARY\n")
                f.write("-" * 20 + "\n")
                f.write("Targets:\n")
                for target in self.targets:
                    f.write(f"  {target}\n")
                f.write(f"\nScan Start Time: {self.results['scan_info']['start_time']}\n")
                f.write(f"Scan End Time: {end_time}\n")
                f.write(f"Scanner Version: {self.results['scan_info']['scanner']}\n")
                f.write(f"Total Live Hosts: {total_hosts}\n")
                f.write(f"Total Open Ports: {total_ports}\n")
                f.write(f"Unresponsive Hosts: {self.results['unresponsive_hosts']}\n\n")

                # WHOIS Information section
                if whois_results:
                    f.write("WHOIS INFORMATION\n")
                    f.write("-" * 20 + "\n")
                    for target, whois_data in whois_results.items():
                        f.write(f"\nTarget: {target}\n")
                        if "error" not in whois_data:
                            if whois_data.get("domain_name", "N/A") != "N/A":
                                f.write(f"  Domain Name: {whois_data['domain_name']}\n")
                            if whois_data.get("registrar", "N/A") != "N/A":
                                f.write(f"  Registrar: {whois_data['registrar']}\n")
                            if whois_data.get("org", "N/A") != "N/A":
                                f.write(f"  Organization: {whois_data['org']}\n")
                            if whois_data.get("country", "N/A") != "N/A":
                                f.write(f"  Country: {whois_data['country']}\n")
                            if whois_data.get("creation_date", "N/A") != "N/A":
                                f.write(f"  Creation Date: {whois_data['creation_date']}\n")
                            if whois_data.get("expiration_date", "N/A") != "N/A":
                                f.write(f"  Expiration Date: {whois_data['expiration_date']}\n")
                            if whois_data.get("name_servers", "N/A") != "N/A":
                                f.write(f"  Name Servers: {whois_data['name_servers']}\n")
                            if whois_data.get("status", "N/A") != "N/A":
                                f.write(f"  Status: {whois_data['status']}\n")
                        else:
                            f.write(f"  Error: {whois_data['error']}\n")
                    f.write("\n")

                # Detailed results section
                f.write("DETAILED RESULTS\n")
                f.write("-" * 20 + "\n")
                if self.results["hosts"]:
                    for host, data in self.results["hosts"].items():
                        # Resolve domain to IP address (with caching)
                        if host not in dns_cache:
                            dns_cache[host] = self.resolve_domain_to_ip(host)
                        ip_address = dns_cache[host]

                        # Perform reverse DNS lookup on the IP address (with caching)
                        if ip_address != "N/A":
                            if ip_address not in rdns_cache:
                                rdns_cache[ip_address] = self.reverse_dns_lookup(ip_address)
                            reverse_dns = rdns_cache[ip_address]
                        else:
                            reverse_dns = "N/A"

                        f.write(f"\nHost: {host}")
                        if ip_address != host and ip_address != "N/A":
                            f.write(f" ({ip_address})")
                        f.write("\n")

                        # Add reverse DNS information if available and different from host
                        if reverse_dns != "N/A" and reverse_dns != host:
                            f.write(f"Reverse DNS: {reverse_dns}\n")

                        f.write("=" * (len(host) + 6 + (len(ip_address) + 3 if ip_address != host and ip_address != "N/A" else 0)) + "\n")

                        if data["ports"]:
                            f.write("Open Ports:\n")
                            for port, port_data in data["ports"].items():
                                service = port_data.get('service', 'unknown')
                                f.write(f"  {port:>5}/tcp  {service}\n")
                        else:
                            f.write("  No open ports detected\n")
                else:
                    f.write("No live hosts discovered\n")

        # Generate CSV report
        if not self.json_only:
            csv_file = os.path.join(self.output_dir, f"{dir_name}_results_{timestamp}.csv")
            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)

                # CSV Headers
                writer.writerow(['Host', 'IP_Address', 'Reverse_DNS', 'Port', 'Protocol', 'State', 'Service', 'Scan_Time'])

                # CSV Data
                scan_time = self.results['scan_info']['start_time']
                if self.results["hosts"]:
                    for host, data in self.results["hosts"].items():
                        # Resolve domain to IP address (with caching)
                        if host not in dns_cache:
                            dns_cache[host] = self.resolve_domain_to_ip(host)
                        ip_address = dns_cache[host]

                        # Perform reverse DNS lookup on the IP address (with caching)
                        if ip_address != "N/A":
                            if ip_address not in rdns_cache:
                                rdns_cache[ip_address] = self.reverse_dns_lookup(ip_address)
                            reverse_dns = rdns_cache[ip_address]
                        else:
                            reverse_dns = "N/A"

                        if data["ports"]:
                            for port, port_data in data["ports"].items():
                                writer.writerow([
                                    host,
                                    ip_address,
                                    reverse_dns,
                                    port,
                                    'tcp',
                                    port_data.get('state', 'open'),
                                    port_data.get('service', 'unknown'),
                                    scan_time
                                ])
                        else:
                            # Host is up but no ports detected
                            writer.writerow([host, ip_address, reverse_dns, '', '', 'host_up', 'no_open_ports', scan_time])

        # Generate JSON report
        if not self.no_json:
            json_file = os.path.join(self.output_dir, f"{dir_name}_results_{timestamp}.json")
            json_payload = {
                "scan_info": {
                    **self.results["scan_info"],
                    "end_time": end_time
                },
                "summary": {
                    "total_live_hosts": total_hosts,
                    "total_open_ports": total_ports,
                    "unresponsive_hosts": self.results["unresponsive_hosts"]
                },
                "whois": whois_results,
                "hosts": self.results["hosts"]
            }
            with open(json_file, 'w') as f:
                json.dump(json_payload, f, indent=2, default=str)

        stop_event.set()
        progress_thread.join(timeout=1)
        print(f"\r{Fore.GREEN}[+] Reports saved to:{Style.RESET_ALL}")
        if txt_file:
            print(f"  - Detailed Report: {txt_file}")
        if csv_file:
            print(f"  - CSV Data: {csv_file}")
        if json_file:
            print(f"  - JSON Data: {json_file}")

    def generate_passive_report(self):
        """Generate simple report for passive discovery mode"""
        print(f"\n{Fore.YELLOW}[+] Generating Passive Discovery Report...{Style.RESET_ALL}")
        stop_event = threading.Event()
        progress_thread = threading.Thread(
            target=self._show_progress_bar,
            args=(stop_event, "Generating passive reports"),
            daemon=True
        )
        progress_thread.start()

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        end_time = datetime.now().isoformat()

        total_hosts = len(self.results["hosts"])

        # DNS lookup caches to avoid redundant lookups
        dns_cache = {}  # hostname -> IP
        rdns_cache = {}  # IP -> reverse DNS

        # Perform WHOIS lookups for targets
        whois_results = {}
        if HAS_WHOIS and self.enable_whois:
            print(f"\n{Fore.YELLOW}[+] Performing WHOIS lookups for targets...{Style.RESET_ALL}")
            for target in self.targets:
                # Extract domain from target (skip IP ranges)
                domain = self.extract_domain(target)
                if domain and domain not in whois_results:
                    whois_results[target] = self.whois_lookup(target)
                elif not domain:
                    # For IP addresses or ranges, try to get the first host
                    try:
                        network = ipaddress.ip_network(target, strict=False)
                        if network.num_addresses == 1:
                            whois_results[target] = self.whois_lookup(str(network.network_address))
                    except:
                        pass

        # Extract the directory name to use as prefix
        dir_name = os.path.basename(self.output_dir)
        txt_file = None
        csv_file = None
        json_file = None

        # Generate simple text report for passive mode
        if not self.json_only:
            txt_file = os.path.join(self.output_dir, f"{dir_name}_passive_{timestamp}.txt")
            with open(txt_file, 'w') as f:
                f.write("PDIVE PASSIVE DISCOVERY REPORT\n")
                f.write("=" * 60 + "\n\n")

                # Summary section
                f.write("DISCOVERY SUMMARY\n")
                f.write("-" * 20 + "\n")
                f.write("Targets:\n")
                for target in self.targets:
                    f.write(f"  {target}\n")
                f.write(f"\nScan Start Time: {self.results['scan_info']['start_time']}\n")
                f.write(f"Scan End Time: {end_time}\n")
                f.write(f"Scanner Version: {self.results['scan_info']['scanner']}\n")
                f.write(f"Discovery Mode: {self.results['scan_info']['discovery_mode'].upper()}\n")
                f.write(f"Total Discovered Hosts: {total_hosts}\n\n")

                # WHOIS Information section
                if whois_results:
                    f.write("WHOIS INFORMATION\n")
                    f.write("-" * 20 + "\n")
                    for target, whois_data in whois_results.items():
                        f.write(f"\nTarget: {target}\n")
                        if "error" not in whois_data:
                            if whois_data.get("domain_name", "N/A") != "N/A":
                                f.write(f"  Domain Name: {whois_data['domain_name']}\n")
                            if whois_data.get("registrar", "N/A") != "N/A":
                                f.write(f"  Registrar: {whois_data['registrar']}\n")
                            if whois_data.get("org", "N/A") != "N/A":
                                f.write(f"  Organization: {whois_data['org']}\n")
                            if whois_data.get("country", "N/A") != "N/A":
                                f.write(f"  Country: {whois_data['country']}\n")
                            if whois_data.get("creation_date", "N/A") != "N/A":
                                f.write(f"  Creation Date: {whois_data['creation_date']}\n")
                            if whois_data.get("expiration_date", "N/A") != "N/A":
                                f.write(f"  Expiration Date: {whois_data['expiration_date']}\n")
                            if whois_data.get("name_servers", "N/A") != "N/A":
                                f.write(f"  Name Servers: {whois_data['name_servers']}\n")
                            if whois_data.get("status", "N/A") != "N/A":
                                f.write(f"  Status: {whois_data['status']}\n")
                        else:
                            f.write(f"  Error: {whois_data['error']}\n")
                    f.write("\n")

                # Host list section
                f.write("DISCOVERED HOSTS\n")
                f.write("-" * 20 + "\n")
                if self.results["hosts"]:
                    for host in sorted(self.results["hosts"].keys()):
                        # Resolve domain to IP address (with caching)
                        if host not in dns_cache:
                            dns_cache[host] = self.resolve_domain_to_ip(host)
                        ip_address = dns_cache[host]

                        # Perform reverse DNS lookup on the IP address (with caching)
                        if ip_address != "N/A":
                            if ip_address not in rdns_cache:
                                rdns_cache[ip_address] = self.reverse_dns_lookup(ip_address)
                            reverse_dns = rdns_cache[ip_address]
                        else:
                            reverse_dns = "N/A"

                        if ip_address != host and ip_address != "N/A":
                            if reverse_dns != "N/A" and reverse_dns != host and reverse_dns != ip_address:
                                f.write(f"{host} ({ip_address}) [rDNS: {reverse_dns}]\n")
                            else:
                                f.write(f"{host} ({ip_address})\n")
                        else:
                            f.write(f"{host}\n")
                else:
                    f.write("No hosts discovered\n")

        # Generate simple CSV with just hostnames
        if not self.json_only:
            csv_file = os.path.join(self.output_dir, f"{dir_name}_hosts_{timestamp}.csv")
            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)

                # CSV Headers
                writer.writerow(['Host', 'IP_Address', 'Reverse_DNS', 'Discovery_Method', 'Scan_Time'])

                # CSV Data
                scan_time = self.results['scan_info']['start_time']
                if self.results["hosts"]:
                    for host, data in self.results["hosts"].items():
                        # Resolve domain to IP address (with caching)
                        if host not in dns_cache:
                            dns_cache[host] = self.resolve_domain_to_ip(host)
                        ip_address = dns_cache[host]

                        # Perform reverse DNS lookup on the IP address (with caching)
                        if ip_address != "N/A":
                            if ip_address not in rdns_cache:
                                rdns_cache[ip_address] = self.reverse_dns_lookup(ip_address)
                            reverse_dns = rdns_cache[ip_address]
                        else:
                            reverse_dns = "N/A"

                        discovery_method = data.get('discovery_method', 'passive')
                        writer.writerow([host, ip_address, reverse_dns, discovery_method, scan_time])

        # Generate JSON report
        if not self.no_json:
            json_file = os.path.join(self.output_dir, f"{dir_name}_hosts_{timestamp}.json")
            json_payload = {
                "scan_info": {
                    **self.results["scan_info"],
                    "end_time": end_time
                },
                "summary": {
                    "total_discovered_hosts": total_hosts
                },
                "whois": whois_results,
                "hosts": self.results["hosts"]
            }
            with open(json_file, 'w') as f:
                json.dump(json_payload, f, indent=2, default=str)

        stop_event.set()
        progress_thread.join(timeout=1)
        print(f"\r{Fore.GREEN}[+] Passive discovery reports saved to:{Style.RESET_ALL}")
        if txt_file:
            print(f"  - Host List Report: {txt_file}")
        if csv_file:
            print(f"  - CSV Host List: {csv_file}")
        if json_file:
            print(f"  - JSON Host List: {json_file}")

    def run_scan(self, enable_nmap=False, masscan_only=False):
        """Execute complete reconnaissance scan"""
        if not self.validate_targets():
            print(f"{Fore.RED}[-] No valid targets found{Style.RESET_ALL}")
            return

        self.print_banner()
        self.scan_state["enable_nmap"] = enable_nmap
        self.scan_state["masscan_only"] = masscan_only
        self._start_checkpointing()

        # Inform user about ping setting
        if not self.enable_ping and self.discovery_mode == "active":
            print(f"{Fore.YELLOW}[!] Ping is disabled by default. Use --ping to enable ICMP ping discovery.{Style.RESET_ALL}")

        if self.discovery_mode == "passive":
            # Passive discovery mode - use passive techniques only
            if "passive_discovery" in self.scan_state["completed_phases"]:
                discovered_hosts = self.scan_state.get("amass_hosts", [])
            else:
                discovered_hosts = self.passive_discovery()
                self.scan_state["amass_hosts"] = discovered_hosts
                self._mark_phase_complete("passive_discovery")
            if not discovered_hosts:
                print(f"{Fore.RED}[-] No hosts discovered through passive methods.{Style.RESET_ALL}")
                self._stop_checkpointing()
                return

            # In passive mode, only return the list of discovered hosts
            print(f"\n{Fore.YELLOW}[+] PASSIVE DISCOVERY RESULTS{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'='*50}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Total hosts discovered: {len(discovered_hosts)}{Style.RESET_ALL}\n")

            print(f"{Fore.GREEN}Discovered hosts:{Style.RESET_ALL}")
            for host in sorted(discovered_hosts):
                print(f"{host}")

            # Generate simple report for passive mode
            if "passive_report" not in self.scan_state["completed_phases"]:
                self.generate_passive_report()
                self._mark_phase_complete("passive_report")

        else:
            # Active discovery mode - amass -> host discovery -> masscan -> nmap
            print(f"\n{Fore.YELLOW}[+] Starting Active Discovery Mode{Style.RESET_ALL}")

            # Only run amass if neither --nmap nor --masscan flags are set
            # When these flags are set, we want ONLY port scanning (masscan/nmap)
            amass_hosts = self.scan_state.get("amass_hosts", [])
            if not enable_nmap and not masscan_only:
                print(f"{Fore.CYAN}[*] Phase 1: Passive subdomain discovery with amass{Style.RESET_ALL}")
                # First, run amass to discover subdomains
                if "amass" not in self.scan_state["completed_phases"]:
                    amass_hosts = self.passive_discovery()
                    self.scan_state["amass_hosts"] = amass_hosts
                    self._mark_phase_complete("amass")
            else:
                print(f"{Fore.CYAN}[*] Phase 1: Skipping amass (running in port-scan-only mode){Style.RESET_ALL}")
                amass_hosts = []

            # Then do traditional host discovery
            print(f"\n{Fore.CYAN}[*] Phase 2: Host discovery and connectivity check{Style.RESET_ALL}")
            live_hosts = self.scan_state.get("live_hosts", [])
            if "host_discovery" not in self.scan_state["completed_phases"]:
                live_hosts = self.host_discovery()
                self.scan_state["live_hosts"] = live_hosts
                self._mark_phase_complete("host_discovery")

            # Combine amass results with live host discovery
            all_discovered_hosts = set(amass_hosts + live_hosts)

            if not all_discovered_hosts:
                print(f"{Fore.RED}[-] No live hosts discovered.{Style.RESET_ALL}")
                self._stop_checkpointing()
                return

            # Ensure all discovered hosts are initialized in results before proceeding
            for host in all_discovered_hosts:
                if host not in self.results["hosts"]:
                    self.results["hosts"][host] = {"status": "up", "ports": {}}

            print(f"\n{Fore.CYAN}[*] Phase 3: Fast port scanning with masscan{Style.RESET_ALL}")
            # Use masscan for fast port discovery
            if "masscan" not in self.scan_state["completed_phases"]:
                masscan_results = self.masscan_scan(list(all_discovered_hosts))
                self._mark_phase_complete("masscan")
            else:
                masscan_results = list(all_discovered_hosts)

            # Always perform service enumeration on discovered ports
            if enable_nmap and masscan_results:
                # Use nmap for detailed service enumeration
                print(f"\n{Fore.CYAN}[*] Phase 4: Detailed service enumeration with nmap{Style.RESET_ALL}")
                if "nmap" not in self.scan_state["completed_phases"]:
                    self.nmap_scan(masscan_results)
                    self._mark_phase_complete("nmap")
            else:
                # Use basic service enumeration on all hosts with open ports
                print(f"\n{Fore.CYAN}[*] Phase 4: Basic service identification{Style.RESET_ALL}")
                if "basic_service" not in self.scan_state["completed_phases"]:
                    for host in all_discovered_hosts:
                        if host in self.results["hosts"] and self.results["hosts"][host]["ports"]:
                            for port in self.results["hosts"][host]["ports"]:
                                service_info = self.enumerate_basic_service(host, port)
                                self.results["hosts"][host]["ports"][port]["service"] = service_info
                                print(f"{Fore.GREEN}[+] Service identified: {host}:{port} -> {service_info}{Style.RESET_ALL}")
                    self._mark_phase_complete("basic_service")

            # Generate full report for active mode
            if "report" not in self.scan_state["completed_phases"]:
                self.generate_report()
                self._mark_phase_complete("report")

        self._stop_checkpointing()
        print(f"\n{Fore.GREEN}[+] Reconnaissance scan completed!{Style.RESET_ALL}")


def load_targets_from_file(file_path):
    """Load targets from a text file, one per line"""
    targets = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                target = line.strip()
                if target and not target.startswith('#'):
                    targets.append(target)
        return targets
    except FileNotFoundError:
        print(f"{Fore.RED}[-] Target file not found: {file_path}{Style.RESET_ALL}")
        return []
    except Exception as e:
        print(f"{Fore.RED}[-] Error reading target file: {e}{Style.RESET_ALL}")
        return []


def main():
    parser = argparse.ArgumentParser(
        description="PDIve - Automated Penetration Testing Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pdive.py -t 192.168.1.0/24
  python pdive.py -t 10.0.0.1 --nmap
  python pdive.py -t 192.168.1.0/24 --masscan (fast scan with basic service enumeration)
  python pdive.py -t 192.168.1.0/24 --ping
  python pdive.py -f targets.txt -o /tmp/scan_results -T 100 (use 100 threads)
  python pdive.py -t "192.168.1.1,example.com,10.0.0.0/24"
  python pdive.py -t example.com -m passive
  python pdive.py -t example.com -m passive --amass-timeout 300 (5 minute amass timeout)
  python pdive.py -t testphp.vulnweb.com -m active --nmap --ping -T 50 (throttle with 50 threads)
  python pdive.py -t example.com -m active --amass-timeout 60 (amass timeout with partial results saved)
  python pdive.py -t example.com --no-whois (skip WHOIS in reports)
  python pdive.py -t example.com --dns-timeout 3 --whois-timeout 10 (tune report lookup timeouts)
  python pdive.py --resume ./scan_results/scan_checkpoint.json (resume from checkpoint)
        """
    )

    target_group = parser.add_mutually_exclusive_group(required=False)
    target_group.add_argument('-t', '--target',
                             help='Target IP address, hostname, CIDR range, or comma-separated list')
    target_group.add_argument('-f', '--file',
                             help='File containing targets (one per line)')

    parser.add_argument('-o', '--output', default='pdive_output',
                       help='Output directory (default: pdive_output)')
    parser.add_argument('-T', '--threads', type=int, default=50,
                       help='Number of threads for scan throttling (default: 50)')
    parser.add_argument('-m', '--mode', choices=['active', 'passive'], default='active',
                       help='Discovery mode: active (default) or passive')
    parser.add_argument('--nmap', action='store_true',
                       help='Enable detailed Nmap scanning after masscan (Active mode only)')
    parser.add_argument('--masscan', action='store_true',
                       help='Skip passive discovery and use masscan for fast port scanning with basic service enumeration (Active mode only)')
    parser.add_argument('--ping', action='store_true',
                       help='Enable ICMP ping for host discovery (disabled by default for stealth)')
    parser.add_argument('--amass-timeout', type=int, metavar='SECONDS', default=180,
                       help='Timeout in seconds for amass scans (saves partial results on timeout, default: 180)')
    parser.add_argument('--json-only', action='store_true',
                       help='Write only JSON reports (skip TXT/CSV)')
    parser.add_argument('--no-json', action='store_true',
                       help='Disable JSON report output')
    parser.add_argument('--dns-timeout', type=int, metavar='SECONDS', default=5,
                       help='DNS lookup timeout in seconds (default: 5)')
    parser.add_argument('--whois-timeout', type=int, metavar='SECONDS', default=15,
                       help='WHOIS lookup timeout in seconds (default: 15)')
    parser.add_argument('--no-whois', action='store_true',
                       help='Disable WHOIS lookups in reports')
    parser.add_argument('--checkpoint-interval', type=int, metavar='SECONDS', default=30,
                       help='Checkpoint interval in seconds (default: 30; 0 to disable)')
    parser.add_argument('--resume', metavar='CHECKPOINT_JSON',
                       help='Resume a prior scan from a checkpoint JSON file')
    parser.add_argument('--version', action='version', version=f'PDIve {VERSION}')

    args = parser.parse_args()

    # Validate argument values
    if args.threads < 1 or args.threads > 1000:
        print(f"{Fore.RED}[-] Error: Thread count must be between 1 and 1000{Style.RESET_ALL}")
        sys.exit(1)

    if args.amass_timeout is not None and (args.amass_timeout < 1 or args.amass_timeout > 3600):
        print(f"{Fore.RED}[-] Error: Amass timeout must be between 1 and 3600 seconds{Style.RESET_ALL}")
        sys.exit(1)

    # Validate mode and scan option combinations
    if args.mode == 'passive' and args.nmap:
        print(f"{Fore.RED}[-] Error: --nmap flag is not compatible with passive mode{Style.RESET_ALL}")
        sys.exit(1)

    if args.mode == 'passive' and args.masscan:
        print(f"{Fore.RED}[-] Error: --masscan flag is not compatible with passive mode{Style.RESET_ALL}")
        sys.exit(1)

    if args.nmap and args.masscan:
        print(f"{Fore.RED}[-] Error: --nmap and --masscan flags cannot be used together{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Use --masscan for fast scanning with basic service enumeration, or --nmap for masscan followed by detailed nmap service enumeration{Style.RESET_ALL}")
        sys.exit(1)

    if args.json_only and args.no_json:
        print(f"{Fore.RED}[-] Error: --json-only and --no-json cannot be used together{Style.RESET_ALL}")
        sys.exit(1)
    if args.dns_timeout < 1 or args.dns_timeout > 60:
        print(f"{Fore.RED}[-] Error: DNS timeout must be between 1 and 60 seconds{Style.RESET_ALL}")
        sys.exit(1)
    if args.whois_timeout < 1 or args.whois_timeout > 300:
        print(f"{Fore.RED}[-] Error: WHOIS timeout must be between 1 and 300 seconds{Style.RESET_ALL}")
        sys.exit(1)

    resume_data = None
    if args.resume:
        try:
            with open(args.resume, 'r') as f:
                resume_data = json.load(f)
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to load resume file: {e}{Style.RESET_ALL}")
            sys.exit(1)

    if not args.resume:
        if args.file:
            targets = load_targets_from_file(args.file)
            if not targets:
                print(f"{Fore.RED}[-] No valid targets found in file{Style.RESET_ALL}")
                sys.exit(1)
        else:
            if not args.target:
                print(f"{Fore.RED}[-] Error: target is required unless --resume is provided{Style.RESET_ALL}")
                sys.exit(1)
            if ',' in args.target:
                targets = [t.strip() for t in args.target.split(',') if t.strip()]
            else:
                targets = [args.target]
    else:
        targets = resume_data.get("config", {}).get("targets", [])
        if not targets:
            print(f"{Fore.RED}[-] Resume file missing targets{Style.RESET_ALL}")
            sys.exit(1)

    print(f"{Fore.RED}WARNING: This tool is for authorized security testing only!{Style.RESET_ALL}")
    print(f"{Fore.RED}Ensure you have proper permission before scanning any network.{Style.RESET_ALL}\n")

    targets_display = ', '.join(targets[:3])
    if len(targets) > 3:
        targets_display += f" ... (+{len(targets) - 3} more)"

    print(f"Targets to scan: {targets_display}")
    response = input("Do you have authorization to scan these targets? (y/N): ")
    if response.lower() != 'y':
        print("Scan aborted.")
        sys.exit(1)

    if resume_data:
        cfg = resume_data.get("config", {})
        pdive = PDIve(
            targets,
            cfg.get("output_dir", args.output),
            cfg.get("threads", args.threads),
            cfg.get("discovery_mode", args.mode),
            enable_ping=cfg.get("enable_ping", args.ping),
            amass_timeout=cfg.get("amass_timeout", args.amass_timeout),
            json_only=cfg.get("json_only", args.json_only),
            no_json=cfg.get("no_json", args.no_json),
            dns_timeout=cfg.get("dns_timeout", args.dns_timeout),
            whois_timeout=cfg.get("whois_timeout", args.whois_timeout),
            enable_whois=cfg.get("enable_whois", (not args.no_whois)),
            checkpoint_interval=args.checkpoint_interval,
            checkpoint_path=args.resume
        )
        pdive.results = resume_data.get("results", pdive.results)
        pdive.scan_state = resume_data.get("scan_state", pdive.scan_state)
        print(f"{Fore.GREEN}[+] Resuming from checkpoint: {args.resume}{Style.RESET_ALL}")
    else:
        pdive = PDIve(
            targets,
            args.output,
            args.threads,
            args.mode,
            enable_ping=args.ping,
            amass_timeout=args.amass_timeout,
            json_only=args.json_only,
            no_json=args.no_json,
            dns_timeout=args.dns_timeout,
            whois_timeout=args.whois_timeout,
            enable_whois=(not args.no_whois),
            checkpoint_interval=args.checkpoint_interval
        )
    if resume_data:
        resume_enable_nmap = resume_data.get("scan_state", {}).get("enable_nmap", args.nmap)
        resume_masscan_only = resume_data.get("scan_state", {}).get("masscan_only", args.masscan)
        pdive.run_scan(enable_nmap=resume_enable_nmap, masscan_only=resume_masscan_only)
    else:
        pdive.run_scan(enable_nmap=args.nmap, masscan_only=args.masscan)


if __name__ == "__main__":
    main()
