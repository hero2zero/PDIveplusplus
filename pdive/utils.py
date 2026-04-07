import os
import sys
import socket
import ipaddress
import logging
import time
import threading
from datetime import datetime
from dataclasses import dataclass
from typing import List, Optional, Union, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("pdive")

# Version constant
VERSION = "1.7.5"

# Dependency flags
try:
    from colorama import init, Fore, Style
    HAS_COLORAMA = True
    init(autoreset=True)
except ImportError:
    HAS_COLORAMA = False
    class MockColor:
        CYAN = YELLOW = GREEN = RED = ""
        RESET_ALL = ""
    Fore = Style = MockColor()

BANNER = fr"""{Fore.CYAN}
  ____  ____  ___              
 |  _ \|  _ \|_ _|             
 | |_) | | | || |_   _____     
 |  __/| |_| || \ \ / / _ \    
 |_|   |____/|___|\_/ \___| ++ 
{Style.RESET_ALL}"""

@dataclass
class ScannerConfig:
    targets: List[str]
    output_dir: str = "pdive_output"
    threads: int = 50
    discovery_mode: str = "active"
    enable_ping: bool = False
    all_ports: bool = False
    amass_timeout: int = 180
    masscan_timeout: int = 300
    enable_amass: bool = True
    enable_dnsdumpster: bool = True
    enable_crtsh: bool = True
    enable_scan: bool = True
    json_only: bool = False
    no_json: bool = False
    dns_timeout: int = 5
    whois_timeout: int = 15
    enable_whois: bool = True
    checkpoint_interval: int = 30
    checkpoint_path: Optional[str] = None
    ca_bundle: Optional[str] = None
    insecure: bool = False
    verify_ssl: Union[bool, str] = True

    def __post_init__(self):
        if not self.checkpoint_path:
            self.checkpoint_path = os.path.join(self.output_dir, "scan_checkpoint.json")
        
        if self.insecure:
            self.verify_ssl = False
        elif self.ca_bundle:
            self.verify_ssl = self.ca_bundle
        else:
            self.verify_ssl = True

# Top 1000 ports
TOP_1000_PORTS = "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3050,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5358,5402,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5811,5814,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5931,5937,5946,5950,5952,5959-5963,5987-5990,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6200,6205,6209,6222,6227,6267,6322,6346,6389,6421,6432,6442,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7272,7402,7435,7443,7496,7512,7625,7627,7659,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9300,9333,9343,9352,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11000-11001,11110-11111,11967,12000,12174,12265,12345,13444,13722,13724,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768,32770-32780,32782-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49400,49999,50000-50003,50006,50030,50440,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55440,55555,56565,57474,57475,57777,58000,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

def detect_virtualenv() -> bool:
    return hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)

def detect_local_venv() -> Optional[str]:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(script_dir) == 'pdive': script_dir = os.path.dirname(script_dir)
    for venv_name in ['venv', '.venv', 'env', '.env']:
        venv_path = os.path.join(script_dir, venv_name)
        if os.path.isdir(venv_path):
            path = os.path.join(venv_path, 'Scripts', 'python.exe') if sys.platform.startswith('win') else os.path.join(venv_path, 'bin', 'python')
            if os.path.exists(path): return path
    return None

def check_sudo_venv_mismatch():
    is_root = False
    try:
        if hasattr(os, 'geteuid'): is_root = os.geteuid() == 0
    except: pass
    if is_root and not detect_virtualenv():
        local_venv = detect_local_venv()
        if local_venv:
            logger.warning("VIRTUALENV MISMATCH DETECTED")
            logger.warning(f"Running as root with system Python: {sys.executable}")
            logger.warning(f"A local virtualenv exists at: {local_venv}")

def _show_progress(stop_event, message):
    spinner = ['|', '/', '-', '\\']
    idx = 0
    start_time = time.time()
    while not stop_event.is_set():
        elapsed = int(time.time() - start_time)
        print(f"\r{Fore.CYAN}[*] {message} {spinner[idx % 4]} ({elapsed}s){Style.RESET_ALL}", end='', flush=True)
        idx += 1
        time.sleep(0.2)

def _show_progress_bar(stop_event, message):
    start_time = time.time()
    while not stop_event.is_set():
        elapsed = time.time() - start_time
        progress = min(95, (elapsed / 60.0) * 100)
        filled = int((progress / 100.0) * 30)
        bar = '=' * (filled - 1) + '>' + ' ' * (30 - filled) if filled > 0 else '>' + ' ' * 29
        print(f"\r{Fore.CYAN}[*] {message} [{bar}] {progress:>5.1f}% ({int(elapsed)}s){Style.RESET_ALL}", end='', flush=True)
        time.sleep(0.3)

def load_targets_from_file(file_path):
    targets = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                target = line.strip()
                if target and not target.startswith('#'): targets.append(target)
        return targets
    except:
        return []

def get_local_ip() -> Optional[str]:
    """Get the local IP address used for outbound connections"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return None

def get_default_gateway() -> Optional[str]:
    """Get the default gateway IP address"""
    try:
        if sys.platform.startswith('win'):
            import subprocess
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if "Default Gateway" in line and ":" in line:
                    gw = line.split(":")[-1].strip()
                    if gw and all(c in "0123456789." for c in gw):
                        return gw
        else:
            # Linux/macOS
            with open("/proc/net/route") as fh:
                for line in fh:
                    fields = line.strip().split()
                    if fields[1] == '00000000':
                        import struct
                        return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    except Exception:
        pass
    return None

def resolve_domain_to_ip(hostname, dns_timeout=5):
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except:
        prev = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(dns_timeout)
            return socket.gethostbyname(hostname)
        except:
            return "N/A"
        finally:
            socket.setdefaulttimeout(prev)

def reverse_dns_lookup(ip_address, dns_timeout=5):
    try:
        ipaddress.ip_address(ip_address)
        prev = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(dns_timeout)
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname
        except:
            return "N/A"
        finally:
            socket.setdefaulttimeout(prev)
    except:
        return "N/A"

def validate_targets(targets):
    valid = []
    for target in targets:
        try:
            ipaddress.ip_network(target, strict=False)
            valid.append(target)
        except:
            try:
                socket.gethostbyname(target)
                valid.append(target)
            except:
                pass
    return valid
