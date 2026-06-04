import os
import sys
import socket
import subprocess
import re
import threading
import time
import platform
import psutil
import requests
import pandas as pd
import queue
import warnings
import json
from datetime import datetime
from colorama import init, Fore
from tqdm import tqdm

init(autoreset=True)

try:
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        from scapy.all import ARP, Ether, srp
    scapy_output = buf.getvalue()
    if scapy_output:
        print(scapy_output.strip())
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
sys.excepthook = lambda *args: None

ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def set_title(title):
    if platform.system() == "Windows":
        os.system(f"title {title}")
    else:
        sys.stdout.write(f"\x1b]2;{title}\x07")
        sys.stdout.flush()

def get_possible_mounts():
    mounts = []
    if platform.system() == "Windows":
        from string import ascii_uppercase
        for letter in ascii_uppercase:
            path = f"{letter}:\\"
            if os.path.exists(path):
                mounts.append(path)
    else:
        for base in ("/Volumes", "/media", "/run/media"):
            if os.path.exists(base):
                try:
                    for name in os.listdir(base):
                        path = os.path.join(base, name)
                        if os.path.ismount(path):
                            mounts.append(path)
                except Exception:
                    pass
    if not mounts:
        mounts.append(os.path.dirname(os.path.abspath(sys.argv[0])))
    return mounts

log_file = None

def get_usb_drive():
    if platform.system() != "Windows":
        return None
    try:
        for part in psutil.disk_partitions():
            opts = part.opts.lower()
            if "removable" in opts:
                return part.mountpoint
    except Exception:
        pass
    return None

def get_save_path():
    if platform.system() == "Windows":
        usb = get_usb_drive()
        if usb and os.path.exists(usb):
            return os.path.join(usb, "log")
    else:
        for base in ("/media", "/run/media", "/mnt", "/Volumes"):
            if not os.path.exists(base):
                continue
            try:
                for user_dir in os.listdir(base):
                    user_path = os.path.join(base, user_dir)
                    if not os.path.isdir(user_path):
                        continue
                    for mnt in os.listdir(user_path):
                        full_path = os.path.join(user_path, mnt)
                        if os.path.ismount(full_path):
                            log_dir = os.path.join(full_path, "log")
                            os.makedirs(log_dir, exist_ok=True)
                            test_file = os.path.join(log_dir, "tmp.txt")
                            with open(test_file, "w") as f:
                                f.write("test")
                            os.remove(test_file)
                            return log_dir
            except Exception:
                continue
    script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    return os.path.join(script_dir, "log")

def init_log():
    global log_file
    filename = datetime.now().strftime("%d.%m.%y_%H-%M") + ".txt"
    save_path = get_save_path()
    os.makedirs(save_path, exist_ok=True)
    try:
        log_file = open(os.path.join(save_path, filename), "a", encoding="utf-8")
        return log_file
    except Exception:
        return None

def log_print(text=""):
    print(text)
    if not log_file:
        return
    try:
        clean_text = ansi_escape.sub('', str(text)).strip()
        if not clean_text:
            return
        if clean_text.startswith("Wi-Fi Networks choose number") or clean_text.startswith("Choose number or q:") or clean_text.startswith(">"):
            return
        log_file.write(clean_text + "\n")
        log_file.flush()
    except Exception:
        pass

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "0.0.0.0"
    finally:
        s.close()
    return ip

def get_gateway():
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output("ipconfig", shell=True, text=True, encoding="cp866", errors='ignore')
            for line in out.splitlines():
                if "Default Gateway" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        gw = parts[1].strip()
                        if gw:
                            return gw
        else:
            out = subprocess.check_output("ip route", shell=True, text=True, errors='ignore')
            for line in out.splitlines():
                if line.startswith("default"):
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
    except Exception:
        pass
    return "Unknown"

def get_dns():
    dns = []
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output("ipconfig /all", shell=True, text=True, encoding="cp866", errors='ignore')
            for line in out.splitlines():
                if "DNS Servers" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        d = parts[1].strip()
                        if d and "::" not in d and d not in dns:
                            dns.append(d)
        else:
            try:
                with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.strip().startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2:
                                d = parts[1].strip()
                                if d not in dns:
                                    dns.append(d)
            except Exception:
                try:
                    out = subprocess.check_output("scutil --dns", shell=True, text=True, errors='ignore')
                    for line in out.splitlines():
                        if "nameserver" in line.lower():
                            parts = line.split()
                            for p in parts:
                                if p.count(".") == 3:
                                    if p not in dns:
                                        dns.append(p)
                except Exception:
                    pass
    except Exception:
        pass
    return dns

def get_local_hostname():
    try:
        return socket.gethostname()
    except Exception:
        return "Unknown"

def get_subnet_mask():
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    return addr.netmask or "Unknown"
    except Exception:
        pass
    return "Unknown"

def get_local_mac():
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            has_global_ipv4 = any(
                a.family == socket.AF_INET and not a.address.startswith("127.")
                for a in addrs
            )
            if has_global_ipv4:
                for addr in addrs:
                    if addr.family == psutil.AF_LINK:
                        return addr.address.upper().replace("-", ":")
    except Exception:
        pass
    return "Unknown"

def get_ipv6():
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET6:
                    ip6 = addr.address.split("%")[0]
                    if not ip6.startswith("fe80") and ip6 != "::1":
                        return ip6
    except Exception:
        pass
    return "Unknown"

def get_dhcp_info():
    info = {"enabled": "Unknown", "server": "Unknown", "lease_obtained": "Unknown", "lease_expires": "Unknown"}
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(
                "wmic nicconfig where IPEnabled=True get DHCPEnabled,DHCPServer,DHCPLeaseObtained,DHCPLeaseExpires",
                shell=True, text=True, encoding="utf-8", errors="ignore", stderr=subprocess.DEVNULL
            )
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            if len(lines) >= 2:
                headers = lines[0].split()
                values = lines[1].split()
                d = dict(zip(headers, values))
                info["enabled"] = d.get("DHCPEnabled", "Unknown")
                info["server"] = d.get("DHCPServer", "Unknown")
                for key, field in [("DHCPLeaseObtained", "lease_obtained"), ("DHCPLeaseExpires", "lease_expires")]:
                    raw = d.get(key, "")
                    if raw:
                        try:
                            info[field] = datetime.strptime(raw[:14], "%Y%m%d%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            info[field] = raw
        else:
            out = subprocess.check_output(
                "nmcli -t -f IP4.ADDRESS,DHCP4.OPTION device show",
                shell=True, text=True, errors="ignore"
            )
            for line in out.splitlines():
                if "dhcp_server_identifier" in line:
                    info["server"] = line.split("=", 1)[-1].strip()
                    info["enabled"] = "Yes"
                if "expiry" in line:
                    ts = line.split("=", 1)[-1].strip()
                    try:
                        info["lease_expires"] = datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        info["lease_expires"] = ts
    except Exception:
        pass
    return info

def get_adapter_info():
    adapters = []
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for iface, addr_list in addrs.items():
            ipv4 = next((a.address for a in addr_list if a.family == socket.AF_INET), None)
            if not ipv4 or ipv4.startswith("127."):
                continue
            mac = next((a.address.upper().replace("-", ":") for a in addr_list if a.family == psutil.AF_LINK), "Unknown")
            speed = stats[iface].speed if iface in stats else 0
            adapters.append({"name": iface, "ipv4": ipv4, "mac": mac, "speed_mbps": speed})
    except Exception:
        pass
    return adapters

def wifi_scan():
    nets = []
    system = platform.system()
    try:
        if system == "Windows":
            out = None
            for encoding in ("utf-8", "cp1251", "cp866"):
                try:
                    out = subprocess.check_output(
                        "netsh wlan show networks mode=Bssid",
                        shell=True, text=True, encoding=encoding,
                        errors='ignore', stderr=subprocess.DEVNULL
                    )
                    break
                except Exception:
                    continue
            if out is None:
                return nets
            for line in out.splitlines():
                line = line.strip()
                if "SSID" in line and "BSSID" not in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        ssid = parts[1].strip()
                        if ssid and ssid not in nets:
                            nets.append(ssid)
        elif system == "Darwin":
            try:
                airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                out = subprocess.check_output([airport, "-s"], text=True, stderr=subprocess.DEVNULL)
                for line in out.splitlines():
                    if not line.strip() or line.startswith("SSID"):
                        continue
                    ssid = line.split()[0]
                    if ssid and ssid not in nets:
                        nets.append(ssid)
            except Exception:
                pass
        elif system == "Linux":
            try:
                out = subprocess.check_output(["nmcli", "-t", "-f", "SSID", "dev", "wifi", "list"], text=True, stderr=subprocess.DEVNULL)
                nets = [line.strip() for line in out.splitlines() if line.strip()]
                if not nets:
                    out = subprocess.check_output(["nmcli", "dev", "wifi", "list"], text=True, stderr=subprocess.DEVNULL)
                    for line in out.splitlines():
                        if line.strip() and not line.startswith("*") and not line.startswith("SSID"):
                            parts = line.split()
                            if parts:
                                ssid = parts[0]
                                if ssid and ssid not in nets:
                                    nets.append(ssid)
            except Exception:
                try:
                    out = subprocess.check_output(["iwlist", "scan"], text=True, stderr=subprocess.DEVNULL)
                    for line in out.splitlines():
                        if 'ESSID:"' in line:
                            ssid = re.search(r'ESSID:"(.+?)"', line)
                            if ssid:
                                ssid = ssid.group(1).strip()
                                if ssid and ssid not in nets:
                                    nets.append(ssid)
                except Exception:
                    pass
    except Exception as e:
        print(f"[wifi_scan] Error: {e}")
    return nets

def wifi_password(ssid):
    try:
        sys_name = platform.system()
        if sys_name == "Windows":
            out = subprocess.check_output(
                f'netsh wlan show profile name="{ssid}" key=clear',
                shell=True, text=True, encoding="cp866",
                errors='ignore', stderr=subprocess.DEVNULL
            )
            for line in out.splitlines():
                if "Key Content" in line:
                    return line.split(":", 1)[1].strip()
        elif sys_name == "Darwin":
            cmd = f'security find-generic-password -D "AirPort network password" -a "{ssid}" -gw'
            try:
                out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
                return out.strip()
            except subprocess.CalledProcessError:
                return "Unknown"
        else:
            try:
                out = subprocess.check_output(
                    f'nmcli -s -g 802-11-wireless-security.psk connection show "{ssid}"',
                    shell=True, text=True, stderr=subprocess.DEVNULL
                )
                password = out.strip()
                if password:
                    return password
            except Exception:
                try:
                    base = "/etc/NetworkManager/system-connections"
                    for fname in os.listdir(base):
                        path = os.path.join(base, fname)
                        try:
                            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                                data = f.read()
                                if f'ssid={ssid}' in data:
                                    for line in data.splitlines():
                                        if line.strip().startswith("psk="):
                                            return line.split("=", 1)[1].strip()
                        except Exception:
                            continue
                except Exception:
                    pass
    except Exception:
        pass
    return "Unknown"

def get_mac_from_arp(ip):
    try:
        if platform.system() == "Windows":
            result = subprocess.check_output("arp -a", shell=True, text=True, errors='ignore')
            for line in result.splitlines():
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2 and ("-" in parts[1] or ":" in parts[1]):
                        return parts[1].strip()
        else:
            result = subprocess.check_output(f"arp -n {ip}", shell=True, text=True, errors='ignore')
            for line in result.splitlines():
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2 and ":" in parts[1]:
                        return parts[1].strip()
    except Exception:
        pass
    return "Unknown"

def ping_sweep(subnet_base, timeout=0.3, threads=100):
    ips = [f"{subnet_base}.{i}" for i in range(1, 255)]
    live = []
    lock = threading.Lock()
    q = queue.Queue()
    for ip in ips:
        q.put(ip)
    pbar = tqdm(total=len(ips), desc="Scanning network", leave=True)
    def worker():
        while True:
            try:
                ip = q.get_nowait()
            except queue.Empty:
                return
            try:
                if platform.system() == "Windows":
                    cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
                else:
                    cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
                result = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result == 0:
                    with lock:
                        live.append(ip)
            except Exception:
                pass
            finally:
                pbar.update(1)
    workers = []
    for _ in range(min(threads, len(ips))):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        workers.append(t)
    for t in workers:
        t.join()
    pbar.close()
    return live

def scan(subnet):
    results = []
    if SCAPY_AVAILABLE:
        try:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            responses = srp(packet, timeout=1, verbose=0)[0]
            for _, recv in responses:
                results.append({'ip': recv.psrc, 'mac': recv.hwsrc})
            return results
        except Exception:
            pass
    try:
        base = ".".join(subnet.split('.')[:3])
        live_ips = ping_sweep(base)
        for ip in live_ips:
            mac = get_mac_from_arp(ip)
            results.append({'ip': ip, 'mac': mac})
    except Exception:
        pass
    return results

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"

def connections_text():
    output = []
    output.append(Fore.WHITE + "[Connections]\n")
    try:
        connections = psutil.net_connections(kind='inet')
    except Exception:
        connections = []
    if not connections:
        return "\n".join(output)
    output.append(Fore.WHITE + "{:<25} {:<25} {:<10} {:<10}".format("Local", "Remote", "Status", "PID"))
    output.append("-" * 80)
    for conn in connections:
        try:
            local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            output.append(Fore.WHITE + f"{local:<25} {remote:<25} {conn.status:<10} {str(conn.pid):<10}")
        except Exception:
            pass
    return "\n".join(output)

def get_external_ip():
    try:
        return requests.get('https://api.ipify.org?format=json', timeout=2).json().get('ip')
    except Exception:
        return "Unknown"

def get_geo_city(ip):
    try:
        resp = requests.get(f'http://ip-api.com/json/{ip}?fields=city', timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            return data.get('city', 'Unknown')
    except Exception:
        pass
    return "Unknown"

def get_traffic_graph(sample_sec: float = 1.0) -> str:
    BAR_WIDTH = 28
    try:
        snap1 = psutil.net_io_counters(pernic=True)
        time.sleep(sample_sec)
        snap2 = psutil.net_io_counters(pernic=True)

        lines = [Fore.WHITE + "[Traffic  (KB/s)]\n",
                 Fore.WHITE + f"{'Interface':<18} {'▲ Sent':>10} {'▼ Recv':>10}  Graph",
                 Fore.WHITE + "─" * 65]

        any_active = False
        for iface in snap1:
            if iface not in snap2:
                continue
            sent = max((snap2[iface].bytes_sent - snap1[iface].bytes_sent) / 1024 / sample_sec, 0)
            recv = max((snap2[iface].bytes_recv - snap1[iface].bytes_recv) / 1024 / sample_sec, 0)
            if sent == 0 and recv == 0:
                continue
            any_active = True
            peak = max(sent, recv, 0.001)
            sb = int(sent / peak * BAR_WIDTH)
            rb = int(recv / peak * BAR_WIDTH)
            bar = Fore.GREEN + "▲" * sb + Fore.CYAN + "▼" * rb + Fore.WHITE
            lines.append(
                Fore.WHITE + f"{iface:<18} {sent:>8.1f}KB {recv:>8.1f}KB  {bar}"
            )

        if not any_active:
            lines.append(Fore.WHITE + "  No active traffic detected")
        lines.append("")
        return "\n".join(lines)

    except Exception as e:
        return Fore.WHITE + f"[Traffic] Error: {e}\n"

def scan_ports(ip: str, timeout: float = 0.5) -> list[int]:
    open_ports: list[int] = []
    lock = threading.Lock()

    def probe(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                with lock:
                    open_ports.append(port)
            s.close()
        except Exception:
            pass

    threads = [threading.Thread(target=probe, args=(p,), daemon=True)
               for p in COMMON_PORTS]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout + 0.2)

    return sorted(open_ports)

def ports_label(open_ports: list[int]) -> str:
    if not open_ports:
        return "none"
    return "  ".join(f"{p}({COMMON_PORTS.get(p, '?')})" for p in open_ports)

def get_os_by_ttl(ip: str) -> str:
    try:
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", "800", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]

        raw = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True,
                                      errors="ignore")
        m = re.search(r'ttl[= ](\d+)', raw, re.IGNORECASE)
        if m:
            ttl = int(m.group(1))
            if ttl <= 64:
                return "Linux/macOS"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Net Device"
    except Exception:
        pass
    return "Unknown"

_vendor_cache: dict[str, str] = {}

def get_vendor(mac: str) -> str:
    oui = mac.replace(":", "").replace("-", "")[:6].upper()
    if oui in _vendor_cache:
        return _vendor_cache[oui]
    try:
        resp = requests.get(f"https://api.macvendors.com/{oui}", timeout=3)
        if resp.status_code == 200:
            vendor = resp.text.strip()[:24]
        elif resp.status_code == 404:
            vendor = "Unknown"
        else:
            vendor = "Unknown"
    except Exception:
        vendor = "Unknown"
    _vendor_cache[oui] = vendor
    return vendor

def run_traceroute(target_ip: str) -> str:
    lines = [Fore.WHITE + f"[Traceroute → {target_ip}]\n"]
    try:
        if platform.system() == "Windows":
            cmd = ["tracert", "-d", "-h", "15", "-w", "500", target_ip]
        else:
            cmd = ["traceroute", "-n", "-m", "15", "-w", "1", target_ip]

        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, errors="ignore"
        )

        hop_re = re.compile(r'^\s*(\d+)')
        for raw_line in proc.stdout:
            stripped = raw_line.strip()
            if not stripped:
                continue
            if hop_re.match(stripped):
                lines.append(Fore.WHITE + f"  {stripped}")
        proc.wait(timeout=60)

    except FileNotFoundError:
        try:
            out = subprocess.check_output(
                ["tracepath", "-n", "-m", "15", target_ip],
                stderr=subprocess.DEVNULL, text=True, errors="ignore", timeout=30
            )
            for raw_line in out.splitlines():
                if re.match(r'^\s*\d+', raw_line):
                    lines.append(Fore.WHITE + f"  {raw_line.strip()}")
        except Exception:
            lines.append(Fore.WHITE + "  traceroute / tracepath not available on this system")
    except Exception as e:
        lines.append(Fore.WHITE + f"  Error: {e}")

    lines.append("")
    return "\n".join(lines)

def snmp_get(ip, oid, community='public'):
    try:
        cmd = ['snmpget', '-v2c', '-c', community, '-Oqv', ip, oid]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None

def snmp_walk(ip, oid, community='public'):
    try:
        cmd = ['snmpwalk', '-v2c', '-c', community, '-Oqv', ip, oid]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception:
        pass
    return []

def get_snmp_info(ip):
    info = {}
    sys_name = snmp_get(ip, '1.3.6.1.2.1.1.5.0')
    if sys_name:
        info['sysName'] = sys_name
    sys_descr = snmp_get(ip, '1.3.6.1.2.1.1.1.0')
    if sys_descr:
        info['sysDescr'] = sys_descr[:100]
    uptime = snmp_get(ip, '1.3.6.1.2.1.1.3.0')
    if uptime:
        info['uptime'] = uptime
    arp_entries = snmp_walk(ip, '1.3.6.1.2.1.4.22.1.2')
    if arp_entries:
        info['arp_count'] = len(arp_entries)
    ifaces = snmp_walk(ip, '1.3.6.1.2.1.2.2.1.2')
    if ifaces:
        info['interfaces'] = ifaces[:5]
    return info

def check_smb_shares(ip):
    try:
        if platform.system() == "Windows":
            cmd = ['net', 'view', f'\\\\{ip}']
        else:
            cmd = ['smbclient', '-L', f'//{ip}', '-N', '-g']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and ('Sharename' in result.stdout or 'Disk' in result.stdout):
            return True
    except Exception:
        pass
    return False

def get_ipv6_neighbors():
    neighbors = []
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output("netsh int ipv6 show neighbors", shell=True, text=True, encoding='cp866', errors='ignore')
            for line in out.splitlines():
                if "fe80" in line.lower() or ":" in line:
                    parts = line.split()
                    for p in parts:
                        if ':' in p and p.count(':') >= 2:
                            ip6 = p.split('%')[0]
                            if ip6 not in neighbors:
                                neighbors.append(ip6)
        else:
            out = subprocess.check_output(["ip", "-6", "neigh", "show"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                if 'lladdr' in line or 'FAILED' not in line:
                    parts = line.split()
                    if parts and ':' in parts[0]:
                        neighbors.append(parts[0])
    except Exception:
        pass
    return neighbors

def banner():
    return Fore.RED + r'''
██╗      ██████╗  █████╗ ██████╗ ██████╗        ██╗    ███╗
██║     ██╔═══██╗██╔══██╗██╔══██╗██╔══██╗       ██║    ██║██╗
██║     ██║   ██║███████║██████╔╝██║  ██║       ██║ █╗ ██║ ██╗
██║     ██║   ██║██╔══██║██╔══██╗██║  ██║       ██║███╗██║  ██╗
███████╗╚██████╔╝██║  ██║██║  ██║██████╔╝       ╚███╔███╔╝  ╚═╝
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝        ╚══╝╚═══╝   
''' + Fore.RED + '--- Wi-Fi tool by Toploardgg ---\n'

def device_records(raw_devices):
    records = []
    for i, device in enumerate(raw_devices):
        ip  = device.get('ip',  'Unknown')
        mac = device.get('mac', 'Unknown').upper()

        hostname = get_hostname(ip)
        os_guess = get_os_by_ttl(ip)

        if i > 0:
            time.sleep(1.1)
        vendor = get_vendor(mac)

        open_ports = scan_ports(ip)
        ports_str  = ports_label(open_ports)

        snmp_info = get_snmp_info(ip)
        smb_vuln = check_smb_shares(ip) if 445 in open_ports else False

        records.append({
            'ip':       ip,
            'mac':      mac,
            'vendor':   vendor,
            'os':       os_guess,
            'hostname': hostname,
            'ports':    ports_str,
            'snmp':     snmp_info if snmp_info else None,
            'smb_anon': smb_vuln,
        })
    return records

def display(local_ip, devices, dns_servers, external_ip, geo_city, show_traffic=True):
    clear()
    log_print(banner())
    log_print(Fore.WHITE + f"Local IP:       {local_ip}")
    log_print(Fore.WHITE + f"Gateway:        {get_gateway()}")
    try:
        subnet = '.'.join(local_ip.split('.')[:3]) + ".1/24"
    except Exception:
        subnet = "Unknown"
    log_print(Fore.WHITE + f"Subnet:         {subnet}\n")
    log_print(Fore.WHITE + f"External IP:    {external_ip} ({geo_city})\n")

    if external_ip and external_ip != "Unknown":
        log_print(run_traceroute(external_ip))

    log_print(connections_text())
    log_print(Fore.WHITE + f"\nHostname:       {get_local_hostname()}")
    log_print(Fore.WHITE + f"Subnet Mask:    {get_subnet_mask()}")
    log_print(Fore.WHITE + f"MAC (local):    {get_local_mac()}")
    log_print(Fore.WHITE + f"IPv6:           {get_ipv6()}")
    log_print(Fore.WHITE + "\nDNS:")
    if dns_servers:
        for dns in dns_servers:
            log_print(Fore.WHITE + f"  - {dns}")
    else:
        log_print(Fore.WHITE + "  None")
    dhcp = get_dhcp_info()
    log_print(Fore.WHITE + f"\nDHCP Enabled:   {dhcp['enabled']}")
    log_print(Fore.WHITE + f"DHCP Server:    {dhcp['server']}")
    log_print(Fore.WHITE + f"Lease Obtained: {dhcp['lease_obtained']}")
    log_print(Fore.WHITE + f"Lease Expires:  {dhcp['lease_expires']}\n")

    if show_traffic:
        log_print(get_traffic_graph())

    adapters = get_adapter_info()
    if adapters:
        log_print(Fore.WHITE + "[Adapters]\n")
        log_print(Fore.WHITE + "{:<20} {:<16} {:<20} {:<10}".format(
            "Adapter", "IP", "MAC", "Speed(Mbps)"))
        log_print(Fore.WHITE + "─" * 70)
        for a in adapters:
            log_print(Fore.WHITE + f"{a['name']:<20} {a['ipv4']:<16} {a['mac']:<20} {a['speed_mbps']:<10}")
        log_print("")

    log_print(Fore.WHITE + "\n[Devices]\n")
    log_print(Fore.WHITE + "{:<16} {:<18} {:<20} {:<14} {:<22}".format(
        "IP", "MAC", "Vendor", "OS", "Hostname"))
    log_print(Fore.WHITE + "─" * 90)
    for device in devices:
        log_print(Fore.WHITE + "{:<16} {:<18} {:<20} {:<14} {:<22}".format(
            device['ip'], device['mac'], device['vendor'],
            device['os'], device['hostname']))
        log_print(Fore.WHITE + f"  {'Ports:':<12} {device['ports']}")
        if device.get('snmp'):
            snmp_str = f"SNMP: {device['snmp'].get('sysName','')} {device['snmp'].get('sysDescr','')[:40]}"
            log_print(Fore.WHITE + f"  {snmp_str}")
        if device.get('smb_anon'):
            log_print(Fore.RED + f"  [!] Anonymous SMB shares available")
        log_print("")

    if devices:
        df = pd.DataFrame(devices)
        log_print(Fore.WHITE + "\n[DataFrame]\n")
        log_print(Fore.WHITE + df.to_string(index=False))

    ipv6_neighbors = get_ipv6_neighbors()
    if ipv6_neighbors:
        log_print(Fore.WHITE + "\n[IPv6 Neighbors]\n")
        for ip6 in ipv6_neighbors[:10]:
            log_print(Fore.WHITE + f"  {ip6}")
    
def export_json(devices, local_ip, external_ip, geo_city, dns_servers):
    data = {
        "scan_time": datetime.now().isoformat(),
        "local_ip": local_ip,
        "external_ip": external_ip,
        "geo_city": geo_city,
        "dns_servers": dns_servers,
        "gateway": get_gateway(),
        "devices": devices
    }
    save_path = get_save_path()
    os.makedirs(save_path, exist_ok=True)
    filename = f"network_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = os.path.join(save_path, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)
    log_print(Fore.GREEN + f"\nJSON exported to {filepath}")

def export_html(devices, local_ip, external_ip, geo_city, dns_servers):
    html_template = """<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Network Scan Report</title>
<style>
body {{ font-family: Arial; margin:20px; }}
table {{ border-collapse: collapse; width:100%; }}
th, td {{ border:1px solid #ddd; padding:8px; text-align:left; }}
th {{ background-color:#4CAF50; color:white; }}
tr:nth-child(even){{background-color:#f2f2f2;}}
</style>
</head>
<body>
<h1>Network Scan Report</h1>
<p>Time: {time}</p>
<p>Local IP: {local_ip}</p>
<p>External IP: {external_ip} ({geo_city})</p>
<p>Gateway: {gateway}</p>
<p>DNS: {dns}</p>
<h2>Devices</h2>
<table>
<tr><th>IP</th><th>MAC</th><th>Vendor</th><th>OS</th><th>Hostname</th><th>Ports</th><th>SMB Anonymous</th></tr>
{rows}
</table>
</body>
</html>"""
    rows = ""
    for d in devices:
        smb = "Yes" if d.get('smb_anon') else "No"
        rows += f"<tr><td>{d['ip']}</td><td>{d['mac']}</td><td>{d['vendor']}</td><td>{d['os']}</td><td>{d['hostname']}</td><td>{d['ports']}</td><td>{smb}</td></tr>"
    html = html_template.format(
        time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        local_ip=local_ip,
        external_ip=external_ip,
        geo_city=geo_city,
        gateway=get_gateway(),
        dns=", ".join(dns_servers),
        rows=rows
    )
    save_path = get_save_path()
    os.makedirs(save_path, exist_ok=True)
    filename = f"network_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    filepath = os.path.join(save_path, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html)
    log_print(Fore.GREEN + f"\nHTML report exported to {filepath}")

def get_connection_type():
    try:
        for iface, stats in psutil.net_if_stats().items():
            if not stats.isup:
                continue
            if any(x in iface.lower() for x in ("wi", "wlan", "wlp", "airport", "wireless")):
                return "wifi"
    except Exception:
        pass
    return "ethernet"

class MountWatcher(threading.Thread):
    def __init__(self, check_interval=1.0):
        super().__init__(daemon=True)
        self.check_interval = check_interval
        self.known_mounts = set(get_possible_mounts())
        self.lock = threading.Lock()

    def find_procs_on_mount(self, mount):
        procs = []
        for proc in psutil.process_iter(['pid', 'exe', 'cmdline']):
            try:
                exe = proc.info.get('exe') or ""
                if exe and exe.startswith(mount):
                    procs.append((proc.pid, exe))
                else:
                    cmd = proc.info.get('cmdline') or []
                    if cmd and isinstance(cmd, (list, tuple)) and len(cmd) and isinstance(cmd[0], str) and cmd[0].startswith(mount):
                        procs.append((proc.pid, cmd[0]))
            except Exception:
                continue
        return procs

    def terminate_procs(self, procs):
        for pid, path in procs:
            try:
                proc = psutil.Process(pid)
                try:
                    proc.terminate()
                    proc.wait(2)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                log_print(Fore.WHITE + f"Terminated process {pid} from removed mount {path}")
            except Exception:
                pass

    def run(self):
        while True:
            current = set(get_possible_mounts())
            removed = self.known_mounts - current
            if removed:
                for mount in list(removed):
                    procs = self.find_procs_on_mount(mount)
                    if procs:
                        with self.lock:
                            self.terminate_procs(procs)
                self.known_mounts = current
            else:
                self.known_mounts = current
            time.sleep(self.check_interval)

def main():
    set_title("loard")
    init_log()
    watcher = MountWatcher()
    watcher.start()

    while True:
        try:
            conn_type = get_connection_type()

            if conn_type == "ethernet":
                ssid = "Ethernet"
                pw = "N/A"
            else:
                log_print(Fore.WHITE + "\nWi-Fi Networks choose number...\n")
                nets = wifi_scan()

                if not nets:
                    log_print(Fore.WHITE + "No Wi-Fi networks found.")
                    log_print(Fore.WHITE + "Press Enter to retry or q to quit")
                    c = input("> ").strip().lower()
                    if c == "q":
                        break
                    continue

                for i, n in enumerate(nets):
                    log_print(Fore.WHITE + f"{i+1}. {n}")

                log_print(Fore.WHITE + "\nChoose number or q:")
                c = input("> ").strip()
                if c.lower() == "q":
                    break
                if not c.isdigit():
                    log_print(Fore.WHITE + "Invalid.")
                    continue

                idx = int(c) - 1
                if idx < 0 or idx >= len(nets):
                    log_print(Fore.WHITE + "Invalid.")
                    continue

                ssid = nets[idx]
                pw = wifi_password(ssid)

            ip  = get_local_ip()
            dns = get_dns()
            ext = get_external_ip()
            geo = get_geo_city(ext) if ext != "Unknown" else "Unknown"

            with tqdm(
                total=100, desc="Initializing...",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                colour="white"
            ) as pbar:

                pbar.set_description("Getting local IP & gateway")
                time.sleep(0.3)
                pbar.update(10)

                pbar.set_description("Getting external IP & DNS")
                time.sleep(0.3)
                pbar.update(10)

                pbar.set_description(f"Scanning network - {ssid}")
                try:
                    base3 = '.'.join(ip.split('.')[:3])
                    raw_devices = scan(base3 + ".0/24")
                except Exception:
                    raw_devices = []
                pbar.update(25)

                pbar.set_description("Vendor lookup / OS detect / port scan / SNMP")
                records = device_records(raw_devices)
                pbar.update(45)

                pbar.set_description("Rendering output")
                time.sleep(0.2)
                pbar.update(10)

            display(ip, records, dns, ext, geo)

            log_print(Fore.WHITE + "\nEnter = refresh, q = quit, --export json, --export html")
            cmd = input("> ").strip().lower()
            if cmd == "q":
                break
            elif cmd == "--export json":
                export_json(records, ip, ext, geo, dns)
                input("Press Enter to continue...")
            elif cmd == "--export html":
                export_html(records, ip, ext, geo, dns)
                input("Press Enter to continue...")
            elif cmd == "":
                continue
            else:
                log_print(Fore.WHITE + "Unknown command")
                time.sleep(0.5)

        except KeyboardInterrupt:
            log_print(Fore.WHITE + "\nProgram terminated.")
            break
        except Exception as e:
            print(f"[ERROR] {e}")
            time.sleep(0.5)

    log_print(Fore.WHITE + "Program terminated.")

if __name__ == "__main__":
    main()
