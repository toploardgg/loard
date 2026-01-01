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
from datetime import datetime
from colorama import init, Fore
from tqdm import tqdm

init(autoreset=True)

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

sys.excepthook = lambda *args: None

ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def process_with_progress(ssid, pw):
    ip = get_local_ip()
    dns = get_dns()
    ext = get_external_ip()

    total_steps = 100
    with tqdm(total=total_steps, desc="Data collection", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]", colour="white") as pbar:

        pbar.set_description("Obtaining a local IP")
        time.sleep(0.3)
        pbar.update(10)

        pbar.set_description("Obtaining DNS and external IP")
        time.sleep(0.4)
        pbar.update(15)

        pbar.set_description(f"Network scanning {ssid}...")
        try:
            base3 = '.'.join(ip.split('.')[:3])
            raw = scan(base3 + ".0/24")
        except:
            raw = []
        scan_time = len(raw) * 0.05 + 1
        time.sleep(0.3)
        pbar.update(40)

        pbar.set_description("Getting device names")
        rec = []
        step_per_device = 25 / max(1, len(raw))
        for device in raw:
            ip_dev = device.get('ip', 'Unknown')
            hostname = get_hostname(ip_dev)
            device['hostname'] = hostname
            rec.append({
                'ip': ip_dev,
                'mac': device.get('mac', 'Unknown').upper(),
                'vendor': "Unknown",
                'hostname': hostname,
                'passkey': f"passkey-({pw})"
            })
            pbar.update(step_per_device)
            time.sleep(0.02)
        pbar.set_description("Output Formation")
        time.sleep(0.3)
        pbar.update(10)

    display(ip, rec if rec else device_records(raw, pw), dns, ext)

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

def init_log():
    global log_file
    filename = datetime.now().strftime("%d.%m.%y_%H-%M") + ".txt"
    drives_to_check = ["G:\\", "H:\\"] if platform.system() == "Windows" else []

    for drive in drives_to_check:
        log_dir = os.path.join(drive, "log")
        try:
            os.makedirs(log_dir, exist_ok=True)
            test_file = os.path.join(log_dir, "tmp.txt")
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)
            log_file = open(os.path.join(log_dir, filename), "a", encoding="utf-8")
            return log_file
        except Exception:
            continue

    if platform.system() != "Windows":
        mount_points = []
        for base in ("/media", "/run/media", "/mnt", "/Volumes"):
            if os.path.exists(base):
                try:
                    for user_dir in os.listdir(base):
                        user_path = os.path.join(base, user_dir)
                        if os.path.isdir(user_path):
                            for mnt in os.listdir(user_path):
                                full_path = os.path.join(user_path, mnt)
                                if os.path.ismount(full_path):
                                    mount_points.append(full_path)
                except Exception:
                    continue
        for mount in mount_points:
            log_dir = os.path.join(mount, "log")
            try:
                os.makedirs(log_dir, exist_ok=True)
                test_file = os.path.join(log_dir, "tmp.txt")
                with open(test_file, "w") as f:
                    f.write("test")
                os.remove(test_file)
                log_file = open(os.path.join(log_dir, filename), "a", encoding="utf-8")
                return log_file
            except Exception:
                continue

    base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    log_dir = os.path.join(base_dir, "log")
    os.makedirs(log_dir, exist_ok=True)
    log_file = open(os.path.join(log_dir, filename), "a", encoding="utf-8")
    return log_file

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
        import netifaces
        g = netifaces.gateways().get('default', {}).get(netifaces.AF_INET)
        return g[0] if g else "Unknown"
    except ImportError:
        return "Unknown"

def get_dns():
    dns = []
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output("ipconfig /all", shell=True, text=True, encoding="cp866", errors='ignore')
            for line in out.splitlines():
                if "DNS Servers" in line or "DNS Servers" in line:
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

def wifi_scan():
    nets = []
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output("netsh wlan show networks", shell=True, text=True, encoding="cp866", errors='ignore')
            for line in out.splitlines():
                if "SSID" in line and "BSSID" not in line:
                    ssid = line.split(":",1)[1].strip()
                    if ssid and ssid not in nets:
                        nets.append(ssid)
        elif platform.system() == "Darwin":
            airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            if os.path.exists(airport):
                out = subprocess.check_output(f'"{airport}" -s', shell=True, text=True, errors='ignore')
                for line in out.splitlines()[1:]:
                    parts = line.strip().split()
                    if parts:
                        ssid = " ".join(parts[:-5]) if len(parts) > 5 else parts[0]
                        if ssid and ssid not in nets:
                            nets.append(ssid)
        else:
            try:
                out = subprocess.check_output("nmcli -t -f SSID dev wifi", shell=True, text=True, errors='ignore')
                for line in out.splitlines():
                    ssid = line.strip()
                    if ssid and ssid not in nets:
                        nets.append(ssid)
            except Exception:
                try:
                    out = subprocess.check_output("iwlist scanning", shell=True, text=True, errors='ignore')
                    for line in out.splitlines():
                        if "ESSID" in line:
                            ssid = line.split("ESSID:")[-1].strip().strip('"')
                            if ssid and ssid not in nets:
                                nets.append(ssid)
                except Exception:
                    pass
    except Exception:
        pass
    return nets

def wifi_password(ssid):
    try:
        sys_name = platform.system()
        if sys_name == "Windows":
            out = subprocess.check_output(
                f'netsh wlan show profile name="{ssid}" key=clear',
                shell=True,
                text=True,
                encoding="cp866",
                errors='ignore',
                stderr=subprocess.DEVNULL
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
                    shell=True,
                    text=True,
                    stderr=subprocess.DEVNULL
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

def banner():
    return Fore.RED + r'''
██╗      ██████╗  █████╗ ██████╗ ██████╗        ██╗    ███╗
██║     ██╔═══██╗██╔══██╗██╔══██╗██╔══██╗       ██║    ██║██╗
██║     ██║   ██║███████║██████╔╝██║  ██║       ██║ █╗ ██║ ██╗
██║     ██║   ██║██╔══██║██╔══██╗██║  ██║       ██║███╗██║  ██╗
███████╗╚██████╔╝██║  ██║██║  ██║██████╔╝       ╚███╔███╔╝  ╚═╝
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝        ╚══╝╚═══╝   
''' + Fore.RED + '--- Wi-Fi tool by Toploardgg ---\n'

def device_records(raw_devices, password):
    records = []
    for device in raw_devices:
        ip = device.get('ip', 'Unknown')
        mac = device.get('mac', 'Unknown').upper()
        hostname = get_hostname(ip)
        records.append({
            'ip': ip,
            'mac': mac,
            'vendor': "Unknown",
            'hostname': hostname,
            'passkey': f"passkey-({password})"
        })
    return records

def display(local_ip, devices, dns_servers, external_ip):
    clear()
    log_print(banner())
    log_print(Fore.WHITE + f"Local IP: {local_ip}")
    log_print(Fore.WHITE + f"Gateway: {get_gateway()}")
    try:
        subnet = '.'.join(local_ip.split('.')[:3]) + ".1/24"
    except Exception:
        subnet = "Unknown"
    log_print(Fore.WHITE + f"Subnet: {subnet}\n")
    log_print(Fore.WHITE + "DNS:")
    if dns_servers:
        for dns in dns_servers:
            log_print(Fore.WHITE + f"- {dns}")
    else:
        log_print(Fore.WHITE + "None")
    log_print("\n" + Fore.WHITE + f"External IP: {external_ip}\n")
    log_print(connections_text())
    log_print(Fore.WHITE + "\n[Devices]\n")
    log_print(Fore.WHITE + "{:<16} {:<18} {:<20} {:<25} {:<20}".format("IP", "MAC", "Vendor", "Hostname", "Passkey"))
    log_print("-" * 100)
    for device in devices:
        log_print(Fore.WHITE + f"{device['ip']:<16} {device['mac']:<18} {device['vendor']:<20} {device['hostname']:<25} {device['passkey']:<20}")
    if devices:
        df = pd.DataFrame(devices)
        log_print(Fore.WHITE + "\n[DataFrame]\n")
        log_print(Fore.WHITE + df.to_string(index=False))

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
                log_print(Fore.WHITE + "Exit.")
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
            ip = get_local_ip()
            dns = get_dns()
            ext = get_external_ip()

            with tqdm(total=100, desc="Initializing...", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]", colour="white") as pbar:
                pbar.set_description("Getting local IP & gateway")
                time.sleep(0.3)
                pbar.update(15)

                pbar.set_description("Getting external IP & DNS")
                time.sleep(0.4)
                pbar.update(15)

                pbar.set_description(f"Scanning network - {ssid}")
                try:
                    base3 = '.'.join(ip.split('.')[:3])
                    raw_devices = scan(base3 + ".0/24")
                except:
                    raw_devices = []
                pbar.update(35)

                pbar.set_description("Resolving hostnames")
                records = []
                if raw_devices:
                    step = 30 / len(raw_devices)
                    for dev in raw_devices:
                        hostname = get_hostname(dev.get('ip', ''))
                        records.append({
                            'ip': dev.get('ip', 'Unknown'),
                            'mac': dev.get('mac', 'Unknown').upper(),
                            'vendor': 'Unknown',
                            'hostname': hostname,
                            'passkey': f"passkey-({pw})"
                        })
                        pbar.update(step)
                        time.sleep(0.008)
                else:
                    pbar.update(30)

                pbar.set_description("Rendering output")
                time.sleep(0.3)
                pbar.update(5)

            clear()
            log_print(banner())
            display(ip, records, dns, ext)

            print(Fore.WHITE + "\nEnter = refresh, q = quit")
            c = input("> ").strip().lower()
            if c == "q":
                break

        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(0.5)

    log_print(Fore.WHITE + "Program terminated.")

if __name__ == "__main__":
    main()