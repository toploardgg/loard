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
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

sys.excepthook = lambda *args: None

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

class MountWatcher(threading.Thread):
    def __init__(self, check_interval=1.0):
        super().__init__(daemon=True)
        self.check_interval = check_interval
        self.known_mounts = set(get_possible_mounts())
        self.lock = threading.Lock()

    def find_procs_on_mount(self, mount):
        procs = []
        for p in psutil.process_iter(['pid', 'exe', 'cmdline']):
            try:
                exe = p.info.get('exe') or ""
                if exe and exe.startswith(mount):
                    procs.append((p.pid, exe))
                else:
                    cmd = p.info.get('cmdline') or []
                    if cmd and isinstance(cmd, (list, tuple)) and len(cmd) and isinstance(cmd[0], str) and cmd[0].startswith(mount):
                        procs.append((p.pid, cmd[0]))
            except Exception:
                continue
        return procs

    def terminate_procs(self, procs):
        for pid, path in procs:
            try:
                p = psutil.Process(pid)
                try:
                    p.terminate()
                    p.wait(2)
                except Exception:
                    try:
                        p.kill()
                    except Exception:
                        pass
            except Exception:
                pass

    def run(self):
        while True:
            current = set(get_possible_mounts())
            removed = self.known_mounts - current
            if removed:
                for m in list(removed):
                    procs = self.find_procs_on_mount(m)
                    if procs:
                        with self.lock:
                            self.terminate_procs(procs)
                self.known_mounts = current
            else:
                self.known_mounts = current
            time.sleep(self.check_interval)

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
                if "DNS Servers" in line or "Серверы DNS" in line:
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
    sys_name = platform.system()

    if sys_name == "Windows":
        try:
            out = subprocess.check_output("netsh wlan show networks", shell=True, text=True, errors="ignore")
            for line in out.splitlines():
                if "SSID" in line and "BSSID" not in line:
                    ssid = line.split(":",1)[1].strip()
                    if ssid and ssid not in nets:
                        nets.append(ssid)
        except:
            pass
        return nets

    if sys_name == "Darwin":
        airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        if os.path.exists(airport):
            try:
                out = subprocess.check_output(f'"{airport}" -s 2>/dev/null', shell=True, text=True, errors="ignore")
                for line in out.splitlines()[1:]:
                    parts = line.split()
                    if parts:
                        ssid = " ".join(parts[:-5]) if len(parts) > 5 else parts[0]
                        if ssid and ssid not in nets:
                            nets.append(ssid)
            except:
                pass
        return nets

    if sys_name == "Linux":
        try:
            out = subprocess.check_output("nmcli -t -f SSID dev wifi 2>/dev/null", shell=True, text=True, errors="ignore")
            for line in out.splitlines():
                ssid = line.strip()
                if ssid and ssid not in nets:
                    nets.append(ssid)
        except:
            pass

        try:
            out = subprocess.check_output("ls /sys/class/net 2>/dev/null", shell=True, text=True, errors="ignore")
            ifaces = [x.strip() for x in out.splitlines() if re.search(r"wl|wifi|wlan", x, re.I)]
        except:
            ifaces = []

        for iface in ifaces:
            try:
                out = subprocess.check_output(f"iw dev {iface} scan 2>/dev/null", shell=True, text=True, errors="ignore")
                for line in out.splitlines():
                    if "SSID:" in line:
                        ssid = line.split("SSID:")[1].strip()
                        if ssid and ssid not in nets:
                            nets.append(ssid)
            except:
                pass

            try:
                out = subprocess.check_output(f"iwlist {iface} scanning 2>/dev/null", shell=True, text=True, errors="ignore")
                for line in out.splitlines():
                    if "ESSID" in line:
                        ssid = line.split("ESSID:")[-1].strip().strip('"')
                        if ssid and ssid not in nets:
                            nets.append(ssid)
            except:
                pass

        return nets

    return nets

def wifi_password(ssid):
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(f'netsh wlan show profile name="{ssid}" key=clear', shell=True, text=True, encoding="cp866", errors='ignore')
            for line in out.splitlines():
                if "Key Content" in line or "Содержимое ключа" in line:
                    return line.split(":",1)[1].strip()
        elif platform.system() == "Darwin":
            cmd = f'security find-generic-password -D "AirPort network password" -a "{ssid}" -gw'
            try:
                out = subprocess.check_output(cmd, shell=True, text=True, errors='ignore')
                return out.strip()
            except subprocess.CalledProcessError:
                return "Unknown"
        else:
            try:
                out = subprocess.check_output(f'nmcli -s -g 802-11-wireless-security.psk connection show "{ssid}"', shell=True, text=True, errors='ignore')
                p = out.strip()
                if p:
                    return p
            except Exception:
                try:
                    base = "/etc/NetworkManager/system-connections"
                    for fname in os.listdir(base):
                        path = os.path.join(base, fname)
                        try:
                            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                                data = f.read()
                                if f'802-11-wireless.ssid={ssid}' in data or f'ssid={ssid}' in data:
                                    for line in data.splitlines():
                                        if line.strip().startswith("psk="):
                                            return line.split("=",1)[1].strip()
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

def ping_sweep(subnet_base, timeout=0.3, threads=60):
    import queue
    ips = [f"{subnet_base}.{i}" for i in range(1, 255)]
    live = []
    lock = threading.Lock()
    q = queue.Queue()
    for ip in ips:
        q.put(ip)
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
                r = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if r == 0:
                    with lock:
                        live.append(ip)
            except Exception:
                pass
    workers = []
    for _ in range(min(threads, len(ips))):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        workers.append(t)
    for t in workers:
        t.join()
    return live

def scan(subnet):
    results = []
    if SCAPY_AVAILABLE:
        try:
            p = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            r = srp(p, timeout=1, verbose=0)[0]
            for _, recv in r:
                results.append({'ip': recv.psrc, 'mac': recv.hwsrc})
            return results
        except Exception:
            pass
    try:
        base = ".".join(subnet.split('.')[:3])
        live = ping_sweep(base)
        for ip in live:
            mac = get_mac_from_arp(ip)
            results.append({'ip': ip, 'mac': mac})
    except Exception:
        pass
    return results

def hostname_of(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"

def ext_ip():
    try:
        return requests.get('https://api.ipify.org?format=json', timeout=2).json().get('ip')
    except Exception:
        return "Unknown"

def device_records(raw, pw):
    r = []
    for d in raw:
        ip = d.get('ip', 'Unknown')
        mac = d.get('mac', 'Unknown').upper()
        h = hostname_of(ip)
        r.append({
            'ip': ip,
            'mac': mac,
            'vendor': "Unknown",
            'hostname': h,
            'passkey': f"passkey-({pw})"
        })
    return r

class WiFiToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("loard Wi-Fi Tool")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1a1a1a')
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#1a1a1a')
        self.style.configure('TLabel', background='#1a1a1a', foreground='white', font=('Consolas', 10))
        self.style.configure('Title.TLabel', foreground='red', font=('Consolas', 12, 'bold'))
        self.style.configure('TButton', background='#333333', foreground='white', font=('Consolas', 10))
        self.style.map('TButton', background=[('active', '#555555')])
        
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.banner_label = ttk.Label(
            self.main_frame,
            text="██╗      ██████╗  █████╗ ██████╗ ██████╗        ██╗    ███╗\n"
                 "██║     ██╔═══██╗██╔══██╗██╔══██╗██╔══██╗       ██║    ██║██╗\n"
                 "██║     ██║   ██║███████║██████╔╝██║  ██║       ██║ █╗ ██║ ██╗\n"
                 "██║     ██║   ██║██╔══██║██╔══██╗██║  ██║       ██║███╗██║  ██╗\n"
                 "███████╗╚██████╔╝██║  ██║██║  ██║██████╔╝       ╚███╔███╔╝  ██╗\n"
                 "╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝        ╚══╝╚══╝    ╚═╝",
            style='Title.TLabel',
            font=('Consolas', 8),
            justify=tk.CENTER
        )
        self.banner_label.pack(pady=(0, 5))
        
        self.subtitle_label = ttk.Label(
            self.main_frame,
            text="--- Wi-Fi tool by Toploardgg ---",
            style='Title.TLabel'
        )
        self.subtitle_label.pack(pady=(0, 15))
        
        self.info_frame = ttk.Frame(self.main_frame)
        self.info_frame.pack(fill=tk.X, pady=10)
        
        self.local_ip_label = ttk.Label(self.info_frame, text="Local IP: Loading...")
        self.local_ip_label.grid(row=0, column=0, sticky=tk.W, padx=5)
        
        self.gateway_label = ttk.Label(self.info_frame, text="Gateway: Loading...")
        self.gateway_label.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        self.external_ip_label = ttk.Label(self.info_frame, text="External IP: Loading...")
        self.external_ip_label.grid(row=1, column=0, sticky=tk.W, padx=5)
        
        self.subnet_label = ttk.Label(self.info_frame, text="Subnet: Loading...")
        self.subnet_label.grid(row=1, column=1, sticky=tk.W, padx=5)
        
        self.dns_label = ttk.Label(self.info_frame, text="DNS: Loading...")
        self.dns_label.grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5)
        
        self.network_frame = ttk.Frame(self.main_frame)
        self.network_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        ttk.Label(self.network_frame, text="Wi-Fi Networks:", font=('Consolas', 11, 'bold')).pack(anchor=tk.W)
        
        self.network_listbox = tk.Listbox(
            self.network_frame,
            bg='#2a2a2a',
            fg='white',
            selectbackground='#555555',
            font=('Consolas', 10),
            height=6
        )
        self.network_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.scan_button = ttk.Button(
            self.network_frame, 
            text="Scan Selected Network", 
            command=self.scan_network,
            style="Accent.TButton"
        )
        self.scan_button.pack(pady=5)
        
        self.devices_frame = ttk.Frame(self.main_frame)
        self.devices_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(self.devices_frame, text="Devices:", font=('Consolas', 11, 'bold')).pack(anchor=tk.W)
        
        self.tree_frame = ttk.Frame(self.devices_frame)
        self.tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.tree_scroll = ttk.Scrollbar(self.tree_frame)
        self.tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree = ttk.Treeview(
            self.tree_frame,
            columns=('IP', 'MAC', 'Vendor', 'Hostname', 'Passkey'),
            show='headings',
            yscrollcommand=self.tree_scroll.set
        )
        self.tree_scroll.config(command=self.tree.yview)
        
        self.tree.heading('IP', text='IP Address')
        self.tree.heading('MAC', text='MAC Address')
        self.tree.heading('Vendor', text='Vendor')
        self.tree.heading('Hostname', text='Hostname')
        self.tree.heading('Passkey', text='Passkey')
        
        self.tree.column('IP', width=120)
        self.tree.column('MAC', width=140)
        self.tree.column('Vendor', width=150)
        self.tree.column('Hostname', width=200)
        self.tree.column('Passkey', width=180)
        
        self.style.configure('Treeview', background='#2a2a2a', foreground='white', fieldbackground='#2a2a2a')
        self.style.map('Treeview', background=[('selected', '#555555')])
        
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        self.status_label = ttk.Label(self.main_frame, text="Ready", font=('Consolas', 9))
        self.status_label.pack(pady=5)
        
        self.log_file = None
        self.load_initial_data()
        
        watcher = MountWatcher()
        watcher.start()

    def init_log(self):
        log_dir = filedialog.askdirectory(title="Select Log Directory")
        if not log_dir:
            log_dir = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "log")
            os.makedirs(log_dir, exist_ok=True)
        filename = datetime.now().strftime("%d.%m.%y_%H-%M") + ".txt"
        return open(os.path.join(log_dir, filename), "a", encoding="utf-8")

    def log_data(self, data):
        if self.log_file:
            self.log_file.write(data + "\n")
            self.log_file.flush()

    def load_initial_data(self):
        threading.Thread(target=self._load_data, daemon=True).start()

    def _load_data(self):
        self.update_status("Loading network information...")
        ip = get_local_ip()
        gateway = get_gateway()
        dns = get_dns()
        ext = ext_ip()
        
        try:
            subnet = '.'.join(ip.split('.')[:3]) + ".1/24"
        except:
            subnet = "Unknown"
        
        self.root.after(0, lambda: self.local_ip_label.config(text=f"Local IP: {ip}"))
        self.root.after(0, lambda: self.gateway_label.config(text=f"Gateway: {gateway}"))
        self.root.after(0, lambda: self.external_ip_label.config(text=f"External IP: {ext}"))
        self.root.after(0, lambda: self.subnet_label.config(text=f"Subnet: {subnet}"))
        self.root.after(0, lambda: self.dns_label.config(text=f"DNS: {', '.join(dns) if dns else 'None'}"))
        
        self.update_status("Scanning Wi-Fi networks...")
        nets = wifi_scan()
        
        self.root.after(0, lambda: self.network_listbox.delete(0, tk.END))
        for net in nets:
            self.root.after(0, lambda n=net: self.network_listbox.insert(tk.END, n))
        
        self.update_status("Ready")

    def scan_network(self):
        selection = self.network_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a Wi-Fi network first")
            return

        ssid = self.network_listbox.get(selection[0])
        
        if self.log_file is None:
            self.log_file = self.init_log()
        
        threading.Thread(target=self._scan_network_thread, args=(ssid,), daemon=True).start()

    def _scan_network_thread(self, ssid):
        try:
            self.update_status(f"Getting password for {ssid}...")
            pw = wifi_password(ssid)
            
            self.update_status("Scanning network devices...")
            ip = get_local_ip()
            
            subnet_parts = ip.split('.')[:3]
            subnet = '.'.join(subnet_parts) + ".1/24"
            
            raw = scan(subnet)
        
        except Exception as e:
            self.update_status(f"Scan error: {str(e)}")
            return

        devices = device_records(raw, pw)
        
        self.root.after(0, lambda: self._update_tree(devices))
        
        self.update_status(f"Found {len(devices)} devices")
        
        log_text = f"SSID: {ssid}\nPassword: {pw}\nDevices:\n"
        for d in devices:
            log_text += f"IP: {d['ip']}, MAC: {d['mac']}, Vendor: {d['vendor']}, Hostname: {d['hostname']}, Passkey: {d['passkey']}\n"
        
        self.log_data(log_text)

    def _update_tree(self, rec):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for d in rec:
            self.tree.insert("", tk.END, values=(d['ip'], d['mac'], d['vendor'], d['hostname'], d['passkey']))

    def update_status(self, msg):
        self.root.after(0, lambda: self.status_label.config(text=msg))

def main():
    root = tk.Tk()
    app = WiFiToolGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()