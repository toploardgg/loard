import os
import sys
import io
import socket
import subprocess
import re
import threading
import time
import platform
import psutil
import requests
import contextlib
import queue
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Scapy — warning only once at startup
try:
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


# ─────────────────────────────────────────────
#  Utility functions
# ─────────────────────────────────────────────

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
            out = subprocess.check_output(
                "ipconfig", shell=True, text=True, encoding="cp866", errors='ignore'
            )
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
            out = subprocess.check_output(
                "ipconfig /all", shell=True, text=True, encoding="cp866", errors='ignore'
            )
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
                                if p.count(".") == 3 and p not in dns:
                                    dns.append(p)
                except Exception:
                    pass
    except Exception:
        pass
    return dns


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


def wifi_scan():
    nets = []
    sys_name = platform.system()

    if sys_name == "Windows":
        try:
            out = subprocess.check_output(
                "netsh wlan show networks mode=Bssid",
                shell=True, text=True, errors="ignore", stderr=subprocess.DEVNULL
            )
            for line in out.splitlines():
                line = line.strip()
                if "SSID" in line and "BSSID" not in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        ssid = parts[1].strip()
                        if ssid and ssid not in nets:
                            nets.append(ssid)
        except Exception:
            pass
        return nets

    if sys_name == "Darwin":
        airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        if os.path.exists(airport):
            try:
                out = subprocess.check_output(
                    f'"{airport}" -s', shell=True, text=True, errors="ignore", stderr=subprocess.DEVNULL
                )
                for line in out.splitlines()[1:]:
                    parts = line.split()
                    if parts:
                        ssid = " ".join(parts[:-5]) if len(parts) > 5 else parts[0]
                        if ssid and ssid not in nets:
                            nets.append(ssid)
            except Exception:
                pass
        return nets

    if sys_name == "Linux":
        try:
            out = subprocess.check_output(
                "nmcli -t -f SSID dev wifi", shell=True, text=True,
                errors="ignore", stderr=subprocess.DEVNULL
            )
            for line in out.splitlines():
                ssid = line.strip()
                if ssid and ssid not in nets:
                    nets.append(ssid)
        except Exception:
            pass
        return nets

    return nets


def wifi_password(ssid):
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(
                f'netsh wlan show profile name="{ssid}" key=clear',
                shell=True, text=True, encoding="cp866", errors='ignore', stderr=subprocess.DEVNULL
            )
            for line in out.splitlines():
                if "Key Content" in line or "Содержимое ключа" in line:
                    return line.split(":", 1)[1].strip()
        elif platform.system() == "Darwin":
            cmd = f'security find-generic-password -D "AirPort network password" -a "{ssid}" -gw'
            out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
            return out.strip()
        else:
            try:
                out = subprocess.check_output(
                    f'nmcli -s -g 802-11-wireless-security.psk connection show "{ssid}"',
                    shell=True, text=True, stderr=subprocess.DEVNULL
                )
                p = out.strip()
                if p:
                    return p
            except Exception:
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


# ─────────────────────────────────────────────
#  Mount watcher
# ─────────────────────────────────────────────

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
                    if cmd and isinstance(cmd, list) and cmd[0].startswith(mount):
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
                    p.kill()
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
            time.sleep(self.check_interval)


# ─────────────────────────────────────────────
#  GUI
# ─────────────────────────────────────────────

class WiFiToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("loard")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1a1a1a')
        self.log_file = None

        self._setup_styles()
        self._build_ui()

        MountWatcher().start()
        self.load_initial_data()

    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use('clam')
        s.configure('TFrame', background='#1a1a1a')
        s.configure('TLabel', background='#1a1a1a', foreground='white', font=('Consolas', 10))
        s.configure('Title.TLabel', background='#1a1a1a', foreground='red', font=('Consolas', 9, 'bold'))
        s.configure('TButton', background='#333333', foreground='white', font=('Consolas', 10))
        s.map('TButton', background=[('active', '#555555')])
        s.configure('Treeview', background='#2a2a2a', foreground='white', fieldbackground='#2a2a2a', font=('Consolas', 9))
        s.configure('Treeview.Heading', background='#333333', foreground='white', font=('Consolas', 9, 'bold'))
        s.map('Treeview', background=[('selected', '#555555')])

    def _build_ui(self):
        main = ttk.Frame(self.root)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Banner
        ttk.Label(
            main,
            text=(
                "██╗      ██████╗  █████╗ ██████╗ ██████╗        ██╗    ███╗\n"
                "██║     ██╔═══██╗██╔══██╗██╔══██╗██╔══██╗       ██║    ██║██╗\n"
                "██║     ██║   ██║███████║██████╔╝██║  ██║       ██║ █╗ ██║ ██╗\n"
                "██║     ██║   ██║██╔══██║██╔══██╗██║  ██║       ██║███╗██║  ██╗\n"
                "███████╗╚██████╔╝██║  ██║██║  ██║██████╔╝       ╚███╔███╔╝  ╚═╝\n"
                "╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝        ╚══╝╚═══╝"
            ),
            style='Title.TLabel', justify=tk.CENTER
        ).pack(pady=(0, 2))
        ttk.Label(main, text="--- Network tool by Toploardgg ---", style='Title.TLabel').pack(pady=(0, 10))

        # Info row
        info = ttk.Frame(main)
        info.pack(fill=tk.X, pady=5)
        self.local_ip_label    = ttk.Label(info, text="Local IP: ...")
        self.gateway_label     = ttk.Label(info, text="Gateway: ...")
        self.external_ip_label = ttk.Label(info, text="External IP: ...")
        self.subnet_label      = ttk.Label(info, text="Subnet: ...")
        self.dns_label         = ttk.Label(info, text="DNS: ...")
        self.local_ip_label.grid(   row=0, column=0, sticky=tk.W, padx=8)
        self.gateway_label.grid(    row=0, column=1, sticky=tk.W, padx=8)
        self.external_ip_label.grid(row=1, column=0, sticky=tk.W, padx=8)
        self.subnet_label.grid(     row=1, column=1, sticky=tk.W, padx=8)
        self.dns_label.grid(        row=2, column=0, columnspan=2, sticky=tk.W, padx=8)

        # Network list
        net_frame = ttk.Frame(main)
        net_frame.pack(fill=tk.X, pady=5)
        ttk.Label(net_frame, text="Networks:", font=('Consolas', 10, 'bold')).pack(anchor=tk.W)
        self.network_listbox = tk.Listbox(
            net_frame, bg='#2a2a2a', fg='white',
            selectbackground='#555555', font=('Consolas', 10), height=5
        )
        self.network_listbox.pack(fill=tk.X, pady=3)

        btn_frame = ttk.Frame(net_frame)
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text="Scan Selected", command=self.scan_network).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_frame, text="Refresh Networks", command=self.load_initial_data).pack(side=tk.LEFT, padx=3)

        # Devices tree
        dev_frame = ttk.Frame(main)
        dev_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        ttk.Label(dev_frame, text="Devices:", font=('Consolas', 10, 'bold')).pack(anchor=tk.W)

        tree_wrap = ttk.Frame(dev_frame)
        tree_wrap.pack(fill=tk.BOTH, expand=True)
        scroll = ttk.Scrollbar(tree_wrap)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree = ttk.Treeview(
            tree_wrap,
            columns=('IP', 'MAC', 'Vendor', 'Hostname', 'Passkey'),
            show='headings',
            yscrollcommand=scroll.set
        )
        scroll.config(command=self.tree.yview)
        for col, w in [('IP', 130), ('MAC', 150), ('Vendor', 140), ('Hostname', 220), ('Passkey', 200)]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w)
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Status bar
        self.status_label = ttk.Label(main, text="Initializing...", font=('Consolas', 9))
        self.status_label.pack(pady=3, anchor=tk.W)

    # ── logging ──────────────────────────────

    def _init_log(self):
        log_dir = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "log")
        os.makedirs(log_dir, exist_ok=True)
        filename = datetime.now().strftime("%d.%m.%y_%H-%M") + ".txt"
        return open(os.path.join(log_dir, filename), "a", encoding="utf-8")

    def log_data(self, data):
        if self.log_file is None:
            try:
                self.log_file = self._init_log()
            except Exception:
                return
        try:
            self.log_file.write(data + "\n")
            self.log_file.flush()
        except Exception:
            pass

    # ── status ───────────────────────────────

    def update_status(self, msg):
        self.root.after(0, lambda: self.status_label.config(text=msg))

    # ── initial load ─────────────────────────

    def load_initial_data(self):
        threading.Thread(target=self._load_data, daemon=True).start()

    def _load_data(self):
        self.update_status("Loading network info...")
        ip      = get_local_ip()
        gateway = get_gateway()
        dns     = get_dns()
        ext     = ext_ip()
        subnet  = '.'.join(ip.split('.')[:3]) + ".1/24"

        self.root.after(0, lambda: self.local_ip_label.config(   text=f"Local IP: {ip}"))
        self.root.after(0, lambda: self.gateway_label.config(     text=f"Gateway: {gateway}"))
        self.root.after(0, lambda: self.external_ip_label.config( text=f"External IP: {ext}"))
        self.root.after(0, lambda: self.subnet_label.config(      text=f"Subnet: {subnet}"))
        self.root.after(0, lambda: self.dns_label.config(         text=f"DNS: {', '.join(dns) if dns else 'None'}"))

        conn_type = get_connection_type()

        if conn_type == "ethernet":
            self.root.after(0, lambda: self.network_listbox.delete(0, tk.END))
            self.root.after(0, lambda: self.network_listbox.insert(tk.END, "Ethernet (auto)"))
            self.root.after(0, lambda: self.network_listbox.selection_set(0))
            self.update_status("Ethernet detected — scanning automatically...")
            self._scan_network_thread("Ethernet")
        else:
            self.update_status("Scanning Wi-Fi networks...")
            nets = wifi_scan()
            self.root.after(0, lambda: self.network_listbox.delete(0, tk.END))
            for n in nets:
                self.root.after(0, lambda x=n: self.network_listbox.insert(tk.END, x))
            self.update_status("Ready — select a network and click Scan")

    # ── scan ─────────────────────────────────

    def scan_network(self):
        sel = self.network_listbox.curselection()
        if not sel:
            messagebox.showwarning("Warning", "Select a network first")
            return
        ssid = self.network_listbox.get(sel[0])
        threading.Thread(target=self._scan_network_thread, args=(ssid,), daemon=True).start()

    def _scan_network_thread(self, ssid):
        try:
            if ssid == "Ethernet":
                pw = "N/A"
            else:
                self.update_status(f"Getting password for {ssid}...")
                pw = wifi_password(ssid)

            self.update_status("Scanning network devices...")
            ip     = get_local_ip()
            subnet = '.'.join(ip.split('.')[:3]) + ".0/24"
            raw    = scan(subnet)
        except Exception as e:
            self.update_status(f"Scan error: {e}")
            return

        devices = device_records(raw, pw)
        self.root.after(0, lambda: self._update_tree(devices))
        self.update_status(f"Done — {len(devices)} device(s) found")

        log_text = f"Connection: {ssid} | Passkey: {pw}\n"
        for d in devices:
            log_text += f"  {d['ip']}  {d['mac']}  {d['hostname']}  {d['passkey']}\n"
        self.log_data(log_text)

    def _update_tree(self, records):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for d in records:
            self.tree.insert("", tk.END, values=(
                d['ip'], d['mac'], d['vendor'], d['hostname'], d['passkey']
            ))


# ─────────────────────────────────────────────

def main():
    root = tk.Tk()
    WiFiToolGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
