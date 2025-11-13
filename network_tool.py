import subprocess
import re
import socket
import ipaddress
import concurrent.futures
import time
import csv
import os
from datetime import datetime
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
try:
    from mac_vendor_lookup import MacLookup, VendorNotFoundError
    MAC_LOOKUP = MacLookup()
except Exception:
    MAC_LOOKUP = None
    class VendorNotFoundError(Exception):
        pass

def list_adapters():
    p = subprocess.run(["ipconfig"], capture_output=True, text=True)
    out = p.stdout.splitlines()
    adapters = []
    name = None
    ip = None
    mask = None
    def push():
        if name and ip and mask and not ip.startswith("169.254"):
            adapters.append({"name": name, "ip": ip, "mask": mask})
    for line in out:
        s = line.strip()
        if not s:
            continue
        if s.endswith(":") and not line.startswith(" "):
            push()
            name = s[:-1]
            ip = None
            mask = None
            continue
        if ("IPv4" in s or "IPv4 地址" in s) and ip is None:
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", s)
            if m:
                ip = m.group(1)
            continue
        if ("Subnet Mask" in s or "子网掩码" in s) and mask is None:
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", s)
            if m:
                mask = m.group(1)
            continue
    push()
    return adapters

def get_ip_mask():
    p = subprocess.run(["ipconfig"], capture_output=True, text=True)
    out = p.stdout.splitlines()
    ip = None
    mask = None
    for i, line in enumerate(out):
        if "IPv4" in line or "IPv4 地址" in line:
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                cand_ip = m.group(1)
                if not cand_ip.startswith("169.254"):
                    ip = cand_ip
        if "Subnet Mask" in line or "子网掩码" in line:
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                mask = m.group(1)
        if ip and mask:
            break
    if not ip or not mask:
        raise RuntimeError("cannot detect ip/mask")
    return ip, mask

def network_hosts(ip, mask):
    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    hosts = [str(h) for h in net.hosts()]
    if len(hosts) >= 254:
        base = str(net.network_address).split(".")
        return [".".join(base[:3] + [str(i)]) for i in range(1, 255)]
    return hosts

def ping(ip):
    try:
        r = subprocess.run(["ping", "-n", "1", "-w", "300", ip], capture_output=True, text=True)
        return r.returncode == 0
    except Exception:
        return False

def scan_online(hosts):
    res = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(ping, ip): ip for ip in hosts}
        for f in concurrent.futures.as_completed(futs):
            ip = futs[f]
            try:
                res[ip] = f.result()
            except Exception:
                res[ip] = False
    return res

def parse_arp():
    r = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    out = r.stdout.splitlines()
    m = {}
    for line in out:
        line = line.strip()
        if re.match(r"^\d+\.\d+\.\d+\.\d+", line):
            parts = re.split(r"\s+", line)
            if len(parts) >= 2:
                ip = parts[0]
                mac = parts[1]
                if mac and mac != "ff-ff-ff-ff-ff-ff":
                    m[ip] = mac
    return m

def resolve_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        try:
            r = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, timeout=2)
            for line in r.stdout.splitlines():
                if "<00>" in line and "UNIQUE" in line:
                    name = line.split()[0]
                    return name
        except Exception:
            pass
    return ""

OUI = {
    "FC-34-97": "Apple",
    "00-1C-B3": "Apple",
    "3C-5A-B4": "Dell",
    "00-50-56": "VMware",
    "00-0C-29": "VMware",
    "F0-9E-4A": "HP",
    "00-1E-65": "Lenovo",
    "AC-2B-6E": "Lenovo",
    "B8-27-EB": "RaspberryPi",
    "C8-2A-14": "Huawei",
    "84-16-F9": "Xiaomi",
    "DC-4A-3E": "Microsoft",
    "D8-CB-8A": "ASUS",
    "50-7A-C5": "TP-Link",
    "08-00-27": "Oracle",
    "00-15-5D": "Microsoft",
    "00-1C-42": "Parallels",
    "00-1D-D8": "Realtek",
    "F8-16-54": "Intel",
    "00-19-E0": "Cisco",
    "AC-3D-05": "Samsung",
}

CUSTOM_OUI = {}

def normalize_mac(mac):
    if not mac:
        return ""
    s = re.sub(r"[^0-9A-Fa-f]", "", mac)
    s = s.upper()
    if len(s) == 12:
        return ":".join(s[i:i+2] for i in range(0, 12, 2))
    mm = mac.upper().replace("-", ":").replace(".", ":")
    return mm

def vendor_from_mac(mac):
    if not mac:
        return ""
    mm = normalize_mac(mac)
    pref = "-".join(mm.split(":")[:3])
    if pref in CUSTOM_OUI:
        return CUSTOM_OUI.get(pref, "Unknown")
    if MAC_LOOKUP:
        try:
            return MAC_LOOKUP.lookup(mm)
        except Exception:
            pass
    for k, v in OUI.items():
        if pref == k:
            return v
    return "Unknown"

class Tooltip:
    def __init__(self, widget):
        self.widget = widget
        self.tip = None
    def show(self, text, x, y):
        if self.tip:
            self.tip.destroy()
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x+10}+{y+10}")
        label = tk.Label(self.tip, text=text, bg="#ffffe0", relief=tk.SOLID, borderwidth=1, font=("Segoe UI", 9))
        label.pack(ipadx=4, ipady=2)
    def hide(self):
        if self.tip:
            self.tip.destroy()
            self.tip = None

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("网络扫描工具")
        top = ttk.Frame(root)
        top.pack(fill=tk.X, padx=8, pady=6)
        ttk.Label(top, text="选择网卡").pack(side=tk.LEFT)
        self.adapter_var = tk.StringVar()
        self.adapter_box = ttk.Combobox(top, textvariable=self.adapter_var, state="readonly", width=40)
        self.adapter_box.pack(side=tk.LEFT, padx=8)
        ttk.Label(top, text="输入网段").pack(side=tk.LEFT)
        self.manual_net_var = tk.StringVar()
        self.manual_net_entry = ttk.Entry(top, textvariable=self.manual_net_var, width=20)
        self.manual_net_entry.pack(side=tk.LEFT, padx=6)
        self.start_btn = ttk.Button(top, text="开始扫描", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=6)
        self.stop_btn = ttk.Button(top, text="停止扫描", command=self.stop_scan)
        self.stop_btn.pack(side=tk.LEFT, padx=6)
        self.rescan_btn = ttk.Button(top, text="重新扫描", command=self.rescan)
        self.rescan_btn.pack(side=tk.LEFT, padx=6)
        self.update_vendor_btn = ttk.Button(top, text="更新厂商库", command=self.manual_update_vendor_db)
        self.update_vendor_btn.pack(side=tk.LEFT, padx=6)
        self.add_prefix_btn = ttk.Button(top, text="添加厂商前缀", command=self.add_prefix)
        self.add_prefix_btn.pack(side=tk.LEFT, padx=6)
        self.progress_var = tk.DoubleVar(value=0)
        self.progress = ttk.Progressbar(top, variable=self.progress_var, maximum=100, length=200)
        self.progress.pack(side=tk.RIGHT)
        self.progress_text = tk.StringVar(value="0%")
        ttk.Label(top, textvariable=self.progress_text).pack(side=tk.RIGHT, padx=6)
        body = ttk.Frame(root)
        body.pack(fill=tk.BOTH, expand=True)
        self.canvas = tk.Canvas(body, width=860, height=520)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.side = ttk.Frame(body, width=280)
        self.side.pack(side=tk.RIGHT, fill=tk.Y)
        ttk.Label(self.side, text="当前网段").pack(anchor="w", padx=8, pady=(8,2))
        self.network_var = tk.StringVar(value="-")
        ttk.Label(self.side, textvariable=self.network_var).pack(anchor="w", padx=16)
        ttk.Label(self.side, text="扫描统计").pack(anchor="w", padx=8, pady=(12,2))
        self.total_var = tk.StringVar(value="总计: 0")
        self.online_var = tk.StringVar(value="在线: 0")
        self.offline_var = tk.StringVar(value="离线: 0")
        ttk.Label(self.side, textvariable=self.total_var).pack(anchor="w", padx=16)
        ttk.Label(self.side, textvariable=self.online_var).pack(anchor="w", padx=16)
        ttk.Label(self.side, textvariable=self.offline_var).pack(anchor="w", padx=16)
        self.elapsed_var = tk.StringVar(value="本次用时: -")
        ttk.Label(self.side, textvariable=self.elapsed_var).pack(anchor="w", padx=16)
        ttk.Label(self.side, text="选中主机").pack(anchor="w", padx=8, pady=(12,2))
        self.sel_ip_var = tk.StringVar(value="IP: -")
        self.sel_status_var = tk.StringVar(value="状态: -")
        self.sel_mac_var = tk.StringVar(value="MAC: -")
        self.sel_name_var = tk.StringVar(value="名称: -")
        self.sel_vendor_var = tk.StringVar(value="类型: -")
        self.sel_evidence_var = tk.StringVar(value="判定依据: -")
        self.sel_reason_var = tk.StringVar(value="离线可能性: -")
        self.sel_last_online_var = tk.StringVar(value="上次在线: -")
        ttk.Label(self.side, textvariable=self.sel_ip_var).pack(anchor="w", padx=16)
        ttk.Label(self.side, textvariable=self.sel_status_var).pack(anchor="w", padx=16)
        ttk.Label(self.side, textvariable=self.sel_mac_var).pack(anchor="w", padx=16)
        ttk.Label(self.side, textvariable=self.sel_name_var).pack(anchor="w", padx=16)
        ttk.Label(self.side, textvariable=self.sel_vendor_var).pack(anchor="w", padx=16)
        ttk.Label(self.side, textvariable=self.sel_evidence_var, wraplength=240).pack(anchor="w", padx=16)
        ttk.Label(self.side, textvariable=self.sel_reason_var, wraplength=240).pack(anchor="w", padx=16)
        ttk.Label(self.side, textvariable=self.sel_last_online_var).pack(anchor="w", padx=16)
        ttk.Label(self.side, text="提示").pack(anchor="w", padx=8, pady=(12,2))
        self.vendor_msg_var = tk.StringVar(value="厂商库状态: -")
        ttk.Label(self.side, textvariable=self.vendor_msg_var, wraplength=240).pack(anchor="w", padx=16)
        self.status = tk.StringVar()
        ttk.Label(root, textvariable=self.status).pack(anchor="w", padx=8, pady=4)
        self.tooltip = Tooltip(self.canvas)
        self.rects = {}
        self.records = {}
        self.adapters = list_adapters()
        vals = [f"{a['name']} ({a['ip']})" for a in self.adapters]
        if vals:
            self.adapter_box["values"] = vals
            self.adapter_box.current(0)
        self.scanning = False
        self.stop_btn.configure(state=tk.DISABLED)
        self.rescan_btn.configure(state=tk.NORMAL)
        self.status.set("请选择网卡后点击开始扫描")
        self.vendor_updated = False
        self.last_online_map = self.load_last_online()
        self.update_vendor_db()
    def start_scan(self):
        if self.scanning:
            return
        ip = None
        mask = None
        cidr = (self.manual_net_var.get() or "").strip()
        if cidr:
            try:
                net = ipaddress.IPv4Network(cidr, strict=False)
                ip = str(net.network_address)
                mask = str(net.netmask)
            except Exception:
                messagebox.showerror("网段错误", "请输入有效的CIDR，如 192.168.146.0/24")
                return
        if not cidr:
            if getattr(self, "adapters", None):
                idx = self.adapter_box.current()
                if idx is not None and idx >= 0:
                    sel = self.adapters[idx]
                    ip = sel["ip"]
                    mask = sel["mask"]
            if not ip or not mask:
                try:
                    ip, mask = get_ip_mask()
                except Exception:
                    self.status.set("无法获取本机IP/子网掩码")
                    return
        hosts = network_hosts(ip, mask)
        self.scan_ip = ip
        self.scan_mask = mask
        self.current_hosts = hosts
        self.draw_grid(hosts)
        self.update_summary()
        self.scanning = True
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.rescan_btn.configure(state=tk.DISABLED)
        self.progress_var.set(0)
        self.progress_text.set("0%")
        self.status.set("扫描进行中")
        self.scan_start_ts = time.time()
        def work():
            import threading
            self.stop_event = threading.Event()
            done = 0
            total = len(hosts)
            online = {}
            arpmap = parse_arp()
            with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
                futs = {ex.submit(ping, ip): ip for ip in hosts}
                for f in concurrent.futures.as_completed(futs):
                    if self.stop_event.is_set():
                        try:
                            ex.shutdown(wait=False, cancel_futures=True)
                        except Exception:
                            pass
                        break
                    ipx = futs[f]
                    try:
                        ok = f.result()
                    except Exception:
                        ok = False
                    online[ipx] = ok
                    done += 1
                    pct = int(done * 100 / total) if total else 100
                    self.root.after(0, lambda p=pct: (self.progress_var.set(p), self.progress_text.set(f"{p}%")))
                    self.root.after(0, lambda ipx=ipx, ok=ok: self.update_cell(ipx, ok))
            recs = {}
            t = datetime.now().isoformat(timespec="seconds")
            for h in hosts:
                on = online.get(h, False)
                mac = arpmap.get(h, "")
                name = resolve_name(h) if on else ""
                vend = vendor_from_mac(mac)
                ev = f"ping={'在线' if on else '离线'}, arp={'有' if mac else '无'}"
                if on:
                    reason = "在线"
                else:
                    reason = "Ping无响应，ARP无记录，可能离线或不在网段" if not mac else "Ping无响应，但ARP存在，可能ICMP被防火墙阻止"
                last_on = t if on else self.last_online_map.get(h, "")
                recs[h] = {"ip": h, "online": on, "mac": mac, "name": name, "vendor": vend, "time": t, "evidence": ev, "reason": reason, "last_online": last_on}
            canceled = self.stop_event.is_set()
            self.root.after(0, lambda: self.finish_scan(recs, canceled))
        import threading
        threading.Thread(target=work, daemon=True).start()
    def stop_scan(self):
        if getattr(self, "stop_event", None):
            self.stop_event.set()
    def rescan(self):
        if self.scanning:
            return
        self.records = {}
        self.progress_var.set(0)
        self.progress_text.set("0%")
        self.start_scan()
    def update_cell(self, ip, online):
        rect = self.rects.get(ip)
        if rect:
            self.canvas.itemconfig(rect, fill="#52c41a" if online else "#ff4d4f")
    def select_ip(self, ip):
        rec = self.records.get(ip, {})
        self.selected_ip = ip
        self.sel_ip_var.set(f"IP: {ip}")
        self.sel_status_var.set(f"状态: {'在线' if rec.get('online') else '离线'}")
        self.sel_mac_var.set(f"MAC: {rec.get('mac') or '-'}")
        self.sel_name_var.set(f"名称: {rec.get('name') or '-'}")
        self.sel_vendor_var.set(f"类型: {rec.get('vendor') or '-'}")
        self.sel_evidence_var.set(f"判定依据: {rec.get('evidence') or '-'}")
        self.sel_reason_var.set(f"离线可能性: {rec.get('reason') or '-'}")
        lo = rec.get('last_online') or self.last_online_map.get(ip, '')
        self.sel_last_online_var.set(f"上次在线: {lo or '-'}")
    def update_summary(self):
        try:
            net = ipaddress.IPv4Network(f"{self.scan_ip}/{self.scan_mask}", strict=False)
            self.network_var.set(str(net))
        except Exception:
            self.network_var.set("-")
        total = len(self.current_hosts or [])
        online = sum(1 for ip in (self.current_hosts or []) if self.records.get(ip, {}).get('online'))
        offline = total - online
        self.total_var.set(f"总计: {total}")
        self.online_var.set(f"在线: {online}")
        self.offline_var.set(f"离线: {offline}")
    def finish_scan(self, recs, canceled):
        self.records = recs
        self.scanning = False
        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.rescan_btn.configure(state=tk.NORMAL)
        if not canceled:
            self.progress_var.set(100)
            self.progress_text.set("100%")
            self.status.set("扫描完成")
            elapsed = time.time() - (self.scan_start_ts or time.time())
            self.elapsed_var.set(f"本次用时: {elapsed:.1f}s")
            self.save_csv(recs)
            self.save_history(recs)
            self.update_last_online(recs)
            self.update_summary()
        else:
            self.status.set("扫描已停止")
    def draw_grid(self, hosts):
        self.canvas.delete("all")
        cols = 17
        size = 28
        pad = 4
        for idx, ip in enumerate(hosts[:254]):
            r = idx // cols
            c = idx % cols
            x0 = pad + c * (size + pad)
            y0 = pad + r * (size + pad)
            x1 = x0 + size
            y1 = y0 + size
            rect = self.canvas.create_rectangle(x0, y0, x1, y1, fill="#ff4d4f", outline="#d9d9d9")
            text = self.canvas.create_text(x0 + size/2, y0 + size/2, text=str(idx+1), font=("Segoe UI", 8))
            self.rects[ip] = rect
            def enter(e, ip=ip):
                rec = self.records.get(ip, {})
                info = []
                info.append(f"IP: {ip}")
                info.append(f"状态: {'在线' if rec.get('online') else '离线'}")
                if rec.get("mac"):
                    info.append(f"MAC: {rec.get('mac')}")
                if rec.get("name"):
                    info.append(f"名称: {rec.get('name')}")
                if rec.get("vendor"):
                    info.append(f"类型: {rec.get('vendor')}")
                lo = rec.get("last_online") or self.last_online_map.get(ip, "")
                if lo:
                    info.append(f"上次在线: {lo}")
                self.tooltip.show("\n".join(info), e.x_root, e.y_root)
            def leave(e):
                self.tooltip.hide()
            self.canvas.tag_bind(rect, "<Enter>", enter)
            self.canvas.tag_bind(text, "<Enter>", enter)
            self.canvas.tag_bind(rect, "<Leave>", leave)
            self.canvas.tag_bind(text, "<Leave>", leave)
            self.canvas.tag_bind(rect, "<Button-1>", lambda e, ip=ip: self.select_ip(ip))
            self.canvas.tag_bind(text, "<Button-1>", lambda e, ip=ip: self.select_ip(ip))
    def update_results(self, recs):
        self.records = recs
        for ip, rec in recs.items():
            rect = self.rects.get(ip)
            if rect:
                if rec["online"]:
                    color = "#52c41a"
                else:
                    was_online = bool(rec.get("last_online") or self.last_online_map.get(ip))
                    color = "#8c8c8c" if was_online else "#ff4d4f"
                self.canvas.itemconfig(rect, fill=color)
        self.status.set("扫描完成")
        self.save_csv(recs)
    def save_csv(self, recs):
        rows = sorted(recs.values(), key=lambda x: x["ip"])
        with open("hosts.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["ip", "online", "mac", "name", "vendor", "time"])
            w.writeheader()
            w.writerows(rows)
    def save_history(self, recs):
        rows = sorted(recs.values(), key=lambda x: x["ip"])
        need_header = not os.path.exists("history.csv")
        with open("history.csv", "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["ip", "online", "mac", "name", "vendor", "time"])
            if need_header:
                w.writeheader()
            w.writerows(rows)
    def load_last_online(self):
        m = {}
        p = "last_online.csv"
        if os.path.exists(p):
            try:
                with open(p, "r", newline="", encoding="utf-8") as f:
                    r = csv.DictReader(f)
                    for row in r:
                        ip = row.get("ip")
                        lo = row.get("last_online")
                        if ip and lo:
                            m[ip] = lo
            except Exception:
                pass
        return m
    def update_last_online(self, recs):
        for ip, rec in recs.items():
            if rec.get("online"):
                self.last_online_map[ip] = rec.get("time")
        rows = [{"ip": ip, "last_online": t} for ip, t in sorted(self.last_online_map.items())]
        with open("last_online.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["ip", "last_online"])
            w.writeheader()
            w.writerows(rows)
    def update_vendor_db(self):
        if getattr(self, "vendor_updated", False):
            return
        if MAC_LOOKUP is None:
            self.vendor_msg_var.set("厂商库状态: 未安装，将使用内置词典")
            self.vendor_updated = True
            return
        def work():
            try:
                MAC_LOOKUP.update_vendors()
                self.root.after(0, lambda: self.vendor_msg_var.set("厂商库状态: 已更新"))
            except Exception:
                self.root.after(0, lambda: self.vendor_msg_var.set("厂商库状态: 更新失败，网络不可用，将使用内置词典"))
            self.vendor_updated = True
        import threading
        threading.Thread(target=work, daemon=True).start()
    def manual_update_vendor_db(self):
        if MAC_LOOKUP is None:
            self.vendor_msg_var.set("厂商库状态: 未安装，将使用内置词典")
            return
        self.update_vendor_btn.configure(state=tk.DISABLED)
        def work():
            ok = True
            try:
                MAC_LOOKUP.update_vendors()
            except Exception:
                ok = False
            def after():
                self.update_vendor_btn.configure(state=tk.NORMAL)
                if ok:
                    self.vendor_msg_var.set("厂商库状态: 已更新")
                    if self.records:
                        for ip, rec in list(self.records.items()):
                            m = rec.get("mac")
                            rec["vendor"] = vendor_from_mac(m) if m else rec.get("vendor")
                        self.update_summary()
                else:
                    self.vendor_msg_var.set("厂商库状态: 更新失败，网络不可用，将使用内置词典")
            self.root.after(0, after)
        import threading
        threading.Thread(target=work, daemon=True).start()
    def add_prefix(self):
        p = simpledialog.askstring("添加前缀", "请输入MAC前缀（格式如 1C-69-7A）：")
        if not p:
            return
        p = p.strip().upper()
        if not re.match(r"^[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}$", p):
            messagebox.showerror("格式错误", "请输入形如 XX-XX-XX 的前缀")
            return
        v = simpledialog.askstring("厂商名称", "请输入厂商名称（例：某某科技）")
        if not v:
            return
        CUSTOM_OUI[p] = v.strip()
        self.vendor_msg_var.set(f"厂商库状态: 已添加 {p} -> {CUSTOM_OUI[p]}")
        if self.records:
            for ip, rec in list(self.records.items()):
                m = rec.get("mac")
                if m:
                    mm = m.upper().replace("-", ":").replace(".", ":")
                    pref = "-".join(mm.split(":")[:3])
                    if pref == p:
                        rec["vendor"] = CUSTOM_OUI[p]
            self.update_summary()

def main():
    root = tk.Tk()
    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
