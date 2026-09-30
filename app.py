#!/usr/bin/env python3
"""
NetAnalyzer - a web-based network analyzer for Ubuntu.

Features
  * Live bandwidth per interface (upload / download rate + history chart)
  * Packet capture with protocol breakdown, top talkers, top ports, live packet list
  * BPF capture filters (e.g. "tcp port 443", "host 192.168.1.10")
  * Active connections with owning process
  * Ping and DNS lookup tools

Packet capture needs root or CAP_NET_RAW (see README.md).
"""
import argparse
import collections
import ipaddress
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import psutil
from flask import Flask, Response, jsonify, request

try:
    from scapy.all import AsyncSniffer, ARP, DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP, conf

    conf.verb = 0
    SCAPY_OK, SCAPY_ERR = True, ""
except Exception as exc:  # scapy missing or broken
    SCAPY_OK, SCAPY_ERR = False, str(exc)

app = Flask(__name__)

HISTORY_SECONDS = 120
WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 137: "NetBIOS",
    143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP",
    993: "IMAPS", 995: "POP3S", 1883: "MQTT", 3306: "MySQL", 3389: "RDP",
    5353: "mDNS", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
}


# --------------------------------------------------------------------------- #
# Bandwidth monitor
# --------------------------------------------------------------------------- #
class BandwidthMonitor(threading.Thread):
    """Samples interface counters once per second and keeps a rolling history."""

    def __init__(self):
        super().__init__(daemon=True)
        self.lock = threading.Lock()
        self.history = collections.defaultdict(lambda: collections.deque(maxlen=HISTORY_SECONDS))
        self.current = {}

    def run(self):
        prev = psutil.net_io_counters(pernic=True)
        prev_t = time.time()
        while True:
            time.sleep(1)
            now = psutil.net_io_counters(pernic=True)
            now_t = time.time()
            dt = max(now_t - prev_t, 1e-6)
            with self.lock:
                for nic, c in now.items():
                    p = prev.get(nic)
                    if not p:
                        continue
                    rx = max(c.bytes_recv - p.bytes_recv, 0) / dt
                    tx = max(c.bytes_sent - p.bytes_sent, 0) / dt
                    self.current[nic] = {
                        "rx_rate": rx, "tx_rate": tx,
                        "bytes_recv": c.bytes_recv, "bytes_sent": c.bytes_sent,
                        "packets_recv": c.packets_recv, "packets_sent": c.packets_sent,
                        "errin": c.errin, "errout": c.errout,
                        "dropin": c.dropin, "dropout": c.dropout,
                    }
                    self.history[nic].append({"t": now_t, "rx": rx, "tx": tx})
            prev, prev_t = now, now_t

    def snapshot(self):
        with self.lock:
            return {
                "current": dict(self.current),
                "history": {k: list(v) for k, v in self.history.items()},
            }


# --------------------------------------------------------------------------- #
# Packet capture
# --------------------------------------------------------------------------- #
class PacketCapture:
    def __init__(self):
        self.lock = threading.Lock()
        self.sniffer = None
        self.iface = None
        self.bpf = ""
        self.error = ""
        self.started_at = None
        self.reset()

    def reset(self):
        with self.lock:
            self.protocols = collections.Counter()
            self.src_bytes = collections.Counter()
            self.dst_bytes = collections.Counter()
            self.ports = collections.Counter()
            self.recent = collections.deque(maxlen=300)
            self.total_packets = 0
            self.total_bytes = 0
            self.pps_window = collections.deque(maxlen=HISTORY_SECONDS)
            self._sec_bucket = [int(time.time()), 0, 0]  # second, packets, bytes

    @property
    def running(self):
        return self.sniffer is not None and getattr(self.sniffer, "running", False)

    def start(self, iface=None, bpf=""):
        if not SCAPY_OK:
            raise RuntimeError(f"Scapy is not available: {SCAPY_ERR}")
        self.stop()
        self.error = ""
        self.iface = iface or None
        self.bpf = bpf.strip()
        try:
            self.sniffer = AsyncSniffer(
                iface=self.iface, filter=self.bpf or None, prn=self._handle, store=False
            )
            self.sniffer.start()
            time.sleep(0.4)  # let scapy surface permission / filter errors
            if getattr(self.sniffer, "exception", None):
                raise self.sniffer.exception
            self.started_at = time.time()
        except PermissionError:
            self.sniffer = None
            raise RuntimeError("Permission denied. Run with sudo or grant CAP_NET_RAW (see README).")
        except Exception as exc:
            self.sniffer = None
            raise RuntimeError(f"Could not start capture: {exc}")

    def stop(self):
        if self.sniffer is not None:
            try:
                if self.sniffer.running:
                    self.sniffer.stop()
            except Exception:
                pass
        self.sniffer = None

    # -- per-packet ---------------------------------------------------------- #
    def _handle(self, pkt):
        length = len(pkt)
        src = dst = ""
        proto, info, port = "Other", "", None

        if ARP in pkt:
            a = pkt[ARP]
            proto, src, dst = "ARP", a.psrc, a.pdst
            info = f"Who has {a.pdst}? Tell {a.psrc}" if a.op == 1 else f"{a.psrc} is at {a.hwsrc}"
        elif IP in pkt or IPv6 in pkt:
            layer = pkt[IP] if IP in pkt else pkt[IPv6]
            src, dst = layer.src, layer.dst
            proto = "IPv4" if IP in pkt else "IPv6"
            if TCP in pkt:
                t = pkt[TCP]
                port = min(t.sport, t.dport)
                proto = WELL_KNOWN_PORTS.get(t.dport) or WELL_KNOWN_PORTS.get(t.sport) or "TCP"
                info = f"{t.sport} → {t.dport} [{t.flags}] len={len(t.payload)}"
            elif UDP in pkt:
                u = pkt[UDP]
                port = min(u.sport, u.dport)
                proto = WELL_KNOWN_PORTS.get(u.dport) or WELL_KNOWN_PORTS.get(u.sport) or "UDP"
                info = f"{u.sport} → {u.dport} len={len(u.payload)}"
                if DNS in pkt and pkt.haslayer(DNSQR):
                    proto = "DNS"
                    qname = pkt[DNSQR].qname
                    qname = qname.decode(errors="ignore") if isinstance(qname, bytes) else str(qname)
                    kind = "response" if pkt[DNS].qr else "query"
                    info = f"{kind} {qname.rstrip('.')}"
            elif ICMP in pkt:
                ic = pkt[ICMP]
                proto = "ICMP"
                names = {0: "echo reply", 3: "unreachable", 8: "echo request", 11: "time exceeded"}
                info = names.get(ic.type, f"type {ic.type}")
            elif IPv6 in pkt and pkt[IPv6].nh == 58:
                proto, info = "ICMPv6", "ICMPv6"

        now = time.time()
        with self.lock:
            self.total_packets += 1
            self.total_bytes += length
            self.protocols[proto] += 1
            if src:
                self.src_bytes[src] += length
            if dst:
                self.dst_bytes[dst] += length
            if port is not None:
                self.ports[port] += 1
            self.recent.append({
                "time": datetime.fromtimestamp(now).strftime("%H:%M:%S.%f")[:-3],
                "src": src, "dst": dst, "proto": proto, "len": length, "info": info,
            })
            sec = int(now)
            if sec != self._sec_bucket[0]:
                self.pps_window.append({"t": self._sec_bucket[0], "pps": self._sec_bucket[1],
                                        "bps": self._sec_bucket[2]})
                self._sec_bucket = [sec, 0, 0]
            self._sec_bucket[1] += 1
            self._sec_bucket[2] += length

    def snapshot(self, limit=100):
        with self.lock:
            return {
                "running": self.running,
                "iface": self.iface or "all",
                "filter": self.bpf,
                "started_at": self.started_at,
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "protocols": self.protocols.most_common(),
                "top_src": self.src_bytes.most_common(10),
                "top_dst": self.dst_bytes.most_common(10),
                "top_ports": [(p, WELL_KNOWN_PORTS.get(p, ""), c) for p, c in self.ports.most_common(10)],
                "recent": list(self.recent)[-limit:][::-1],
                "pps": list(self.pps_window),
                "scapy_ok": SCAPY_OK,
                "scapy_err": SCAPY_ERR,
            }


# --------------------------------------------------------------------------- #
# Network / host scanner  (LAN host discovery + common-port scan)
# --------------------------------------------------------------------------- #
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443]


class NetworkScanner:
    """Discovers live hosts on a subnet, then scans common TCP ports on each."""

    def __init__(self):
        self.lock = threading.Lock()
        self.thread = None
        self.stop_flag = threading.Event()
        self.reset()

    def reset(self):
        self.state = "idle"          # idle | running | done | error
        self.cidr = ""
        self.message = ""
        self.started_at = None
        self.done_at = None
        self.total = 0
        self.scanned = 0
        self.hosts = {}              # ip -> {ip, mac, hostname, ports:[...], responded}

    @property
    def running(self):
        return self.state == "running"

    def start(self, cidr, do_ports=True):
        if self.running:
            raise RuntimeError("A scan is already running.")
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise RuntimeError(f"Invalid network: {exc}")
        if net.version != 4:
            raise RuntimeError("Only IPv4 ranges are supported.")
        if net.num_addresses > 4096:
            raise RuntimeError("Range too large (max /20, 4096 addresses). Narrow it down.")

        with self.lock:
            self.reset()
            self.state = "running"
            self.cidr = str(net)
            self.started_at = time.time()
            hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
            self.total = len(hosts)
        self.stop_flag.clear()
        self.thread = threading.Thread(target=self._run, args=(hosts, do_ports), daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_flag.set()

    # -- discovery ----------------------------------------------------------- #
    def _arp_table(self):
        """Read the kernel ARP cache -> {ip: mac} (fills in MACs for free)."""
        table = {}
        try:
            with open("/proc/net/arp") as fh:
                next(fh, None)
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                        table[parts[0]] = parts[3]
        except OSError:
            pass
        return table

    def _arp_scan(self, hosts):
        """Fast layer-2 discovery with scapy (LAN only). Returns {ip: mac}."""
        if not SCAPY_OK:
            return {}
        found = {}
        try:
            from scapy.all import Ether, srp
            for i in range(0, len(hosts), 256):
                if self.stop_flag.is_set():
                    break
                chunk = [str(h) for h in hosts[i:i + 256]]
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=chunk)
                ans, _ = srp(pkt, timeout=2, verbose=0)
                for _s, r in ans:
                    found[r.psrc] = r.hwsrc
        except Exception:
            pass
        return found

    def _tcp_alive(self, ip):
        """Fallback probe: a host is 'up' if any common port answers or refuses."""
        for port in (80, 443, 22, 445, 3389):
            if self.stop_flag.is_set():
                return False
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.4)
                    if s.connect_ex((ip, port)) == 0:
                        return True
            except OSError:
                pass
        return False

    def _scan_ports(self, ip):
        open_ports = []
        for port in COMMON_PORTS:
            if self.stop_flag.is_set():
                break
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports.append({"port": port, "service": WELL_KNOWN_PORTS.get(port, "")})
            except OSError:
                pass
        return open_ports

    def _run(self, hosts, do_ports):
        try:
            arp_pre = self._arp_table()
            arp_scan = self._arp_scan(hosts)

            def probe(host):
                ip = str(host)
                if self.stop_flag.is_set():
                    return
                mac = arp_scan.get(ip) or arp_pre.get(ip, "")
                alive = bool(mac) or self._tcp_alive(ip)
                with self.lock:
                    self.scanned += 1
                    if not alive:
                        return
                    hostname = ""
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except OSError:
                        pass
                    self.hosts[ip] = {"ip": ip, "mac": mac, "hostname": hostname,
                                      "ports": [], "scanning_ports": do_ports}

            with ThreadPoolExecutor(max_workers=100) as pool:
                pool.map(probe, hosts)

            if do_ports and not self.stop_flag.is_set():
                with self.lock:
                    targets = list(self.hosts.keys())

                def portscan(ip):
                    if self.stop_flag.is_set():
                        return
                    ports = self._scan_ports(ip)
                    with self.lock:
                        if ip in self.hosts:
                            self.hosts[ip]["ports"] = ports
                            self.hosts[ip]["scanning_ports"] = False

                with ThreadPoolExecutor(max_workers=50) as pool:
                    pool.map(portscan, targets)

            with self.lock:
                self.state = "done"
                self.done_at = time.time()
                self.message = "Scan cancelled." if self.stop_flag.is_set() else ""
        except Exception as exc:
            with self.lock:
                self.state = "error"
                self.message = str(exc)
                self.done_at = time.time()

    def snapshot(self):
        with self.lock:
            hosts = sorted(self.hosts.values(),
                           key=lambda h: tuple(int(x) for x in h["ip"].split(".")))
            return {
                "state": self.state,
                "cidr": self.cidr,
                "message": self.message,
                "total": self.total,
                "scanned": self.scanned,
                "elapsed": (self.done_at or time.time()) - self.started_at if self.started_at else 0,
                "host_count": len(hosts),
                "hosts": hosts,
            }


def local_ipv4_networks():
    """Guess the local subnets from interface addresses/netmasks."""
    nets = []
    for name, addr_list in psutil.net_if_addrs().items():
        if name == "lo":
            continue
        for a in addr_list:
            if a.family == socket.AF_INET and a.netmask:
                try:
                    net = ipaddress.ip_network(f"{a.address}/{a.netmask}", strict=False)
                    if net.num_addresses <= 4096 and not net.is_loopback:
                        nets.append({"cidr": str(net), "iface": name, "address": a.address})
                except ValueError:
                    pass
    return nets


bandwidth = BandwidthMonitor()
capture = PacketCapture()
scanner = NetworkScanner()

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:]{0,252}$")


def valid_host(host: str) -> bool:
    return bool(host) and bool(HOST_RE.match(host))


def interfaces_info():
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    out = []
    for name, addr_list in addrs.items():
        st = stats.get(name)
        ipv4 = [a.address for a in addr_list if a.family == socket.AF_INET]
        ipv6 = [a.address.split("%")[0] for a in addr_list if a.family == socket.AF_INET6]
        mac = next((a.address for a in addr_list if a.family == psutil.AF_LINK), "")
        out.append({
            "name": name, "ipv4": ipv4, "ipv6": ipv6, "mac": mac,
            "up": bool(st and st.isup), "speed": st.speed if st else 0, "mtu": st.mtu if st else 0,
        })
    return sorted(out, key=lambda i: (not i["up"], i["name"] == "lo", i["name"]))


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


@app.route("/api/system")
def api_system():
    return jsonify({
        "hostname": socket.gethostname(),
        "uptime": time.time() - psutil.boot_time(),
        "cpu": psutil.cpu_percent(interval=None),
        "mem": psutil.virtual_memory().percent,
        "scapy_ok": SCAPY_OK,
    })


@app.route("/api/interfaces")
def api_interfaces():
    return jsonify(interfaces_info())


@app.route("/api/bandwidth")
def api_bandwidth():
    return jsonify(bandwidth.snapshot())


@app.route("/api/connections")
def api_connections():
    kind = request.args.get("kind", "inet")
    if kind not in ("inet", "inet4", "inet6", "tcp", "udp"):
        kind = "inet"
    rows, denied = [], False
    try:
        conns = psutil.net_connections(kind=kind)
    except psutil.AccessDenied:
        conns, denied = [], True
    names = {}
    for c in conns:
        pname = ""
        if c.pid:
            if c.pid not in names:
                try:
                    names[c.pid] = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    names[c.pid] = ""
            pname = names[c.pid]
        rows.append({
            "proto": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
            "family": "IPv6" if c.family == socket.AF_INET6 else "IPv4",
            "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
            "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
            "status": c.status if c.status != "NONE" else "",
            "pid": c.pid or "",
            "process": pname,
        })
    rows.sort(key=lambda r: (r["status"] != "ESTABLISHED", r["status"] != "LISTEN", r["laddr"]))
    return jsonify({"connections": rows, "denied": denied})


@app.route("/api/capture/status")
def api_capture_status():
    return jsonify(capture.snapshot())


@app.route("/api/capture/start", methods=["POST"])
def api_capture_start():
    data = request.get_json(silent=True) or {}
    iface = data.get("iface") or None
    if iface and iface not in psutil.net_if_addrs():
        return jsonify({"ok": False, "error": "Unknown interface"}), 400
    try:
        capture.start(iface, data.get("filter", ""))
        return jsonify({"ok": True})
    except RuntimeError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.route("/api/capture/stop", methods=["POST"])
def api_capture_stop():
    capture.stop()
    return jsonify({"ok": True})


@app.route("/api/capture/reset", methods=["POST"])
def api_capture_reset():
    capture.reset()
    return jsonify({"ok": True})


@app.route("/api/scan/networks")
def api_scan_networks():
    return jsonify(local_ipv4_networks())


@app.route("/api/scan/status")
def api_scan_status():
    return jsonify(scanner.snapshot())


@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    data = request.get_json(silent=True) or {}
    try:
        scanner.start((data.get("cidr") or "").strip(), bool(data.get("ports", True)))
        return jsonify({"ok": True})
    except RuntimeError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.route("/api/scan/stop", methods=["POST"])
def api_scan_stop():
    scanner.stop()
    return jsonify({"ok": True})


@app.route("/api/tools/ping", methods=["POST"])
def api_ping():
    host = ((request.get_json(silent=True) or {}).get("host") or "").strip()
    if not valid_host(host):
        return jsonify({"ok": False, "output": "Invalid host name or IP."}), 400
    try:
        res = subprocess.run(["ping", "-c", "4", "-W", "2", host],
                             capture_output=True, text=True, timeout=20)
        return jsonify({"ok": res.returncode == 0, "output": res.stdout + res.stderr})
    except FileNotFoundError:
        return jsonify({"ok": False, "output": "ping not found. Install: sudo apt install iputils-ping"})
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "output": "Ping timed out."})


@app.route("/api/tools/dns", methods=["POST"])
def api_dns():
    host = ((request.get_json(silent=True) or {}).get("host") or "").strip()
    if not valid_host(host):
        return jsonify({"ok": False, "output": "Invalid host name or IP."}), 400
    lines = []
    try:
        infos = socket.getaddrinfo(host, None)
        seen = []
        for fam, *_rest, sa in infos:
            ip = sa[0]
            if ip not in seen:
                seen.append(ip)
                lines.append(f"{'AAAA' if fam == socket.AF_INET6 else 'A   '}  {ip}")
        try:
            rev = socket.gethostbyaddr(seen[0])[0] if seen else ""
            if rev:
                lines.append(f"PTR   {rev}")
        except OSError:
            pass
        return jsonify({"ok": True, "output": "\n".join(lines) or "No records"})
    except socket.gaierror as exc:
        return jsonify({"ok": False, "output": f"Lookup failed: {exc}"})


# --------------------------------------------------------------------------- #
# Web dashboard (built in, so no templates folder is needed)
# --------------------------------------------------------------------------- #
INDEX_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetAnalyzer</title>
<style>
  :root{
    --bg:#0f1419; --panel:#171e26; --panel2:#1e2731; --line:#2a3542;
    --text:#e6edf3; --muted:#8b98a5; --accent:#3fb6a8; --accent2:#e3a13b;
    --good:#4cc38a; --bad:#e5534b; --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Ubuntu,sans-serif}
  header{display:flex;align-items:center;gap:16px;padding:14px 20px;border-bottom:1px solid var(--line);flex-wrap:wrap}
  header h1{font-size:18px;margin:0;letter-spacing:.3px}
  header h1 span{color:var(--accent)}
  .meta{color:var(--muted);font-size:13px;display:flex;gap:14px;flex-wrap:wrap}
  nav{display:flex;gap:4px;margin-left:auto;flex-wrap:wrap}
  nav button{background:transparent;border:1px solid transparent;color:var(--muted);padding:7px 14px;border-radius:6px;cursor:pointer;font:inherit}
  nav button.active{background:var(--panel2);color:var(--text);border-color:var(--line)}
  main{padding:20px;max-width:1400px;margin:0 auto}
  .tab{display:none}.tab.active{display:block}
  .grid{display:grid;gap:14px}
  .g4{grid-template-columns:repeat(auto-fit,minmax(200px,1fr))}
  .g2{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
  .card h3{margin:0 0 10px;font-size:13px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);font-weight:600}
  .stat{font-size:24px;font-weight:600;font-variant-numeric:tabular-nums}
  .stat small{font-size:13px;color:var(--muted);font-weight:400}
  .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
  select,input{background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:8px 10px;font:inherit}
  input{min-width:220px}
  .btn{background:var(--accent);color:#08201d;border:0;border-radius:6px;padding:8px 16px;font:inherit;font-weight:600;cursor:pointer}
  .btn.sec{background:var(--panel2);color:var(--text);border:1px solid var(--line)}
  .btn.stop{background:var(--bad);color:#fff}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
  th{color:var(--muted);font-weight:600;position:sticky;top:0;background:var(--panel)}
  td.mono,.mono{font-family:var(--mono);font-size:12.5px}
  .scroll{max-height:460px;overflow:auto}
  .pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11.5px;font-weight:600;background:var(--panel2);border:1px solid var(--line)}
  .up{color:var(--good)} .down{color:var(--bad)}
  .bar{height:6px;background:var(--panel2);border-radius:3px;overflow:hidden;margin-top:3px}
  .bar i{display:block;height:100%;background:var(--accent)}
  .msg{padding:10px 12px;border-radius:6px;background:#3a2a12;color:#f3cf8f;border:1px solid #5c4119;margin-bottom:14px;display:none}
  pre{background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:12px;min-height:120px;overflow:auto;font-family:var(--mono);font-size:12.5px;margin:10px 0 0;white-space:pre-wrap}
  .dot{width:9px;height:9px;border-radius:50%;display:inline-block;background:var(--muted)}
  .dot.on{background:var(--good);box-shadow:0 0 8px var(--good)}
  .chartbox{position:relative;height:260px}
  .ifsel{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
  .ifsel button{background:var(--panel2);border:1px solid var(--line);color:var(--muted);padding:4px 10px;border-radius:6px;cursor:pointer;font:inherit;font-size:12.5px}
  .ifsel button.active{color:var(--text);border-color:var(--accent)}
  @media (max-width:640px){main{padding:12px} nav{margin-left:0} input{min-width:0;flex:1}}
</style>
</head>
<body>
<header>
  <h1>Net<span>Analyzer</span></h1>
  <div class="meta"><span id="host">—</span><span id="uptime"></span><span id="cpu"></span><span id="mem"></span></div>
  <nav>
    <button class="active" data-tab="overview">Overview</button>
    <button data-tab="capture">Packet Capture</button>
    <button data-tab="discovery">Discovery</button>
    <button data-tab="connections">Connections</button>
    <button data-tab="tools">Tools</button>
  </nav>
</header>

<main>
  <!-- OVERVIEW -->
  <section class="tab active" id="overview">
    <div class="grid g4" id="totals"></div>
    <div class="card" style="margin-top:14px">
      <h3>Live bandwidth</h3>
      <div class="ifsel" id="ifButtons"></div>
      <div class="chartbox"><canvas id="bwChart"></canvas></div>
    </div>
    <div class="card" style="margin-top:14px">
      <h3>Interfaces</h3>
      <div class="scroll"><table id="ifTable"><thead><tr>
        <th>Interface</th><th>State</th><th>IPv4</th><th>MAC</th><th>Download</th><th>Upload</th>
        <th>Total RX</th><th>Total TX</th><th>Errors</th><th>Drops</th></tr></thead><tbody></tbody></table></div>
    </div>
  </section>

  <!-- CAPTURE -->
  <section class="tab" id="capture">
    <div class="msg" id="capMsg"></div>
    <div class="card">
      <div class="row">
        <span class="dot" id="capDot"></span>
        <select id="capIface"><option value="">All interfaces</option></select>
        <input id="capFilter" placeholder='BPF filter, e.g. "tcp port 443" or "host 10.0.0.5"'>
        <button class="btn" id="capStart">Start</button>
        <button class="btn stop" id="capStop">Stop</button>
        <button class="btn sec" id="capReset">Clear</button>
      </div>
    </div>
    <div class="grid g4" style="margin-top:14px">
      <div class="card"><h3>Packets</h3><div class="stat" id="cPackets">0</div></div>
      <div class="card"><h3>Data</h3><div class="stat" id="cBytes">0 B</div></div>
      <div class="card"><h3>Packets / sec</h3><div class="stat" id="cPps">0</div></div>
      <div class="card"><h3>Throughput</h3><div class="stat" id="cBps">0 B/s</div></div>
    </div>
    <div class="grid g2" style="margin-top:14px">
      <div class="card"><h3>Protocols</h3><div class="chartbox"><canvas id="protoChart"></canvas></div></div>
      <div class="card"><h3>Packet rate</h3><div class="chartbox"><canvas id="ppsChart"></canvas></div></div>
      <div class="card"><h3>Top sources (bytes)</h3><div id="topSrc"></div></div>
      <div class="card"><h3>Top destinations (bytes)</h3><div id="topDst"></div></div>
    </div>
    <div class="card" style="margin-top:14px">
      <h3>Top ports</h3>
      <div class="row" id="topPorts"></div>
    </div>
    <div class="card" style="margin-top:14px">
      <h3>Live packets</h3>
      <div class="scroll"><table id="pktTable"><thead><tr>
        <th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>Info</th></tr></thead><tbody></tbody></table></div>
    </div>
  </section>

  <!-- DISCOVERY -->
  <section class="tab" id="discovery">
    <div class="msg" id="scanMsg"></div>
    <div class="card">
      <div class="row">
        <select id="scanNet"><option value="">Detecting subnets…</option></select>
        <input id="scanCidr" placeholder="or type a range, e.g. 192.168.1.0/24" style="flex:1">
        <label class="row" style="gap:6px"><input type="checkbox" id="scanPorts" checked style="min-width:0"> scan ports</label>
        <button class="btn" id="scanStart">Scan</button>
        <button class="btn stop" id="scanStop">Stop</button>
      </div>
      <div style="margin-top:10px" id="scanProgress"></div>
      <div class="bar" style="margin-top:6px"><i id="scanBar" style="width:0%"></i></div>
    </div>
    <div class="card" style="margin-top:14px">
      <h3>Discovered hosts <span id="scanCount" class="meta"></span></h3>
      <div class="scroll" style="max-height:620px"><table id="scanTable"><thead><tr>
        <th>IP address</th><th>Hostname</th><th>MAC</th><th>Open ports</th></tr></thead><tbody></tbody></table></div>
    </div>
  </section>

  <!-- CONNECTIONS -->
  <section class="tab" id="connections">
    <div class="msg" id="connMsg"></div>
    <div class="card">
      <div class="row" style="margin-bottom:10px">
        <select id="connKind"><option value="inet">All</option><option value="tcp">TCP</option><option value="udp">UDP</option></select>
        <input id="connSearch" placeholder="Search address, process, status…">
        <span class="meta" id="connCount"></span>
      </div>
      <div class="scroll" style="max-height:620px"><table id="connTable"><thead><tr>
        <th>Proto</th><th>Local address</th><th>Remote address</th><th>Status</th><th>PID</th><th>Process</th></tr></thead><tbody></tbody></table></div>
    </div>
  </section>

  <!-- TOOLS -->
  <section class="tab" id="tools">
    <div class="grid g2">
      <div class="card"><h3>Ping</h3>
        <div class="row"><input id="pingHost" placeholder="8.8.8.8 or example.com"><button class="btn" id="pingBtn">Ping</button></div>
        <pre id="pingOut"></pre></div>
      <div class="card"><h3>DNS lookup</h3>
        <div class="row"><input id="dnsHost" placeholder="example.com"><button class="btn" id="dnsBtn">Lookup</button></div>
        <pre id="dnsOut"></pre></div>
    </div>
  </section>
</main>

<script>
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function fmtBytes(b){const u=["B","KB","MB","GB","TB"];let i=0;while(b>=1024&&i<u.length-1){b/=1024;i++}return (i?b.toFixed(1):Math.round(b))+" "+u[i]}
const fmtRate = b => fmtBytes(b)+"/s";
function fmtDur(s){s=Math.floor(s);const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return (d?d+"d ":"")+h+"h "+m+"m"}
async function api(url, body){
  const opt = body!==undefined ? {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)} : {};
  const r = await fetch(url, opt); return r.json();
}

// ---------- tabs ----------
let activeTab = "overview";
document.querySelectorAll("nav button").forEach(b => b.onclick = () => {
  document.querySelectorAll("nav button").forEach(x=>x.classList.toggle("active", x===b));
  document.querySelectorAll(".tab").forEach(t=>t.classList.toggle("active", t.id===b.dataset.tab));
  activeTab = b.dataset.tab; tick();
});

// ---------- charts ----------
// Tiny dependency-free canvas charts (works fully offline).
const PALETTE=["#3fb6a8","#e3a13b","#6c8cff","#e5534b","#b07cf0","#4cc38a","#d8699b","#58b0e0","#c9c95a","#8b98a5"];
const C_MUTED="#8b98a5", C_GRID="#2a3542", C_TEXT="#e6edf3";
class MiniChart{
  constructor(canvas, type, series, yFmt){
    this.cv=canvas; this.type=type; this.yFmt=yFmt||(v=>Math.round(v));
    this.data={labels:[],datasets:series.map(s=>({...s,data:[]}))};
    new ResizeObserver(()=>this.update()).observe(canvas.parentElement);
  }
  prep(){
    const dpr=window.devicePixelRatio||1, r=this.cv.parentElement.getBoundingClientRect();
    this.w=r.width; this.h=r.height; this.cv.width=r.width*dpr; this.cv.height=r.height*dpr;
    this.cv.style.width=r.width+"px"; this.cv.style.height=r.height+"px";
    const g=this.cv.getContext("2d"); g.setTransform(dpr,0,0,dpr,0,0); g.clearRect(0,0,r.width,r.height);
    g.font="12px system-ui,sans-serif"; return g;
  }
  update(){ if(!this.cv.offsetParent) return; const g=this.prep();
    this.type==="doughnut" ? this.donut(g) : this.axes(g); }
  axes(g){
    const ds=this.data.datasets, L=this.data.labels, n=L.length;
    // legend
    let lx=8; if(ds.length>1) ds.forEach(d=>{g.fillStyle=d.color;g.fillRect(lx,6,10,10);g.fillStyle=C_MUTED;g.fillText(d.label,lx+14,15);lx+=g.measureText(d.label).width+30;});
    const top=ds.length>1?28:10, left=78, right=10, bottom=24, W=this.w-left-right, H=this.h-top-bottom;
    const max=Math.max(1,...ds.flatMap(d=>d.data))*1.15;
    g.textAlign="right"; g.strokeStyle=C_GRID; g.lineWidth=1;
    for(let i=0;i<=4;i++){const y=top+H-H*i/4; g.beginPath();g.moveTo(left,y);g.lineTo(left+W,y);g.stroke();
      g.fillStyle=C_MUTED; g.fillText(this.yFmt(max*i/4),left-8,y+4);}
    if(!n){g.textAlign="center";g.fillText("Waiting for data…",left+W/2,top+H/2);return;}
    g.textAlign="center"; const step=Math.max(1,Math.ceil(n/Math.max(1,Math.floor(W/80))));
    const X=i=>left+(this.type==="bar"? (i+.5)*W/n : (n===1?W/2:i*W/(n-1)));
    for(let i=0;i<n;i+=step){const x=X(i),tw=g.measureText(L[i]).width/2; g.fillText(L[i],Math.min(Math.max(x,left+tw),left+W-tw),this.h-6);}
    const Y=v=>top+H-H*v/max;
    ds.forEach(d=>{
      if(this.type==="bar"){ g.fillStyle=d.color; const bw=Math.max(1,W/n*0.7);
        d.data.forEach((v,i)=>g.fillRect(X(i)-bw/2,Y(v),bw,top+H-Y(v))); return; }
      g.beginPath(); d.data.forEach((v,i)=>i?g.lineTo(X(i),Y(v)):g.moveTo(X(i),Y(v)));
      g.strokeStyle=d.color; g.lineWidth=2; g.stroke();
      g.lineTo(X(d.data.length-1),top+H); g.lineTo(X(0),top+H); g.closePath();
      g.globalAlpha=.13; g.fillStyle=d.color; g.fill(); g.globalAlpha=1;
    });
  }
  donut(g){
    const vals=this.data.datasets[0].data, L=this.data.labels, tot=vals.reduce((a,b)=>a+b,0);
    const cx=Math.min(this.w*0.28,this.h/2)+4, cy=this.h/2, R=Math.min(cx-6,this.h/2-6), r=R*0.6;
    if(!tot){g.fillStyle=C_MUTED;g.textAlign="center";g.fillText("No packets yet",this.w/2,cy);return;}
    let a=-Math.PI/2;
    vals.forEach((v,i)=>{const e=a+2*Math.PI*v/tot; g.beginPath();g.arc(cx,cy,R,a,e);g.arc(cx,cy,r,e,a,true);g.closePath();
      g.fillStyle=PALETTE[i%PALETTE.length];g.fill(); a=e;});
    g.fillStyle=C_TEXT; g.textAlign="center"; g.font="600 16px system-ui"; g.fillText(tot.toLocaleString(),cx,cy+2);
    g.font="11px system-ui"; g.fillStyle=C_MUTED; g.fillText("packets",cx,cy+17);
    g.textAlign="left"; g.font="12px system-ui"; const lx=cx+R+24;
    L.forEach((l,i)=>{const y=cy-(L.length*20)/2+i*20+12; g.fillStyle=PALETTE[i%PALETTE.length]; g.fillRect(lx,y-9,10,10);
      g.fillStyle=C_TEXT; g.fillText(l,lx+16,y); g.fillStyle=C_MUTED;
      g.textAlign="right"; g.fillText((vals[i]/tot*100).toFixed(1)+"%",this.w-6,y); g.textAlign="left";});
  }
}
const bwChart = new MiniChart($("#bwChart"),"line",
  [{label:"Download",color:"#3fb6a8"},{label:"Upload",color:"#e3a13b"}], v=>fmtRate(v));
const protoChart = new MiniChart($("#protoChart"),"doughnut",[{label:"Protocols"}]);
const ppsChart = new MiniChart($("#ppsChart"),"bar",[{label:"Packets/s",color:"#3fb6a8"}]);

// ---------- overview ----------
let selIface = null, ifaceMeta = [];
async function loadInterfaces(){
  ifaceMeta = await api("/api/interfaces");
  const sel = $("#capIface"); const cur = sel.value;
  sel.innerHTML = '<option value="">All interfaces</option>' + ifaceMeta.map(i=>`<option ${i.name===cur?"selected":""}>${esc(i.name)}</option>`).join("");
  if(!selIface){ const first = ifaceMeta.find(i=>i.up && i.name!=="lo") || ifaceMeta[0]; selIface = first && first.name; }
  $("#ifButtons").innerHTML = ifaceMeta.map(i=>`<button class="${i.name===selIface?"active":""}" data-if="${esc(i.name)}">${esc(i.name)}</button>`).join("");
  document.querySelectorAll("#ifButtons button").forEach(b=>b.onclick=()=>{selIface=b.dataset.if;loadInterfaces();refreshBandwidth()});
}
async function refreshBandwidth(){
  const d = await api("/api/bandwidth");
  let rx=0,tx=0,trx=0,ttx=0;
  const rows = ifaceMeta.map(i=>{
    const c = d.current[i.name] || {};
    if(i.name!=="lo"){rx+=c.rx_rate||0;tx+=c.tx_rate||0;trx+=c.bytes_recv||0;ttx+=c.bytes_sent||0}
    return `<tr><td><b>${esc(i.name)}</b></td>
      <td>${i.up?'<span class="up">● up</span>':'<span class="down">● down</span>'}${i.speed?` <span class="meta">${i.speed} Mb/s</span>`:""}</td>
      <td class="mono">${esc(i.ipv4.join(", ")||"—")}</td><td class="mono">${esc(i.mac||"—")}</td>
      <td class="mono">${fmtRate(c.rx_rate||0)}</td><td class="mono">${fmtRate(c.tx_rate||0)}</td>
      <td class="mono">${fmtBytes(c.bytes_recv||0)}</td><td class="mono">${fmtBytes(c.bytes_sent||0)}</td>
      <td class="mono">${(c.errin||0)+(c.errout||0)}</td><td class="mono">${(c.dropin||0)+(c.dropout||0)}</td></tr>`;
  });
  $("#ifTable tbody").innerHTML = rows.join("");
  $("#totals").innerHTML = `
    <div class="card"><h3>Download now</h3><div class="stat">${fmtRate(rx)}</div></div>
    <div class="card"><h3>Upload now</h3><div class="stat">${fmtRate(tx)}</div></div>
    <div class="card"><h3>Received (since boot)</h3><div class="stat">${fmtBytes(trx)}</div></div>
    <div class="card"><h3>Sent (since boot)</h3><div class="stat">${fmtBytes(ttx)}</div></div>`;
  const h = d.history[selIface] || [];
  bwChart.data.labels = h.map(p=>new Date(p.t*1000).toLocaleTimeString([],{hour12:false}));
  bwChart.data.datasets[0].data = h.map(p=>p.rx);
  bwChart.data.datasets[1].data = h.map(p=>p.tx);
  bwChart.update();
}

// ---------- capture ----------
function talkerList(list){
  if(!list.length) return '<div class="meta">No data yet</div>';
  const max = list[0][1] || 1;
  return list.map(([ip,b])=>`<div style="margin-bottom:8px"><div class="row" style="justify-content:space-between">
    <span class="mono">${esc(ip)}</span><span class="mono meta">${fmtBytes(b)}</span></div>
    <div class="bar"><i style="width:${(b/max*100).toFixed(1)}%"></i></div></div>`).join("");
}
function showMsg(el, text){ el.textContent = text; el.style.display = text ? "block" : "none"; }
async function refreshCapture(){
  const d = await api("/api/capture/status");
  if(!d.scapy_ok) showMsg($("#capMsg"), "Scapy is not installed: "+d.scapy_err+"  →  pip install scapy");
  $("#capDot").classList.toggle("on", d.running);
  $("#cPackets").textContent = d.total_packets.toLocaleString();
  $("#cBytes").textContent = fmtBytes(d.total_bytes);
  const last = d.pps[d.pps.length-1] || {pps:0,bps:0};
  $("#cPps").textContent = d.running ? last.pps : 0;
  $("#cBps").textContent = fmtRate(d.running ? last.bps : 0);
  protoChart.data.labels = d.protocols.slice(0,10).map(p=>p[0]);
  protoChart.data.datasets[0].data = d.protocols.slice(0,10).map(p=>p[1]);
  protoChart.update();
  const pw = d.pps.slice(-60);
  ppsChart.data.labels = pw.map(p=>new Date(p.t*1000).toLocaleTimeString([],{hour12:false}));
  ppsChart.data.datasets[0].data = pw.map(p=>p.pps);
  ppsChart.update();
  $("#topSrc").innerHTML = talkerList(d.top_src);
  $("#topDst").innerHTML = talkerList(d.top_dst);
  $("#topPorts").innerHTML = d.top_ports.length ? d.top_ports.map(([p,n,c])=>`<span class="pill">${p}${n?" · "+esc(n):""} <span class="meta">${c}</span></span>`).join("") : '<div class="meta">No data yet</div>';
  $("#pktTable tbody").innerHTML = d.recent.map(p=>`<tr><td class="mono">${p.time}</td><td class="mono">${esc(p.src)}</td>
    <td class="mono">${esc(p.dst)}</td><td><span class="pill">${esc(p.proto)}</span></td><td class="mono">${p.len}</td>
    <td class="mono">${esc(p.info)}</td></tr>`).join("");
}
$("#capStart").onclick = async () => {
  const r = await api("/api/capture/start", {iface:$("#capIface").value, filter:$("#capFilter").value});
  showMsg($("#capMsg"), r.ok ? "" : r.error); refreshCapture();
};
$("#capStop").onclick = async () => { await api("/api/capture/stop", {}); refreshCapture(); };
$("#capReset").onclick = async () => { await api("/api/capture/reset", {}); refreshCapture(); };

// ---------- discovery ----------
let scanNetsLoaded = false;
async function loadScanNets(){
  const nets = await api("/api/scan/networks");
  const sel = $("#scanNet");
  sel.innerHTML = (nets.length ? nets.map(n=>`<option value="${esc(n.cidr)}">${esc(n.cidr)} (${esc(n.iface)})</option>`).join("")
                 : '<option value="">No local subnet found — type one</option>');
  if(nets.length && !$("#scanCidr").value) $("#scanCidr").value = nets[0].cidr;
  sel.onchange = () => { $("#scanCidr").value = sel.value; };
  scanNetsLoaded = true;
}
function portPills(h){
  if(h.scanning_ports) return '<span class="meta">scanning…</span>';
  if(!h.ports || !h.ports.length) return '<span class="meta">—</span>';
  return h.ports.map(p=>`<span class="pill">${p.port}${p.service?" · "+esc(p.service):""}</span>`).join(" ");
}
async function refreshScan(){
  const d = await api("/api/scan/status");
  const pct = d.total ? Math.round(d.scanned/d.total*100) : 0;
  $("#scanBar").style.width = pct + "%";
  const label = {idle:"Ready.",running:"Scanning",done:"Scan complete",error:"Error"}[d.state] || "";
  $("#scanProgress").innerHTML = d.state==="idle" ? '<span class="meta">Pick a subnet and press Scan.</span>' :
    `<b>${label}</b> ${d.cidr?esc(d.cidr):""} — ${d.scanned}/${d.total} addresses, `+
    `${d.host_count} host${d.host_count===1?"":"s"} found · ${d.elapsed.toFixed(1)}s`;
  showMsg($("#scanMsg"), d.state==="error" ? d.message : (d.message||""));
  $("#scanCount").textContent = d.host_count ? "("+d.host_count+")" : "";
  $("#scanTable tbody").innerHTML = d.hosts.map(h=>`<tr>
    <td class="mono"><b>${esc(h.ip)}</b></td><td>${esc(h.hostname||"—")}</td>
    <td class="mono">${esc(h.mac||"—")}</td><td>${portPills(h)}</td></tr>`).join("")
    || (d.state==="running" ? '<tr><td colspan="4" class="meta">Searching…</td></tr>'
                            : '<tr><td colspan="4" class="meta">No hosts yet.</td></tr>');
}
$("#scanStart").onclick = async () => {
  const r = await api("/api/scan/start", {cidr:$("#scanCidr").value, ports:$("#scanPorts").checked});
  showMsg($("#scanMsg"), r.ok ? "" : r.error); refreshScan();
};
$("#scanStop").onclick = async () => { await api("/api/scan/stop", {}); };
$("#scanCidr").onkeydown = e => e.key==="Enter" && $("#scanStart").click();

// ---------- connections ----------
let connData = [];
function renderConns(){
  const q = $("#connSearch").value.toLowerCase();
  const rows = connData.filter(c => !q || Object.values(c).join(" ").toLowerCase().includes(q));
  $("#connCount").textContent = rows.length + " connections";
  $("#connTable tbody").innerHTML = rows.map(c=>`<tr><td><span class="pill">${c.proto}${c.family==="IPv6"?"6":""}</span></td>
    <td class="mono">${esc(c.laddr)}</td><td class="mono">${esc(c.raddr||"—")}</td>
    <td>${c.status==="ESTABLISHED"?'<span class="up">ESTABLISHED</span>':esc(c.status)}</td>
    <td class="mono">${c.pid}</td><td>${esc(c.process)}</td></tr>`).join("");
}
async function refreshConns(){
  const d = await api("/api/connections?kind="+$("#connKind").value);
  connData = d.connections;
  showMsg($("#connMsg"), d.denied ? "Run with sudo to see all connections and their processes." : "");
  renderConns();
}
$("#connSearch").oninput = renderConns;
$("#connKind").onchange = refreshConns;

// ---------- tools ----------
async function runTool(url, inp, out, btn){
  const host = $(inp).value.trim(); if(!host) return;
  $(out).textContent = "Running…"; $(btn).disabled = true;
  try { const r = await api(url, {host}); $(out).textContent = r.output; }
  catch(e){ $(out).textContent = "Error: "+e; }
  $(btn).disabled = false;
}
$("#pingBtn").onclick = () => runTool("/api/tools/ping","#pingHost","#pingOut","#pingBtn");
$("#dnsBtn").onclick  = () => runTool("/api/tools/dns","#dnsHost","#dnsOut","#dnsBtn");
$("#pingHost").onkeydown = e => e.key==="Enter" && $("#pingBtn").click();
$("#dnsHost").onkeydown  = e => e.key==="Enter" && $("#dnsBtn").click();

// ---------- system + loop ----------
async function refreshSystem(){
  const s = await api("/api/system");
  $("#host").textContent = "🖥 " + s.hostname;
  $("#uptime").textContent = "up " + fmtDur(s.uptime);
  $("#cpu").textContent = "CPU " + s.cpu.toFixed(0) + "%";
  $("#mem").textContent = "RAM " + s.mem.toFixed(0) + "%";
}
let n = 0;
async function tick(){
  try{
    if(activeTab==="overview") await refreshBandwidth();
    if(activeTab==="capture") await refreshCapture();
    if(activeTab==="discovery"){ if(!scanNetsLoaded) await loadScanNets(); await refreshScan(); }
    if(activeTab==="connections" && (n%3===0 || !connData.length)) await refreshConns();
    if(n%5===0) await refreshSystem();
    if(n%15===0) await loadInterfaces();
  }catch(e){ console.error(e); }
}
(async()=>{ await loadInterfaces(); await refreshSystem(); tick(); setInterval(()=>{n++;tick()},1000); })();
</script>
</body>
</html>
'''


# --------------------------------------------------------------------------- #
def main():
    parser = argparse.ArgumentParser(description="Web-based network analyzer")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Address to listen on (use 0.0.0.0 to allow other machines)")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--iface", default=None, help="Start capturing on this interface at launch")
    args = parser.parse_args()

    psutil.cpu_percent(interval=None)
    bandwidth.start()
    if args.iface:
        try:
            capture.start(args.iface)
        except RuntimeError as exc:
            print(f"[!] {exc}")

    print(f"[*] NetAnalyzer running on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
