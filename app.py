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
import re
import socket
import subprocess
import threading
import time
from datetime import datetime

import psutil
from flask import Flask, jsonify, render_template, request

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


bandwidth = BandwidthMonitor()
capture = PacketCapture()

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
    return render_template("index.html")


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
