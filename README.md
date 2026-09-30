# NetAnalyzer

A web-based network analyzer for Ubuntu, written in Python (Flask + psutil + Scapy).
Open it in any browser and you get:

- **Overview** – live download/upload speed per interface, 2-minute history chart, totals, errors and drops
- **Packet Capture** – live packet list, protocol breakdown (HTTPS, DNS, SSH, ARP, ICMP…), packets/sec,
  top source & destination IPs, top ports, and BPF filters such as `tcp port 443` or `host 192.168.1.10`
- **Connections** – every open TCP/UDP connection and listening port with its process name, searchable
- **Tools** – ping and DNS lookup

It works fully offline – no CDN or internet access needed.

## Files

```
netanalyzer/
├── app.py              # backend (Flask server, bandwidth monitor, packet sniffer)
├── templates/index.html# web dashboard
├── requirements.txt
├── install.sh          # one-time setup
└── run.sh              # start the server
```

## Install (Ubuntu 20.04 / 22.04 / 24.04)

```bash
cd netanalyzer
chmod +x install.sh run.sh
./install.sh
```

This installs `python3-venv`, `libpcap` and `ping`, creates a virtual environment in `venv/`,
and installs Flask, psutil and Scapy into it.

## Run

```bash
sudo ./run.sh
```

Then open **http://127.0.0.1:5000** in your browser.

`sudo` is needed because capturing packets requires raw-socket access. Without it, the Overview,
Connections (partially) and Tools tabs still work, but Packet Capture will show a permission error.

### Options

```bash
sudo ./run.sh --port 8080              # different port
sudo ./run.sh --iface eth0             # start capturing on eth0 immediately
sudo ./run.sh --host 0.0.0.0           # allow access from other computers on your network
```

Find your interface names with `ip -br link` (typically `eth0`, `enp3s0`, `wlp2s0`, `ens33`).

### Access from another computer

Start with `--host 0.0.0.0`, then browse to `http://<ubuntu-ip>:5000`.
If the firewall is on: `sudo ufw allow 5000/tcp`.

⚠️ The dashboard has **no login**. Anyone who can reach the port can see your traffic.
Only expose it on a trusted network, or keep the default `127.0.0.1` and use an SSH tunnel:

```bash
ssh -L 5000:127.0.0.1:5000 user@ubuntu-server   # then open http://127.0.0.1:5000 locally
```

### Run without sudo (optional)

Give the venv's Python the capture capability once:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f venv/bin/python)"
./run.sh
```

## Run automatically at boot (systemd)

Create `/etc/systemd/system/netanalyzer.service` (change the path to where you put the folder):

```ini
[Unit]
Description=NetAnalyzer web network analyzer
After=network-online.target

[Service]
WorkingDirectory=/opt/netanalyzer
ExecStart=/opt/netanalyzer/venv/bin/python app.py --host 127.0.0.1 --port 5000
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now netanalyzer
sudo systemctl status netanalyzer
```

## Troubleshooting

| Problem | Fix |
|---|---|
| "Permission denied" when starting capture | Run with `sudo ./run.sh` (or use the `setcap` step) |
| "Cannot set filter: libpcap is not available" | `sudo apt install libpcap0.8 libpcap-dev` |
| No packets appear | Pick the right interface in the dropdown; check your BPF filter |
| Connections tab shows a warning / no process names | Run with `sudo` |
| "ping not found" | `sudo apt install iputils-ping` |
| Port 5000 in use | `sudo ./run.sh --port 8080` |

## Notes

- Capture statistics are kept in memory; the live packet list keeps the latest 300 packets.
  Use **Clear** to reset the counters.
- Only analyze networks you own or are authorized to monitor.
