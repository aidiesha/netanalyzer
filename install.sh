#!/usr/bin/env bash
# One-time setup for NetAnalyzer on Ubuntu
set -e
cd "$(dirname "$0")"
sudo apt update
sudo apt install -y python3 python3-venv python3-pip libpcap0.8 libpcap-dev iputils-ping
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt
echo
echo "Done. Start it with:  sudo ./run.sh"
echo "Then open:            http://127.0.0.1:5000"
