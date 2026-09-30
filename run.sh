#!/usr/bin/env bash
# Start NetAnalyzer. Packet capture needs root, so run with sudo.
# Extra options are passed through, e.g.  sudo ./run.sh --host 0.0.0.0 --port 8080
cd "$(dirname "$0")"
exec ./venv/bin/python app.py "$@"
