#!/bin/bash
# NetAudit - tool and dependency installation
set -e
echo "== System tools =="
sudo apt update
sudo apt install -y mtr-tiny tcptraceroute dnsutils iputils-arping iperf3 curl openssl

echo "== Python dependencies =="
pip install -r requirements.txt --break-system-packages

echo "Done. Run:"
echo "  CLI:  python3 netaudit.py list"
echo "  Web:  python3 netaudit.py web   (then open http://127.0.0.1:8000)"
