#!/bin/bash
# NetAudit - tool and dependency installation
set -e
echo "== System tools =="
sudo apt update
sudo apt install -y mtr-tiny tcptraceroute dnsutils iputils-arping iperf3 curl openssl

echo "== Ookla Speedtest CLI =="
# Ookla's own apt repo doesn't support every distro/release (confirmed missing
# on Ubuntu 26.04 as of this writing) - fall back to the direct per-arch
# tarball from the same official source if the repo/package isn't available.
if ! command -v speedtest >/dev/null 2>&1; then
    curl -s https://install.speedtest.net/app/cli/install.deb.sh | sudo bash || true
    if ! sudo apt install -y speedtest 2>/dev/null; then
        echo "  apt package unavailable for this distro, installing via direct tarball"
        ARCH=$(uname -m)
        curl -sL "https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-${ARCH}.tgz" -o /tmp/speedtest.tgz
        tar xzf /tmp/speedtest.tgz -C /tmp speedtest
        sudo install -m 0755 /tmp/speedtest /usr/local/bin/speedtest
        rm -f /tmp/speedtest.tgz /tmp/speedtest
    fi
fi
speedtest --version || echo "  WARNING: speedtest install failed, the speedtest check will be skipped at runtime"

echo "== Python dependencies =="
pip install -r requirements.txt --break-system-packages

echo "Done. Run:"
echo "  CLI:  python3 netaudit.py list"
echo "  Web:  python3 netaudit.py web   (then open http://127.0.0.1:8000)"
