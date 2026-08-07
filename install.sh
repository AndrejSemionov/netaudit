#!/bin/bash
# NetAudit — установка инструментов и зависимостей
set -e
echo "== Системные инструменты =="
sudo apt update
sudo apt install -y mtr-tiny tcptraceroute dnsutils iputils-arping iperf3 curl openssl

echo "== Python-зависимости =="
pip install -r requirements.txt --break-system-packages

echo "Готово. Запуск:"
echo "  Консоль:  python3 netaudit.py list"
echo "  Веб:      python3 netaudit.py web   (затем открой http://127.0.0.1:8000)"
