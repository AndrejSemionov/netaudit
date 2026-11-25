#!/usr/bin/env bash
# Network audit E2E stand (docs/research/network_audit.md §10, contract N9):
# one Docker network = one office segment, 172.30.10.0/24.
#   .254 gw      fake MikroTik: FTP and SSH banners nmap reads as RouterOS
#                6.49.7, Telnet, WinBox 8291, bandwidth test 2000 - and the
#                scanner's default gateway
#   .20  legacy  SMBv1 with optional signing, anonymous FTP, Telnet, Redis
#                without a password
#   .40  quiet   drops every TCP and ICMP packet, answers ARP only
#   .50  clean   OpenSSH with Debian 12 defaults
#   .10  scanner runs lan_audit as uid 1000 with no capabilities, twice:
#                level 1 and level 2; results in $RUNNER_TEMP/lan-stand
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
OUT="${RUNNER_TEMP:-/tmp}/lan-stand"
NET=nalan
mkdir -p "$OUT"
chmod 0777 "$OUT"

docker network create --subnet 172.30.10.0/24 "$NET"
docker build -q -t nalan-scanner -f "$HERE/scanner.Dockerfile" "$ROOT"
docker build -q -t nalan-legacy -f "$HERE/legacy.Dockerfile" "$HERE"
docker build -q -t nalan-clean -f "$HERE/clean.Dockerfile" "$HERE"

docker run -d --name gw --network "$NET" --ip 172.30.10.254 -v "$HERE:/stand:ro" python:3.12-slim \
  python3 /stand/banners.py 21:ftp 22:ssh 23:telnet 8291:silent 2000:silent
docker run -d --name legacy --network "$NET" --ip 172.30.10.20 nalan-legacy
docker run -d --name clean --network "$NET" --ip 172.30.10.50 nalan-clean
docker run -d --name quiet --network "$NET" --ip 172.30.10.40 --cap-add NET_ADMIN alpine:3.20 \
  sh -c 'apk add --no-cache iptables >/dev/null && iptables -A INPUT -p tcp -j DROP \
         && iptables -A INPUT -p icmp -j DROP && touch /ready && exec sleep infinity'

# every service answers before the scan starts
python3 - <<'WAIT'
import socket, time
for host, port in [('172.30.10.254', 21), ('172.30.10.254', 8291), ('172.30.10.20', 445),
                   ('172.30.10.20', 21), ('172.30.10.20', 23), ('172.30.10.20', 6379), ('172.30.10.50', 22)]:
    for _ in range(90):
        try:
            socket.create_connection((host, port), timeout=2).close()
            break
        except OSError:
            time.sleep(1)
    else:
        raise SystemExit(f'{host}:{port} did not start')
WAIT
for _ in $(seq 60); do docker exec quiet test -f /ready && break; sleep 1; done
docker exec quiet test -f /ready

for level in 1 2; do
  docker run --rm --name scanner --network "$NET" --ip 172.30.10.10 --cap-add NET_ADMIN \
    -v "$ROOT:/src:ro" -v "$OUT:/out" nalan-scanner sh -c \
    "ip route replace default via 172.30.10.254 \
     && exec setpriv --reuid=1000 --regid=1000 --init-groups --inh-caps=-all --bounding-set=-all -- \
        env HOME=/tmp python3 /src/tests/e2e_lan/run_scan.py $level > /out/level$level.json 2> /out/level$level.log"
done
ls -l "$OUT"
