#!/bin/sh
# Starts the old server's services in the foreground (CI stand only).
set -eu
# in segment B the way back to segment A is through the gateway (PR 2 stand)
if [ -n "${ROUTE_VIA:-}" ]; then
    ip route add 172.30.10.0/24 via "$ROUTE_VIA"
fi
smbd --foreground --no-process-group --debug-stdout &
vsftpd /etc/vsftpd.conf &
redis-server --protected-mode no --bind 0.0.0.0 --daemonize no &
python3 /stand/banners.py 23:telnet &
wait
