#!/bin/sh
# Starts the old server's services in the foreground (CI stand only).
set -eu
smbd --foreground --no-process-group --debug-stdout &
vsftpd /etc/vsftpd.conf &
redis-server --protected-mode no --bind 0.0.0.0 --daemonize no &
python3 /stand/banners.py 23:telnet &
wait
