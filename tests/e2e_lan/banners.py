"""Fake services for the network audit stand (docs/research/network_audit.md
§10): each `port:kind` argument opens a TCP port that sends what the real
service sends first, so nmap's version detection reads it as that service.
The MikroTik lines are the ones nmap-service-probes matches. CI only."""

import socket
import sys
import threading

BANNERS = {
    'ftp': b'220 gw FTP server (MikroTik 6.49.7) ready\r\n',
    'ssh': b'SSH-2.0-ROSSSH\r\n',
    # telnet option negotiation (IAC DO TERMINAL-TYPE, IAC DO TSPEED, ...)
    'telnet': b'\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27',
    'silent': b'',
}


def serve(port: int, banner: bytes) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', port))   # a container on the stand network
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=talk, args=(conn, banner), daemon=True).start()


def talk(conn: socket.socket, banner: bytes) -> None:
    with conn:
        conn.settimeout(5)
        try:
            if banner:
                conn.sendall(banner)
            conn.recv(1024)
        except OSError:
            pass


if __name__ == '__main__':
    for spec in sys.argv[1:]:
        port, kind = spec.split(':')
        threading.Thread(target=serve, args=(int(port), BANNERS[kind]), daemon=True).start()
    threading.Event().wait()
