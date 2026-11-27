# Network audit E2E: an old office server - SMBv1 with optional signing,
# anonymous FTP, Telnet, Redis without a password (docs/research/network_audit.md §10). CI only.
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends samba vsftpd redis-server python3 iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /srv/share /srv/ftp /var/run/vsftpd/empty \
 && echo 'stand' > /srv/ftp/readme.txt
COPY legacy-smb.conf /etc/samba/smb.conf
COPY legacy-vsftpd.conf /etc/vsftpd.conf
COPY banners.py /stand/banners.py
COPY legacy.sh /stand/legacy.sh
ENTRYPOINT ["sh", "/stand/legacy.sh"]
