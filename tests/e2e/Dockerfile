# E2E SSH stand for NetAudit (docs/research/e2e_ssh_stand.md). CI only.
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server sudo nginx procps lynis chkrootkit \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/bash -G sudo pwsudo \
 && useradd -m -s /bin/bash scoped \
 && useradd -m -s /bin/bash nosudo \
 && useradd -m -s /bin/bash pwlogin \
 && printf '%s\n' 'scoped ALL=(root) NOPASSWD: /usr/sbin/nginx -T, /usr/sbin/sshd -T, /usr/sbin/sysctl -a' \
      > /etc/sudoers.d/scoped \
 && chmod 0440 /etc/sudoers.d/scoped
COPY sshd_e2e.conf /etc/ssh/sshd_config.d/e2e.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
