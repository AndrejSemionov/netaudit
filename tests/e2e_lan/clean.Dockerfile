# Network audit E2E: a clean host - only OpenSSH with Debian 12 defaults (CI stand only).
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd
CMD ["sh", "-c", "ssh-keygen -A && exec /usr/sbin/sshd -D -e"]
