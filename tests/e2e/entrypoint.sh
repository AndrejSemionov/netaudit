#!/bin/sh
# Sets the per-run password and authorized key, then runs sshd in the
# foreground. E2E_PASSWORD comes from the CI job; the public key is mounted
# read-only at /stand/authorized_keys.
set -eu
: "${E2E_PASSWORD:?E2E_PASSWORD is not set}"
for u in pwsudo scoped nosudo pwlogin; do
    printf '%s:%s\n' "$u" "$E2E_PASSWORD" | chpasswd
done
for u in pwsudo scoped nosudo; do
    install -d -m 700 -o "$u" -g "$u" "/home/$u/.ssh"
    install -m 600 -o "$u" -g "$u" /stand/authorized_keys "/home/$u/.ssh/authorized_keys"
done
ssh-keygen -A
exec /usr/sbin/sshd -D -e
