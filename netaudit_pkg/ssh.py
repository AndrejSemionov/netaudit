"""
Shared SSH executor used by every SSH-based check (server_audit, lynis_audit,
rootkit_check, aide_check, backup_check, docker_audit, cve_audit, ssh_audit,
history_capture, mikrotik_sniffer).

Before this module existed, every one of those files had its own copy of
_ssh_connect()/_run()/_run_sudo() — byte-identical in most cases. That meant
any fix (a timeout tweak, a security fix) had to be applied N times, and
inevitably some copies would drift. This is the single place that logic lives now.

Host key verification
----------------------
Every one of the duplicated _ssh_connect() implementations used
`paramiko.AutoAddPolicy()` — silently trusting whatever host key the server
presents, on every single connection, forever. That's not a first-connection
convenience trade-off, it's simply no verification at all: a MITM on
connection #50 to a server you've audited 49 times before would sail through
unnoticed.

This module uses Trust-On-First-Use (TOFU) instead:
  - First connection to a given host: the key is unknown, so it's accepted,
    logged loudly (so the person doing the audit sees exactly what happened),
    and saved to netaudit's own known_hosts file.
  - Every subsequent connection: the key must match what was saved. If it
    doesn't, the connection is refused with a clear error — this is what
    actually catches MITM and "the server was reinstalled and nobody told me"
    situations, which is the case TOFU is meant to protect against.

known_hosts lives at ~/.netaudit/known_hosts, separate from the user's own
~/.ssh/known_hosts, so NetAudit's TOFU history doesn't get mixed with (or
silently rely on) whatever the person's regular SSH client has already trusted.
"""

from __future__ import annotations

from pathlib import Path

from .utils import log

try:
    import paramiko
except ImportError:
    paramiko = None

KNOWN_HOSTS_PATH = Path.home() / '.netaudit' / 'known_hosts'


class HostKeyMismatchError(Exception):
    """Raised when a host presents a different key than the one NetAudit
    already trusts for it — the actual MITM/reinstalled-server detection."""


class TofuPolicy(paramiko.MissingHostKeyPolicy if paramiko else object):
    """Trust-On-First-Use: accept and save an unknown host's key, but require
    an exact match on every later connection to the same host."""

    def missing_host_key(self, client, hostname, key):
        # this only fires for hosts with NO matching entry in the loaded
        # known_hosts at all — paramiko itself already raises before this
        # if a DIFFERENT key exists for a known hostname, so reaching here
        # always means "first time seeing this host"
        fingerprint = key.get_fingerprint().hex(':')
        log.warning(f'SSH: first connection to {hostname} — key fingerprint {key.get_name()} {fingerprint}')
        log.warning(f'SSH: saving to {KNOWN_HOSTS_PATH} — future connections will verify against this key')
        client.get_host_keys().add(hostname, key.get_name(), key)
        KNOWN_HOSTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        client.save_host_keys(str(KNOWN_HOSTS_PATH))


class SSHExecutor:
    """
    Usage:
        with SSHExecutor(host, user, port, key_path, password) as ssh:
            out, err = ssh.run('whoami')
            out2, err2 = ssh.sudo('cat /etc/shadow')

    Raises on connect():
        HostKeyMismatchError  — the host's key doesn't match what's saved
                                (likely MITM, or the server was reinstalled/rekeyed)
        Whatever paramiko itself raises for auth/network failures — callers
        already catch broad Exception around connection setup, so this
        deliberately doesn't introduce a new exception type for those cases.
    """

    def __init__(self, host: str, user: str = 'root', port: int = 22,
                 key_path: str = '', password: str = '', timeout: int = 10):
        if paramiko is None:
            raise RuntimeError('paramiko is not installed')
        self.host = host
        self.user = user
        self.port = int(port)
        self.key_path = key_path
        self.password = password
        self.timeout = timeout
        self.client: 'paramiko.SSHClient | None' = None
        self._no_password_sudo: bool | None = None  # cached after first sudo() check

    def connect(self) -> 'SSHExecutor':
        client = paramiko.SSHClient()
        # load whatever hosts NetAudit has already trusted, so a repeat
        # connection to a known host verifies strictly instead of re-TOFU'ing
        if KNOWN_HOSTS_PATH.exists():
            client.load_host_keys(str(KNOWN_HOSTS_PATH))
        client.set_missing_host_key_policy(TofuPolicy())

        kwargs = {'hostname': self.host, 'port': self.port, 'username': self.user,
                  'timeout': self.timeout,
                  'look_for_keys': bool(self.key_path), 'allow_agent': bool(self.key_path)}
        if self.key_path and self.key_path.strip():
            kwargs['key_filename'] = str(Path(self.key_path).expanduser())
        elif self.password:
            kwargs['password'] = self.password

        try:
            client.connect(**kwargs)
        except paramiko.BadHostKeyException as e:
            raise HostKeyMismatchError(
                f'{self.host} presented a different SSH host key than the one NetAudit has '
                f'on file — this could mean the server was reinstalled/rekeyed, or a '
                f'man-in-the-middle. If you\'re sure the new key is legitimate, remove the '
                f'old entry for {self.host} from {KNOWN_HOSTS_PATH} and reconnect.'
            ) from e

        self.client = client
        return self

    def __enter__(self) -> 'SSHExecutor':
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def run(self, cmd: str, timeout: int = 20) -> tuple[str, str]:
        """Runs a command as the connected user. Returns (stdout, stderr)."""
        _, so, se = self.client.exec_command(cmd, timeout=timeout)
        return so.read().decode(errors='replace'), se.read().decode(errors='replace')

    def sudo(self, cmd: str, timeout: int = 20) -> tuple[str, str]:
        """
        Runs a command via sudo. Tries passwordless sudo first (`sudo -n`);
        if that's unavailable, falls back to `sudo -S` reading the password
        from stdin — this works without a TTY and without any sudoers
        pre-configuration on the target machine, which matters for servers
        that aren't yours to configure (client servers, one-off audits).
        """
        if self._no_password_sudo is None:
            check_out, _ = self.run('sudo -n true 2>&1 && echo OK || echo NOPASS', timeout=10)
            self._no_password_sudo = 'NOPASS' not in check_out

        if self._no_password_sudo:
            return self.run(f'sudo {cmd}', timeout=timeout)

        stdin, so, se = self.client.exec_command(f'sudo -S -p "" {cmd}', timeout=timeout)
        stdin.write((self.password or '') + '\n')
        stdin.flush()
        stdin.channel.shutdown_write()
        return so.read().decode(errors='replace'), se.read().decode(errors='replace')

    def needs_sudo_password(self) -> bool:
        """True if sudo requires a password and none was provided — callers
        should surface a clear error rather than let every sudo() call
        silently fail with an empty stdin."""
        if self._no_password_sudo is None:
            check_out, _ = self.run('sudo -n true 2>&1 && echo OK || echo NOPASS', timeout=10)
            self._no_password_sudo = 'NOPASS' not in check_out
        return (not self._no_password_sudo) and not self.password

    def is_tool_installed(self, tool: str) -> bool:
        """Checks whether a binary is on PATH on the remote host."""
        out, _ = self.run(f'which {tool} || echo NOTFOUND')
        return 'NOTFOUND' not in out

    def ensure_tool_installed(self, tool: str, timeout: int = 120) -> tuple[bool, str | None]:
        """
        Installs `tool` via apt on the remote host if it's missing, using the
        same package allowlist as the local ToolManager (see tools.py) - this
        was previously duplicated inline in lynis_audit/rootkit_check/aide_check,
        each with its own copy of the same which-then-apt-install pattern.

        Returns (installed, error). installed is True if the tool is now present
        (whether it already was, or was just installed). error explains why not,
        if installed is False - most commonly "not on the allowlist" or an apt
        failure.
        """
        from .tools import TOOL_PACKAGES  # local import - avoids a circular import at module load time

        if self.is_tool_installed(tool):
            return True, None

        package = TOOL_PACKAGES.get(tool)
        if package is None:
            return False, f'{tool} is not on the install allowlist (see tools.py TOOL_PACKAGES)'

        self.sudo(f'apt-get install -y {package} 2>&1', timeout=timeout)
        if self.is_tool_installed(tool):
            return True, None
        return False, f'failed to install {tool} (package {package})'

    def close(self) -> None:
        if self.client:
            self.client.close()
            self.client = None
