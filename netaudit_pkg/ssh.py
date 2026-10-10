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
from typing import Self

from .utils import log

try:
    import paramiko
except ImportError:
    paramiko = None

KNOWN_HOSTS_PATH = Path.home() / '.netaudit' / 'known_hosts'


class HostKeyMismatchError(Exception):
    """Raised when a host presents a different key than the one NetAudit
    already trusts for it — the actual MITM/reinstalled-server detection."""


class EncryptedKeyError(Exception):
    """Raised when key_path is an encrypted private key that ssh-agent did
    not provide either. Checks report it like any connect failure."""


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
        EncryptedKeyError     — key_path is encrypted and ssh-agent didn't
                                provide it (NetAudit takes no key passphrase)
        Whatever paramiko itself raises for other auth/network failures —
        callers already catch broad Exception around connection setup.
    """

    def __init__(self, host: str, user: str = 'root', port: int = 22,
                 key_path: str = '', password: str = '', timeout: int = 10,  # nosec B107 - empty default is a CLI/API parameter, not a hardcoded credential
                 sudo_password: str = ''):  # nosec B107 - same
        if paramiko is None:
            raise RuntimeError('paramiko is not installed')
        self.host = host
        self.user = user
        self.port = int(port)
        self.key_path = key_path
        # `password` is the SSH login password, used only when there is no
        # key_path (see connect()). `sudo_password` is what `sudo -S` gets on
        # stdin; when it is not set, the SSH password is used, which is what
        # sudo asks for by default (the invoking user's own password). Task 10.
        self.password = password
        self.sudo_password = sudo_password or password
        self.timeout = timeout
        self.client: paramiko.SSHClient | None = None

    def connect(self) -> SSHExecutor:
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
        except paramiko.PasswordRequiredException as e:
            # NetAudit takes no key passphrase (task 7, D2-A): paramiko gets
            # here only when ssh-agent (allow_agent=True with a key_path)
            # did not hold the key either
            raise EncryptedKeyError(
                f'the private key {self.key_path} is encrypted; load it into ssh-agent (CLI) '
                f'or use an unencrypted key for the account NetAudit runs as'
            ) from e
        except paramiko.BadHostKeyException as e:
            raise HostKeyMismatchError(
                f'{self.host} presented a different SSH host key than the one NetAudit has '
                f'on file — this could mean the server was reinstalled/rekeyed, or a '
                f'man-in-the-middle. If you\'re sure the new key is legitimate, remove the '
                f'old entry for {self.host} from {KNOWN_HOSTS_PATH} and reconnect.'
            ) from e

        self.client = client
        return self

    def __enter__(self) -> Self:
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def run(self, cmd: str, timeout: int = 20, stdin_data: str | None = None) -> tuple[str, str]:
        """Runs a command as the connected user. Returns (stdout, stderr).
        stdin_data, when given, is written to the command's stdin, which is
        then closed (ssh_utils.run_sudo_with_exit_code() passes the sudo
        password this way)."""
        stdin, so, se = self.client.exec_command(cmd, timeout=timeout)  # nosec B601 - SSHExecutor core purpose: remote exec_command with fixed, non-shell-form commands
        if stdin_data is not None:
            stdin.write(stdin_data)
            stdin.flush()
            stdin.channel.shutdown_write()
        return so.read().decode(errors='replace'), se.read().decode(errors='replace')

    def sudo(self, cmd: str, timeout: int = 20) -> tuple[str, str]:
        """
        Runs a command via sudo. If a sudo password was provided, uses it
        directly via `sudo -S`. Otherwise, attempts passwordless sudo via
        `sudo -n` for THIS command - never a generic capability probe
        (like `sudo -n true`) against a different, unrelated command.

        Why not a generic probe: sudo capability is a property of the
        specific command being run, not of the session as a whole. A
        host can have scoped sudoers rules like
        `NOPASSWD: /usr/bin/fail2ban-client` that permit exactly one
        command without a password while refusing everything else,
        including `true` - so testing `sudo -n true` first and caching
        that single result for every subsequent sudo() call produces
        false negatives on any host configured this way (confirmed
        empirically against a real production host during this
        project's fail2ban work - see session notes). Probing the
        actual command directly is both simpler and correct for both
        the scoped-sudoers case and the traditional blanket-NOPASSWD
        case.

        No fallback from `sudo -n` to `sudo -S` when no password was
        given: if passwordless sudo genuinely isn't available for this
        command, the correct behavior is to return that refusal as-is,
        not to attempt `sudo -S` with an empty stdin write (which
        doesn't produce a meaningful error - it silently fails or hangs
        depending on the target's sudo configuration). A caller that
        wants password-based sudo must supply a password explicitly.

        Note: `self.password` here is used purely as a sudo password
        for `sudo -S`, distinct from SSH authentication (which uses
        key_path, or this same self.password as an SSH login password
        only when no key_path is given - see connect()). There is no
        SSH key passphrase (task 7, D2-A: encrypted keys go through
        ssh-agent), and this method must never be extended to treat key
        material as sudo credential material.
        """
        if self.sudo_password:
            stdin, so, se = self.client.exec_command(f'sudo -S -p "" {cmd}', timeout=timeout)  # nosec B601 - SSHExecutor core purpose: remote exec_command with fixed, non-shell-form commands
            stdin.write(self.sudo_password + '\n')
            stdin.flush()
            stdin.channel.shutdown_write()
            return so.read().decode(errors='replace'), se.read().decode(errors='replace')

        return self.run(f'sudo -n {cmd}', timeout=timeout)

    def is_tool_installed(self, tool: str) -> bool:
        """True only when tool_presence() confirms the binary (F8: system
        directories in front of PATH, exit marker; Bash exit 1 / dash 127
        with empty output is absent, anything else unknown). Callers that
        must tell "absent" from "could not tell" use tool_presence().
        History below: the earlier `which`/bare `command -v` versions.

        Returns a plain bool (not a three-state PRESENT/NOT_PRESENT/
        UNKNOWN result) to avoid an API-breaking change to every caller
        of this widely-used method - see project session notes for the
        quality-audit finding that motivated this fix. The ambiguous/
        collection-failure case conservatively returns False, same as
        this method's previous return value in that situation (a failed
        `which` also produced a falsy result before this fix) - so this
        change corrects the common, high-value 0-vs-127 distinction
        without altering behavior in the failure case any caller could
        already have been relying on.

        Previously used `which tool || echo NOTFOUND` (bash-fallback
        text-sniffing) - the exact which-collapse bug pattern already
        found and fixed in firewall_config.py/fail2ban_config.py/
        sql_config.py/cve_audit.py during this project's broader
        quality audit: `||` fires on ANY nonzero exit of `which` -
        including an SSH transport hiccup or `which` itself being
        unavailable on a minimal image - not just genuine absence of
        the tool, so a collection failure was silently reported as
        confirmed-not-installed. This method is used (directly or via
        ensure_tool_installed()) by lynis_audit.py, aide_check.py, and
        rootkit_check.py; a false "not installed" here could cause a
        security check to silently skip running at all.
        """
        return self.tool_presence(tool).status == 'present'

    def tool_presence(self, tool: str):
        """present / absent / unknown for `tool` (ssh_utils.ToolProbe), via
        ssh_utils.probe_remote_tool(): /usr/sbin and /sbin in front of the
        user's PATH and an exit marker (F8). A non-root user's PATH on
        Debian has no /usr/sbin, where lynis and chkrootkit live, so the
        bare `command -v` this method used to run called them missing."""
        from .ssh_utils import probe_remote_tool

        return probe_remote_tool(self, tool)

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
        from .tools import (
            TOOL_PACKAGES,  # local import - avoids a circular import at module load time
        )

        presence = self.tool_presence(tool)
        if presence.status == 'present':
            return True, None
        if presence.status == 'unknown':
            # never install over a probe that did not answer (F8)
            return False, f'could not determine whether {tool} is installed: {presence.detail}'

        package = TOOL_PACKAGES.get(tool)
        if package is None:
            return False, f'{tool} is not on the install allowlist (see tools.py TOOL_PACKAGES)'

        self.sudo(f'apt-get install -y {package} 2>&1', timeout=timeout)
        after = self.tool_presence(tool)
        if after.status == 'present':
            return True, None
        if after.status == 'unknown':
            return False, (f'ran apt-get install {package}, but could not determine whether '
                           f'{tool} is installed now: {after.detail}')
        return False, f'failed to install {tool} (package {package})'

    def close(self) -> None:
        if self.client:
            self.client.close()
            self.client = None
