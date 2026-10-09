"""Task 7 (docs/research/sudo_privilege_handling.md): sudo runs only the real
command, so scoped NOPASSWD sudoers rules match; sudo's own refusal is
reported; the unused generic sudo probe is gone; an encrypted key gets a
clear connect error.

Two layers:
  - command shape and result classification against FakeSSHExecutor;
  - the same helper against a real /bin/sh with a fake `sudo` first in PATH
    that behaves like a scoped sudoers allow-list. No real sudo, no sshd.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

import netaudit_pkg.ssh as ssh_mod
from netaudit_pkg.ssh import SSHExecutor
from netaudit_pkg.ssh_utils import SudoResult, run_sudo_with_exit_code
from tests.conftest import FakeSSHExecutor

_MARKER_RE = re.compile(r"'(__NETAUDIT_RC_[0-9a-f]+__)'")


class _ScriptedSSH(FakeSSHExecutor):
    """Captures the wrapped command and answers with the marker it carries."""

    def __init__(self, stdout='', exit_code: int | None = 0, stderr='', password=''):
        super().__init__(password=password)
        self.reply_stdout = stdout
        self.reply_exit_code = exit_code
        self.reply_stderr = stderr

    def run(self, cmd, timeout=20, stdin_data=None):
        self.calls.append(cmd)
        self.stdin_data.append(stdin_data)
        if self.reply_exit_code is None:
            return self.reply_stdout, self.reply_stderr
        marker = _MARKER_RE.search(cmd).group(1)
        return f'{self.reply_stdout}\n{marker}:{self.reply_exit_code}\n', self.reply_stderr


# ===========================================================================
# S1 - command shape
# ===========================================================================

def test_sudo_wraps_only_the_real_command_not_sh():
    ssh = _ScriptedSSH('ruleset')
    run_sudo_with_exit_code(ssh, ['nft', 'list', 'ruleset'])
    sent = ssh.calls[0]
    assert sent.startswith('{ sudo -n -- nft list ruleset; rc=$?; ')
    assert 'sh -c' not in sent
    assert ssh.stdin_data == [None]


def test_sudo_with_password_uses_dash_s_and_writes_password_to_stdin():
    ssh = _ScriptedSSH('ok', password='FAKE-TEST-PW')
    run_sudo_with_exit_code(ssh, ['ufw', 'status'])
    sent = ssh.calls[0]
    assert sent.startswith("{ sudo -S -p '' -- ufw status; rc=$?; ")
    assert 'FAKE-TEST-PW' not in sent
    assert ssh.stdin_data == ['FAKE-TEST-PW\n']


def test_every_argv_element_stays_one_argument():
    ssh = _ScriptedSSH('')
    run_sudo_with_exit_code(ssh, ['systemd-analyze', 'security', 'x; touch /tmp/PWNED'])
    assert "systemd-analyze security 'x; touch /tmp/PWNED';" in ssh.calls[0]


def test_empty_argv_is_rejected():
    with pytest.raises(ValueError):
        run_sudo_with_exit_code(_ScriptedSSH(''), [])


def test_a_plain_string_is_rejected():
    """A str is a sequence of characters; joining it would quote each
    character. Callers must pass argv."""
    with pytest.raises(TypeError):
        run_sudo_with_exit_code(_ScriptedSSH(''), 'iptables -S')


# ===========================================================================
# S1 - result classification
# ===========================================================================

def test_success_returns_stdout_and_exit_code():
    result = run_sudo_with_exit_code(_ScriptedSSH('Status\n|- Number of jail: 2', 0), ['fail2ban-client', 'status'])
    assert result == SudoResult(completed=True, exit_code=0, stdout='Status\n|- Number of jail: 2',
                                stderr='', sudo_error=None, command='fail2ban-client status')


def test_command_exit_code_passes_through():
    result = run_sudo_with_exit_code(_ScriptedSSH('', 3), ['nft', 'list', 'ruleset'])
    assert (result.completed, result.exit_code, result.sudo_error) == (True, 3, None)


def test_sudo_refusal_is_reported_as_sudo_error():
    result = run_sudo_with_exit_code(
        _ScriptedSSH('', 1, stderr='sudo: a password is required\n'), ['nft', 'list', 'ruleset'])
    assert result.completed is True
    assert result.exit_code == 1
    assert result.sudo_error == 'sudo: a password is required'
    assert result.stderr == 'sudo: a password is required\n'


def test_wrong_password_reports_the_sudo_line_not_sorry():
    stderr = 'Sorry, try again.\nsudo: 1 incorrect password attempt\n'
    result = run_sudo_with_exit_code(_ScriptedSSH('', 1, stderr=stderr, password='x'), ['ufw', 'status'])
    assert result.sudo_error == 'sudo: 1 incorrect password attempt'


def test_command_failure_without_sudo_line_is_not_a_sudo_error():
    result = run_sudo_with_exit_code(
        _ScriptedSSH('', 1, stderr='ERROR  Failed to access socket path\n'), ['fail2ban-client', 'status'])
    assert result.sudo_error is None


def test_sudo_line_with_other_exit_code_is_not_a_sudo_error():
    result = run_sudo_with_exit_code(_ScriptedSSH('', 2, stderr='sudo: something\n'), ['iptables', '-S'])
    assert result.sudo_error is None


def test_sudo_error_is_truncated():
    long_line = 'sudo: ' + 'x' * 500
    result = run_sudo_with_exit_code(_ScriptedSSH('', 1, stderr=long_line), ['iptables', '-S'])
    assert len(result.sudo_error) == 200


def test_missing_marker_is_incomplete():
    result = run_sudo_with_exit_code(_ScriptedSSH('partial', None, stderr='sudo: x\n'), ['iptables', '-S'])
    assert (result.completed, result.exit_code, result.sudo_error) == (False, None, None)


# ===========================================================================
# S1 against a real shell: fake scoped sudoers
# ===========================================================================

_FAKE_SUDO = r"""#!/bin/sh
# Scoped sudoers stand-in: NOPASSWD only for basenames in $FAKE_SUDO_ALLOW.
mode=
while [ $# -gt 0 ]; do
  case "$1" in
    -n) mode=n; shift ;;
    -S) mode=S; shift ;;
    -p) shift 2 ;;
    --) shift; break ;;
    -*) echo "sudo: unsupported option $1" >&2; exit 1 ;;
    *) break ;;
  esac
done
name=$(basename "$1")
for allowed in $FAKE_SUDO_ALLOW; do
  if [ "$allowed" = "$name" ]; then exec "$@"; fi
done
if [ "$mode" = S ]; then
  IFS= read -r pw || pw=
  if [ -n "$pw" ] && [ "$pw" = "$FAKE_SUDO_PASSWORD" ]; then exec "$@"; fi
  echo "Sorry, try again." >&2
  echo "sudo: 1 incorrect password attempt" >&2
  exit 1
fi
echo "sudo: a password is required" >&2
exit 1
"""

_FAKE_NFT = """#!/bin/sh
echo "table inet filter {"
echo "}"
exit "${FAKE_NFT_RC:-0}"
"""


def _write_exe(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class _LocalShellSSH:
    """SSHExecutor stand-in that runs the command through a real /bin/sh."""

    def __init__(self, bin_dir: Path, password: str = '', **env):
        self.password = password
        self.env = {**os.environ, 'PATH': f'{bin_dir}{os.pathsep}{os.environ.get("PATH", "")}', **env}

    def run(self, cmd, timeout=20, stdin_data=None):
        proc = subprocess.run(['/bin/sh', '-c', cmd], input=stdin_data or '', capture_output=True,  # nosec B603 - test-only local shell
                              text=True, timeout=timeout, env=self.env, check=False)
        return proc.stdout, proc.stderr


@pytest.fixture
def scoped_bin(tmp_path):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    _write_exe(bin_dir / 'sudo', _FAKE_SUDO)
    _write_exe(bin_dir / 'nft', _FAKE_NFT)
    return bin_dir


def test_real_shell_scoped_rule_allows_the_real_binary(scoped_bin):
    ssh = _LocalShellSSH(scoped_bin, FAKE_SUDO_ALLOW='nft')
    result = run_sudo_with_exit_code(ssh, ['nft', 'list', 'ruleset'])
    assert result.completed and result.exit_code == 0
    assert result.stdout == 'table inet filter {\n}'
    assert result.sudo_error is None


def test_real_shell_exit_code_of_the_command_comes_through(scoped_bin):
    ssh = _LocalShellSSH(scoped_bin, FAKE_SUDO_ALLOW='nft', FAKE_NFT_RC='3')
    result = run_sudo_with_exit_code(ssh, ['nft', 'list', 'ruleset'])
    assert (result.completed, result.exit_code) == (True, 3)


def test_real_shell_binary_outside_the_rule_is_refused_with_sudo_error(scoped_bin):
    ssh = _LocalShellSSH(scoped_bin, FAKE_SUDO_ALLOW='nft')
    result = run_sudo_with_exit_code(ssh, ['iptables', '-S'])
    assert (result.completed, result.exit_code) == (True, 1)
    assert result.sudo_error == 'sudo: a password is required'


def test_real_shell_pre_fix_sh_dash_c_shape_is_refused_by_the_same_rule(scoped_bin):
    """Regression evidence for E1: the old `sudo -n sh -c '<cmd>; marker'`
    asks sudoers for `sh`, so a rule scoped to `nft` refuses it."""
    ssh = _LocalShellSSH(scoped_bin, FAKE_SUDO_ALLOW='nft')
    out, err = ssh.run("sudo -n sh -c 'nft list ruleset; rc=$?; printf %s:%s\\\\n M \"$rc\"'")
    assert 'M:' not in out
    assert err.strip() == 'sudo: a password is required'


def test_real_shell_password_path(scoped_bin):
    ssh = _LocalShellSSH(scoped_bin, password='FAKE-TEST-PW', FAKE_SUDO_ALLOW='', FAKE_SUDO_PASSWORD='FAKE-TEST-PW')
    result = run_sudo_with_exit_code(ssh, ['nft', 'list', 'ruleset'])
    assert (result.completed, result.exit_code, result.sudo_error) == (True, 0, None)

    wrong = _LocalShellSSH(scoped_bin, password='nope', FAKE_SUDO_ALLOW='', FAKE_SUDO_PASSWORD='FAKE-TEST-PW')
    refused = run_sudo_with_exit_code(wrong, ['nft', 'list', 'ruleset'])
    assert refused.sudo_error == 'sudo: 1 incorrect password attempt'


def test_real_shell_argument_with_shell_syntax_is_not_executed(scoped_bin, tmp_path):
    pwned = tmp_path / 'PWNED'
    ssh = _LocalShellSSH(scoped_bin, FAKE_SUDO_ALLOW='echo')
    result = run_sudo_with_exit_code(ssh, ['echo', f'x; touch {pwned}'])
    assert result.exit_code == 0
    assert result.stdout == f'x; touch {pwned}'
    assert not pwned.exists()


_FAKE_F2B = """#!/bin/sh
if [ -n "$1" ]; then
  printf 'Status for the jail: %s\\n|- Currently banned:\\t0\\n`- Total banned:\\t4\\n' "$1"
else
  printf 'Status\\n|- Number of jail:\\t1\\n`- Jail list:\\tsshd\\n'
fi
"""


def test_real_shell_fail2ban_status_wrapper_mode_works_with_a_wrapper_only_rule(scoped_bin):
    """The user-facing scenario behind E1: sudoers allows only the
    status wrapper, no password. Before the fix sudo was asked for `sh`
    and refused, so this mode could not work."""
    from netaudit_pkg.checks.server_security import (
        _fail2ban_jail_verdict,
        _fail2ban_status_verdict,
    )
    from netaudit_pkg.fail2ban_config import Fail2banCommands, collect_fail2ban_config

    wrapper = scoped_bin / 'fail2ban-status-only'
    _write_exe(wrapper, _FAKE_F2B)
    _write_exe(scoped_bin / 'fail2ban-client', '#!/bin/sh\necho "ERROR Permission denied (you must be root)"\n')
    ssh = _LocalShellSSH(scoped_bin, FAKE_SUDO_ALLOW='fail2ban-status-only')

    wrapped = collect_fail2ban_config(ssh, commands=Fail2banCommands(mode='status-wrapper', wrapper_path=str(wrapper)))
    assert _fail2ban_status_verdict(wrapped) == ('SUCCESS', {'jail_names': ['sshd']})
    assert _fail2ban_jail_verdict(wrapped.jails[0]) == ('CONFIRMED', {'currently_banned': 0, 'total_banned': 4})

    client = collect_fail2ban_config(ssh, commands=Fail2banCommands(mode='client'))
    verdict, ctx = _fail2ban_status_verdict(client)
    assert verdict == 'ACCESS_DENIED'
    assert ctx['sudo_error'] == 'sudo: a password is required'


# ===========================================================================
# S1a - SSHExecutor.run(stdin_data=...)
# ===========================================================================

class _Stdin:
    def __init__(self):
        self.written = []
        self.shut = False
        stdin = self

        class _Channel:
            def shutdown_write(self):
                stdin.shut = True
        self.channel = _Channel()

    def write(self, s):
        self.written.append(s)

    def flush(self):
        pass


class _Stream:
    def __init__(self, text):
        self.text = text.encode()

    def read(self):
        return self.text


class _Client:
    def __init__(self):
        self.stdins = []

    def exec_command(self, cmd, timeout=15):
        stdin = _Stdin()
        self.stdins.append(stdin)
        return stdin, _Stream('out'), _Stream('err')


def test_run_writes_stdin_data_and_closes_write_side():
    ex = SSHExecutor('host', 'user', 22, '', 'pw')
    ex.client = _Client()
    assert ex.run('cat', stdin_data='pw\n') == ('out', 'err')
    assert ex.client.stdins[0].written == ['pw\n']
    assert ex.client.stdins[0].shut is True


def test_run_without_stdin_data_does_not_touch_stdin():
    ex = SSHExecutor('host', 'user', 22, '', '')
    ex.client = _Client()
    ex.run('true')
    assert ex.client.stdins[0].written == []
    assert ex.client.stdins[0].shut is False


# ===========================================================================
# S3 - the generic sudo probe is gone (D1)
# ===========================================================================

def test_needs_sudo_password_is_removed():
    assert not hasattr(SSHExecutor, 'needs_sudo_password')
    assert not hasattr(SSHExecutor('host'), '_no_password_sudo')
    assert not hasattr(FakeSSHExecutor, 'needs_sudo_password')


# ===========================================================================
# S5 / D2-A - encrypted key error and the password field label
# ===========================================================================

def test_encrypted_key_gets_a_clear_connect_error(monkeypatch, tmp_path):
    import paramiko

    class _EncryptedKeyClient:
        def load_host_keys(self, path):
            pass

        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, **kwargs):
            raise paramiko.PasswordRequiredException('private key file is encrypted')

    monkeypatch.setattr(ssh_mod, 'KNOWN_HOSTS_PATH', tmp_path / 'known_hosts')
    monkeypatch.setattr(ssh_mod.paramiko, 'SSHClient', _EncryptedKeyClient)
    with pytest.raises(Exception, match='ssh-agent') as exc:
        SSHExecutor('host', 'user', 22, '~/.ssh/id_ed25519', '').connect()
    assert 'encrypted' in str(exc.value)


# task 10 split the field: `password` is the SSH login password only, the
# sudo password has its own `sudo_password` field (tests/test_sudo_password.py)
PASSWORD_LABEL = 'SSH password (if no key)'
PASSWORD_LABEL_RU = 'Пароль SSH (если без ключа)'


def test_ssh_check_password_label_is_the_ssh_login_password():
    import netaudit_pkg.checks  # noqa: F401 - registers every check
    from netaudit_pkg.registry import registry

    ssh_checks = [spec for spec in registry.all()
                  if {p['name'] for p in spec.params} >= {'key_path', 'password'}]
    assert len(ssh_checks) >= 17
    for spec in ssh_checks:
        label = next(p['label'] for p in spec.params if p['name'] == 'password')
        assert label == PASSWORD_LABEL, spec.id


def test_ru_password_label_matches():
    i18n = (Path(__file__).resolve().parent.parent / 'web' / 'static' / 'i18n.js').read_text(encoding='utf-8')
    assert 'Пароль (если без ключа)' not in i18n
    assert PASSWORD_LABEL_RU in i18n
