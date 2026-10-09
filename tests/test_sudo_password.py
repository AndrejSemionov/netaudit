"""Task 10 (docs/research/sudo_password.md): a separate `sudo_password` for SSH
checks, clear sudo diagnostics for nginx -T / sshd -T / sysctl -a, sysctl -a
without sudo when sudo is refused, a CLI prompt instead of argv, and the
password never stored.

Shell-level tests run the real collectors through /bin/sh with a fake `sudo`
that needs a password (or has a NOPASSWD rule); nothing touches a real host.
"""

from __future__ import annotations

import json
import os
import subprocess
from argparse import Namespace
from pathlib import Path

import pytest

import netaudit_pkg.ssh as ssh_mod
from netaudit_pkg.kernel_config import collect_kernel_config
from netaudit_pkg.nginx_config import collect_nginx_config
from netaudit_pkg.redaction import (
    SECRET_PARAM_NAMES,
    redact_preset_checks,
    redact_report,
)
from netaudit_pkg.ssh import SSHExecutor
from netaudit_pkg.ssh_utils import run_sudo_with_exit_code
from tests.conftest import ExitCodeFakeSSHExecutor
from tests.test_kernel_config import _VM_BASELINE

SPW = 'FAKE-SUDO-PW'

# ===========================================================================
# C1: SSHExecutor uses sudo_password for sudo, never for login
# ===========================================================================


class _Stdin:
    def __init__(self):
        self.written = []
        stdin = self

        class _Channel:
            def shutdown_write(self):
                stdin.closed = True
        self.channel = _Channel()

    def write(self, s):
        self.written.append(s)

    def flush(self):
        pass


class _Stream:
    def __init__(self, text=''):
        self.text = text.encode()

    def read(self):
        return self.text


class _Client:
    def __init__(self):
        self.commands = []
        self.stdins = []

    def exec_command(self, cmd, timeout=15):
        self.commands.append(cmd)
        stdin = _Stdin()
        self.stdins.append(stdin)
        return stdin, _Stream('ok'), _Stream('')


def test_sudo_uses_sudo_password_with_key_login():
    ex = SSHExecutor('h', 'audit', 22, '~/.ssh/id_ed25519', '', sudo_password=SPW)
    ex.client = _Client()
    ex.sudo('nginx -T')
    assert ex.client.commands == ['sudo -S -p "" nginx -T']
    assert ex.client.stdins[0].written == [SPW + '\n']
    assert all(SPW not in c for c in ex.client.commands)


def test_sudo_password_falls_back_to_the_ssh_password():
    ex = SSHExecutor('h', 'audit', 22, '', 'LOGIN-PW')
    ex.client = _Client()
    ex.sudo('sshd -T')
    assert ex.client.stdins[0].written == ['LOGIN-PW\n']


def test_sudo_password_wins_over_the_ssh_password():
    ex = SSHExecutor('h', 'audit', 22, '', 'LOGIN-PW', sudo_password=SPW)
    ex.client = _Client()
    ex.sudo('sshd -T')
    assert ex.client.stdins[0].written == [SPW + '\n']


def test_without_any_password_sudo_is_non_interactive():
    ex = SSHExecutor('h', 'audit', 22, '~/.ssh/k', '')
    ex.client = _Client()
    ex.sudo('sysctl -a')
    assert ex.client.commands == ['sudo -n sysctl -a']


def test_sudo_password_never_reaches_ssh_login(monkeypatch, tmp_path):
    seen = {}

    class _Recorder:
        def load_host_keys(self, path):
            pass

        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, **kwargs):
            seen.update(kwargs)

    monkeypatch.setattr(ssh_mod, 'KNOWN_HOSTS_PATH', tmp_path / 'known_hosts')
    monkeypatch.setattr(ssh_mod.paramiko, 'SSHClient', _Recorder)
    SSHExecutor('h', 'audit', 22, '~/.ssh/k', '', sudo_password=SPW).connect()
    assert 'password' not in seen
    assert SPW not in json.dumps(seen, default=str)


def test_run_sudo_with_exit_code_sends_the_sudo_password_on_stdin():
    fake = ExitCodeFakeSSHExecutor(responses={'nginx -T': 'conf'}, exit_codes={'nginx -T': 0},
                                   password='', sudo_password=SPW)
    run_sudo_with_exit_code(fake, ['nginx', '-T'])
    assert fake.stdin_data == [SPW + '\n']
    assert all(SPW not in c for c in fake.calls)


# ===========================================================================
# C4: diagnostics through a real shell and a fake sudo
# ===========================================================================

_FAKE_SUDO = r"""#!/bin/sh
mode=
while [ $# -gt 0 ]; do
  case "$1" in
    -n) mode=n; shift ;;
    -S) mode=S; shift ;;
    -p) shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done
if [ -n "$FAKE_SUDO_DENY" ]; then
  echo "Sorry, user audit is not allowed to execute '$*' as root on host." >&2
  exit 1
fi
name=$(basename "$1")
for allowed in $FAKE_SUDO_NOPASSWD; do
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

_FAKE_NGINX = r"""#!/bin/sh
case "$1" in
  -v) echo "nginx version: nginx/1.24.0" >&2 ;;
  -T)
    if [ -n "$FAKE_NGINX_BROKEN" ]; then
      echo "nginx: [emerg] unknown directive \"foo\" in /etc/nginx/nginx.conf:3" >&2
      exit 1
    fi
    echo "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok" >&2
    printf '# configuration file /etc/nginx/nginx.conf:\nhttp {\n    server_tokens off;\n}\n'
    ;;
esac
"""


class _LocalShellSSH:
    def __init__(self, bin_dir: Path, password: str = '', sudo_password: str = '', **env):
        self.password = password
        self.sudo_password = sudo_password or password
        self.env = {**os.environ, 'PATH': f'{bin_dir}{os.pathsep}{os.environ.get("PATH", "")}',
                    'FAKE_SUDO_PASSWORD': SPW, **env}

    def run(self, cmd, timeout=20, stdin_data=None):
        proc = subprocess.run(['/bin/sh', '-c', cmd], input=stdin_data or '', capture_output=True,  # nosec B603 - test-only local shell
                              text=True, timeout=timeout, env=self.env, check=False)
        return proc.stdout, proc.stderr

    def sudo(self, cmd, timeout=20):
        if self.sudo_password:
            return self.run(f"sudo -S -p '' {cmd}", timeout, stdin_data=self.sudo_password + '\n')
        return self.run(f'sudo -n {cmd}', timeout)


@pytest.fixture
def bin_dir(tmp_path):
    d = tmp_path / 'bin'
    d.mkdir()
    for name, body in (('sudo', _FAKE_SUDO), ('nginx', _FAKE_NGINX)):
        (d / name).write_text(body)
        (d / name).chmod(0o755)
    return d


def test_right_sudo_password_reads_the_nginx_config(bin_dir):
    cfg = collect_nginx_config(_LocalShellSSH(bin_dir, sudo_password=SPW))
    assert cfg.readable is True
    assert cfg.server_tokens == 'off'
    assert cfg.error is None


def test_nopasswd_rule_needs_no_password(bin_dir):
    cfg = collect_nginx_config(_LocalShellSSH(bin_dir, FAKE_SUDO_NOPASSWD='nginx'))
    assert cfg.readable is True


def test_no_sudo_password_says_what_to_fill_in(bin_dir):
    cfg = collect_nginx_config(_LocalShellSSH(bin_dir))
    assert cfg.readable is False
    assert cfg.error == ('sudo needs a password to run nginx -T: fill in "Sudo password", '
                         'or allow nginx -T for this user with a NOPASSWD sudoers rule')


def test_wrong_sudo_password_is_reported(bin_dir):
    cfg = collect_nginx_config(_LocalShellSSH(bin_dir, sudo_password='wrong'))
    assert cfg.error == 'the sudo password was not accepted for nginx -T'


def test_sudoers_denial_is_reported(bin_dir):
    cfg = collect_nginx_config(_LocalShellSSH(bin_dir, sudo_password=SPW, FAKE_SUDO_DENY='1'))
    assert cfg.error == 'the SSH user may not run nginx -T with sudo (sudoers)'


def test_broken_nginx_config_is_not_reported_as_missing_root(bin_dir):
    cfg = collect_nginx_config(_LocalShellSSH(bin_dir, sudo_password=SPW, FAKE_NGINX_BROKEN='1'))
    assert cfg.readable is False
    assert 'requires root' not in cfg.error
    assert '[emerg] unknown directive' in cfg.error


def test_nginx_hardening_error_carries_the_diagnostic(bin_dir, monkeypatch):
    from netaudit_pkg.checks.nginx_hardening import check_nginx_hardening
    shell = _LocalShellSSH(bin_dir, sudo_password='wrong')
    shell.connect = lambda: shell
    shell.close = lambda: None
    monkeypatch.setattr('netaudit_pkg.checks.nginx_hardening.SSHExecutor', lambda *a, **kw: shell)
    result = check_nginx_hardening(host='h', sudo_password='wrong')
    assert result['error'] == 'the sudo password was not accepted for nginx -T'


def test_ssh_hardening_error_carries_the_diagnostic(monkeypatch):
    from netaudit_pkg.checks.ssh_hardening import check_ssh_hardening
    fake = ExitCodeFakeSSHExecutor(
        responses={'which sshd': '/usr/sbin/sshd', 'sshd -V': 'OpenSSH_9.6', 'sudo -n -- sshd -T': ''},
        exit_codes={'sudo -n -- sshd -T': 1},
        stderrs={'sudo -n -- sshd -T': 'sudo: a password is required\n'})
    monkeypatch.setattr('netaudit_pkg.checks.ssh_hardening.SSHExecutor', lambda *a, **kw: fake)
    result = check_ssh_hardening(host='h')
    assert result['error'].startswith('sudo needs a password to run sshd -T: fill in "Sudo password"')


# ===========================================================================
# C5: sysctl -a without sudo
# ===========================================================================

def _kernel_fake(unprivileged_output: str) -> ExitCodeFakeSSHExecutor:
    return ExitCodeFakeSSHExecutor(
        responses={'uname -r': '6.8.0-45-generic\n', 'sudo -n -- sysctl -a': '',
                   '{ sysctl -a': unprivileged_output},
        exit_codes={'sudo -n -- sysctl -a': 1, '{ sysctl -a': 0},
        stderrs={'sudo -n -- sysctl -a': 'sudo: a password is required\n'})


def test_sysctl_is_read_without_sudo_when_sudo_is_refused():
    cfg = collect_kernel_config(_kernel_fake(_VM_BASELINE))
    assert cfg.readable is True
    assert cfg.collected_without_sudo is True
    assert cfg.randomize_va_space == 2
    assert cfg.sudo_reason.startswith('sudo needs a password to run sysctl -a')


def test_kernel_hardening_runs_in_full_without_sudo(monkeypatch):
    from netaudit_pkg.checks.kernel_hardening import check_kernel_hardening
    fake = _kernel_fake(_VM_BASELINE)
    monkeypatch.setattr('netaudit_pkg.checks.kernel_hardening.SSHExecutor', lambda *a, **kw: fake)
    result = check_kernel_hardening(host='h')
    assert 'error' not in result
    assert isinstance(result['hardening']['score'], int)
    assert result['collected_without_sudo'] is True
    assert result['sudo_note'].startswith('sudo needs a password to run sysctl -a')


def test_kernel_hardening_names_the_keys_it_could_not_read(monkeypatch):
    from netaudit_pkg.checks.kernel_hardening import check_kernel_hardening
    partial = '\n'.join(line for line in _VM_BASELINE.splitlines() if not line.startswith('kernel.kptr_restrict'))
    fake = _kernel_fake(partial)
    monkeypatch.setattr('netaudit_pkg.checks.kernel_hardening.SSHExecutor', lambda *a, **kw: fake)
    result = check_kernel_hardening(host='h')
    assert 'kernel.kptr_restrict' in result['error']
    assert 'sudo needs a password to run sysctl -a' in result['error']
    assert 'hardening' not in result


def test_sysctl_with_working_sudo_does_not_fall_back():
    fake = ExitCodeFakeSSHExecutor(
        responses={'uname -r': '6.8.0\n', 'sudo -n -- sysctl -a': _VM_BASELINE},
        exit_codes={'sudo -n -- sysctl -a': 0})
    cfg = collect_kernel_config(fake)
    assert cfg.readable is True
    assert cfg.collected_without_sudo is False
    assert not any(c.startswith('{ sysctl -a') for c in fake.calls)


# ===========================================================================
# C3: never stored or sent
# ===========================================================================

def test_sudo_password_is_a_secret_param_everywhere():
    assert 'sudo_password' in SECRET_PARAM_NAMES
    report = {'execution_context': {'kernel_hardening': {'host': 'h', 'sudo_password': SPW}}}
    assert SPW not in json.dumps(redact_report(report))
    assert SPW not in json.dumps(redact_preset_checks([{'id': 'x', 'params': {'sudo_password': SPW}}]))


def test_saved_report_row_has_no_sudo_password(isolated_db):
    from netaudit_pkg.engine import run_checks
    from netaudit_pkg.registry import CheckSpec, registry

    def _fake_check(host='', sudo_password=''):
        return {'host': host, 'used_sudo': bool(sudo_password)}

    registry._checks['_t10_check'] = CheckSpec(
        id='_t10_check', label='t10', category='server', func=_fake_check,
        params=[{'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
                {'name': 'sudo_password', 'type': 'password', 'label': 'Sudo password', 'default': ''}])
    try:
        report = run_checks([{'id': '_t10_check', 'params': {'host': 'h', 'sudo_password': SPW}}])
        report_id = isolated_db.save_report(report)
        assert report['results']['_t10_check']['used_sudo'] is True
    finally:
        del registry._checks['_t10_check']
    import sqlite3
    conn = sqlite3.connect(isolated_db.DB_PATH)
    try:
        raw = conn.execute('SELECT data FROM reports WHERE id=?', (report_id,)).fetchone()[0]
    finally:
        conn.close()
    assert SPW not in raw


# ===========================================================================
# C2: CLI prompt
# ===========================================================================

def test_cli_dash_value_prompts_with_getpass(monkeypatch):
    import netaudit
    asked = []
    monkeypatch.setattr('getpass.getpass', lambda prompt='': asked.append(prompt) or SPW)
    captured = {}
    monkeypatch.setattr(netaudit, 'run_checks', lambda selected: captured.setdefault('selected', selected) and {
        'timestamp': 't', 'results': {}, 'total_time': 0})
    monkeypatch.setattr(netaudit, 'save_report', lambda report: 1)
    netaudit.cmd_run(Namespace(checks=['kernel_hardening'], rest=['--host', 'h', '--sudo_password', '-'],
                               ai=False, quick=False, json=False))
    params = captured['selected'][0]['params']
    assert params['sudo_password'] == SPW
    assert len(asked) == 1 and 'sudo_password' in asked[0]


# ===========================================================================
# C1: which checks get the field, labels
# ===========================================================================

SUDO_CHECKS = {'server_audit', 'nginx_hardening', 'kernel_hardening', 'ssh_hardening', 'systemd_hardening',
               'lynis_audit', 'rootkit_check', 'aide_check', 'docker_audit', 'ssh_audit', 'ssh_auth_audit',
               'nginx_logs_audit', 'kern_log_audit', 'fail2ban_logs_audit'}
NO_SUDO_SSH_CHECKS = {'backup_check', 'cve_audit', 'log_discovery_audit'}


def test_sudo_checks_have_sudo_password_after_password():
    import netaudit_pkg.checks  # noqa: F401 - registers every check
    from netaudit_pkg.registry import registry
    for check_id in SUDO_CHECKS:
        names = [p['name'] for p in registry.get(check_id).params]
        assert names[names.index('password') + 1] == 'sudo_password', check_id
        params = {p['name']: p for p in registry.get(check_id).params}
        assert params['sudo_password']['type'] == 'password'
        assert params['sudo_password']['label'] == 'Sudo password (if sudo asks for one)'
        assert params['password']['label'] == 'SSH password (if no key)'
    for check_id in NO_SUDO_SSH_CHECKS:
        assert 'sudo_password' not in {p['name'] for p in registry.get(check_id).params}, check_id


def test_ru_labels():
    i18n = (Path(__file__).resolve().parent.parent / 'web' / 'static' / 'i18n.js').read_text(encoding='utf-8')
    assert "sudo_password: { ru: 'Пароль sudo (если sudo его спрашивает)' }" in i18n
    assert 'Пароль SSH (если без ключа) / пароль sudo' not in i18n
