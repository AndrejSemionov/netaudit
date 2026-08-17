"""
Tests for netaudit_pkg.ssh: SSHExecutor and the TOFU host-key policy.

These mock paramiko.SSHClient's exec_command directly (not FakeSSHExecutor from
conftest, which stands in for SSHExecutor itself in check-level tests) - this
file tests SSHExecutor's own internals, so it needs the layer underneath it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import netaudit_pkg.ssh as ssh_mod
from netaudit_pkg.ssh import HostKeyMismatchError, SSHExecutor, TofuPolicy


class _FakeStdin:
    def __init__(self):
        self.written = []

    def write(self, s):
        self.written.append(s)

    def flush(self):
        pass

    class channel:
        @staticmethod
        def shutdown_write():
            pass


class _FakeStream:
    def __init__(self, text):
        self.text = text.encode()

    def read(self):
        return self.text


class _FakeParamikoClient:
    """A minimal stand-in for paramiko.SSHClient, used only within this file
    to test SSHExecutor's own run()/sudo() logic against a scripted command->
    output mapping."""

    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []
        self.closed = False

    def exec_command(self, cmd, timeout=15):
        self.calls.append(cmd)
        for substr, out in self.responses.items():
            if substr in cmd:
                return _FakeStdin(), _FakeStream(out), _FakeStream('')
        return _FakeStdin(), _FakeStream(''), _FakeStream('')

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def isolated_known_hosts(monkeypatch, tmp_path):
    """Every test gets its own known_hosts path, so TOFU state from one test
    never leaks into another (the real path is a fixed ~/.netaudit/known_hosts)."""
    monkeypatch.setattr(ssh_mod, 'KNOWN_HOSTS_PATH', tmp_path / 'known_hosts')
    yield


def test_sudo_no_password_uses_sudo_dash_n_on_actual_command():
    """New contract: password='' means sudo() goes straight to `sudo -n
    <actual-command>` for the REAL command being run - never a
    preliminary `sudo -n true` probe against a different, unrelated
    command. This is the direct fix for the scoped-sudoers bug found
    during fail2ban VM verification (46.62.147.41, session notes): a
    NOPASSWD rule scoped to one specific binary makes `sudo -n true`
    fail while the actual target command succeeds - so probing `true`
    can never be a correct substitute for probing the real command."""
    ex = SSHExecutor('host', 'user', 22, '', '')
    ex.client = _FakeParamikoClient({
        'sudo -n fail2ban-client status': 'Status\n|- Number of jail: 6',
    })
    out, _err = ex.sudo('fail2ban-client status')
    assert out == 'Status\n|- Number of jail: 6'
    # the exact command sent must be the real command under `sudo -n`,
    # not a generic capability probe
    assert any('sudo -n fail2ban-client status' in c for c in ex.client.calls)


def test_sudo_no_password_never_probes_sudo_true():
    """The old `sudo -n true` capability probe must be gone entirely -
    not called before, during, or as a side effect of any sudo() call,
    regardless of what the actual command is or how many times sudo()
    is called."""
    ex = SSHExecutor('host', 'user', 22, '', '')
    ex.client = _FakeParamikoClient({
        'sudo -n fail2ban-client status': 'jail data',
        'sudo -n nginx -T': 'server {}',
    })
    ex.sudo('fail2ban-client status')
    ex.sudo('nginx -T')
    assert not any('sudo -n true' in c for c in ex.client.calls)


def test_sudo_no_password_command_denied_returns_real_refusal_no_fallback():
    """When `sudo -n <actual-command>` itself is refused (command not
    covered by any NOPASSWD rule) and no password was provided, sudo()
    must return that refusal as-is - it must NOT silently fall back to
    `sudo -S` with an empty/absent password (the second half of the
    original bug: an empty stdin write to `sudo -S` doesn't produce a
    meaningful error, it just hangs or fails opaquely)."""
    ex = SSHExecutor('host', 'user', 22, '', '')
    ex.client = _FakeParamikoClient({
        'sudo -n some-other-command': 'sudo: a password is required',
    })
    out, _err = ex.sudo('some-other-command')
    assert out == 'sudo: a password is required'
    # must never have attempted the -S branch
    assert not any('sudo -S' in c for c in ex.client.calls)


def test_sudo_two_different_commands_each_evaluated_independently():
    """No session-level capability cache of any kind: two different
    commands with two different (simulated) scoped-sudoers outcomes
    must each be evaluated on their own - one succeeding must have no
    bearing on the other."""
    ex = SSHExecutor('host', 'user', 22, '', '')
    ex.client = _FakeParamikoClient({
        'sudo -n fail2ban-client status': 'jail data - allowed',
        'sudo -n some-other-command': 'sudo: a password is required',
    })
    out_a, _ = ex.sudo('fail2ban-client status')
    out_b, _ = ex.sudo('some-other-command')
    assert out_a == 'jail data - allowed'
    assert out_b == 'sudo: a password is required'


def test_sudo_with_password_uses_sudo_dash_s_directly_no_probe():
    """New contract: password='secret' means sudo() goes straight to
    `sudo -S -p "" <actual-command>` and writes the password to stdin -
    no `sudo -n` probe of any kind first, on the real command or on
    `true`."""
    ex = SSHExecutor('host', 'user', 22, '', 'secret')
    ex.client = _FakeParamikoClient({
        'sudo -S': 'ran with sudo -S',
    })
    out, _err = ex.sudo('whoami')
    assert out == 'ran with sudo -S'
    assert not any('sudo -n' in c for c in ex.client.calls)


def test_sudo_with_password_writes_exact_password_to_stdin():
    """The exact password (and only the password) must be written to
    the sudo -S stdin - this is the assertion that would catch any
    future accidental conflation with a different credential (e.g. an
    SSH key passphrase, which is explicitly NOT the same thing as a
    sudo password - see this project's session notes on why
    key_passphrase support is deliberately out of scope for this
    fix)."""
    ex = SSHExecutor('host', 'user', 22, '', 'my-sudo-password')
    fake_client = _FakeParamikoClient({'sudo -S': 'ok'})
    captured_stdin = {}

    orig_exec = fake_client.exec_command
    def _capturing_exec(cmd, timeout=15):
        stdin, so, se = orig_exec(cmd, timeout)
        captured_stdin['stdin'] = stdin
        return stdin, so, se
    fake_client.exec_command = _capturing_exec

    ex.client = fake_client
    ex.sudo('whoami')
    assert captured_stdin['stdin'].written == ['my-sudo-password\n']


def test_sudo_key_auth_with_empty_password_uses_sudo_n_not_key_material():
    """Reproduces the real infrastructure model (session notes,
    46.62.147.41): SSH authenticates via key_path, password='' (no sudo
    password configured at all - direct root login is closed, sudo
    access is via scoped NOPASSWD). sudo() must use `sudo -n
    <actual-command>` - it must never attempt to use anything related
    to the SSH key (key_path itself, or any future key_passphrase) as
    sudo credential material. This test uses today's actual API surface
    (key_path + password='') since key_passphrase is explicitly out of
    scope for this fix."""
    ex = SSHExecutor('host', 'andreykapro', 4444, '~/.ssh/andreykapro_writter', '')
    ex.client = _FakeParamikoClient({
        'sudo -n fail2ban-client status': 'Status\n|- Number of jail: 6',
    })
    out, _err = ex.sudo('fail2ban-client status')
    assert out == 'Status\n|- Number of jail: 6'
    assert not any('sudo -S' in c for c in ex.client.calls)


def test_sudo_no_longer_reads_or_writes_no_password_sudo_cache():
    """sudo() itself must not read or mutate `_no_password_sudo` at all -
    no session-level capability cache drives its behavior anymore. The
    attribute itself still exists on the instance (needs_sudo_password()
    still uses it - that method's own contract is a separate, later
    piece of work per project session notes, deliberately not touched
    in this pass), so this test checks that sudo() calls leave it
    exactly as it started (None, i.e. never touched), rather than
    asserting the attribute doesn't exist on the class at all.

    This replaces the old test_sudo_availability_check_is_cached, which
    asserted the OPPOSITE - that a single `sudo -n true` probe was
    cached and reused for every subsequent command - as if that were
    correct. It has been removed rather than adapted, since adapting it
    would mean continuing to assert the wrong contract."""
    ex = SSHExecutor('host', 'user', 22, '', '')
    ex.client = _FakeParamikoClient({
        'sudo -n cmd1': 'result1',
        'sudo -n cmd2': 'result2',
    })
    assert ex._no_password_sudo is None
    ex.sudo('cmd1')
    ex.sudo('cmd2')
    assert ex._no_password_sudo is None
    assert not any('sudo -n true' in c for c in ex.client.calls)


@pytest.mark.parametrize('no_password_sudo,password,expected', [
    (False, '', True),    # needs a password, none given
    (False, 'secret', False),  # needs a password, one given
    (True, '', False),    # passwordless available, no password needed
])
def test_needs_sudo_password(no_password_sudo, password, expected):
    ex = SSHExecutor('host', 'user', 22, '', password)
    sudo_check_response = 'OK' if no_password_sudo else 'NOPASS'
    ex.client = _FakeParamikoClient({'sudo -n true': sudo_check_response})
    assert ex.needs_sudo_password() is expected


def test_host_key_mismatch_raises_clear_error(monkeypatch):
    import paramiko

    class RaisingClient:
        def load_host_keys(self, path):
            pass

        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, **kwargs):
            raise paramiko.BadHostKeyException('host', None, None)

    monkeypatch.setattr(paramiko, 'SSHClient', RaisingClient)
    ex = SSHExecutor('host', 'user', 22, '', password='pw')
    with pytest.raises(HostKeyMismatchError, match='different SSH host key'):
        ex.connect()


def test_tofu_policy_saves_key_on_first_connection(tmp_path, monkeypatch):
    monkeypatch.setattr(ssh_mod, 'KNOWN_HOSTS_PATH', tmp_path / 'known_hosts')

    class FakeKey:
        def get_fingerprint(self):
            class FP:
                def hex(self, sep=':'):
                    return 'aa:bb:cc'
            return FP()

        def get_name(self):
            return 'ssh-ed25519'

    class FakeHostKeys(dict):
        def add(self, hostname, keytype, key):
            self[hostname] = key

    class FakeClient:
        def __init__(self):
            self._hk = FakeHostKeys()

        def get_host_keys(self):
            return self._hk

        def save_host_keys(self, path):
            Path(path).write_text('saved')

    policy = TofuPolicy()
    client = FakeClient()
    policy.missing_host_key(client, 'testhost', FakeKey())

    assert 'testhost' in client._hk
    assert ssh_mod.KNOWN_HOSTS_PATH.exists()


def test_context_manager_closes_connection(monkeypatch):
    import paramiko

    fake_client = _FakeParamikoClient({'whoami': 'hello'})

    class ConnectableClient:
        def load_host_keys(self, path):
            pass

        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, **kwargs):
            pass

        def exec_command(self, cmd, timeout=15):
            return fake_client.exec_command(cmd, timeout)

        def close(self):
            fake_client.close()

    monkeypatch.setattr(paramiko, 'SSHClient', ConnectableClient)

    with SSHExecutor('host', 'user', 22, '', password='pw') as ex:
        out, err = ex.run('whoami')
        assert out == 'hello'

    assert fake_client.closed is True


def test_ensure_tool_installed_rejects_unknown_tool():
    ex = SSHExecutor('host', 'user', 22, '', 'pw')
    ex.client = _FakeParamikoClient({'which': 'NOTFOUND'})
    installed, err = ex.ensure_tool_installed('some-random-tool-xyz')
    assert installed is False
    assert 'not on the install allowlist' in err


def test_ensure_tool_installed_success_path():
    ex = SSHExecutor('host', 'user', 22, '', 'pw')
    call_count = {'which': 0}

    class ScriptedClient(_FakeParamikoClient):
        def exec_command(self, cmd, timeout=15):
            self.calls.append(cmd)
            if 'sudo -n true' in cmd:
                return _FakeStdin(), _FakeStream('OK'), _FakeStream('')
            if 'which lynis' in cmd:
                call_count['which'] += 1
                out = 'NOTFOUND' if call_count['which'] == 1 else '/usr/sbin/lynis'
                return _FakeStdin(), _FakeStream(out), _FakeStream('')
            if 'apt-get install' in cmd:
                return _FakeStdin(), _FakeStream('Setting up lynis'), _FakeStream('')
            return _FakeStdin(), _FakeStream(''), _FakeStream('')

    ex.client = ScriptedClient()
    installed, err = ex.ensure_tool_installed('lynis')
    assert installed is True
    assert err is None
    assert call_count['which'] == 2  # checked before and after install


def test_ensure_tool_installed_skips_when_already_present():
    ex = SSHExecutor('host', 'user', 22, '', 'pw')
    ex.client = _FakeParamikoClient({'which lynis': '/usr/sbin/lynis'})
    installed, err = ex.ensure_tool_installed('lynis')
    assert installed is True
    apt_calls = [c for c in ex.client.calls if 'apt-get install' in c]
    assert apt_calls == []
