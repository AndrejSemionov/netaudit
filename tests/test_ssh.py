"""
Tests for netaudit_pkg.ssh: SSHExecutor and the TOFU host-key policy.

These mock paramiko.SSHClient's exec_command directly (not FakeSSHExecutor from
conftest, which stands in for SSHExecutor itself in check-level tests) - this
file tests SSHExecutor's own internals, so it needs the layer underneath it.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

import netaudit_pkg.ssh as ssh_mod
from netaudit_pkg.ssh import SSHExecutor, HostKeyMismatchError, TofuPolicy


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


def test_sudo_uses_passwordless_when_available():
    ex = SSHExecutor('host', 'user', 22, '', 'pw')
    ex.client = _FakeParamikoClient({
        'sudo -n true': 'OK',
        'sudo whoami': 'ran with passwordless sudo',
    })
    out, err = ex.sudo('whoami')
    assert out == 'ran with passwordless sudo'
    assert ex._no_password_sudo is True


def test_sudo_falls_back_to_stdin_password():
    ex = SSHExecutor('host', 'user', 22, '', 'mypassword')
    ex.client = _FakeParamikoClient({
        'sudo -n true': 'NOPASS',
        'sudo -S': 'ran with sudo -S',
    })
    out, err = ex.sudo('whoami')
    assert out == 'ran with sudo -S'
    assert ex._no_password_sudo is False


def test_sudo_availability_check_is_cached():
    ex = SSHExecutor('host', 'user', 22, '', 'pw')
    ex.client = _FakeParamikoClient({'sudo -n true': 'OK'})
    ex.sudo('cmd1')
    ex.sudo('cmd2')
    check_calls = [c for c in ex.client.calls if 'sudo -n true' in c]
    assert len(check_calls) == 1


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
