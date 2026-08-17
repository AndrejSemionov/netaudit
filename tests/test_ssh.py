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
    call_count = {'command -v lynis': 0}

    class ScriptedClient(_FakeParamikoClient):
        def exec_command(self, cmd, timeout=15):
            self.calls.append(cmd)
            if 'sudo -S' in cmd:
                return _FakeStdin(), _FakeStream('Setting up lynis'), _FakeStream('')
            if 'command -v lynis' in cmd:
                call_count['command -v lynis'] += 1
                # run_command_with_exit_code() wraps the real command in a
                # shell group with a fresh uuid4 marker each call - extract
                # it from the command text itself (it's embedded in the
                # printf) so the fake can echo back a matching completion
                # line, exactly mirroring what a real shell would produce.
                import re as _re
                m = _re.search(r"__NETAUDIT_RC_[0-9a-f]+__", cmd)
                marker = m.group(0)
                if call_count['command -v lynis'] == 1:
                    # not present yet - command -v exits 1 (or 127; either
                    # nonzero is "not found" for this test's purposes)
                    return _FakeStdin(), _FakeStream(f'\n{marker}:127\n'), _FakeStream('')
                # present after the simulated install
                return _FakeStdin(), _FakeStream(f'/usr/sbin/lynis\n{marker}:0\n'), _FakeStream('')
            return _FakeStdin(), _FakeStream(''), _FakeStream('')

    ex.client = ScriptedClient()
    installed, err = ex.ensure_tool_installed('lynis')
    assert installed is True
    assert err is None
    assert call_count['command -v lynis'] == 2  # checked before and after install


def test_ensure_tool_installed_skips_when_already_present():
    ex = SSHExecutor('host', 'user', 22, '', 'pw')

    class AlreadyPresentClient(_FakeParamikoClient):
        def exec_command(self, cmd, timeout=15):
            self.calls.append(cmd)
            if 'command -v lynis' in cmd:
                import re as _re
                m = _re.search(r"__NETAUDIT_RC_[0-9a-f]+__", cmd)
                marker = m.group(0)
                return _FakeStdin(), _FakeStream(f'/usr/sbin/lynis\n{marker}:0\n'), _FakeStream('')
            return _FakeStdin(), _FakeStream(''), _FakeStream('')

    ex.client = AlreadyPresentClient()
    installed, _err = ex.ensure_tool_installed('lynis')
    assert installed is True
    apt_calls = [c for c in ex.client.calls if 'apt-get install' in c]
    assert apt_calls == []


# ===========================================================================
# is_tool_installed() - direct unit tests (previously untested entirely;
# found during a quality-audit pass over the whole project's error
# handling after the fail2ban/firewall sudo-capability work). Locks in
# the fix for the same which-collapse bug class already fixed in
# fail2ban_config.py/firewall_config.py/sql_config.py/cve_audit.py:
# `which tool || echo NOTFOUND` collapsed ANY nonzero exit of `which`
# (including a collection failure) into "not installed" - now replaced
# with `command -v` and its own documented exit-code convention.
# ===========================================================================

def _client_for_command_v(exit_code: int, stdout: str = '', completed: bool = True):
    """Builds a _FakeParamikoClient whose exec_command() responds to any
    `command -v <tool>` call (wrapped in run_command_with_exit_code()'s
    shell-group/marker) with the given exit code - or, if completed is
    False, never emits a completion marker at all, simulating a genuine
    collection failure (SSH channel drop, timeout)."""
    class Client(_FakeParamikoClient):
        def exec_command(self, cmd, timeout=15):
            self.calls.append(cmd)
            if 'command -v' in cmd:
                if not completed:
                    return _FakeStdin(), _FakeStream('connection reset'), _FakeStream('')
                import re as _re
                m = _re.search(r"__NETAUDIT_RC_[0-9a-f]+__", cmd)
                marker = m.group(0)
                return _FakeStdin(), _FakeStream(f'{stdout}\n{marker}:{exit_code}\n'), _FakeStream('')
            return _FakeStdin(), _FakeStream(''), _FakeStream('')
    return Client()


def test_is_tool_installed_true_on_exit_0():
    ex = SSHExecutor('host', 'user', 22, '', '')
    ex.client = _client_for_command_v(exit_code=0, stdout='/usr/sbin/lynis')
    assert ex.is_tool_installed('lynis') is True


def test_is_tool_installed_false_on_exit_127_confirmed_absent():
    """command -v's own documented 'not found' convention - a genuine,
    confirmed absence, not a collection failure."""
    ex = SSHExecutor('host', 'user', 22, '', '')
    ex.client = _client_for_command_v(exit_code=127)
    assert ex.is_tool_installed('some-tool-not-installed') is False


def test_is_tool_installed_false_on_collection_failure():
    """A genuine collection failure (no completion marker recovered at
    all) must not be reported as 'installed' - conservatively False,
    matching this method's pre-fix behavior in this same scenario (a
    failed `which` also produced a falsy result), so no caller's
    existing assumption about the failure case changes."""
    ex = SSHExecutor('host', 'user', 22, '', '')
    ex.client = _client_for_command_v(exit_code=0, completed=False)
    assert ex.is_tool_installed('lynis') is False


def test_is_tool_installed_uses_command_dash_v_not_which():
    """Direct regression for the which-collapse fix: the actual command
    sent must be `command -v <tool>`, never a bare `which <tool>` (with
    or without a `|| echo NOTFOUND` fallback) - locks in that the fix
    isn't just a different exit-code interpretation of the same old
    command, but genuinely uses the exit-code-safe primitive."""
    ex = SSHExecutor('host', 'user', 22, '', '')
    ex.client = _client_for_command_v(exit_code=0, stdout='/usr/sbin/lynis')
    ex.is_tool_installed('lynis')
    assert any('command -v lynis' in c for c in ex.client.calls)
    assert not any(c.strip().startswith('which ') for c in ex.client.calls)
    assert not any('NOTFOUND' in c for c in ex.client.calls)
