"""Tests for netaudit_pkg.ssh_utils.run_command_with_exit_code() - the
shared exit-code-recovery helper used by both cve_audit.py (dpkg-query,
apt-cache show) and firewall_config.py (ufw, nft, iptables, cat on
config files) to distinguish "command completed with empty output" from
"command's completion could not be confirmed" over SSHExecutor.run(),
which itself returns no exit code.
"""

from __future__ import annotations

import re

from netaudit_pkg.ssh_utils import run_command_with_exit_code
from tests.conftest import FakeSSHExecutor


def _wrap_like_real_shell(stdout: str, exit_code: int, marker: str) -> str:
    """Builds the stdout a real shell would produce for the wrapped
    command - i.e. what `{ <cmd>; rc=$?; printf '\\n%s:%s\\n' '<marker>'
    "$rc"; }` actually writes to the channel. Tests use this instead of
    hardcoding the marker, since run_command_with_exit_code() generates
    a fresh uuid4 marker per call and tests can't predict it in advance -
    they must capture the wrapped command FakeSSHExecutor received and
    extract the marker from it."""
    return f'{stdout}\n{marker}:{exit_code}\n'


def _extract_marker_from_wrapped_command(wrapped_cmd: str) -> str:
    """Reverse-engineers the marker run_command_with_exit_code() embedded
    in its own wrapped shell command, so a test can build a realistic
    canned response containing that exact marker."""
    m = re.search(r"printf '\\n%s:%s\\n' '(__NETAUDIT_RC_[0-9a-f]+__)'", wrapped_cmd)
    assert m, f'could not find marker in wrapped command: {wrapped_cmd!r}'
    return m.group(1)


class _CapturingFakeSSH(FakeSSHExecutor):
    """A FakeSSHExecutor that, on the FIRST call, captures the exact
    wrapped command it received (so the test can extract the generated
    marker from it) and returns a response built with that marker - this
    is necessary because the marker is randomly generated per call and
    can't be known before the call happens."""

    def __init__(self, stdout: str, exit_code: int):
        super().__init__()
        self.stdout = stdout
        self.exit_code = exit_code
        self.captured_cmd = None

    def run(self, cmd: str, timeout: int = 20) -> tuple[str, str]:
        self.captured_cmd = cmd
        marker = _extract_marker_from_wrapped_command(cmd)
        return _wrap_like_real_shell(self.stdout, self.exit_code, marker), ''


def test_run_command_with_exit_code_success_with_output():
    fake = _CapturingFakeSSH('hello world', 0)
    out, code = run_command_with_exit_code(fake, 'echo hello world')
    assert out == 'hello world'
    assert code == 0


def test_run_command_with_exit_code_success_with_empty_output():
    """A command can legitimately succeed with empty stdout - e.g. `nft
    list ruleset` on a host with zero configured tables. This must be
    exit_code=0 with out='', NOT confused with a collection failure."""
    fake = _CapturingFakeSSH('', 0)
    out, code = run_command_with_exit_code(fake, 'true')
    assert out == ''
    assert code == 0


def test_run_command_with_exit_code_nonzero_exit_confirmed_failure():
    """A command that runs to completion and reports failure (e.g. `ufw
    status` refusing without root) must return the real exit code, not
    None - this is a CONFIRMED failure, distinct from an unconfirmed
    unknown."""
    fake = _CapturingFakeSSH('', 1)
    _, code = run_command_with_exit_code(fake, 'false')
    assert code == 1


def test_run_command_with_exit_code_returns_none_when_marker_absent():
    """No marker anywhere in stdout - completion could not be confirmed
    (dropped SSH channel, timeout, truncated output)."""
    fake = FakeSSHExecutor(responses={
        'whoami': ('some output with no marker at all', ''),
    })
    _, code = run_command_with_exit_code(fake, 'whoami')
    assert code is None


def test_run_command_with_exit_code_returns_none_on_malformed_exit_value():
    """Marker present but what follows isn't a parseable integer -
    treated as unknown, not as a crash and not as a guessed exit code."""

    class _MalformedFakeSSH(FakeSSHExecutor):
        def run(self, cmd, timeout=20):
            marker = _extract_marker_from_wrapped_command(cmd)
            return f'output\n{marker}:not-a-number\n', ''

    fake = _MalformedFakeSSH()
    _, code = run_command_with_exit_code(fake, 'whoami')
    assert code is None


def test_run_command_with_exit_code_preserves_multiline_stdout():
    fake = _CapturingFakeSSH('line1\nline2\nline3', 0)
    out, code = run_command_with_exit_code(fake, 'cat somefile')
    assert out == 'line1\nline2\nline3'
    assert code == 0


def test_run_command_with_exit_code_marker_is_fresh_per_call():
    """Each call generates a new random marker - two consecutive calls
    must not reuse the same marker, so a stale/leftover marker from a
    previous command sitting in some buffered channel output could never
    be mistaken for the current call's completion signal."""

    class _RecordingFakeSSH(FakeSSHExecutor):
        def __init__(self):
            super().__init__()
            self.seen_markers = []

        def run(self, cmd, timeout=20):
            marker = _extract_marker_from_wrapped_command(cmd)
            self.seen_markers.append(marker)
            return f'ok\n{marker}:0\n', ''

    fake = _RecordingFakeSSH()
    run_command_with_exit_code(fake, 'echo one')
    run_command_with_exit_code(fake, 'echo two')
    assert len(fake.seen_markers) == 2
    assert fake.seen_markers[0] != fake.seen_markers[1]


def test_run_command_with_exit_code_survives_command_output_containing_marker_like_text():
    """If the remote command's own stdout happens to contain text that
    LOOKS like a netaudit marker (extremely unlikely in practice, but
    the parsing must still be safe) - rpartition() on the REAL marker
    (a fresh uuid4, which the fake command's coincidental text cannot
    actually match) still finds the real, last occurrence and parses it
    correctly, because the fake text uses a different (hardcoded, wrong)
    suffix than the real generated marker."""
    fake = _CapturingFakeSSH(
        'some output mentioning __NETAUDIT_RC_deadbeef__:99 as literal text',
        0,
    )
    out, code = run_command_with_exit_code(fake, 'echo weird')
    # the real marker (uuid4-generated) is distinct from the coincidental
    # text above, so it's found correctly at the end, and the
    # coincidental text remains part of the returned stdout body
    assert '__NETAUDIT_RC_deadbeef__:99' in out
    assert code == 0


def test_run_command_with_exit_code_does_not_mutate_ssh_run_signature_usage():
    """run_command_with_exit_code() must call ssh.run() with the
    (cmd, timeout=...) signature FakeSSHExecutor/SSHExecutor both expose
    - not some other calling convention - since this helper is meant to
    be a drop-in addition on top of the existing SSHExecutor contract,
    not a parallel one."""
    fake = _CapturingFakeSSH('x', 0)
    run_command_with_exit_code(fake, 'whoami', timeout=5)
    assert 'whoami' in fake.captured_cmd
