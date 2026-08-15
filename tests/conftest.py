"""
Shared pytest fixtures.

The central one is FakeSSHExecutor: every SSH-based check (aide_check,
rootkit_check, lynis_audit, docker_audit, backup_check, cve_audit,
server_audit, ssh_audit, capture.check_mikrotik_sniffer) now goes through
netaudit_pkg.ssh.SSHExecutor - so a single well-tested fake stands in for all
of them, instead of every test file reinventing its own mock client.

Usage pattern in a test:

    def test_something(monkeypatch):
        fake = FakeSSHExecutor(responses={'which docker': ('/usr/bin/docker', '')})
        monkeypatch.setattr('netaudit_pkg.checks.docker_audit.SSHExecutor',
                             lambda *a, **kw: fake)
        result = check_docker_audit(host='1.2.3.4')
        ...

Responses are matched by substring against the command, checked in insertion
order - the first matching key wins. This mirrors how the real command strings
are built (e.g. 'which docker || echo NOTFOUND') without requiring exact
string matches, which would make tests brittle against minor wording changes.
"""

from __future__ import annotations

import re

import pytest


class FakeSSHExecutor:
    """
    Stands in for netaudit_pkg.ssh.SSHExecutor in tests. Construct with a
    `responses` dict mapping a substring of the command to a (stdout, stderr)
    tuple; `run()` and `sudo()` both consult it. `sudo_calls` is left None by
    default (uses passwordless sudo); set to True/False to control
    needs_sudo_password()/ensure_tool_installed() behavior explicitly.

    Every constructor arg from the real SSHExecutor is accepted and ignored,
    so `FakeSSHExecutor` can be substituted 1:1 wherever `SSHExecutor(...)` is
    called in check code - tests don't need to know the real signature changed.
    """

    def __init__(self, *args, responses: dict[str, tuple[str, str]] | None = None,
                 installed_tools: set[str] | None = None,
                 no_password_sudo: bool = True, password: str = '', **kwargs):
        self.responses = responses or {}
        self.installed_tools = installed_tools if installed_tools is not None else set()
        self._no_password_sudo = no_password_sudo
        self.password = password
        self.calls: list[str] = []
        self.closed = False

    def connect(self):
        return self

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()

    def _match(self, cmd: str) -> tuple[str, str]:
        self.calls.append(cmd)
        for substr, response in self.responses.items():
            if substr in cmd:
                return response
        return ('', '')

    def run(self, cmd: str, timeout: int = 20) -> tuple[str, str]:
        return self._match(cmd)

    def sudo(self, cmd: str, timeout: int = 20) -> tuple[str, str]:
        return self._match(cmd)

    def needs_sudo_password(self) -> bool:
        return (not self._no_password_sudo) and not self.password

    def is_tool_installed(self, tool: str) -> bool:
        return tool in self.installed_tools

    def ensure_tool_installed(self, tool: str, timeout: int = 120) -> tuple[bool, str | None]:
        if tool in self.installed_tools:
            return True, None
        # simulate a successful install by adding it, mirroring what a real
        # `apt-get install` followed by a re-check would do
        self.installed_tools.add(tool)
        return True, None

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake_ssh():
    """A FakeSSHExecutor with no canned responses - tests set .responses directly."""
    return FakeSSHExecutor()


_RC_MARKER_RE = re.compile(r'(__NETAUDIT_RC_[0-9a-f]+__)')


class ExitCodeFakeSSHExecutor(FakeSSHExecutor):
    """A FakeSSHExecutor for collectors built on
    netaudit_pkg.ssh_utils.run_command_with_exit_code(), which wraps every
    command in a shell group with a FRESH RANDOM (uuid4) completion
    marker per call - see ssh_utils.py's docstring for why it's random
    rather than a fixed string. Because the marker can't be known in
    advance, a plain substring-keyed `responses` dict (as ordinary
    FakeSSHExecutor uses) can't pre-bake the right marker into its canned
    stdout.

    This subclass keeps the same substring-matching `responses` dict.
    Each value may be either a plain stdout string (for a command NOT
    wrapped by run_command_with_exit_code(), e.g. `nginx -v`) or a
    (stdout, stderr) tuple (same shape ordinary FakeSSHExecutor uses) -
    both are accepted so existing non-exit-code fixtures don't need
    reshaping. A parallel `exit_codes` dict (same substring-matching
    keys) gives the exit code to report for commands that DO go through
    run_command_with_exit_code() (e.g. `dpkg-query ...`) - only commands
    present in both `responses` AND `exit_codes` get the completion
    marker appended; others are returned as-is, unmarked (correct for
    plain ssh.run() calls, which never look for a marker anyway).

    A command with no matching key in `responses` (or a key present in
    `responses` but absent from `exit_codes`, when the command IS a
    run_command_with_exit_code() call) gets NO marker at all in its
    response - the same as a real dropped/truncated SSH command - which
    is the correct way to test the collection_ok=False / exit_code=None
    path: simply don't register an exit code for it.
    """

    def __init__(self, *args, responses: dict[str, object] | None = None,
                 exit_codes: dict[str, int] | None = None, **kwargs):
        super().__init__(*args, responses={}, **kwargs)
        self._raw_responses = responses or {}
        self._exit_codes = exit_codes or {}

    def _respond(self, cmd: str) -> tuple[str, str]:
        self.calls.append(cmd)
        m = _RC_MARKER_RE.search(cmd)
        marker = m.group(1) if m else None

        stdout = ''
        exit_code = None
        matched_substr = None
        for substr, response in self._raw_responses.items():
            if substr in cmd:
                stdout = response[0] if isinstance(response, tuple) else response
                matched_substr = substr
                break
        if matched_substr is not None:
            exit_code = self._exit_codes.get(matched_substr)

        if marker is None or exit_code is None:
            # No marker in the wrapped command (shouldn't happen for a
            # run_command_with_exit_code()/_run_sudo_with_exit_code()
            # caller) or no exit code registered for this command -
            # simulate a collection failure: raw stdout with no
            # completion marker at all, exactly like a dropped/truncated
            # SSH command.
            return stdout, ''
        return f'{stdout}\n{marker}:{exit_code}\n', ''

    def run(self, cmd: str, timeout: int = 20) -> tuple[str, str]:
        return self._respond(cmd)

    def sudo(self, cmd: str, timeout: int = 20) -> tuple[str, str]:
        # Same marker-recovery logic as run() - firewall_config.py's
        # _run_sudo_with_exit_code() wraps its script differently (`sh -c
        # <quoted script>` rather than a bare `{ ... }` group, since sudo
        # can't parse a shell reserved word as a bare argument - see that
        # module's docstring), but the marker itself is still just
        # __NETAUDIT_RC_<hex>__ embedded somewhere in the command text,
        # which _RC_MARKER_RE finds regardless of the surrounding
        # shell-quoting style.
        return self._respond(cmd)


def exit_marked(stdout: str, exit_code: int, marker: str = '__NETAUDIT_CVE_AUDIT_EXIT__') -> str:
    """DEPRECATED - kept only for reference/history. This built a
    response for a FIXED marker string, which matched cve_audit's
    original local _run_with_exit_code() before it was generalized into
    ssh_utils.run_command_with_exit_code() (which uses a fresh random
    marker per call instead - see that module's docstring for why).
    Tests exercising run_command_with_exit_code()-based collectors should
    use ExitCodeFakeSSHExecutor instead, which handles the random marker
    correctly. Not removed outright in case any in-flight branch still
    references it, but nothing in the current test suite should call
    this anymore."""
    return f'{stdout}\n{marker}:{exit_code}\n'


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    """
    Points netaudit_pkg.storage at a temporary SQLite file for the duration of
    a test, instead of the real ~/.netaudit/netaudit.db - so tests that touch
    settings/presets/cve_cache/etc don't read or write the user's actual data,
    and don't leak state between tests either.

    storage.py caches one connection per thread in a threading.local, so
    switching DB_PATH after a connection was already opened wouldn't take
    effect for that thread - this fixture clears the cached connection
    attribute too, forcing a fresh connect() against the new path.
    """
    import netaudit_pkg.storage as storage

    monkeypatch.setattr(storage, 'DB_PATH', tmp_path / 'test.db')
    if hasattr(storage._local, 'conn'):
        storage._local.conn.close()
        del storage._local.conn
    yield storage
    if hasattr(storage._local, 'conn'):
        storage._local.conn.close()
        del storage._local.conn
