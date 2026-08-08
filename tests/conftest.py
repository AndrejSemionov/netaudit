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
