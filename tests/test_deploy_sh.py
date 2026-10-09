"""Task 9 (docs/research/deploy_backup_rollback.md): deploy.sh backs up what it
changes, rolls back by itself when a step fails, deploys everything since the
last deployed commit, and can be rolled back by hand.

The real deploy.sh runs with HOME set to a temporary directory holding a git
mirror (~/netaudit-git), a runtime copy (~/netaudit) and a SQLite database
(~/.netaudit/netaudit.db). Fake sudo, systemctl, curl and a python3 wrapper
(only `-m pytest` is faked) come first in PATH. Nothing touches a real service.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
DEPLOY = REPO / 'deploy.sh'

pytestmark = pytest.mark.skipif(shutil.which('bash') is None or shutil.which('git') is None,
                                reason='deploy.sh tests need bash and git')

_FAKE_SYSTEMCTL = r'''#!/bin/sh
# state: $FAKE_STATE/restarts (count), $FAKE_STATE/started (timestamp), $FAKE_STATE/active
cmd="$1"; shift
case "$cmd" in
  restart)
    n=$(cat "$FAKE_STATE/restarts" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$FAKE_STATE/restarts"
    date -u '+%a %Y-%m-%d %H:%M:%S UTC' > "$FAKE_STATE/started"
    if [ "$n" -le "${FAKE_INACTIVE_RESTARTS:-0}" ]; then echo 0 > "$FAKE_STATE/active"; else echo 1 > "$FAKE_STATE/active"; fi
    ;;
  show) cat "$FAKE_STATE/started" 2>/dev/null || echo "" ;;
  is-active) [ "$(cat "$FAKE_STATE/active" 2>/dev/null || echo 1)" = 1 ] ;;
  status) echo "fake status" ;;
  *) echo "fake systemctl: unsupported $cmd" >&2; exit 1 ;;
esac
'''

_FAKE_CURL = r'''#!/bin/sh
code="${FAKE_SMOKE_CODE:-200}"
if [ "$code" = 200 ]; then printf '[{"id": "a"}, {"id": "b"}]'; else printf '{"detail": "x"}'; fi
printf '\n%s' "$code"
'''

_FAKE_PYTHON = r'''#!/bin/sh
if [ "$1" = "-m" ] && [ "$2" = "pytest" ]; then
  echo "fake pytest"
  exit "${FAKE_PYTEST_RC:-0}"
fi
exec "$REAL_PYTHON" "$@"
'''


def _exe(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(0o755)


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(['git', *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def _tree(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob('*')) if p.is_file()}


class Env:
    def __init__(self, tmp: Path):
        self.home = tmp / 'home'
        self.mirror = self.home / 'netaudit-git'
        self.runtime = self.home / 'netaudit'
        self.backups = self.home / 'netaudit-deploy-backups'
        self.db = self.home / '.netaudit' / 'netaudit.db'
        self.state = tmp / 'state'
        self.bin = tmp / 'bin'
        for d in (self.mirror, self.runtime, self.db.parent, self.state, self.bin):
            d.mkdir(parents=True)
        _exe(self.bin / 'sudo', '#!/bin/sh\nexec "$@"\n')
        _exe(self.bin / 'systemctl', _FAKE_SYSTEMCTL)
        _exe(self.bin / 'curl', _FAKE_CURL)
        _exe(self.bin / 'python3', _FAKE_PYTHON)
        _git(self.mirror, 'init', '-q')  # no -b: git < 2.28 on the target host
        _git(self.mirror, 'config', 'user.email', 'test@example.invalid')
        _git(self.mirror, 'config', 'user.name', 'test')

    def commit(self, write: dict[str, str] | None = None, delete: tuple[str, ...] = ()) -> str:
        for rel, text in (write or {}).items():
            path = self.mirror / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        for rel in delete:
            (self.mirror / rel).unlink()
        _git(self.mirror, 'add', '-A')
        _git(self.mirror, 'commit', '-q', '-m', 'change')
        return _git(self.mirror, 'rev-parse', '--short', 'HEAD')

    def install(self) -> None:
        """Runtime copy == mirror HEAD, as after a successful deploy."""
        for rel in _git(self.mirror, 'ls-files').splitlines():
            dest = self.runtime / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.mirror / rel, dest)
        head = _git(self.mirror, 'rev-parse', '--short', 'HEAD')
        (self.runtime / '.deployed_manifest').write_text(f'DEPLOYED_COMMIT={head}\nDEPLOYED_AT=2026-01-01T00:00:00Z\n')

    def make_db(self) -> None:
        conn = sqlite3.connect(self.db)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('CREATE TABLE reports (id INTEGER PRIMARY KEY, data TEXT)')
        conn.execute("INSERT INTO reports (data) VALUES ('{}')")
        conn.commit()
        conn.close()

    def run(self, *args: str, **fake: str) -> subprocess.CompletedProcess:
        env = {'HOME': str(self.home), 'PATH': f'{self.bin}{os.pathsep}{os.environ["PATH"]}',
               'REAL_PYTHON': sys.executable, 'FAKE_STATE': str(self.state), 'DEPLOY_RESTART_WAIT': '0',
               'LANG': 'C', **fake}
        return subprocess.run(['bash', str(DEPLOY), *args], cwd=self.home, env=env,
                              capture_output=True, text=True, timeout=120, check=False)

    def restarts(self) -> int:
        path = self.state / 'restarts'
        return int(path.read_text()) if path.exists() else 0

    def backup_dirs(self, include_rolled_back: bool = False) -> list[Path]:
        if not self.backups.exists():
            return []
        return sorted(p for p in self.backups.iterdir()
                      if p.is_dir() and (include_rolled_back or not p.name.endswith('.rolled-back')))

    def manifest_commit(self) -> str:
        for line in (self.runtime / '.deployed_manifest').read_text().splitlines():
            if line.startswith('DEPLOYED_COMMIT='):
                return line.split('=', 1)[1]
        return ''


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.commit({'app.py': 'VERSION = 1\n', 'old.py': 'OLD = True\n', 'tests/test_app.py': 'def test(): pass\n'})
    e.install()
    e.make_db()
    return e


def _change(env: Env) -> str:
    return env.commit({'app.py': 'VERSION = 2\n', 'new.py': 'NEW = True\n'}, delete=('old.py',))


# ===========================================================================
# S1 + S2: what is deployed, and the backup made first
# ===========================================================================

def test_success_deploys_changes_removes_deleted_files_and_keeps_a_private_backup(env):
    head = _change(env)
    result = env.run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert (env.runtime / 'app.py').read_text() == 'VERSION = 2\n'
    assert (env.runtime / 'new.py').exists()
    assert not (env.runtime / 'old.py').exists()
    assert env.manifest_commit() == head

    [backup] = env.backup_dirs()
    assert stat.S_IMODE(backup.stat().st_mode) == 0o700
    assert (backup / 'files' / 'app.py').read_text() == 'VERSION = 1\n'
    assert (backup / 'files' / 'old.py').read_text() == 'OLD = True\n'
    assert (backup / 'added.txt').read_text().split() == ['new.py']
    assert 'DEPLOYED_COMMIT=' in (backup / 'manifest').read_text()
    conn = sqlite3.connect(backup / 'netaudit.db')
    try:
        assert conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert conn.execute('SELECT count(*) FROM reports').fetchone()[0] == 1
    finally:
        conn.close()
    for name in ('netaudit.db', 'added.txt', 'manifest'):
        assert stat.S_IMODE((backup / name).stat().st_mode) == 0o600, name
    # code files keep their mode, so a rollback restores it; the 0700
    # directory keeps them private
    assert stat.S_IMODE((backup / 'files' / 'app.py').stat().st_mode) == \
        stat.S_IMODE((env.mirror / 'app.py').stat().st_mode)


def test_everything_since_the_last_deployed_commit_is_deployed(env):
    env.commit({'a.py': 'A = 1\n'})
    env.commit({'b.py': 'B = 1\n'})  # two pulls, no deploy in between
    assert env.run().returncode == 0
    assert (env.runtime / 'a.py').exists() and (env.runtime / 'b.py').exists()


def test_without_manifest_and_without_a_file_list_nothing_changes(env):
    (env.runtime / '.deployed_manifest').unlink()
    _change(env)
    before = _tree(env.runtime)
    result = env.run()
    assert result.returncode != 0
    assert 'explicit file list' in result.stdout + result.stderr
    assert _tree(env.runtime) == before
    assert env.backup_dirs() == []
    assert env.restarts() == 0


def test_explicit_file_list_still_works_and_is_backed_up(env):
    env.commit({'app.py': 'VERSION = 3\n'})
    result = env.run('app.py')
    assert result.returncode == 0, result.stdout + result.stderr
    assert (env.runtime / 'app.py').read_text() == 'VERSION = 3\n'
    assert len(env.backup_dirs()) == 1


def test_missing_database_is_not_an_error(env):
    env.db.unlink()
    _change(env)
    assert env.run().returncode == 0
    [backup] = env.backup_dirs()
    assert not (backup / 'netaudit.db').exists()


# ===========================================================================
# S3: automatic rollback
# ===========================================================================

def test_failing_pytest_rolls_back_the_runtime_tree(env):
    before = _tree(env.runtime)
    _change(env)
    result = env.run(FAKE_PYTEST_RC='1')
    assert result.returncode == 1
    assert 'ROLLED BACK' in result.stdout
    assert _tree(env.runtime) == before


def test_inactive_service_after_restart_rolls_back_and_restarts_again(env):
    before = _tree(env.runtime)
    _change(env)
    result = env.run(FAKE_INACTIVE_RESTARTS='1')
    assert result.returncode == 1
    assert 'ROLLED BACK' in result.stdout
    assert _tree(env.runtime) == before
    assert env.restarts() == 2


def test_smoke_test_server_error_rolls_back(env):
    before = _tree(env.runtime)
    _change(env)
    result = env.run(FAKE_SMOKE_CODE='500')
    assert result.returncode == 1
    assert 'ROLLED BACK' in result.stdout
    assert _tree(env.runtime) == before


def test_smoke_test_401_is_success_with_a_warning(env):
    head = _change(env)
    result = env.run(FAKE_SMOKE_CODE='401')
    assert result.returncode == 0, result.stdout + result.stderr
    assert '401' in result.stdout and 'curl -u' in result.stdout
    assert env.manifest_commit() == head
    assert 'ROLLED BACK' not in result.stdout


def test_failed_rollback_says_so_and_exits_2(env):
    _change(env)
    result = env.run(FAKE_INACTIVE_RESTARTS='99')
    assert result.returncode == 2
    assert 'ROLLBACK FAILED' in result.stdout
    assert str(env.backups) in result.stdout


def test_database_is_never_restored_automatically(env):
    _change(env)
    conn = sqlite3.connect(env.db)
    conn.execute("INSERT INTO reports (data) VALUES ('{\"after\": 1}')")
    conn.commit()
    conn.close()
    result = env.run(FAKE_PYTEST_RC='1')
    assert result.returncode == 1
    conn = sqlite3.connect(env.db)
    try:
        assert conn.execute('SELECT count(*) FROM reports').fetchone()[0] == 2
    finally:
        conn.close()
    assert 'netaudit.db' in result.stdout  # the manual restore command is printed


# ===========================================================================
# S4: manual rollback
# ===========================================================================

def test_manual_rollback_restores_the_previous_deploy(env):
    before = _tree(env.runtime)
    _change(env)
    assert env.run().returncode == 0
    restarts = env.restarts()
    result = env.run('--rollback')
    assert result.returncode == 0, result.stdout + result.stderr
    assert _tree(env.runtime) == before
    assert env.restarts() == restarts + 1
    assert env.backup_dirs() == []  # nothing left to roll back to
    [used] = env.backup_dirs(include_rolled_back=True)
    assert (used / 'netaudit.db').exists()  # the database copy stays for a manual restore
    assert 'git -C' in result.stdout and 'checkout' in result.stdout


def test_manual_rollback_without_a_backup_fails_cleanly(env):
    result = env.run('--rollback')
    assert result.returncode != 0
    assert 'no deploy backup' in result.stdout + result.stderr


# ===========================================================================
# Retention and the existing guard
# ===========================================================================

def test_rollback_restores_file_modes(env):
    script = env.mirror / 'run.sh'
    env.commit({'run.sh': '#!/bin/sh\n'})
    script.chmod(0o755)
    _git(env.mirror, 'add', '-A')
    _git(env.mirror, 'commit', '-q', '-m', 'exec')
    env.install()
    (env.runtime / 'run.sh').chmod(0o755)
    env.commit({'run.sh': '#!/bin/sh\necho 2\n'})
    assert env.run(FAKE_PYTEST_RC='1').returncode == 1
    assert stat.S_IMODE((env.runtime / 'run.sh').stat().st_mode) == 0o755


def test_only_the_last_five_backups_are_kept(env):
    for i in range(6):
        env.commit({'app.py': f'VERSION = {10 + i}\n'})
        assert env.run().returncode == 0
    assert len(env.backup_dirs()) == 5


def test_not_implemented_guard_stops_before_any_backup_or_copy(env):
    before = _tree(env.runtime)
    env.commit({'stub.py': 'def f():\n    raise NotImplementedError\n'})
    result = env.run()
    assert result.returncode == 1
    assert _tree(env.runtime) == before
    assert env.backup_dirs() == []


def test_guard_ignores_test_files_and_intentional_raises(env):
    """The guard is for half-finished code. Test files may contain the text
    (this very file does), and a reserved code path marked
    `# deploy-guard: intentional` is finished code (log_collection.py's
    FULL/WINDOW modes). Neither may block a deploy."""
    head = env.commit({
        'tests/test_stub.py': "def test():\n    src = 'raise NotImplementedError'\n",
        'reserved.py': "def f(mode):\n    raise NotImplementedError('reserved')  # deploy-guard: intentional\n",
    })
    result = env.run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert env.manifest_commit() == head


def test_repository_code_passes_the_guard():
    """Every tracked Python file outside tests/ that raises NotImplementedError
    marks it intentional, so deploying this repository is never blocked."""
    files = subprocess.run(['git', 'ls-files', '*.py'], cwd=REPO, check=True,
                           capture_output=True, text=True).stdout.split()
    for rel in files:
        if rel.startswith('tests/'):
            continue
        for line in (REPO / rel).read_text(encoding='utf-8').splitlines():
            if 'raise NotImplementedError' in line:
                assert 'deploy-guard: intentional' in line, rel

