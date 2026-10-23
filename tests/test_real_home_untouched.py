"""
Tests never write to the user's real ~/.netaudit (FINDINGS 2026-10-23: a report
of the test-only check __test_stream_multi__ was found in a real database). A
Web stream test returned while its background thread was still saving, after
isolated_db had pointed storage back at ~/.netaudit/netaudit.db.

The last two tests run in this order on purpose: the first leaves a thread
that saves a report 0.2 s later, the second must not receive it.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

REAL = Path.home() / '.netaudit'
_first_db: list[Path] = []


def test_the_database_outside_isolated_db_is_never_the_real_one():
    from netaudit_pkg import storage
    assert REAL not in Path(storage.DB_PATH).parents


def test_known_hosts_outside_a_test_fixture_is_never_the_real_one():
    from netaudit_pkg import ssh
    assert REAL not in Path(ssh.KNOWN_HOSTS_PATH).parents


def _late_report():
    time.sleep(0.2)
    from netaudit_pkg import storage
    storage.save_report({'timestamp': '2026-10-23 00:00:00', 'results': {'late_thread': {}},
                         'timing': {}, 'meta': {}, 'execution_context': {}, 'total_time': 0})


def test_a_thread_still_saving_when_its_test_ends(isolated_db):
    _first_db.append(Path(isolated_db.DB_PATH))
    threading.Thread(target=_late_report, daemon=True).start()


def test_does_not_save_into_the_next_tests_database(isolated_db):
    time.sleep(0.4)  # longer than the first test's thread needs
    assert isolated_db.list_reports() == []
    import sqlite3
    [first] = _first_db
    count = sqlite3.connect(first).execute('SELECT COUNT(*) FROM reports').fetchone()[0]
    assert count == 1  # it landed in the database of the test that started it


# --- review #55: after the session, and threads the first wait missed -----------

_parent_db: list[Path] = []


def _parent_then_child():
    def child():
        time.sleep(0.2)
        from netaudit_pkg import storage
        storage.save_report({'timestamp': '2026-10-23 00:00:01', 'results': {'child_thread': {}},
                             'timing': {}, 'meta': {}, 'execution_context': {}, 'total_time': 0})
    time.sleep(0.1)
    threading.Thread(target=child, daemon=True).start()


def test_a_thread_that_starts_a_child_and_ends(isolated_db):
    _parent_db.append(Path(isolated_db.DB_PATH))
    threading.Thread(target=_parent_then_child, daemon=True).start()


def test_its_child_does_not_save_into_the_next_tests_database(isolated_db):
    time.sleep(0.5)
    assert isolated_db.list_reports() == []
    import sqlite3
    [first] = _parent_db
    assert sqlite3.connect(first).execute('SELECT COUNT(*) FROM reports').fetchone()[0] == 1


PROBE = '''
import threading
from netaudit_pkg import storage

release = threading.Event()
threads = []


def _write():
    release.wait()
    storage.save_report({"timestamp": "2026-10-23 00:00:02", "results": {"after_session": {}},
                         "timing": {}, "meta": {}, "execution_context": {}, "total_time": 0})


def test_leaves_a_writer_behind():
    t = threading.Thread(target=_write, daemon=True)
    threads.append(t)
    t.start()


def test_never_reached():
    pass
'''

RUNNER = '''
import sys
import pytest
sys.path.insert(0, sys.argv[2])
code = pytest.main([sys.argv[1], "-q", "-p", "no:cacheprovider", "-p", "tests.conftest"])
import probe_late_writer as probe
probe.release.set()
for t in probe.threads:
    t.join(5)
print("EXIT", int(code))
'''


def test_a_writer_alive_at_the_deadline_stops_the_run_and_never_reaches_home(tmp_path):
    import os
    import subprocess
    import sys
    repo = Path(__file__).resolve().parent.parent
    (tmp_path / 'probe_late_writer.py').write_text(PROBE, encoding='utf-8')
    (tmp_path / 'runner.py').write_text(RUNNER, encoding='utf-8')
    home = tmp_path / 'home'
    home.mkdir()
    env = {**os.environ, 'HOME': str(home), 'NETAUDIT_TEST_THREAD_DEADLINE': '0.5',
           'PYTHONPATH': f'{repo}{os.pathsep}{tmp_path}'}
    out = subprocess.run([sys.executable, str(tmp_path / 'runner.py'), str(tmp_path / 'probe_late_writer.py'),
                          str(tmp_path)], cwd=repo, env=env, capture_output=True, text=True, timeout=60, check=False)
    text = out.stdout + out.stderr
    assert 'EXIT 0' not in text, text           # the run did not go on as if nothing happened
    assert 'left threads running' in text, text
    assert not (home / '.netaudit').exists(), text  # the late write did not reach HOME
