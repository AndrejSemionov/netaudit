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
