"""
history_capture.start()/stop() lifecycle across repeated web app lifespans in
one process (several TestClient(app) contexts, an in-process restart).

The first watcher pass is held inside get_settings() - standing in for a slow
SSH snapshot - so the old thread is still alive when the next start() comes.
"""

from __future__ import annotations

import threading
import time

import pytest

from netaudit_pkg import history_capture

DISABLED = {'enabled': False, 'interval_sec': 10, 'retention_hours': 1}


@pytest.fixture
def held_first_pass(monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    first_caller = []

    def get_settings():
        if not first_caller:
            first_caller.append(threading.current_thread())
            entered.set()
            release.wait(5)
        return dict(DISABLED)

    monkeypatch.setattr(history_capture, 'get_settings', get_settings)
    yield entered, release
    release.set()
    history_capture.stop()
    thread = history_capture._watcher_thread
    if thread is not None:
        thread.join(2)


def test_restart_while_previous_watcher_is_still_stopping(held_first_pass):
    entered, release = held_first_pass
    history_capture.start()
    assert entered.wait(2)
    old = history_capture._watcher_thread

    t0 = time.monotonic()
    history_capture.stop()
    assert time.monotonic() - t0 < 0.5  # stop() never waits for a hung pass
    history_capture.start()

    release.set()
    old.join(2)
    assert not old.is_alive()
    current = history_capture._watcher_thread
    assert current is not old
    assert current.is_alive()
    assert history_capture.get_status()['running'] is True


def test_start_twice_while_running_keeps_one_watcher(held_first_pass):
    entered, _ = held_first_pass
    history_capture.start()
    assert entered.wait(2)
    first = history_capture._watcher_thread
    history_capture.start()
    assert history_capture._watcher_thread is first
