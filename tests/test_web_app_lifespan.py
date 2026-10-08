"""
web/app.py starts the traffic-history watcher from a FastAPI lifespan handler
instead of the deprecated @app.on_event('startup'), and stops it on shutdown.

history_capture.start/stop are patched: the real watcher is a background
thread that reads settings from SQLite.
"""

from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from web.app import app


def test_no_deprecated_startup_or_shutdown_hooks():
    assert list(getattr(app.router, 'on_startup', [])) == []
    assert list(getattr(app.router, 'on_shutdown', [])) == []


def test_lifespan_starts_watcher_on_startup_and_stops_it_on_shutdown():
    with patch('web.app.history_capture.start') as start, \
            patch('web.app.history_capture.stop') as stop:
        with TestClient(app):
            start.assert_called_once_with()
            stop.assert_not_called()
        stop.assert_called_once_with()
