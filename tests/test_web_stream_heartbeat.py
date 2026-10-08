"""
/api/stream/{task_id}: a queue timeout (queue.Empty) becomes an SSE
keep-alive comment; any other failure ends the stream instead of looping on
keep-alives forever (Ruff BLE001 review, stage 3).
"""

from __future__ import annotations

import queue

import pytest
from fastapi.testclient import TestClient

import web.app as web_app


class _ScriptedQueue:
    def __init__(self, *steps):
        self.steps = list(steps)

    def get(self, block=True, timeout=None):
        step = self.steps.pop(0)
        if isinstance(step, BaseException):
            raise step
        return step


class _Task:
    def __init__(self, q):
        self.q = q


@pytest.fixture
def stream(monkeypatch):
    def _register(*steps):
        monkeypatch.setitem(web_app._stream_tasks, 'tid', _Task(_ScriptedQueue(*steps)))
        return TestClient(web_app.app)
    return _register


def test_queue_timeout_is_a_keep_alive_then_events_continue(stream):
    client = stream(queue.Empty(), {'type': 'point', 'v': 1}, {'type': '_end'})
    body = client.get('/api/stream/tid').text
    assert body.startswith(': keep-alive\n\n')
    assert 'data: {"type": "point", "v": 1}' in body


def test_unexpected_queue_error_is_not_swallowed_as_keep_alive(stream):
    client = stream(RuntimeError('broken queue'), {'type': '_end'})
    with pytest.raises(RuntimeError, match='broken queue'):
        client.get('/api/stream/tid')
