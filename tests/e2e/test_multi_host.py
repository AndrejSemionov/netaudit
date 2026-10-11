"""B2.5 (docs/research/b2_5_e2e_multi_host.md): several hosts in one run
against the real SSH stand - one reachable, one refused - through the engine
and the Web streaming path, with the per-run password nowhere in the output;
and TOFU pinning two real servers connected in parallel (#34).

Runs only in the CI job `e2e-ssh` (NETAUDIT_E2E_* variables). Skipped
everywhere else.
"""

from __future__ import annotations

import json
import logging
import os
import socket

import pytest

HOST = os.environ.get('NETAUDIT_E2E_HOST', '')
PORT = int(os.environ.get('NETAUDIT_E2E_PORT', '22'))
PORT2 = int(os.environ.get('NETAUDIT_E2E_PORT2', '0'))
KEY = os.environ.get('NETAUDIT_E2E_KEY', '')
PASSWORD = os.environ.get('NETAUDIT_E2E_PASSWORD', '')

pytestmark = pytest.mark.skipif(not (HOST and KEY and PASSWORD),
                                reason='needs the CI SSH stand (NETAUDIT_E2E_* variables)')


def _closed_port() -> int:
    """A local port nothing listens on: bound once, then released."""
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _instance(host: str, port: int) -> dict:
    return {'host': host, 'user': 'pwsudo', 'port': port, 'key_path': KEY, 'password': '',
            'sudo_password': PASSWORD}


def _two_hosts() -> list[dict]:
    # 'localhost' keeps the refused host's by_host key apart from HOST (127.0.0.1)
    return [{'id': 'ssh_hardening', 'instances': [_instance(HOST, PORT),
                                                  _instance('localhost', _closed_port())]}]


def _assert_one_ok_one_refused(by_host: dict) -> None:
    assert set(by_host) == {HOST, 'localhost'}, by_host
    assert 'error' not in by_host[HOST], by_host[HOST]
    assert isinstance(by_host[HOST]['hardening']['score'], int), by_host[HOST]
    assert 'could not connect' in by_host['localhost']['error'], by_host['localhost']


def _db_bytes(storage) -> bytes:
    return b''.join(p.read_bytes() for p in storage.DB_PATH.parent.glob(storage.DB_PATH.name + '*'))


def _ai_request_body(report, monkeypatch) -> str:
    import httpx

    from netaudit_pkg import history

    sent = {}

    def fake_post(url, **kwargs):
        sent['body'] = json.dumps(kwargs.get('json'))
        raise httpx.HTTPError('no network in this test')

    monkeypatch.setattr(httpx, 'post', fake_post)
    history.ai_analyze(report, api_key='test-key', language='en')
    assert sent.get('body'), 'no AI request was built'
    return sent['body']


# 1. engine -------------------------------------------------------------------

def test_engine_keeps_the_reachable_result_and_the_exact_refusal(isolated_db):
    from netaudit_pkg import engine, history

    report = engine.run_checks_multi(_two_hosts())
    _assert_one_ok_one_refused(report['results']['ssh_hardening']['by_host'])

    saved = history.load_report(history.save_report(report))
    _assert_one_ok_one_refused(saved['results']['ssh_hardening']['by_host'])
    ctx = saved['execution_context']['ssh_hardening']
    assert set(ctx) == {HOST, 'localhost'}
    assert all('password' not in p and 'sudo_password' not in p for p in ctx.values()), ctx


# 2. Web streaming path ---------------------------------------------------------

def test_stream_reports_each_host_and_the_password_goes_nowhere(isolated_db, monkeypatch, caplog):
    from netaudit_pkg import storage, streaming

    caplog.set_level(logging.DEBUG)
    task = streaming.StreamTask('e2e-multi-host', _two_hosts())
    streaming.run_stream(task)
    events = []
    while not task.q.empty():
        events.append(task.q.get_nowait())

    done = {e['host']: e['result'] for e in events if e.get('type') == 'check_done' and 'host' in e}
    _assert_one_ok_one_refused(done)
    [final] = [e for e in events if e.get('type') == 'all_done']
    _assert_one_ok_one_refused(final['report']['results']['ssh_hardening']['by_host'])

    assert PASSWORD not in json.dumps(events, default=str)
    assert PASSWORD.encode() not in _db_bytes(storage)
    assert PASSWORD not in caplog.text
    assert PASSWORD not in _ai_request_body(final['report'], monkeypatch)


# 3. TOFU: two real servers, first connections in parallel (#34) ---------------

@pytest.mark.skipif(not PORT2, reason='needs the second stand container (NETAUDIT_E2E_PORT2)')
def test_parallel_first_connections_pin_both_real_servers(isolated_db, monkeypatch, tmp_path):
    import paramiko

    from netaudit_pkg import engine
    from netaudit_pkg import ssh as ssh_mod

    known_hosts = tmp_path / 'known_hosts'
    monkeypatch.setattr(ssh_mod, 'KNOWN_HOSTS_PATH', known_hosts)
    selected = [{'id': 'ssh_hardening', 'instances': [_instance(HOST, PORT), _instance(HOST, PORT2)]}]

    for _ in range(2):  # the second run verifies both pins strictly
        by_host = engine.run_checks_multi(selected)['results']['ssh_hardening']['by_host']
        assert all('error' not in r for r in by_host.values()), by_host
        pinned = paramiko.HostKeys(str(known_hosts))
        assert pinned.lookup(f'[{HOST}]:{PORT}'), known_hosts.read_text()
        assert pinned.lookup(f'[{HOST}]:{PORT2}'), known_hosts.read_text()
