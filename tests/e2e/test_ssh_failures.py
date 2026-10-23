"""
An SSH failure is never reported as a clean result
(docs/research/e2e_ssh_failures.md). A small TCP proxy in the test sits
between NetAudit and the stand and makes the server go silent, close the
connection, drop it after the login, or hold its replies back.

"silent" and "close" need no stand and run in every test job; the rest run in
the CI job `e2e-ssh` only (NETAUDIT_E2E_* variables).
"""

from __future__ import annotations

import os
import socket
import threading
import time

import pytest

from netaudit_pkg import ssh as ssh_mod
from netaudit_pkg.engine import run_checks, run_checks_multi

HOST = os.environ.get('NETAUDIT_E2E_HOST', '')
PORT = int(os.environ.get('NETAUDIT_E2E_PORT', '22'))
KEY = os.environ.get('NETAUDIT_E2E_KEY', '')
PASSWORD = os.environ.get('NETAUDIT_E2E_PASSWORD', '')

needs_stand = pytest.mark.skipif(not (HOST and KEY and PASSWORD),
                                 reason='needs the CI SSH stand (NETAUDIT_E2E_* variables)')


class _Proxy:
    """127.0.0.1:<port> -> the stand. `mode` is 'silent', 'close' or 'forward';
    in 'forward', cut() closes every connection and stall() holds the
    server's replies back."""

    def __init__(self, mode: str):
        self.mode = mode
        self._cut = threading.Event()
        self._stall = threading.Event()
        self._cut_after: int | None = None   # server bytes after arming, then cut
        self._server_bytes = 0
        self.cut_mid_reply = False
        self._closed = threading.Event()
        self._socks: list[socket.socket] = []
        self._lock = threading.Lock()
        self._listener = socket.create_server(('127.0.0.1', 0))
        # closing a socket does not wake a blocked accept() on Linux: poll
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _keep(self, *socks):
        with self._lock:
            self._socks.extend(socks)

    def _accept(self):
        while not self._closed.is_set():
            try:
                client, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            client.settimeout(None)
            if self.mode == 'silent':
                self._keep(client)          # accepted, no banner ever sent
                continue
            if self.mode == 'close':
                client.close()
                continue
            upstream = socket.create_connection((HOST, PORT), timeout=10)
            upstream.settimeout(None)
            self._keep(client, upstream)
            threading.Thread(target=self._pipe, args=(client, upstream, False), daemon=True).start()
            threading.Thread(target=self._pipe, args=(upstream, client, True), daemon=True).start()

    def _pipe(self, src, dst, from_server):
        while not self._cut.is_set():
            try:
                data = src.recv(65536)
            except OSError:
                break
            if not data:
                break
            while from_server and self._stall.is_set() and not self._closed.is_set():
                time.sleep(0.05)            # the server's reply is held back
            if self._cut.is_set() or self._closed.is_set():
                break
            if from_server and self._cut_after is not None:
                self._server_bytes += len(data)
                if self._server_bytes >= self._cut_after:
                    # part of the reply went through, the rest never will
                    dst.sendall(data[:len(data) // 2])
                    self.cut_mid_reply = True
                    self.cut()
                    break
            try:
                dst.sendall(data)
            except OSError:
                break
        self._shut(src, dst)

    @staticmethod
    def _shut(*socks):
        for s in socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()

    def cut(self):
        self._cut.set()
        with self._lock:
            self._shut(*self._socks)

    def stall(self):
        self._stall.set()

    def cut_after(self, server_bytes: int):
        """Cut every connection once the server has sent `server_bytes` more:
        in the middle of a command's output when the output is larger."""
        self._server_bytes = 0
        self._cut_after = server_bytes

    def close(self):
        self._closed.set()
        self._listener.close()
        self.cut()


@pytest.fixture
def proxy(isolated_db):
    """Depends on isolated_db so that it closes first: its threads end before
    isolated_db waits for the test's threads (conftest, review #55)."""
    made = []

    def make(mode):
        made.append(_Proxy(mode))
        return made[-1]

    yield make
    for p in made:
        p.close()


def _after_login(monkeypatch, action):
    """Run `action` right after a successful SSH login (and before any of the
    check's commands)."""
    original = ssh_mod.SSHExecutor.connect

    def connect(self):
        result = original(self)
        action()
        return result

    monkeypatch.setattr(ssh_mod.SSHExecutor, 'connect', connect)


def _params(port, host='127.0.0.1'):
    return {'host': host, 'user': 'pwsudo', 'port': port, 'key_path': KEY, 'password': '',
            'sudo_password': PASSWORD}


def _not_a_pass(result: dict) -> bool:
    """The run is reported as failed: a non-empty error, no hardening score
    and no finding that reads as a clean result (review #58 E2)."""
    error = result.get('error')
    if not (isinstance(error, str) and error.strip()):
        return False
    if isinstance((result.get('hardening') or {}).get('score'), (int, float)):
        return False
    return not any(isinstance(f, dict) and f.get('severity') == 'ok' for f in result.get('findings') or [])


@pytest.mark.parametrize('result', [
    {'ok': True, 'findings': [{'severity': 'ok', 'title': 'all clear'}]},
    {'error': '', 'hardening': {'score': 100}},
    {'error': '   '},
    {'error': 'could not connect', 'hardening': {'score': 80}},
    {'error': 'partial', 'findings': [{'severity': 'ok', 'title': 'no issues'}]},
    {'hardening': {'score': None}},
])
def test_the_oracle_never_takes_a_clean_looking_result(result):
    assert not _not_a_pass(result)


def test_the_oracle_takes_a_reported_failure():
    assert _not_a_pass({'error': 'could not connect: [Errno 111] Connection refused'})
    assert _not_a_pass({'error': 'sudo sysctl -a did not complete', 'hardening': {'score': None}})


# --- no stand needed ---------------------------------------------------------

def test_a_server_that_never_sends_a_banner_is_an_error(proxy, isolated_db):
    p = proxy('silent')
    started = time.monotonic()
    result = run_checks([{'id': 'ssh_hardening', 'params': _params(p.port)}])['results']['ssh_hardening']
    assert 'could not connect' in result.get('error', ''), result
    assert time.monotonic() - started < 60


def test_a_server_that_closes_at_once_is_an_error(proxy, isolated_db):
    p = proxy('close')
    result = run_checks([{'id': 'kernel_hardening', 'params': _params(p.port)}])['results']['kernel_hardening']
    assert 'could not connect' in result.get('error', ''), result


# --- against the stand -------------------------------------------------------

@needs_stand
@pytest.mark.parametrize('check_id', ['ssh_hardening', 'kernel_hardening', 'nginx_hardening'])
def test_a_connection_dropped_after_the_login_is_not_a_pass(check_id, proxy, monkeypatch):
    p = proxy('forward')
    _after_login(monkeypatch, p.cut)
    result = run_checks([{'id': check_id, 'params': _params(p.port)}])['results'][check_id]
    assert _not_a_pass(result), result


@needs_stand
def test_a_server_that_stops_answering_after_the_login_is_not_a_pass(proxy, monkeypatch, isolated_db):
    p = proxy('forward')
    _after_login(monkeypatch, p.stall)
    started = time.monotonic()
    result = run_checks([{'id': 'kernel_hardening', 'params': _params(p.port)}])['results']['kernel_hardening']
    assert _not_a_pass(result), result
    assert time.monotonic() - started < 180      # the command timeouts end it


@needs_stand
def test_a_connection_dropped_in_the_middle_of_a_commands_output_is_not_a_pass(proxy, monkeypatch):
    """`sysctl -a` prints tens of kilobytes: the cut falls inside its output,
    after part of it reached NetAudit (review #58 E3)."""
    p = proxy('forward')
    _after_login(monkeypatch, lambda: p.cut_after(8192))
    result = run_checks([{'id': 'kernel_hardening', 'params': _params(p.port)}])['results']['kernel_hardening']
    assert p.cut_mid_reply, 'the output was smaller than the cut point; the test proved nothing'
    assert _not_a_pass(result), result


@needs_stand
def test_one_slow_host_leaves_the_healthy_one_whole(proxy, monkeypatch):
    p = proxy('forward')
    original = ssh_mod.SSHExecutor.connect

    def connect(self):
        result = original(self)
        if self.port == p.port:
            p.stall()
        return result

    monkeypatch.setattr(ssh_mod.SSHExecutor, 'connect', connect)
    started = time.monotonic()
    report = run_checks_multi([{'id': 'kernel_hardening', 'instances': [
        _params(PORT, host=HOST), _params(p.port, host='localhost')]}])
    by_host = report['results']['kernel_hardening']['by_host']
    assert 'error' not in by_host[HOST], by_host[HOST]
    assert isinstance(by_host[HOST]['hardening']['score'], int), by_host[HOST]
    assert _not_a_pass(by_host['localhost']), by_host['localhost']
    assert time.monotonic() - started < 180


@needs_stand
def test_one_host_dropped_after_the_login_leaves_the_other_whole(proxy, monkeypatch, isolated_db):
    p = proxy('forward')
    original = ssh_mod.SSHExecutor.connect

    def connect(self):
        result = original(self)
        if self.port == p.port:
            p.cut()
        return result

    monkeypatch.setattr(ssh_mod.SSHExecutor, 'connect', connect)
    # 'localhost' keeps the dropped host's by_host key apart from HOST (127.0.0.1)
    report = run_checks_multi([{'id': 'ssh_hardening', 'instances': [
        _params(PORT, host=HOST), _params(p.port, host='localhost')]}])
    by_host = report['results']['ssh_hardening']['by_host']
    assert 'error' not in by_host[HOST], by_host[HOST]
    assert isinstance(by_host[HOST]['hardening']['score'], int), by_host[HOST]
    assert _not_a_pass(by_host['localhost']), by_host['localhost']
