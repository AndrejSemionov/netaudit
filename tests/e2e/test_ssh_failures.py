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
        self._throttle = threading.Event()   # server replies in small, slow slices
        self.was_cut = False
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
            try:
                if from_server and self._throttle.is_set():
                    for i in range(0, len(data), 512):
                        if self._cut.is_set():
                            break
                        dst.sendall(data[i:i + 512])
                        time.sleep(0.02)
                else:
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
        self.was_cut = True
        self._cut.set()
        with self._lock:
            self._shut(*self._socks)

    def stall(self):
        self._stall.set()

    def throttle(self):
        """From now on the server's replies trickle through (512 bytes every
        20 ms), so a long output is still on its way when NetAudit reads its
        first part."""
        self._throttle.set()

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


MARKER = '__NETAUDIT_RC_'


def _cut_after_first_output(monkeypatch, p, command_part):
    """While a command containing `command_part` runs, the server's replies
    trickle through the proxy, and every connection is cut right after
    NetAudit has read the first part of that command's output. Returns what
    was seen: bytes NetAudit read before the cut, and the stdout the real
    SSHExecutor.run() returned (review #58 E3)."""
    import paramiko

    seen = {'read': 0, 'stdout': None}
    running = threading.Event()
    original_run = ssh_mod.SSHExecutor.run
    original_recv = paramiko.Channel.recv

    def run(self, cmd, timeout=20, stdin_data=None):
        watched = command_part in cmd
        if watched:
            p.throttle()
            running.set()
        try:
            out = original_run(self, cmd, timeout=timeout, stdin_data=stdin_data)
        finally:
            running.clear()
        if watched and seen['stdout'] is None:
            seen['stdout'] = out[0]
        return out

    def recv(self, nbytes):
        data = original_recv(self, nbytes)
        if data and running.is_set() and not p.was_cut:
            seen['read'] += len(data)
            p.cut()
        return data

    monkeypatch.setattr(ssh_mod.SSHExecutor, 'run', run)
    monkeypatch.setattr(paramiko.Channel, 'recv', recv)
    return seen


@needs_stand
def test_a_cut_in_the_middle_of_a_long_output_leaves_partial_stdout_and_no_exit_code(proxy, monkeypatch):
    """The command/exit wrapper itself: 200 KB of output, cut after its first
    part arrived -> the real stdout is partial, no completion marker, no exit
    code."""
    from netaudit_pkg.ssh_utils import run_command_with_exit_code

    p = proxy('forward')
    seen = _cut_after_first_output(monkeypatch, p, 'head -c 200000')
    executor = ssh_mod.SSHExecutor('127.0.0.1', 'pwsudo', p.port, KEY, '').connect()
    try:
        stdout, exit_code = run_command_with_exit_code(executor, "head -c 200000 /dev/zero | tr '\\0' a")
    except Exception as e:  # noqa: BLE001 - a raised error would mean no partial stdout reached the wrapper
        pytest.fail(f'the wrapper raised instead of returning partial output: {type(e).__name__}: {e}')
    finally:
        executor.close()
    assert p.was_cut and seen['read'] > 0
    assert 0 < len(seen['stdout']) < 200000, len(seen['stdout'])
    assert MARKER not in seen['stdout']
    assert exit_code is None
    assert 0 < len(stdout) < 200000


@needs_stand
def test_a_check_cut_in_the_middle_of_its_output_is_not_a_pass(proxy, monkeypatch):
    """kernel_hardening's `sysctl -a`, cut after its first part arrived."""
    p = proxy('forward')
    seen = _cut_after_first_output(monkeypatch, p, 'sysctl -a')
    result = run_checks([{'id': 'kernel_hardening', 'params': _params(p.port)}])['results']['kernel_hardening']
    assert p.was_cut and seen['read'] > 0, 'the cut did not happen inside sysctl -a'
    assert seen['stdout'], 'no part of the output reached NetAudit'
    assert MARKER not in seen['stdout'], 'the whole output arrived before the cut'
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
