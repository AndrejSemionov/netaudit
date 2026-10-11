"""
TOFU under parallel first connections (docs/research/tofu_known_hosts_lock.md):
a pinned key is never lost, and a different key for a host another worker
just pinned is refused instead of overwriting the pin.

The clients are real paramiko.SSHClient objects prepared exactly the way
SSHExecutor.connect() prepares them; no network is involved - the policy is
called the way paramiko calls it after the handshake.
"""

from __future__ import annotations

import os
import threading

import paramiko
import pytest

from netaudit_pkg import ssh as ssh_mod
from netaudit_pkg.ssh import HostKeyMismatchError, SSHExecutor, TofuPolicy


@pytest.fixture(autouse=True)
def known_hosts(monkeypatch, tmp_path):
    path = tmp_path / 'netaudit' / 'known_hosts'
    monkeypatch.setattr(ssh_mod, 'KNOWN_HOSTS_PATH', path)
    return path


def _client():
    """A client prepared as in SSHExecutor.connect()."""
    c = paramiko.SSHClient()
    if ssh_mod.KNOWN_HOSTS_PATH.exists():
        c.load_host_keys(str(ssh_mod.KNOWN_HOSTS_PATH))
    return c


def _key():
    return paramiko.ECDSAKey.generate()


def _pinned(path) -> paramiko.HostKeys:
    return paramiko.HostKeys(str(path))


def test_fresh_install_keeps_both_first_keys(known_hosts):
    a, b = _client(), _client()  # both start before the file exists
    key_a, key_b = _key(), _key()
    TofuPolicy().missing_host_key(a, 'host-a', key_a)
    TofuPolicy().missing_host_key(b, 'host-b', key_b)

    pinned = _pinned(known_hosts)
    assert pinned.check('host-a', key_a)
    assert pinned.check('host-b', key_b)


@pytest.mark.parametrize('existing', [False, True])
def test_twenty_parallel_first_connections_keep_every_key(known_hosts, existing):
    old_key = _key()
    if existing:
        known_hosts.parent.mkdir(parents=True)
        seed = paramiko.HostKeys()
        seed.add('old-host', old_key.get_name(), old_key)
        seed.save(str(known_hosts))
    keys = {f'host-{i}': _key() for i in range(20)}
    clients = {h: _client() for h in keys}
    start = threading.Barrier(len(keys))
    errors = []

    def pin(host):
        try:
            start.wait()
            TofuPolicy().missing_host_key(clients[host], host, keys[host])
        except Exception as e:  # noqa: BLE001 - collected and asserted below
            errors.append(e)

    threads = [threading.Thread(target=pin, args=(h,)) for h in keys]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    pinned = _pinned(known_hosts)
    assert all(pinned.check(h, k) for h, k in keys.items())
    if existing:
        assert pinned.check('old-host', old_key)


def test_different_key_for_a_host_just_pinned_is_refused(known_hosts):
    first, second = _client(), _client()
    real_key, other_key = _key(), _key()
    TofuPolicy().missing_host_key(first, 'host', real_key)

    with pytest.raises(paramiko.BadHostKeyException):
        TofuPolicy().missing_host_key(second, 'host', other_key)

    pinned = _pinned(known_hosts)
    assert pinned.check('host', real_key)
    assert not pinned.check('host', other_key)
    assert len(pinned.lookup('host')) == 1


def test_same_key_from_two_workers_is_accepted_once(known_hosts):
    first, second = _client(), _client()
    key = _key()
    TofuPolicy().missing_host_key(first, 'host', key)
    TofuPolicy().missing_host_key(second, 'host', key)

    lines = [line for line in known_hosts.read_text().splitlines() if line.strip()]
    assert len(lines) == 1
    assert second.get_host_keys().check('host', key)


def test_written_file_loads_back_including_a_non_default_port(known_hosts):
    key_a, key_b = _key(), _key()
    TofuPolicy().missing_host_key(_client(), 'host-a', key_a)
    TofuPolicy().missing_host_key(_client(), '[host-b]:2222', key_b)

    client = paramiko.SSHClient()
    client.load_host_keys(str(known_hosts))
    assert client.get_host_keys().check('host-a', key_a)
    assert client.get_host_keys().check('[host-b]:2222', key_b)


def test_failed_write_keeps_the_old_file_and_releases_the_lock(known_hosts, monkeypatch):
    key_a, key_b = _key(), _key()
    TofuPolicy().missing_host_key(_client(), 'host-a', key_a)
    before = known_hosts.read_text()

    real_replace = os.replace

    def failing_replace(src, dst):
        raise OSError('simulated disk failure')

    monkeypatch.setattr(ssh_mod.os, 'replace', failing_replace)
    with pytest.raises(OSError, match='simulated disk failure'):
        TofuPolicy().missing_host_key(_client(), 'host-b', key_b)
    assert known_hosts.read_text() == before
    assert sorted(p.name for p in known_hosts.parent.iterdir()) == ['known_hosts', 'known_hosts.lock']

    monkeypatch.setattr(ssh_mod.os, 'replace', real_replace)
    TofuPolicy().missing_host_key(_client(), 'host-b', key_b)  # the lock was released
    assert _pinned(known_hosts).check('host-b', key_b)


def test_concurrent_different_key_surfaces_as_host_key_mismatch(known_hosts, monkeypatch):
    real_key, other_key = _key(), _key()
    TofuPolicy().missing_host_key(_client(), 'host', real_key)

    class StaleHandshakeClient(paramiko.SSHClient):
        """Calls the policy the way paramiko does for a host missing from the
        client's table - i.e. a worker whose table was loaded before the pin
        above landed - and stops there."""

        def connect(self, hostname, **kwargs):
            self._policy.missing_host_key(self, hostname, other_key)

    monkeypatch.setattr(paramiko, 'SSHClient', StaleHandshakeClient)

    with pytest.raises(HostKeyMismatchError, match='different SSH host key'):
        SSHExecutor('host', 'user', 22, '', password='pw').connect()
    assert _pinned(known_hosts).check('host', real_key)
