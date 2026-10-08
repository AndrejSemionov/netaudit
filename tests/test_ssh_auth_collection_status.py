"""The SSH audit must not treat a failed log command as a clean scan."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from netaudit_pkg.checks import ssh_auth_audit


def _collection(completed: bool, exit_code: int | None, stdout: str = ''):
    return SimpleNamespace(result=SimpleNamespace(
        completed=completed, exit_code=exit_code, stdout=stdout,
    ))


@pytest.fixture
def run_audit(monkeypatch):
    calls = []

    class FakeSSH:
        def connect(self):
            return self

        def close(self):
            calls.append('close')

    monkeypatch.setattr(ssh_auth_audit, 'paramiko', object())
    monkeypatch.setattr(ssh_auth_audit, 'SSHExecutor', lambda *a, **kw: FakeSSH())
    monkeypatch.setattr(ssh_auth_audit, 'probe_log_file', lambda *a, **kw: object())
    monkeypatch.setattr(ssh_auth_audit, 'file_verdict',
                        lambda *a, **kw: SimpleNamespace(available=True))

    def run(file_result, journal_result):
        calls.clear()

        def file_collector(*a, **kw):
            calls.append('file')
            return file_result

        def journal_collector(*a, **kw):
            calls.append('journal')
            return journal_result

        monkeypatch.setattr(ssh_auth_audit, 'collect_file', file_collector)
        monkeypatch.setattr(ssh_auth_audit, 'collect_journal', journal_collector)
        result = ssh_auth_audit.check_ssh_auth_audit(host='example.invalid')
        return result, list(calls)

    return run


def test_failed_auth_log_falls_back_to_journal_events(run_audit):
    line = (f'{datetime.now(timezone.utc).isoformat()} host sshd[123]: '
            'Failed password for root from 192.0.2.1 port 22 ssh2')
    report, calls = run_audit(_collection(True, 1), _collection(True, 0, line))

    assert calls == ['file', 'journal', 'close']
    assert report['meta']['selected_source'] == 'journal'
    assert report['meta']['fallback_used'] is True
    assert report['meta']['events_parsed'] == 1
    assert any(f['severity'] != 'ok' for f in report['findings'])
    assert 'error' not in report


def test_two_failed_sources_report_error_not_ok(run_audit):
    report, calls = run_audit(_collection(True, 1), _collection(True, 1))

    assert calls == ['file', 'journal', 'close']
    assert report['meta']['selected_source'] == 'none'
    assert not any(f['severity'] == 'ok' for f in report['findings'])
    assert report['error'] == 'no SSH authentication source could be collected'


def test_confirmed_empty_auth_log_is_valid_and_does_not_fall_back(run_audit):
    report, calls = run_audit(_collection(True, 0), _collection(True, 0, 'ignored'))

    assert calls == ['file', 'close']
    assert report['meta']['selected_source'] == 'file'
    assert report['meta']['fallback_used'] is False
    assert report['meta']['events_parsed'] == 0
    assert any(f['severity'] == 'ok' for f in report['findings'])
    assert 'error' not in report


def test_unconfirmed_file_completion_uses_journal(run_audit):
    report, calls = run_audit(_collection(False, None), _collection(True, 0))

    assert calls == ['file', 'journal', 'close']
    assert report['meta']['selected_source'] == 'journal'
    assert report['meta']['fallback_used'] is True
    assert 'error' not in report
