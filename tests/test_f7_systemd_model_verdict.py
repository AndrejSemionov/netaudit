"""F7 RA-19: systemd's unit and directive model need confirmed evidence."""

from __future__ import annotations

import pytest

from netaudit_pkg.checks.systemd_hardening import check_systemd_hardening
from tests.conftest import ExitCodeFakeSSHExecutor


def _run(monkeypatch, *, load_state='', load_exit=None, json_model='[]'):
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'systemctl show': load_state,
            '--json=short': json_model,
            'security nginx.service --no-pager;': 'Overall exposure level for nginx.service: 4.5 OK',
        },
        exit_codes={
            **({'systemctl show': load_exit} if load_exit is not None else {}),
            '--json=short': 0,
            'security nginx.service --no-pager;': 0,
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.systemd_hardening.SSHExecutor', lambda *a, **kw: fake)
    return check_systemd_hardening(host='127.0.0.1', unit='nginx.service'), fake


@pytest.mark.parametrize('load_state,load_exit', [('', None),
                                                  ('Failed to connect to bus', 1),
                                                  ('', 0)])
def test_unconfirmed_unit_state_never_runs_security_analysis(monkeypatch, load_state, load_exit):
    result, fake = _run(monkeypatch, load_state=load_state, load_exit=load_exit)
    assert 'error' in result
    assert not any('--json=short' in cmd for cmd in fake.calls)


def test_confirmed_not_found_unit_returns_specific_error(monkeypatch):
    result, fake = _run(monkeypatch, load_state='not-found\n', load_exit=0)
    assert 'not found' in result['error']
    assert not any('--json=short' in cmd for cmd in fake.calls)


@pytest.mark.parametrize('model', ['[]', '{"entries": []}'])
def test_empty_successful_security_model_cannot_be_clean(monkeypatch, model):
    result, _ = _run(monkeypatch, load_state='loaded\n', load_exit=0, json_model=model)
    assert 'error' in result
    assert not any(f['severity'] == 'ok' for f in result.get('findings', []))


def test_loaded_unit_with_nonempty_model_still_reports_its_findings(monkeypatch):
    model = ('[{"set": false, "name": "PrivateNetwork=", "description": "network access", '
             '"exposure": "0.5"}]')
    result, _ = _run(monkeypatch, load_state='loaded\n', load_exit=0, json_model=model)
    assert 'error' not in result
    assert any(f['title'] == 'PrivateNetwork= not restricted' for f in result['findings'])
