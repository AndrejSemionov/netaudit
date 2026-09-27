"""
Tests for netaudit_pkg.redaction - secret params never leave the check call.

Decision: .ai-agreed variant 4 (see docs note in tests/test_engine.py,
"execution_context" contract header). Params whose name is in
SECRET_PARAM_NAMES are dropped from report['execution_context'] - on write
(engine/streaming), as the last barrier in storage.save_report(), on read
(storage.load_report(), so reports saved before this fix are covered without
rewriting the DB) and before the AI prompt is built (history.ai_analyze()).
Identity params (host/url/...) are kept, so history and trends still work.
"""

from __future__ import annotations

import copy

from netaudit_pkg import checks  # noqa: F401  (registers every check)
from netaudit_pkg.redaction import SECRET_PARAM_NAMES, redact_params, redact_report
from netaudit_pkg.registry import registry

PW = 'FAKE-TEST-PW'


def test_every_registered_password_type_param_is_a_secret_name():
    """Guard: a new check with a {'type': 'password'} param under a new name
    must extend SECRET_PARAM_NAMES, or it would be stored in reports."""
    password_names = {
        p['name']
        for spec in registry.all()
        for p in (spec.params or [])
        if p.get('type') == 'password'
    }
    assert password_names, 'expected SSH checks with a password param to be registered'
    assert password_names <= SECRET_PARAM_NAMES


def test_redact_params_drops_secret_keeps_identity():
    params = {'host': '10.0.0.1', 'user': 'root', 'port': 22, 'password': PW, 'key_path': '~/.ssh/id'}

    assert redact_params(params) == {'host': '10.0.0.1', 'user': 'root', 'port': 22, 'key_path': '~/.ssh/id'}
    assert params['password'] == PW  # input untouched


def test_redact_params_without_secret_is_equal_copy():
    params = {'target': '8.8.8.8', 'count': 3}
    out = redact_params(params)
    assert out == params and out is not params


def test_redact_report_flat_context():
    report = {'results': {'c': {}}, 'execution_context': {'c': {'host': 'h', 'password': PW}}}
    assert redact_report(report)['execution_context'] == {'c': {'host': 'h'}}


def test_redact_report_multi_host_context():
    report = {'execution_context': {'c': {
        'h': {'host': 'h', 'password': PW},
        'h#2': {'host': 'h', 'password': PW},
    }}}
    assert redact_report(report)['execution_context'] == {'c': {'h': {'host': 'h'}, 'h#2': {'host': 'h'}}}


def test_redact_report_does_not_mutate_input():
    report = {'execution_context': {'c': {'h': {'host': 'h', 'password': PW}}}}
    before = copy.deepcopy(report)
    redact_report(report)
    assert report == before


def test_redact_report_without_execution_context_is_unchanged():
    """Reports saved before execution_context existed, and history entries
    (timestamp/checks/results only) - no key is added."""
    report = {'timestamp': 't', 'results': {'ping': {'loss_pct': 0}}}
    assert redact_report(report) == report


def test_redact_report_ignores_malformed_context():
    report = {'execution_context': {'c': 'not-a-dict', 'd': None}}
    assert redact_report(report) == report
