"""
`run` refuses a check whose default target is example.com when no target is
given (docs/research/cli_example_targets.md): before, `run dns_audit` audited
the DNS of example.com and `run ssl` the TLS of https://example.com, with no
word that this is only a placeholder.
"""

from __future__ import annotations

import logging
from argparse import Namespace

import pytest

import netaudit
from netaudit_pkg import storage
from netaudit_pkg.engine import list_available

EXAMPLE_CHECKS = {
    ('ssl', 'url'), ('http', 'url'), ('security_headers', 'url'), ('web_security_external', 'url'),
    ('dns_audit', 'domain'), ('cert_transparency', 'domain'),
}


def _ns(checks, rest, quick=False):
    return Namespace(checks=checks, ai=False, quick=quick, rest=rest, notify=False)


@pytest.fixture
def ran(monkeypatch, isolated_db):
    """What reached the engine; nothing is executed."""
    calls = []

    def report():
        return {'timestamp': '2026-10-18 12:00:00', 'results': {}, 'timing': {}, 'meta': {},
                'execution_context': {}, 'total_time': 0}

    monkeypatch.setattr(netaudit, 'run_checks', lambda selected: calls.append(selected) or report())
    return calls


def _refused(ns, caplog, capsys, *needles):
    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exc:
        netaudit.cmd_run(ns)
    assert exc.value.code not in (0, None)
    out = capsys.readouterr()
    text = caplog.text + out.out + out.err
    for needle in needles:
        assert needle in text, f'{needle!r} not in {text!r}'
    return text


# --- which checks ------------------------------------------------------------

def test_the_checks_with_an_example_default_are_exactly_these():
    found = {(c['id'], p['name']) for c in list_available() for p in c['params']
             if p['name'] in storage.IDENTITY_PARAM_KEYS and p['default'] in netaudit.EXAMPLE_TARGETS}
    assert found == EXAMPLE_CHECKS


def test_every_example_default_in_the_registry_is_covered():
    """A new check with an example.* default needs a decision: required or not."""
    found = {(c['id'], p['name']) for c in list_available() for p in c['params']
             if 'example.' in str(p['default'])}
    assert found == EXAMPLE_CHECKS


# --- refused -----------------------------------------------------------------

@pytest.mark.parametrize('check_id, flag, example', [
    ('ssl', '--url', 'https://example.com'),
    ('dns_audit', '--domain', 'example.com'),
    ('cert_transparency', '--domain', 'example.com'),
])
def test_a_check_alone_without_its_target_is_refused(ran, caplog, capsys, check_id, flag, example):
    _refused(_ns([check_id], []), caplog, capsys, check_id, flag, example)
    assert ran == []


def test_a_mixed_run_refuses_the_check_whose_target_is_missing(ran, caplog, capsys):
    text = _refused(_ns(['ssl', 'dns_audit'], ['--url', 'https://site.example']), caplog, capsys,
                    'dns_audit', '--domain')
    assert 'ssl needs' not in text
    assert ran == []


def test_several_checks_are_named_in_one_message_in_the_given_order(ran, caplog, capsys):
    text = _refused(_ns(['dns_audit', 'security_headers', 'http'], []), caplog, capsys,
                    'dns_audit needs --domain', 'security_headers needs --url', 'http needs --url')
    assert text.index('dns_audit') < text.index('security_headers') < text.index('http needs')
    assert ran == []


def test_refusal_comes_before_any_password_prompt(ran, caplog, capsys, monkeypatch):
    monkeypatch.setattr(netaudit.getpass, 'getpass', lambda prompt: pytest.fail('asked for a password'))
    _refused(_ns(['ssl', 'server_audit'], ['--host', '10.0.0.5', '--password', '-']), caplog, capsys,
             'ssl needs --url')
    assert ran == []


def test_an_explicit_quick_selection_is_refused_too(ran, caplog, capsys):
    _refused(_ns(['ssl'], [], quick=True), caplog, capsys, 'ssl needs --url')
    assert ran == []


def test_main_exits_non_zero(ran, caplog, monkeypatch):
    import sys
    monkeypatch.setattr(sys, 'argv', ['netaudit.py', 'run', 'dns_audit'])
    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exc:
        netaudit.main()
    assert exc.value.code not in (0, None)
    assert 'dns_audit needs --domain' in caplog.text
    assert ran == []


# --- unchanged ---------------------------------------------------------------

def test_a_given_target_still_runs(ran):
    netaudit.cmd_run(_ns(['ssl'], ['--url', 'https://site.example']))
    netaudit.cmd_run(_ns(['dns_audit'], ['--domain', 'site.example']))
    netaudit.cmd_run(_ns(['ssl', 'dns_audit', 'cert_transparency'],
                         ['--url', 'https://site.example', '--domain', 'site.example']))
    assert [[(s['id'], s['params']) for s in selection] for selection in ran] == [
        [('ssl', {'url': 'https://site.example'})],
        [('dns_audit', {'domain': 'site.example'})],
        [('ssl', {'url': 'https://site.example'}), ('dns_audit', {'domain': 'site.example'}),
         ('cert_transparency', {'domain': 'site.example'})],
    ]


def test_quick_site_bundle_still_works(ran):
    netaudit.cmd_run(_ns([], ['--url', 'https://site.example'], quick=True))
    netaudit.cmd_run(_ns([], ['--url', 'https://site.example', '--domain', 'site.example'], quick=True))
    assert [[s['id'] for s in selection] for selection in ran] == [
        ['ssl', 'security_headers', 'web_security_external'],
        ['ssl', 'security_headers', 'web_security_external', 'dns_audit'],
    ]


def test_network_diagnostics_keep_their_real_default(ran):
    netaudit.cmd_run(_ns(['ping'], []))
    netaudit.cmd_run(_ns(['dig'], []))
    assert [selection[0]['params'] for selection in ran] == [{}, {}]


def test_list_shows_the_example_target_as_required(capsys):
    netaudit.cmd_list(Namespace())
    out = capsys.readouterr().out
    params, current = {}, None
    for line in out.splitlines():
        if line.startswith('['):
            current = line.split('] ', 1)[1].split()[0]
        else:
            name = line.split('--', 1)[1].split()[0]
            params[(current, name)] = line
    for key in EXAMPLE_CHECKS:
        assert 'required' in params[key] and 'example.com' not in params[key], params[key]
    assert params[('ping', 'target')].endswith('(text, default=8.8.8.8)')
    assert 'required' not in params[('ssh_hardening', 'host')]
