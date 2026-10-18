"""
`--quick` bundles audit the target the user named
(docs/research/quick_bundle_targets.md): no bundle check runs on the NetAudit
machine itself (`ports`, `firewall`) or on a default target (`dns_audit` on
example.com).
"""

from __future__ import annotations

import logging
from argparse import Namespace

import pytest

import netaudit
from netaudit_pkg.engine import list_available

SSH_FLAGS = ['--user', 'audit', '--port', '2222', '--key_path', '/keys/id_ed25519']


def _ns(checks, rest):
    return Namespace(checks=checks, ai=False, quick=True, rest=rest)


def _params(check_id):
    return {p['name'] for p in {c['id']: c for c in list_available()}[check_id]['params']}


@pytest.fixture
def selected(monkeypatch, isolated_db):
    """Captures what cmd_run hands to the engine; nothing is executed."""
    calls = []

    def fake_single(selection):
        calls.append(selection)
        return {'timestamp': '2026-10-17 12:00:00', 'results': {}, 'timing': {}, 'meta': {},
                'execution_context': {}, 'total_time': 0}

    monkeypatch.setattr(netaudit, 'run_checks', fake_single)
    return calls


# --- what the bundles may contain --------------------------------------------

def test_every_server_bundle_check_audits_the_named_host():
    for check_id in netaudit.QUICK_BUNDLE_SERVER:
        assert 'host' in _params(check_id), f'{check_id} would run on the NetAudit machine'


def test_every_site_bundle_check_audits_the_named_site_or_domain():
    for check_id in netaudit.QUICK_BUNDLE_SITE:
        assert _params(check_id) & {'url', 'domain'}, check_id


# --- server bundle -----------------------------------------------------------

def test_server_bundle_runs_remote_checks_on_the_named_host(selected):
    netaudit.cmd_run(_ns([], ['--host', '10.0.0.5', *SSH_FLAGS]))

    [selection] = selected
    assert [item['id'] for item in selection] == ['server_audit', 'ssh_audit', 'lynis_audit', 'cve_audit']
    for item in selection:
        params = item['params']
        assert (params['host'], params['user'], params['port'], params['key_path']) == \
            ('10.0.0.5', 'audit', 2222, '/keys/id_ed25519')


def test_server_bundle_asks_each_password_once_for_all_checks(selected, monkeypatch):
    prompts = []
    monkeypatch.setattr(netaudit.getpass, 'getpass', lambda prompt: prompts.append(prompt) or 'PW-FROM-PROMPT')

    netaudit.cmd_run(_ns([], ['--host', '10.0.0.5', '--password', '-', '--sudo_password', '-']))

    [selection] = selected
    assert len(prompts) == 2
    assert all(item['params']['password'] == 'PW-FROM-PROMPT' for item in selection)
    # cve_audit has no sudo_password parameter
    assert [item['id'] for item in selection if item['params'].get('sudo_password') == 'PW-FROM-PROMPT'] == \
        ['server_audit', 'ssh_audit', 'lynis_audit']


# --- site bundle -------------------------------------------------------------

def test_site_bundle_without_domain_skips_dns_audit_with_a_hint(selected, caplog):
    with caplog.at_level(logging.WARNING):
        netaudit.cmd_run(_ns([], ['--url', 'https://shop.example.org']))

    [selection] = selected
    assert [item['id'] for item in selection] == ['ssl', 'security_headers', 'web_security_external']
    assert all(item['params'] == {'url': 'https://shop.example.org'} for item in selection)
    assert 'skipping dns_audit' in caplog.text
    assert '--domain' in caplog.text


def test_site_bundle_with_domain_runs_dns_audit_on_that_domain(selected, caplog):
    with caplog.at_level(logging.WARNING):
        netaudit.cmd_run(_ns([], ['--url', 'https://www.example.org', '--domain', 'example.org']))

    [selection] = selected
    assert [item['id'] for item in selection] == ['ssl', 'security_headers', 'web_security_external', 'dns_audit']
    assert selection[-1]['params'] == {'domain': 'example.org'}
    assert 'skipping' not in caplog.text


# --- unchanged ---------------------------------------------------------------

def test_explicit_checks_with_quick_run_exactly_those(selected, caplog):
    with caplog.at_level(logging.WARNING):
        netaudit.cmd_run(_ns(['ssl'], ['--url', 'https://example.org']))

    [selection] = selected
    assert selection == [{'id': 'ssl', 'params': {'url': 'https://example.org'}}]
    assert 'skipping' not in caplog.text


def test_url_and_host_together_are_refused(selected, caplog):
    # --url picks the site bundle, which takes no --host: before, --host was
    # dropped silently (docs/research/cli_unused_flags.md)
    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit):
        netaudit.cmd_run(_ns([], ['--url', 'https://example.org', '--host', '10.0.0.5']))

    assert '--host' in caplog.text
    assert selected == []


def test_quick_without_url_or_host_is_refused(selected, caplog):
    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exc:
        netaudit.cmd_run(_ns([], ['--domain', 'example.org']))

    assert exc.value.code != 0
    assert '--quick needs --url' in caplog.text
    assert selected == []
