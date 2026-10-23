"""
A4.1 (docs/research/a4_1_param_audit.md): a target, a domain, a URL, an email
or an interface is checked for its form, and a number for its range, before
anything runs. Before, `dig` with hostname '-f<file>' read a local file and
showed its lines; a target could be an option of ping/mtr/...; URLs took
file://.
"""

from __future__ import annotations

import logging
from argparse import Namespace

import pytest

import netaudit
from netaudit_pkg import engine
from netaudit_pkg.registry import param_value, registry

SECRET = 'SECRETMARKER' + 'a' * 60


def _param(check_id, name):
    [p] = [p for p in registry.get(check_id).params if p['name'] == name]
    return p


def _refused(check_id, name, value):
    with pytest.raises(ValueError) as exc:
        param_value(_param(check_id, name), value)
    if isinstance(value, str) and len(value) > 2:
        assert value not in str(exc.value)  # the value is never printed
    return str(exc.value)


# --- targets -----------------------------------------------------------------

TARGETS = [('ping', 'target'), ('mtr', 'target'), ('tcptraceroute', 'target'), ('arping', 'target'),
           ('dig', 'hostname'), ('iperf', 'server'), ('mikrotik_sniffer', 'router'),
           ('cert_transparency', 'domain'), ('dns_audit', 'domain')]


@pytest.mark.parametrize('check_id, name', TARGETS)
@pytest.mark.parametrize('value', ['-f/etc/hostname', '-V', '--help', 'a b', 'h;id', 'h/x', '@resolver'])
def test_a_target_that_is_not_a_host_is_refused(check_id, name, value):
    assert 'host name or an IP address' in _refused(check_id, name, value)


@pytest.mark.parametrize('check_id, name', TARGETS)
@pytest.mark.parametrize('value', ['192.0.2.1', '2001:db8::1', 'example.org', 'mail-1.example.org',
                                   '_dmarc.example.com', 'пример.рф', 'localhost'])
def test_real_hosts_pass(check_id, name, value):
    assert param_value(_param(check_id, name), value) == value


def test_an_empty_target_is_left_to_the_check():
    """iperf's server is empty by default; the check says 'server not specified'."""
    assert param_value(_param('iperf', 'server'), '') == ''


def test_subdomains_are_a_comma_list_of_hosts():
    p = _param('dns_audit', 'subdomains_to_check')
    assert param_value(p, 'www, mail,blog') == 'www, mail,blog'
    assert param_value(p, '') == ''
    assert 'host names separated by commas' in _refused('dns_audit', 'subdomains_to_check', 'www,-f/etc/hostname')


# --- dig record type ---------------------------------------------------------

def test_record_type_is_a_list_and_lowercase_works():
    p = _param('dig', 'record_type')
    assert p['type'] == 'select'
    assert param_value(p, 'MX') == 'MX'
    assert param_value(p, 'mx') == 'MX'
    assert 'takes one of' in _refused('dig', 'record_type', '-f/etc/hostname')


# --- URLs --------------------------------------------------------------------

URLS = [('ssl', 'url'), ('http', 'url'), ('security_headers', 'url'), ('sql_injection', 'url'),
        ('web_security_external', 'url')]


@pytest.mark.parametrize('check_id, name', URLS)
@pytest.mark.parametrize('value', ['file:///etc/hostname', '--url=file:///etc/hostname', 'ftp://h.example',
                                   'https://-x.example', '-K/etc/x://', 'https://', 'https://h ex'])
def test_a_url_that_is_not_http_is_refused(check_id, name, value):
    assert 'http:// or https:// URL' in _refused(check_id, name, value)


@pytest.mark.parametrize('check_id, name', URLS)
@pytest.mark.parametrize('value', ['example.com', 'https://example.com', 'http://h.example:8080',
                                   'https://h.example/p?q=1&r=2', 'https://[2001:db8::1]/', 'site.example/path'])
def test_http_urls_pass(check_id, name, value):
    assert param_value(_param(check_id, name), value) == value


def test_an_empty_url_is_left_to_the_check():
    assert param_value(_param('sql_injection', 'url'), '') == ''


# --- emails, interface -------------------------------------------------------

def test_emails():
    p = _param('breach_check', 'emails')
    assert param_value(p, 'a@b.example, c.d@e.example') == 'a@b.example, c.d@e.example'
    assert param_value(p, '') == ''
    for bad in ['no-at-sign', 'x/../y@b.example', 'a@b.example?x=1', 'a b@c.example']:
        assert 'email addresses separated by commas' in _refused('breach_check', 'emails', bad)


def test_interface():
    p = _param('tshark_capture', 'interface')
    for good in ['any', 'eth0', 'wlp3s0', 'br-1a2b', 'eth0.100']:
        assert param_value(p, good) == good
    assert param_value(p, '') == ''  # left to the check, as for every format
    for bad in ['-D', 'eth0 -w /tmp/x']:
        assert 'network interface name' in _refused('tshark_capture', 'interface', bad)


# --- number ranges -----------------------------------------------------------

@pytest.mark.parametrize('check_id, name, low, high', [
    ('ssh_hardening', 'port', 1, 65535), ('iperf', 'port', 1, 65535), ('tcptraceroute', 'port', 1, 65535),
    ('ping', 'count', 1, 1000), ('arping', 'count', 1, 1000), ('mtr', 'duration_sec', 1, 3600),
    ('iperf', 'duration', 1, 3600), ('tshark_capture', 'duration', 1, 3600),
    ('ssh_auth_audit', 'lines', 1, 100000), ('tcptraceroute', 'max_hops', 1, 64),
    ('ssh_auth_audit', 'window_hours', 1, 720), ('backup_check', 'max_age_hours', 1, 8760),
    ('backup_check', 'min_copies', 0, 1000),
])
def test_number_ranges(check_id, name, low, high):
    p = _param(check_id, name)
    assert param_value(p, low) == low
    assert param_value(p, high) == high
    for bad in (low - 1, high + 1):
        assert f'takes a number from {low} to {high}' in _refused(check_id, name, bad)


# --- the registry ------------------------------------------------------------

# free text by design: never a command-argument position (bpf_filter and
# expected_issuer_contains), or validated in the check (directories, unit,
# target_ip), or an SSH field that goes to Paramiko only
FREE_TEXT = {'bpf_filter', 'expected_issuer_contains', 'directories', 'unit', 'target_ip',
             'host', 'user', 'key_path'}


def test_every_text_parameter_has_a_format_or_is_free_by_decision():
    missing = [f'{c.id}.{p["name"]}' for c in registry.all() for p in c.params
               if p['type'] == 'text' and 'format' not in p and p['name'] not in FREE_TEXT]
    assert missing == []


def test_every_number_parameter_has_a_range():
    missing = [f'{c.id}.{p["name"]}' for c in registry.all() for p in c.params
               if p['type'] == 'number' and ('min' not in p or 'max' not in p)]
    assert missing == []


def test_every_default_passes_its_own_rules():
    for c in registry.all():
        for p in c.params:
            if 'default' in p:
                param_value(p, p['default'])


# --- end to end: the dig hole ------------------------------------------------

@pytest.fixture
def secret_file(tmp_path):
    path = tmp_path / 'secret.txt'
    path.write_text(SECRET + '\n', encoding='utf-8')
    return str(path)


def test_cli_refuses_dig_reading_a_file(monkeypatch, isolated_db, secret_file, caplog, capsys):
    ran = []
    report = {'timestamp': '2026-10-23 12:00:00', 'results': {}, 'timing': {}, 'meta': {},
              'execution_context': {}, 'total_time': 0}
    monkeypatch.setattr(netaudit, 'run_checks', lambda selected: ran.append(selected) or report)
    ns = Namespace(checks=['dig'], ai=False, quick=False, notify=False, rest=['--hostname', f'-f{secret_file}'])
    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exc:
        netaudit.cmd_run(ns)
    assert exc.value.code not in (0, None)
    text = caplog.text + capsys.readouterr().err
    assert '--hostname (dig)' in text
    assert secret_file not in text and SECRET not in text
    assert ran == []


def test_web_api_refuses_dig_reading_a_file(monkeypatch, isolated_db, secret_file):
    from fastapi.testclient import TestClient

    from web.app import app
    calls = []
    monkeypatch.setattr(engine.registry.get('dig'), 'func', lambda **kw: calls.append(kw) or {})
    resp = TestClient(app).post('/api/run', json={'checks': [{'id': 'dig', 'params': {'hostname': f'-f{secret_file}'}}]})
    assert resp.status_code == 400
    assert 'dig: hostname takes a host name or an IP address' in resp.text
    assert SECRET not in resp.text and secret_file not in resp.text
    assert calls == []
