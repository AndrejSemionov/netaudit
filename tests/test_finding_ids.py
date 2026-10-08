"""
Stable finding IDs - contract docs/research/stable_finding_ids_research.md
(rev.3, approved 2026-09-27), catalogue docs/checks/finding_ids.md.

Two layers:
  * a static guard over the AST of every in-scope function: each
    _finding(...) call whose severity is not 'ok'/'info' passes id=, and the
    control id is catalogued with a compatible severity - covers every call
    site, not only the branches some scenario happens to reach;
  * behavioural tests for the subject rules (per-control subject tuples,
    percent-encoding, empty parts, CNAME subject is the subdomain).
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path
from unittest.mock import patch
from urllib.parse import unquote

import pytest

from netaudit_pkg.checks import (
    backup_check,
    dns_audit,
    docker_audit,
    server_security,
    systemd_hardening,
)
from netaudit_pkg.findings import subject_id

ROOT = Path(__file__).resolve().parents[1]
CATALOGUE = ROOT / 'docs' / 'checks' / 'finding_ids.md'
ID_RE = re.compile(r'^[A-Z][A-Z0-9]{1,3}(-[A-Z]+)?-\d{3}(:[A-Za-z0-9%._~-]*)*$')
CONTROL_RE = re.compile(r'^[A-Z][A-Z0-9]{1,3}(-[A-Z]+)?-\d{3}$')
SEVERITIES = {'critical', 'high', 'medium', 'low'}

# in-scope functions (contract "Scope of the first migration")
IN_SCOPE = {
    server_security: ['audit_fail2ban', 'audit_firewall', 'audit_sql', '_audit_cookies',
                      '_audit_cors', '_audit_error_page', 'check_web_security_external'],
    docker_audit: None,        # None = every function in the module
    systemd_hardening: None,
    backup_check: None,
    dns_audit: None,
}


def _catalogue() -> dict[str, set[str]]:
    controls: dict[str, set[str]] = {}
    for line in CATALOGUE.read_text().splitlines():
        cells = [c.strip() for c in line.strip().strip('|').split('|')]
        if len(cells) >= 3 and CONTROL_RE.match(cells[0]):
            assert cells[0] not in controls, f'duplicate control {cells[0]}'
            controls[cells[0]] = {s.strip() for s in cells[1].split(',')}
    return controls


def _in_scope_functions():
    for module, names in IN_SCOPE.items():
        tree = ast.parse(inspect.getsource(module))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and (names is None or node.name in names):
                yield module.__name__, node


def _finding_calls():
    for module_name, fn in _in_scope_functions():
        for node in ast.walk(fn):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == '_finding'):
                yield module_name, fn.name, node


def _literal_severity(call: ast.Call):
    if call.args and isinstance(call.args[0], ast.Constant):
        return call.args[0].value
    return None


def _control_of(expr) -> str | None:
    """Control id a literal id= expression names: 'X-001' or subject_id('X-001', ...)."""
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return expr.value
    if (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name) and expr.func.id == 'subject_id'
            and expr.args and isinstance(expr.args[0], ast.Constant)):
        return expr.args[0].value
    return None


# ===========================================================================
# format and encoding
# ===========================================================================

@pytest.mark.parametrize('good', [
    'KRN-001', 'NGX-TLS-002', 'SSH-AUTH-005', 'F2B-INST-001', 'FW-UFW-001', 'SQL-BIND-001',
    'WEB-COOKIE-001', 'DCK-PRIV-001', 'SYS-SBX-001', 'BKP-AGE-001', 'DNS-SPF-001',
    'BKP-AGE-001:%2Fvar%2Fbackups%2Fdb', 'WEB-COOKIE-002:', 'DCK-MNT-001:web:%2Fetc',
])
def test_id_regex_accepts(good):
    assert ID_RE.match(good)


@pytest.mark.parametrize('bad', ['krn-001', 'KRN', 'DCK-MNT-001:/etc', 'X-001:a b', 'KRN-001:a\nb', 'F-001'])
def test_id_regex_rejects(bad):
    assert not ID_RE.match(bad)


def test_subject_id_encodes_every_part_reversibly():
    sid = subject_id('DCK-MNT-001', 'web', '/var/run:x y\nz')
    assert ID_RE.match(sid)
    control, *parts = sid.split(':')
    assert control == 'DCK-MNT-001'
    assert [unquote(p) for p in parts] == ['web', '/var/run:x y\nz']


def test_subject_id_empty_part():
    sid = subject_id('WEB-COOKIE-002', '')
    assert sid == 'WEB-COOKIE-002:'
    assert ID_RE.match(sid)
    assert [unquote(p) for p in sid.split(':')[1:]] == ['']


def test_subject_id_distinct_subjects_never_collide():
    assert subject_id('X-A-001', 'a:b') != subject_id('X-A-001', 'a', 'b')


# ===========================================================================
# catalogue + static guard over every call site
# ===========================================================================

def test_catalogue_is_well_formed():
    controls = _catalogue()
    assert len(controls) > 50
    for control, sevs in controls.items():
        assert sevs and sevs <= SEVERITIES, (control, sevs)


def test_every_problem_finding_call_has_an_id():
    missing = [
        f'{mod}.{fn}:{call.lineno}'
        for mod, fn, call in _finding_calls()
        if _literal_severity(call) not in ('ok', 'info')
        and not any(kw.arg == 'id' for kw in call.keywords)
    ]
    assert missing == []


def test_literal_ids_are_catalogued_with_compatible_severity():
    controls = _catalogue()
    problems = []
    for mod, fn, call in _finding_calls():
        id_kw = next((kw.value for kw in call.keywords if kw.arg == 'id'), None)
        control = _control_of(id_kw) if id_kw is not None else None
        if control is None:
            continue  # computed id (e.g. per-header mapping) - checked below via source constants
        if control not in controls:
            problems.append(f'{mod}.{fn}:{call.lineno} {control} not catalogued')
            continue
        sev = _literal_severity(call)
        if sev is not None and sev not in controls[control]:
            problems.append(f'{mod}.{fn}:{call.lineno} {control} severity {sev} not in {controls[control]}')
    assert problems == []


def test_catalogue_and_code_name_the_same_controls():
    """Every control-shaped string constant in the in-scope functions is
    catalogued (covers mapping tables), and every catalogued control is used."""
    controls = _catalogue()
    used = set()
    for _mod, fn in _in_scope_functions():
        for node in ast.walk(fn):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and CONTROL_RE.match(node.value):
                used.add(node.value)
    for module in IN_SCOPE:  # module-level mapping tables
        for node in ast.walk(ast.parse(inspect.getsource(module))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and CONTROL_RE.match(node.value) \
                    and node.value.split('-')[0] in {c.split('-')[0] for c in controls}:
                used.add(node.value)
    new_prefixes = {'F2B', 'FW', 'SQL', 'WEB', 'DCK', 'SYS', 'BKP', 'DNS'}
    used_new = {u for u in used if u.split('-')[0] in new_prefixes}
    assert used_new - set(controls) == set()
    assert set(controls) - used_new == set()


# ===========================================================================
# behaviour: subjects
# ===========================================================================

def _container(**over):
    info = {'Name': '/web', 'Config': {'User': 'app', 'Image': 'nginx:1.25'},
            'HostConfig': {'Privileged': False, 'CapAdd': [], 'PortBindings': {}, 'Binds': []}}
    info['HostConfig'].update(over)
    return info


def test_docker_two_sensitive_mounts_in_one_container_have_distinct_ids():
    findings = docker_audit._audit_one_container(_container(Binds=['/etc:/host-etc:ro', '/root:/r']))
    ids = sorted(f['id'] for f in findings if f['severity'] != 'ok')
    assert ids == [subject_id('DCK-MNT-001', 'web', '/etc'), subject_id('DCK-MNT-001', 'web', '/root')]


def test_docker_one_mount_removed_changes_only_its_id():
    before = {f['id'] for f in docker_audit._audit_one_container(_container(Binds=['/etc:/e', '/root:/r']))}
    after = {f['id'] for f in docker_audit._audit_one_container(_container(Binds=['/etc:/e']))}
    assert before - after == {subject_id('DCK-MNT-001', 'web', '/root')}
    assert after <= before


def test_docker_same_control_different_containers_distinct_ids():
    a = docker_audit._audit_one_container({**_container(Privileged=True), 'Name': '/a'})
    b = docker_audit._audit_one_container({**_container(Privileged=True), 'Name': '/b'})
    assert {f['id'] for f in a} != {f['id'] for f in b}


def test_web_cookie_with_empty_name_gets_empty_subject_and_unchanged_title():
    findings = server_security._audit_cookies(['=value; Path=/'])
    f = next(f for f in findings if 'missing flag' in f['title'])
    assert f['id'] == 'WEB-COOKIE-002:'
    assert f['title'] == 'cookie "": missing flag(s) Secure, HttpOnly, SameSite'
    assert f['severity'] == 'high'


def test_systemd_subject_includes_unit_and_directive():
    parsed = {'directives': [{'name': 'PrivateTmp', 'description': 'd', 'set': False, 'exposure': 0.5}]}
    a = systemd_hardening._to_findings(parsed, 'nginx.service')
    b = systemd_hardening._to_findings(parsed, 'php-fpm.service')
    assert a[0]['id'] == subject_id('SYS-SBX-001', 'nginx.service', 'PrivateTmp')
    assert a[0]['id'] != b[0]['id']


def _cname_world(target):
    def fake(rtype, name, **_kw):
        if rtype == 'CNAME':
            return dns_audit.DNSQueryResult(status='NOERROR', records=[target + '.'])
        return dns_audit.DNSQueryResult(status='NOERROR', records=[])
    return fake


def test_dns_dangling_cname_id_is_the_subdomain_not_the_target():
    with patch.object(dns_audit, '_dig_query', _cname_world('old.herokuapp.com')):
        first = [f for f in dns_audit._check_dangling_cnames('example.com', ['shop']) if f['severity'] != 'ok']
    with patch.object(dns_audit, '_dig_query', _cname_world('new.example.net')):
        second = [f for f in dns_audit._check_dangling_cnames('example.com', ['shop']) if f['severity'] != 'ok']
    assert first[0]['id'] == second[0]['id'] == subject_id('DNS-CNAME-001', 'shop.example.com')
    assert {first[0]['severity'], second[0]['severity']} == {'high', 'medium'}
