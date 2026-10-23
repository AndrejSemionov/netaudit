"""
Second migration of stable finding ids (docs/research/finding_ids_second_migration.md):
the subjects of the remaining state checks, and that trends now see which
problem was fixed. The static guard is in test_finding_ids.py.
"""

from __future__ import annotations

from netaudit_pkg.checks import (
    cve_audit,
    log_discovery_audit,
    lynis_audit,
    rootkit_check,
    sqli,
)
from netaudit_pkg.checks.log_discovery_audit import (
    JournalInfo,
    LogDiscoveryReport,
    LogFileState,
    LogrotateInfo,
    LogSource,
    SourceType,
)
from netaudit_pkg.trends import compute_trend, snapshots_from_report
from tests.test_finding_ids import ID_RE


def _ids(findings):
    return [f.get('id') for f in findings]


def test_lynis_ids_are_the_test_ids():
    findings = lynis_audit._to_findings({'warnings': [('SSH-7408', 'Weak SSH setting')],
                                          'suggestions': [('AUTH-9230', 'Harden password hashing')]})
    assert _ids(findings) == ['LYN-WARN-001:SSH-7408', 'LYN-SUGG-001:AUTH-9230']


def test_chkrootkit_ids_are_the_test_names_without_the_ports():
    raw = "Checking `bindshell'... INFECTED (PORTS:  465)\nChecking `sshd'... Vulnerable but disabled"
    assert _ids(rootkit_check._parse_chkrootkit(raw)) == ['RKT-CHK-001:bindshell', 'RKT-CHK-002:sshd']


def test_rkhunter_warnings_share_one_id():
    raw = ("Warning: Process '/usr/sbin/dhclient' (PID 1022) is listening on the network.\n"
           "Warning: Hidden directory found: /etc/.java")
    assert _ids(rootkit_check._parse_rkhunter(raw)) == ['RKT-RKH-001', 'RKT-RKH-001']


class _NoSSH:
    def connect(self):
        return self

    def close(self):
        pass


def _cve_run(monkeypatch, vulns):
    monkeypatch.setattr(cve_audit, 'SSHExecutor', lambda *a, **k: _NoSSH())
    monkeypatch.setattr(cve_audit, 'collect_packages', lambda ssh: [{'name': 'nginx', 'version': '1.18.0'}])
    monkeypatch.setattr(cve_audit, 'collect_composer_packages', lambda ssh: [])
    monkeypatch.setattr(cve_audit, 'collect_os_release', lambda ssh: ('ubuntu', '22.04'))
    monkeypatch.setattr(cve_audit, 'query_osv', lambda queryable, os_id, version_id: ({'nginx': vulns}, set()))
    monkeypatch.setattr(cve_audit, 'fetch_vuln_details', lambda vid: {'summary': f'{vid} summary', 'severity': '7.5'})
    return cve_audit.check_cve_audit(host='192.0.2.10')


def test_cve_id_is_package_and_vulnerability(monkeypatch):
    result = _cve_run(monkeypatch, ['CVE-2023-44487', 'UBUNTU-CVE-2021-23017'])
    assert _ids(result['findings']) == ['CVE-VULN-001:nginx:CVE-2023-44487',
                                        'CVE-VULN-001:nginx:UBUNTU-CVE-2021-23017']
    assert all(ID_RE.match(i) for i in _ids(result['findings']))


def test_trend_sees_which_cve_was_fixed(monkeypatch):
    def report(ts, result):
        return {'timestamp': ts, 'results': {'cve_audit': result}, 'timing': {}, 'meta': {},
                'execution_context': {'cve_audit': {'host': '192.0.2.10'}}, 'total_time': 0}

    before = report('2026-10-21 10:00:00', _cve_run(monkeypatch, ['CVE-2023-44487', 'CVE-2021-23017']))
    after = report('2026-10-22 10:00:00', _cve_run(monkeypatch, ['CVE-2023-44487']))
    change = compute_trend(snapshots_from_report(before) + snapshots_from_report(after))['latest_change']
    assert change['resolved'] == ['CVE-VULN-001:nginx:CVE-2021-23017']
    assert change['persisting'] == ['CVE-VULN-001:nginx:CVE-2023-44487']


def _source(source_type, available=True, state=LogFileState.ACTIVE):
    return LogSource(source_type=source_type, path=f'/var/log/{source_type.value}', available=available,
                     readable=True, requires_sudo=False, state=state if available else None,
                     size_bytes=10 if state == LogFileState.ACTIVE else 0, last_modified_epoch=1,
                     owner='syslog', group='adm', mode='640')


def test_log_discovery_ids_name_the_source_type():
    report = LogDiscoveryReport(
        fixed_sources=[_source(SourceType.AUTH_LOG, available=False),
                       _source(SourceType.SYSLOG, state=LogFileState.STALE_EMPTY),
                       _source(SourceType.KERN_LOG)],
        nginx_sources=[], nginx_rotated_count=0,
        journal=JournalInfo(available=False, disk_usage_bytes=None, disk_usage_raw=None, on_defaults=None),
        logrotate=[LogrotateInfo(name='rsyslog', has_config=False)],
    )
    ids = [i for i in _ids(log_discovery_audit.build_findings(report)) if i]
    assert ids == ['LOG-SRC-001:auth_log', 'LOG-SRC-002:syslog', 'LOG-ROT-001:syslog',
                   'LOG-ROT-001:kern_log', 'LOG-JRN-001']


def test_sqlmap_parameter_is_the_subject(monkeypatch):
    output = ("sqlmap identified the following injection point(s):\n"
              "Parameter: id (GET)\n    Type: boolean-based blind\nback-end DBMS: MySQL >= 5.0\n")
    monkeypatch.setattr(sqli, 'tool_available', lambda name: True)
    monkeypatch.setattr(sqli, 'run_cmd', lambda cmd, timeout=0: (0, output, ''))
    result = sqli._run_sqlmap('https://site.example/?id=1', crawl=False)
    assert _ids(result['findings']) == ['SQLI-INJ-001:id%20%28GET%29', 'SQLI-INJ-002', 'SQLI-DBMS-001']
