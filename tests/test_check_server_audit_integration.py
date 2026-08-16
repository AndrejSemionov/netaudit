"""Integration tests for check_server_audit() - the registered check that
wires together audit_nginx(), audit_fail2ban(), audit_firewall(),
audit_sql(), audit_ssh_hardening() into one report.

These tests exist specifically to verify the new FirewallEvidence-based
audit_firewall() (see test_audit_firewall.py for its own dedicated
regression suite) is correctly INTEGRATED into the existing
check_server_audit() pipeline - not just correct in isolation. Per the
quality-audit review: unit/regression tests on audit_firewall() alone
prove the algorithm is right, but not that summary counting, severity
registration, and the overall report shape still work end-to-end through
the actual registered check.
"""

from __future__ import annotations

from netaudit_pkg.checks.server_security import check_server_audit
from tests.conftest import ExitCodeFakeSSHExecutor


def _baseline_responses():
    """A full set of canned responses covering every section
    check_server_audit() touches (nginx, fail2ban, firewall, sql, ssh),
    all wired to produce clean 'ok' results - tests override only the
    specific response(s) relevant to what they're checking, so each test
    stays focused on one thing without needing to hand-roll the entire
    fixture every time."""
    return {
        # nginx
        'which nginx': '/usr/sbin/nginx',
        'nginx -v': 'nginx/1.24.0',
        'nginx -T': ('server_tokens off;\nssl_protocols TLSv1.2 TLSv1.3;\n'
                     'add_header Strict-Transport-Security "max-age=1" always;\n'
                     'add_header X-Frame-Options DENY always;\n'
                     'add_header X-Content-Type-Options nosniff always;'),
        # fail2ban
        'which fail2ban-client': 'NONE',
        # firewall
        'command -v ufw': '',
        'nft list ruleset': 'table inet filter {\n  chain input {\n  }\n}',
        'iptables -S': '-P INPUT DROP',
        # sql
        'command -v mysql': '',
        'command -v mariadb': '',
        'ss -tlnp': '',
        "grep -rh '^\\s*bind-address' /etc/mysql/": '',
        # ssh
        'sshd -T': 'permitrootlogin prohibit-password\npasswordauthentication no\n'
                   'permitemptypasswords no\nport 22\nmaxauthtries 6',
    }


def _baseline_exit_codes():
    return {
        'command -v ufw': 127,
        'nft list ruleset': 0,
        'iptables -S': 0,
        'command -v mysql': 127,
        'command -v mariadb': 127,
        'ss -tlnp': 0,
        "grep -rh '^\\s*bind-address' /etc/mysql/": 1,
    }


def test_check_server_audit_calls_new_firewall_collector():
    """The firewall section must come from the new FirewallEvidence-based
    audit_firewall(), not some leftover parallel raw-SSH path - verified
    by confirming the exact commands the new collector uses (`command -v
    ufw`, `nft list ruleset`, `iptables -S`) were actually sent, and the
    OLD text-marker commands (`which ufw && ufw status ... || echo
    NOUFW`, `... || echo NONFT`, `... || echo NOIPT`) were NOT."""
    fake = ExitCodeFakeSSHExecutor(
        responses=_baseline_responses(),
        exit_codes=_baseline_exit_codes(),
    )
    import netaudit_pkg.checks.server_security as ss
    orig_executor = ss.SSHExecutor
    ss.SSHExecutor = lambda *a, **kw: fake
    try:
        check_server_audit(host='1.2.3.4')
    finally:
        ss.SSHExecutor = orig_executor

    assert any('command -v ufw' in c for c in fake.calls)
    assert any('nft list ruleset' in c for c in fake.calls)
    assert any('iptables -S' in c for c in fake.calls)
    # the old bug-ridden marker commands must be gone
    assert not any('echo NOUFW' in c for c in fake.calls)
    assert not any('echo NONFT' in c for c in fake.calls)
    assert not any('echo NOIPT' in c for c in fake.calls)


def test_check_server_audit_firewall_section_has_only_new_findings():
    """The firewall section's findings must come exclusively from the
    new per-backend verdict logic - no leftover/duplicate findings from
    an old code path running in parallel. With the baseline fixture
    (ufw absent, nftables active, iptables filtered), exactly 2 findings
    are expected: one 'ok' for nftables, one 'ok' for iptables (ufw
    absent produces none)."""
    fake = ExitCodeFakeSSHExecutor(
        responses=_baseline_responses(),
        exit_codes=_baseline_exit_codes(),
    )
    import netaudit_pkg.checks.server_security as ss
    orig_executor = ss.SSHExecutor
    ss.SSHExecutor = lambda *a, **kw: fake
    try:
        result = check_server_audit(host='1.2.3.4')
    finally:
        ss.SSHExecutor = orig_executor

    fw_findings = result['sections']['firewall']['findings']
    assert len(fw_findings) == 2
    titles = [f['title'] for f in fw_findings]
    assert any('nftables' in t.lower() for t in titles)
    assert any('iptables' in t.lower() for t in titles)
    assert all(f['severity'] == 'ok' for f in fw_findings)


def test_check_server_audit_summary_counts_new_firewall_findings():
    """Regression test for the exact integration risk this review
    flagged: the summary dict must correctly count every severity the
    new audit_firewall() can produce (high/low/ok - all already in
    check_server_audit()'s counts dict), not silently drop or miscount
    any of them via the counts.get(severity, 0) fallback."""
    responses = _baseline_responses()
    exit_codes = _baseline_exit_codes()
    # force a HIGH firewall finding: iptables open
    responses['iptables -S'] = '-P INPUT ACCEPT\n-A INPUT -j ACCEPT'
    fake = ExitCodeFakeSSHExecutor(responses=responses, exit_codes=exit_codes)

    import netaudit_pkg.checks.server_security as ss
    orig_executor = ss.SSHExecutor
    ss.SSHExecutor = lambda *a, **kw: fake
    try:
        result = check_server_audit(host='1.2.3.4')
    finally:
        ss.SSHExecutor = orig_executor

    fw_findings = result['sections']['firewall']['findings']
    high_fw = [f for f in fw_findings if f['severity'] == 'high']
    assert len(high_fw) == 1
    # the summary's 'high' count must include this firewall finding
    # alongside whatever other sections contributed
    assert result['summary']['high'] >= 1


def test_check_server_audit_summary_counts_low_unknown_findings():
    """A firewall UNKNOWN finding (severity='low') must be reflected in
    summary['low'] - this is the exact severity this fix's UNKNOWN
    findings use (see audit_firewall()'s docstring for why 'low' was
    chosen over introducing a new severity)."""
    responses = _baseline_responses()
    exit_codes = _baseline_exit_codes()
    # force UFW UNKNOWN: present, but status collection fails
    responses['command -v ufw'] = '/usr/sbin/ufw'
    responses['ufw status'] = 'sudo: a password is required'
    exit_codes['command -v ufw'] = 0
    exit_codes['ufw status'] = 1
    fake = ExitCodeFakeSSHExecutor(responses=responses, exit_codes=exit_codes)

    import netaudit_pkg.checks.server_security as ss
    orig_executor = ss.SSHExecutor
    ss.SSHExecutor = lambda *a, **kw: fake
    try:
        result = check_server_audit(host='1.2.3.4')
    finally:
        ss.SSHExecutor = orig_executor

    fw_findings = result['sections']['firewall']['findings']
    low_fw = [f for f in fw_findings if f['severity'] == 'low']
    assert len(low_fw) == 1
    assert result['summary']['low'] >= 1


def test_check_server_audit_requires_manual_verification_reaches_result():
    """requires_manual_verification=True (set on UNKNOWN firewall
    findings) must survive all the way through to the final
    check_server_audit() result dict - not get stripped anywhere in the
    sections/summary assembly."""
    responses = _baseline_responses()
    exit_codes = _baseline_exit_codes()
    # force nftables LIVE_UNKNOWN with a readable config (the FW-3 case)
    del responses['nft list ruleset']
    del exit_codes['nft list ruleset']
    responses['cat /etc/nftables.conf'] = 'table inet filter {\n  chain input {\n  }\n}'
    exit_codes['cat /etc/nftables.conf'] = 0
    fake = ExitCodeFakeSSHExecutor(responses=responses, exit_codes=exit_codes)

    import netaudit_pkg.checks.server_security as ss
    orig_executor = ss.SSHExecutor
    ss.SSHExecutor = lambda *a, **kw: fake
    try:
        result = check_server_audit(host='1.2.3.4')
    finally:
        ss.SSHExecutor = orig_executor

    fw_findings = result['sections']['firewall']['findings']
    nft_finding = next(f for f in fw_findings if 'nftables' in f['title'].lower())
    assert nft_finding.get('requires_manual_verification') is True


def test_check_server_audit_nginx_and_ssh_sections_unaffected():
    """The firewall refactor must not have touched nginx or SSH
    sections' behavior at all - same findings, same shape, as the
    pre-existing (already well-tested) audit_nginx()/
    audit_ssh_hardening() would produce on their own."""
    fake = ExitCodeFakeSSHExecutor(
        responses=_baseline_responses(),
        exit_codes=_baseline_exit_codes(),
    )
    import netaudit_pkg.checks.server_security as ss
    orig_executor = ss.SSHExecutor
    ss.SSHExecutor = lambda *a, **kw: fake
    try:
        result = check_server_audit(host='1.2.3.4')
    finally:
        ss.SSHExecutor = orig_executor

    nginx_findings = result['sections']['nginx']['findings']
    assert len(nginx_findings) == 1
    assert nginx_findings[0]['severity'] == 'ok'

    ssh_findings = result['sections']['ssh']['findings']
    assert len(ssh_findings) == 1
    assert ssh_findings[0]['severity'] == 'ok'
    assert result['sections']['ssh']['root_login'] == 'prohibit-password'


def test_check_server_audit_does_not_crash_on_minimal_evidence():
    """A host where every firewall-related command fails to complete
    (total collection failure across the board) must produce UNKNOWN
    findings, not raise an exception that would take down the entire
    check_server_audit() report (nginx/fail2ban/sql/ssh sections would
    be lost too if firewall raised)."""
    responses = _baseline_responses()
    # remove every firewall-related response/exit_code entirely -
    # simulates total collection failure for all three backends
    for key in ('command -v ufw', 'nft list ruleset', 'iptables -S'):
        responses.pop(key, None)
    fake = ExitCodeFakeSSHExecutor(responses=responses, exit_codes={})

    import netaudit_pkg.checks.server_security as ss
    orig_executor = ss.SSHExecutor
    ss.SSHExecutor = lambda *a, **kw: fake
    try:
        result = check_server_audit(host='1.2.3.4')  # must not raise
    finally:
        ss.SSHExecutor = orig_executor

    assert 'error' not in result
    fw_findings = result['sections']['firewall']['findings']
    assert len(fw_findings) >= 1
    assert all(f['severity'] in ('low', 'ok', 'high') for f in fw_findings)


def test_check_server_audit_result_shape_is_compatible():
    """The overall result dict shape (host/sections/summary, each
    section having a 'findings' list of dicts with severity/title/
    detail/confidence) must be unchanged from before the firewall
    refactor - this is what the web UI and history/AI-analysis code
    already expect from every registered check's output."""
    fake = ExitCodeFakeSSHExecutor(
        responses=_baseline_responses(),
        exit_codes=_baseline_exit_codes(),
    )
    import netaudit_pkg.checks.server_security as ss
    orig_executor = ss.SSHExecutor
    ss.SSHExecutor = lambda *a, **kw: fake
    try:
        result = check_server_audit(host='1.2.3.4')
    finally:
        ss.SSHExecutor = orig_executor

    assert set(result.keys()) == {'host', 'sections', 'summary'}
    assert result['host'] == '1.2.3.4'
    assert set(result['sections'].keys()) == {'nginx', 'fail2ban', 'firewall', 'sql', 'ssh'}
    assert set(result['summary'].keys()) == {'high', 'medium', 'low', 'ok'}
    # As of the SQL quality-audit fix, audit_sql() always includes a
    # 'findings' key, even when MySQL/MariaDB is confirmed not installed
    # (an empty list - N/A, not a security 'ok' - rather than a bare
    # {'installed': False} with no findings key at all - see the SQL-3
    # regression this closes).
    assert 'findings' in result['sections']['firewall']
    assert 'findings' in result['sections']['sql']
    for section in result['sections'].values():
        for f in section.get('findings', []):
            assert 'severity' in f
            assert 'title' in f
            assert f['severity'] in result['summary']  # every severity used is a known summary key
