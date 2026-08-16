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
        'command -v fail2ban-client': '',
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
        'command -v fail2ban-client': 127,
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


# ===========================================================================
# audit_fail2ban() integration into check_server_audit() - post-collector-
# rewrite regression suite. See test_audit_fail2ban.py for the dedicated
# unit/verdict-level suite; these three tests exist specifically to prove
# the fail2ban rewrite is correctly WIRED into the top-level orchestration
# layer (summary counting, requires_manual_verification propagation,
# other sections left untouched) - the same integration-level guarantee
# already established above for the firewall rewrite.
# ===========================================================================

def test_check_server_audit_fail2ban_not_present_other_sections_unaffected():
    """Fail2ban confirmed NOT_PRESENT (the corrected baseline fixture -
    exit_code=127, not an unregistered/UNKNOWN command) must produce
    exactly the pre-existing 'medium: not installed' finding, and must
    not perturb nginx/firewall/sql/ssh sections at all."""
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

    assert 'fail2ban' in result['sections']
    f2b = result['sections']['fail2ban']
    assert f2b['installed'] is False
    assert len(f2b['findings']) == 1
    assert f2b['findings'][0]['severity'] == 'medium'
    assert 'not installed' in f2b['findings'][0]['title']
    assert result['summary']['medium'] >= 1

    # other sections unaffected - same assertions as the pre-existing
    # nginx/ssh unaffected test, reused here to prove the fail2ban
    # baseline fixture fix (which/command -v swap) didn't perturb them
    nginx_findings = result['sections']['nginx']['findings']
    assert len(nginx_findings) == 1
    assert nginx_findings[0]['severity'] == 'ok'
    ssh_findings = result['sections']['ssh']['findings']
    assert len(ssh_findings) == 1
    assert ssh_findings[0]['severity'] == 'ok'
    fw_findings = result['sections']['firewall']['findings']
    assert len(fw_findings) == 2
    assert all(f['severity'] == 'ok' for f in fw_findings)


def test_check_server_audit_fail2ban_unknown_binary_reaches_summary_as_low():
    """Fail2ban binary check collection failure (FB-1 fix): the summary
    must count this as 'low', requires_manual_verification=True must
    survive to the final result, and this must NEVER be silently folded
    into a confident 'not installed' (medium) or dropped entirely - the
    exact regression check_server_audit_integration.py already
    established for firewall's UNKNOWN case, applied to fail2ban."""
    responses = _baseline_responses()
    exit_codes = _baseline_exit_codes()
    # remove the fail2ban binary check entirely -> no completion marker
    # -> genuine collection failure, distinct from a confirmed exit 127
    del responses['command -v fail2ban-client']
    del exit_codes['command -v fail2ban-client']
    fake = ExitCodeFakeSSHExecutor(responses=responses, exit_codes=exit_codes)

    import netaudit_pkg.checks.server_security as ss
    orig_executor = ss.SSHExecutor
    ss.SSHExecutor = lambda *a, **kw: fake
    try:
        result = check_server_audit(host='1.2.3.4')
    finally:
        ss.SSHExecutor = orig_executor

    f2b = result['sections']['fail2ban']
    assert f2b['installed'] is True  # collection failure != confirmed absence
    low_findings = [f for f in f2b['findings'] if f['severity'] == 'low']
    assert len(low_findings) >= 1
    unknown_finding = next(f for f in f2b['findings']
                           if 'could not determine whether fail2ban is installed' in f['title'])
    assert unknown_finding.get('requires_manual_verification') is True
    assert not any(f['severity'] == 'medium' and 'not installed' in f['title'] for f in f2b['findings']), \
        'a collection failure must never be reported as confirmed not-installed'
    assert result['summary']['low'] >= 1


def test_check_server_audit_fail2ban_partial_jail_collection_reaches_summary_as_low():
    """The central aggregation-contract regression at the orchestration
    layer: 6 jails, 5 confirmed, 1 unconfirmed - the resulting LOW +
    requires_manual_verification finding must reach check_server_audit()'s
    top-level result and summary counts intact, and must never be
    counted as 'ok' anywhere in the summary."""
    responses = _baseline_responses()
    exit_codes = _baseline_exit_codes()
    responses['command -v fail2ban-client'] = '/usr/bin/fail2ban-client'
    exit_codes['command -v fail2ban-client'] = 0
    for jail in ('nginx-botsearch', 'nginx-http-auth', 'nginx-limit-req', 'sshd-ddos', 'sshd'):
        responses[f'status {jail}'] = (
            f'Status for the jail: {jail}\n`- Currently banned:\t0\n`- Total banned:\t1')
        exit_codes[f'status {jail}'] = 0
    status_text = ('Status\n|- Number of jail:\t6\n'
                   '`- Jail list:\tnginx-botsearch, nginx-http-auth, nginx-limit-req, '
                   'recidive, sshd, sshd-ddos')
    responses['fail2ban-client status'] = status_text
    exit_codes['fail2ban-client status'] = 0

    class OneJailFailsFake(ExitCodeFakeSSHExecutor):
        """Simulates a genuine per-jail collection failure for
        'recidive' specifically. Leaving 'status recidive' simply
        unregistered is NOT sufficient here - ExitCodeFakeSSHExecutor's
        substring matching would fall through to the shorter, already-
        registered 'fail2ban-client status' key (needed for the
        top-level status call), which also matches 'fail2ban-client
        status recidive' and would give it the full 6-jail status text
        with an exit code, i.e. a false CONFIRMED instead of the
        intended collection failure. Overriding sudo() directly for
        this one jail avoids relying on substring-matching fallthrough
        to produce the failure shape."""
        def sudo(self, cmd, timeout=20):
            self.calls.append(cmd)
            if 'status recidive' in cmd:
                return 'dropped mid-command, no completion marker', ''
            return self._respond(cmd)

    fake = OneJailFailsFake(responses=responses, exit_codes=exit_codes)
    import netaudit_pkg.checks.server_security as ss
    orig_executor = ss.SSHExecutor
    ss.SSHExecutor = lambda *a, **kw: fake
    try:
        result = check_server_audit(host='1.2.3.4')
    finally:
        ss.SSHExecutor = orig_executor

    f2b = result['sections']['fail2ban']
    assert f2b['installed'] is True
    assert len(f2b['jails']) == 6
    recidive_entry = next(j for j in f2b['jails'] if j['jail'] == 'recidive')
    assert recidive_entry['currently_banned'] is None
    assert recidive_entry['total_banned'] is None

    assert not any(f['severity'] == 'ok' for f in f2b['findings']), \
        'partial jail collection must never surface as ok, even at the top-level report'
    partial_finding = next(f for f in f2b['findings'] if 'could not fully determine' in f['title'])
    assert partial_finding['severity'] == 'low'
    assert partial_finding.get('requires_manual_verification') is True
    assert '5 of 6 jails confirmed' in partial_finding['detail']

    assert result['summary']['low'] >= 1
    assert not any(
        f['severity'] == 'ok' and 'jail' in f.get('title', '').lower()
        for sec in result['sections'].values() for f in sec.get('findings', [])
    )
