"""Tests for netaudit_pkg.checks.server_security.audit_firewall() - the
semantic layer that turns netaudit_pkg.firewall_config.FirewallEvidence
(raw, uninterpreted evidence) into ACTIVE/INACTIVE/UNKNOWN verdicts and
findings.

This is the regression suite for the quality-audit findings FW-1 (UFW
collection failure previously read as "not installed"), FW-3 (a readable
nftables config file previously counted as proof the firewall is
active), and FW-4 (iptables open-firewall detection previously only
checked rule COUNT, missing an explicit unconditional ACCEPT rule).

Two layers of tests:
  - Unit tests for the pure verdict functions (_ufw_verdict,
    _nftables_verdict, _iptables_verdict, _parse_iptables_input) -
    these take a FirewallEvidence and return (verdict, context) with no
    I/O, so they're tested directly without any SSH mocking.
  - Integration tests for audit_firewall() itself, verifying the actual
    findings (severity, title, requires_manual_verification) it produces
    for each evidence shape - this is what proves the original security
    bugs are actually fixed, not just that evidence is parsed correctly.
"""

from __future__ import annotations

from netaudit_pkg.checks.server_security import (
    _iptables_verdict,
    _nftables_verdict,
    _parse_iptables_input,
    _ufw_verdict,
    audit_firewall,
)
from netaudit_pkg.firewall_config import CommandResult, FileResult, FirewallEvidence
from tests.conftest import ExitCodeFakeSSHExecutor

# ===========================================================================
# Evidence-building helpers
# ===========================================================================

def _cr(completed=True, exit_code=0, stdout='', command='') -> CommandResult:
    return CommandResult(completed=completed, exit_code=exit_code, stdout=stdout, command=command)


def _fr(completed=True, exit_code=0, content='', path='/etc/nftables.conf') -> FileResult:
    return FileResult(completed=completed, exit_code=exit_code, content=content, path=path)


def _evidence(
    ufw_present=None, ufw_status=None,
    nftables_live=None, nftables_config=None,
    iptables_live=None,
) -> FirewallEvidence:
    """Builds a FirewallEvidence with sensible defaults (ufw not present,
    nftables/iptables collection failed) - tests override only the
    field(s) relevant to what they're checking."""
    return FirewallEvidence(
        ufw_present=ufw_present if ufw_present is not None else _cr(exit_code=127),
        ufw_status=ufw_status,
        nftables_live=nftables_live if nftables_live is not None else _cr(completed=False, exit_code=None),
        nftables_config=nftables_config if nftables_config is not None else _fr(completed=False, exit_code=None, content=''),
        iptables_live=iptables_live if iptables_live is not None else _cr(completed=False, exit_code=None),
    )


# ===========================================================================
# _ufw_verdict — unit tests
# ===========================================================================

def test_ufw_verdict_not_present():
    ev = _evidence(ufw_present=_cr(exit_code=127))
    verdict, _ = _ufw_verdict(ev)
    assert verdict == 'NOT_PRESENT'


def test_ufw_verdict_active():
    ev = _evidence(
        ufw_present=_cr(exit_code=0, stdout='/usr/sbin/ufw'),
        ufw_status=_cr(exit_code=0, stdout='Status: active'),
    )
    verdict, _ = _ufw_verdict(ev)
    assert verdict == 'ACTIVE'


def test_ufw_verdict_inactive():
    ev = _evidence(
        ufw_present=_cr(exit_code=0, stdout='/usr/sbin/ufw'),
        ufw_status=_cr(exit_code=0, stdout='Status: inactive'),
    )
    verdict, _ = _ufw_verdict(ev)
    assert verdict == 'INACTIVE'


def test_ufw_verdict_unknown_on_presence_collection_failure():
    """Regression test for FW-1: presence check itself couldn't be
    confirmed - must be UNKNOWN, never silently treated as absent."""
    ev = _evidence(ufw_present=_cr(completed=False, exit_code=None))
    verdict, ctx = _ufw_verdict(ev)
    assert verdict == 'UNKNOWN'
    assert 'reason' in ctx


def test_ufw_verdict_unknown_on_status_sudo_failure():
    """Regression test for FW-1: ufw IS present, but `ufw status` itself
    failed (e.g. sudo auth failure) - must be UNKNOWN, not silently
    absent and not 'ok'."""
    ev = _evidence(
        ufw_present=_cr(exit_code=0, stdout='/usr/sbin/ufw'),
        ufw_status=_cr(exit_code=1, stdout='sudo: a password is required'),
    )
    verdict, ctx = _ufw_verdict(ev)
    assert verdict == 'UNKNOWN'
    assert '1' in ctx['reason']


def test_ufw_verdict_unknown_on_status_collection_failure():
    ev = _evidence(
        ufw_present=_cr(exit_code=0, stdout='/usr/sbin/ufw'),
        ufw_status=_cr(completed=False, exit_code=None),
    )
    verdict, _ = _ufw_verdict(ev)
    assert verdict == 'UNKNOWN'


def test_ufw_verdict_unknown_on_unrecognized_output():
    ev = _evidence(
        ufw_present=_cr(exit_code=0, stdout='/usr/sbin/ufw'),
        ufw_status=_cr(exit_code=0, stdout='some unexpected format'),
    )
    verdict, _ = _ufw_verdict(ev)
    assert verdict == 'UNKNOWN'


# ===========================================================================
# _nftables_verdict — unit tests
# ===========================================================================

def test_nftables_verdict_live_active_ignores_config():
    """Live ruleset confirms rules are loaded - ACTIVE, regardless of
    what the config file says (or whether it's even readable)."""
    ev = _evidence(
        nftables_live=_cr(exit_code=0, stdout='table inet filter {\n  chain input {\n  }\n}'),
        nftables_config=_fr(completed=False, exit_code=None, content=''),
    )
    verdict, _ = _nftables_verdict(ev)
    assert verdict == 'LIVE_ACTIVE'


def test_nftables_verdict_config_alone_never_yields_active():
    """Regression test for FW-3, the core bug: a readable, non-empty
    config file with NO live confirmation must NOT produce LIVE_ACTIVE."""
    ev = _evidence(
        nftables_live=_cr(completed=False, exit_code=None),
        nftables_config=_fr(exit_code=0, content='table inet filter {\n  chain input {\n  }\n}'),
    )
    verdict, ctx = _nftables_verdict(ev)
    assert verdict != 'LIVE_ACTIVE'
    assert verdict == 'LIVE_UNKNOWN'
    assert ctx['config_readable'] is True


def test_nftables_verdict_live_empty_confirmed():
    """A confirmed empty live ruleset (exit 0, empty stdout) with no
    config file - a real, confirmed fact, not a collection failure."""
    ev = _evidence(
        nftables_live=_cr(exit_code=0, stdout=''),
        nftables_config=_fr(completed=False, exit_code=None, content=''),
    )
    verdict, ctx = _nftables_verdict(ev)
    assert verdict == 'LIVE_EMPTY'
    assert ctx['config_readable'] is False


def test_nftables_verdict_live_empty_but_config_has_rules():
    """The declared-vs-loaded discrepancy: live kernel ruleset is
    confirmed empty, but the config file has rules - config_readable
    context must be True so the caller can build the stronger
    'config exists but isn't loaded' finding, without upgrading the
    verdict itself to anything ACTIVE-shaped."""
    ev = _evidence(
        nftables_live=_cr(exit_code=0, stdout=''),
        nftables_config=_fr(exit_code=0, content='table inet filter {\n  chain input {\n  }\n}',
                             path='/etc/nftables.conf'),
    )
    verdict, ctx = _nftables_verdict(ev)
    assert verdict == 'LIVE_EMPTY'
    assert ctx['config_readable'] is True
    assert ctx['config_path'] == '/etc/nftables.conf'
    assert ctx['config_rule_lines'] > 0


def test_nftables_verdict_live_unknown_permission_denied():
    """Regression test: nft list ruleset fails (permission denied,
    confirmed nonzero exit) - must be LIVE_UNKNOWN, never conflated with
    LIVE_EMPTY (which requires a CONFIRMED empty result, exit 0)."""
    ev = _evidence(nftables_live=_cr(exit_code=1, stdout=''))
    verdict, _ = _nftables_verdict(ev)
    assert verdict == 'LIVE_UNKNOWN'


def test_nftables_verdict_live_unknown_collection_failure():
    ev = _evidence(nftables_live=_cr(completed=False, exit_code=None))
    verdict, _ = _nftables_verdict(ev)
    assert verdict == 'LIVE_UNKNOWN'


# ===========================================================================
# _parse_iptables_input — unit tests
# ===========================================================================

def test_parse_iptables_input_policy_and_rules():
    stdout = (
        '-P INPUT DROP\n'
        '-P FORWARD DROP\n'
        '-P OUTPUT ACCEPT\n'
        '-A INPUT -p tcp --dport 22 -j ACCEPT\n'
        '-A INPUT -p tcp --dport 443 -j ACCEPT\n'
    )
    policy, rules = _parse_iptables_input(stdout)
    assert policy == 'DROP'
    assert len(rules) == 2


def test_parse_iptables_input_no_policy_line():
    policy, rules = _parse_iptables_input('some garbage output')
    assert policy is None
    assert rules == []


def test_parse_iptables_input_ignores_forward_and_output_rules():
    stdout = (
        '-P INPUT ACCEPT\n'
        '-A FORWARD -j DROP\n'
        '-A OUTPUT -j ACCEPT\n'
    )
    policy, rules = _parse_iptables_input(stdout)
    assert policy == 'ACCEPT'
    assert rules == []


# ===========================================================================
# _iptables_verdict — unit tests, including the FW-4 regression
# ===========================================================================

def test_iptables_verdict_open_accept_policy_zero_rules():
    ev = _evidence(iptables_live=_cr(exit_code=0, stdout='-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT'))
    verdict, ctx = _iptables_verdict(ev)
    assert verdict == 'OPEN'
    assert ctx['unconditional_accept'] is False
    assert ctx['rule_count'] == 0


def test_iptables_verdict_open_unconditional_accept_rule():
    """Regression test for FW-4, the core bug: INPUT policy ACCEPT WITH
    an explicit unconditional '-A INPUT -j ACCEPT' rule - the old code
    only checked `ipt.count('-A INPUT') == 0`, which missed this exact
    case (nonzero rule count, but the rule itself accepts everything)."""
    stdout = '-P INPUT ACCEPT\n-A INPUT -j ACCEPT\n'
    ev = _evidence(iptables_live=_cr(exit_code=0, stdout=stdout))
    verdict, ctx = _iptables_verdict(ev)
    assert verdict == 'OPEN'
    assert ctx['unconditional_accept'] is True
    assert ctx['rule_count'] == 1


def test_iptables_verdict_filtered_accept_policy_conditional_rules():
    """ACCEPT policy is fine when every rule is match-qualified (the
    common, safe pattern: default ACCEPT is backstopped by specific
    ACCEPT rules plus, typically, a final DROP - though this function
    only looks at INPUT here)."""
    stdout = '-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j DROP\n'
    ev = _evidence(iptables_live=_cr(exit_code=0, stdout=stdout))
    verdict, _ = _iptables_verdict(ev)
    assert verdict == 'FILTERED'


def test_iptables_verdict_filtered_drop_policy():
    stdout = '-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n'
    ev = _evidence(iptables_live=_cr(exit_code=0, stdout=stdout))
    verdict, _ = _iptables_verdict(ev)
    assert verdict == 'FILTERED'


def test_iptables_verdict_unknown_permission_denied():
    ev = _evidence(iptables_live=_cr(exit_code=1, stdout=''))
    verdict, _ = _iptables_verdict(ev)
    assert verdict == 'UNKNOWN'


def test_iptables_verdict_unknown_collection_failure():
    ev = _evidence(iptables_live=_cr(completed=False, exit_code=None))
    verdict, _ = _iptables_verdict(ev)
    assert verdict == 'UNKNOWN'


def test_iptables_verdict_unknown_no_policy_line_found():
    ev = _evidence(iptables_live=_cr(exit_code=0, stdout='garbage, no policy line'))
    verdict, _ = _iptables_verdict(ev)
    assert verdict == 'UNKNOWN'


# ===========================================================================
# audit_firewall() — integration tests: findings actually produced,
# using ExitCodeFakeSSHExecutor to drive the real collect_firewall_config()
# ===========================================================================

def test_audit_firewall_ufw_installed_disabled_gives_high():
    """Regression test: UFW installed and confirmed inactive must
    produce a HIGH finding, unconditionally (not suppressed if another
    backend happens to be active)."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v ufw': '/usr/sbin/ufw',
            'ufw status': 'Status: inactive',
            'nft list ruleset': '',
            'iptables -S': '-P INPUT DROP',
        },
        exit_codes={
            'command -v ufw': 0, 'ufw status': 0,
            'nft list ruleset': 0, 'iptables -S': 0,
        },
    )
    result = audit_firewall(fake)
    ufw_findings = [f for f in result['findings'] if 'ufw' in f['title'].lower()]
    assert any(f['severity'] == 'high' and 'disabled' in f['title'] for f in ufw_findings)


def test_audit_firewall_ufw_collection_failure_is_unknown_not_absent():
    """Regression test for FW-1: the exact original bug - `ufw status`
    fails (simulating no-root), must produce a low/UNKNOWN finding with
    requires_manual_verification, NOT silence UFW as if not installed."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v ufw': '/usr/sbin/ufw',
            'ufw status': 'sudo: a password is required',
            'nft list ruleset': '',
            'iptables -S': '-P INPUT DROP',
        },
        exit_codes={
            'command -v ufw': 0, 'ufw status': 1,
            'nft list ruleset': 0, 'iptables -S': 0,
        },
    )
    result = audit_firewall(fake)
    ufw_findings = [f for f in result['findings'] if 'ufw' in f['title'].lower()]
    assert len(ufw_findings) == 1
    assert ufw_findings[0]['severity'] == 'low'
    assert ufw_findings[0].get('requires_manual_verification') is True
    assert 'active' not in ufw_findings[0]['title'].lower() or 'not' in ufw_findings[0]['title'].lower()


def test_audit_firewall_nftables_config_present_live_unknown_not_ok():
    """Regression test for FW-3, the core bug: a readable nftables config
    file with NO live confirmation must NOT produce an 'ok' finding."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v ufw': '',
            'nft list ruleset': '',
            'cat /etc/nftables.conf': 'table inet filter {\n  chain input {\n  }\n}',
            'iptables -S': '-P INPUT DROP',
        },
        exit_codes={
            'command -v ufw': 127,
            # nft list ruleset: no exit code registered -> collection failure
            'cat /etc/nftables.conf': 0,
            'iptables -S': 0,
        },
    )
    result = audit_firewall(fake)
    nft_findings = [f for f in result['findings'] if 'nftables' in f['title'].lower()]
    assert len(nft_findings) == 1
    assert nft_findings[0]['severity'] != 'ok'
    assert nft_findings[0].get('requires_manual_verification') is True


def test_audit_firewall_nftables_config_present_live_confirmed_empty_gives_high():
    """Regression test for the declared-vs-loaded discrepancy: live
    ruleset CONFIRMED empty (exit 0), but config file has rules - a real
    mismatch, HIGH severity, not silently 'ok'."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v ufw': '',
            'nft list ruleset': '',
            'cat /etc/nftables.conf': 'table inet filter {\n  chain input {\n  }\n}',
            'iptables -S': '-P INPUT DROP',
        },
        exit_codes={
            'command -v ufw': 127,
            'nft list ruleset': 0,  # CONFIRMED empty, not a collection failure
            'cat /etc/nftables.conf': 0,
            'iptables -S': 0,
        },
    )
    result = audit_firewall(fake)
    nft_findings = [f for f in result['findings'] if 'nftables' in f['title'].lower()]
    assert len(nft_findings) == 1
    assert nft_findings[0]['severity'] == 'high'
    assert nft_findings[0].get('requires_manual_verification') is True
    assert 'empty' in nft_findings[0]['title'].lower()


def test_audit_firewall_iptables_unconditional_accept_gives_high():
    """Regression test for FW-4: the exact original bug - iptables with
    an explicit unconditional ACCEPT rule (nonzero rule count) must be
    flagged HIGH, not read as 'rules are present' == ok."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v ufw': '',
            'nft list ruleset': '',
            'iptables -S': '-P INPUT ACCEPT\n-A INPUT -j ACCEPT',
        },
        exit_codes={
            'command -v ufw': 127,
            'nft list ruleset': 0,
            'iptables -S': 0,
        },
    )
    result = audit_firewall(fake)
    ipt_findings = [f for f in result['findings'] if 'iptables' in f['title'].lower()]
    assert len(ipt_findings) == 1
    assert ipt_findings[0]['severity'] == 'high'
    assert 'open' in ipt_findings[0]['title'].lower()


def test_audit_firewall_iptables_permission_failure_gives_unknown():
    """Regression test: iptables -S fails (permission denied) - must be
    low/UNKNOWN, not silently 'ok' via the old NOIPT-never-triggers bug."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v ufw': '',
            'nft list ruleset': '',
            'iptables -S': '',
        },
        exit_codes={
            'command -v ufw': 127,
            'nft list ruleset': 0,
            'iptables -S': 1,
        },
    )
    result = audit_firewall(fake)
    ipt_findings = [f for f in result['findings'] if 'iptables' in f['title'].lower()]
    assert len(ipt_findings) == 1
    assert ipt_findings[0]['severity'] == 'low'
    assert ipt_findings[0].get('requires_manual_verification') is True


def test_audit_firewall_multiple_backends_do_not_suppress_each_other():
    """Regression test: nftables ACTIVE (ok) must NOT suppress a
    simultaneously-open iptables chain or a disabled UFW - all three
    facts must be visible as independent findings, no aggregate verdict
    that lets one 'good' backend hide problems in another."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v ufw': '/usr/sbin/ufw',
            'ufw status': 'Status: inactive',
            'nft list ruleset': 'table inet filter {\n  chain input {\n  }\n}',
            'iptables -S': '-P INPUT ACCEPT\n-A INPUT -j ACCEPT',
        },
        exit_codes={
            'command -v ufw': 0, 'ufw status': 0,
            'nft list ruleset': 0, 'iptables -S': 0,
        },
    )
    result = audit_firewall(fake)
    severities_by_backend = {}
    for f in result['findings']:
        title_lower = f['title'].lower()
        if 'ufw' in title_lower:
            severities_by_backend['ufw'] = f['severity']
        elif 'nftables' in title_lower:
            severities_by_backend['nftables'] = f['severity']
        elif 'iptables' in title_lower:
            severities_by_backend['iptables'] = f['severity']

    assert severities_by_backend['ufw'] == 'high'       # disabled
    assert severities_by_backend['nftables'] == 'ok'    # genuinely active
    assert severities_by_backend['iptables'] == 'high'  # open despite nftables being fine
    # exactly 3 findings - one per backend, no aggregate/suppressed 4th
    assert len(result['findings']) == 3


def test_audit_firewall_ufw_not_present_produces_no_ufw_finding():
    """ufw genuinely absent (confirmed via command -v exit 127) produces
    NO finding at all for ufw - this is not an error state, just a fact
    about this host's setup."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v ufw': '',
            'nft list ruleset': 'table inet filter { }',
            'iptables -S': '-P INPUT DROP',
        },
        exit_codes={
            'command -v ufw': 127,
            'nft list ruleset': 0,
            'iptables -S': 0,
        },
    )
    result = audit_firewall(fake)
    ufw_findings = [f for f in result['findings'] if 'ufw' in f['title'].lower()]
    assert ufw_findings == []
