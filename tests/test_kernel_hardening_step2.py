"""
Regression tests for netaudit_pkg.checks.kernel_hardening — Step 2 scope:
_build_findings(). Builds on Step 1's fixtures (all-PASS / all-FAIL /
VM-baseline) and adds coverage specific to findings: correct id/severity
per control, no finding on PASS, and the suid_dumpable three-way branch.
"""

from __future__ import annotations

from netaudit_pkg.kernel_config import KernelConfig
from netaudit_pkg.checks.kernel_hardening import _build_components, _build_findings


def _all_pass_config() -> KernelConfig:
    return KernelConfig(
        readable=True, kernel_version='7.0.0-29-generic',
        randomize_va_space=2, dmesg_restrict=True, kptr_restrict=2,
        yama_ptrace_scope=1, suid_dumpable=0, ip_forward=False,
        ipv6_forwarding=False, tcp_syncookies=True,
        icmp_echo_ignore_broadcasts=True, accept_source_route=False,
        accept_redirects=False, secure_redirects=False, send_redirects=False,
        log_martians=True, rp_filter_all=1, rp_filter_default=1,
    )


def _all_fail_config() -> KernelConfig:
    return KernelConfig(
        readable=True, kernel_version='7.0.0-29-generic',
        randomize_va_space=0, dmesg_restrict=False, kptr_restrict=0,
        yama_ptrace_scope=0, suid_dumpable=1, ip_forward=True,
        ipv6_forwarding=True, tcp_syncookies=False,
        icmp_echo_ignore_broadcasts=False, accept_source_route=True,
        accept_redirects=True, secure_redirects=True, send_redirects=True,
        log_martians=False, rp_filter_all=0, rp_filter_default=0,
    )


# ===========================================================================
# No findings on all-PASS
# ===========================================================================

def test_all_pass_produces_zero_findings():
    findings = _build_findings(_all_pass_config())
    assert findings == []


# ===========================================================================
# All-FAIL produces exactly 16 findings, one per control
# ===========================================================================

def test_all_fail_produces_16_findings():
    findings = _build_findings(_all_fail_config())
    assert len(findings) == 16


def test_all_fail_finding_ids_match_krn_001_through_016():
    findings = _build_findings(_all_fail_config())
    ids = {f['id'] for f in findings}
    expected = {f'KRN-{i:03d}' for i in range(1, 17)}
    assert ids == expected


def test_all_fail_findings_have_no_duplicate_ids():
    findings = _build_findings(_all_fail_config())
    ids = [f['id'] for f in findings]
    assert len(ids) == len(set(ids))


# ===========================================================================
# Every finding_id on a FAILing Component has a matching Finding, and
# vice versa — the link the spec's section 7 requires.
# ===========================================================================

def test_every_failing_component_finding_id_has_a_matching_finding():
    cfg = _all_fail_config()
    components = _build_components(cfg)
    findings = _build_findings(cfg)
    finding_ids = {f['id'] for f in findings}

    for c in components:
        if c.finding_id is not None:
            assert c.finding_id in finding_ids, (
                f'{c.name} references finding_id={c.finding_id!r} '
                f'but no such finding was generated'
            )


def test_every_finding_id_has_a_matching_failing_component():
    cfg = _all_fail_config()
    components = _build_components(cfg)
    findings = _build_findings(cfg)
    component_finding_ids = {c.finding_id for c in components if c.finding_id}

    for f in findings:
        assert f['id'] in component_finding_ids, (
            f"finding id={f['id']!r} has no matching Component.finding_id"
        )


# ===========================================================================
# Individual control findings — severity and presence, spot-checked
# against the spec's section 3 severity table
# ===========================================================================

def test_high_severity_findings_on_all_fail():
    findings = {f['id']: f for f in _build_findings(_all_fail_config())}
    for krn_id in ('KRN-001', 'KRN-003', 'KRN-005', 'KRN-007'):
        assert findings[krn_id]['severity'] == 'high', krn_id


def test_medium_severity_findings_on_all_fail():
    findings = {f['id']: f for f in _build_findings(_all_fail_config())}
    for krn_id in ('KRN-002', 'KRN-008', 'KRN-009', 'KRN-010', 'KRN-012',
                   'KRN-014', 'KRN-016'):
        assert findings[krn_id]['severity'] == 'medium', krn_id


def test_low_severity_findings_on_all_fail():
    findings = {f['id']: f for f in _build_findings(_all_fail_config())}
    for krn_id in ('KRN-004', 'KRN-006', 'KRN-011', 'KRN-013', 'KRN-015'):
        assert findings[krn_id]['severity'] == 'low', krn_id


# ===========================================================================
# rp_filter / kptr_restrict range-tolerance — no finding for value 1 or 2
# ===========================================================================

def test_rp_filter_1_produces_no_finding():
    cfg = _all_pass_config()
    cfg.rp_filter_all = 1
    cfg.rp_filter_default = 1
    findings = _build_findings(cfg)
    assert not any(f['id'] in ('KRN-012', 'KRN-013') for f in findings)


def test_rp_filter_2_produces_no_finding():
    cfg = _all_pass_config()
    cfg.rp_filter_all = 2
    cfg.rp_filter_default = 2
    findings = _build_findings(cfg)
    assert not any(f['id'] in ('KRN-012', 'KRN-013') for f in findings)


def test_rp_filter_0_produces_a_finding_stating_the_actual_value():
    """Spec section 4.1: the finding text must state the actual observed
    value, not a bare 'FAIL'."""
    cfg = _all_pass_config()
    cfg.rp_filter_all = 0
    findings = {f['id']: f for f in _build_findings(cfg)}
    assert 'KRN-012' in findings
    assert '0' in findings['KRN-012']['detail']


def test_kptr_restrict_1_and_2_produce_no_finding():
    for value in (1, 2):
        cfg = _all_pass_config()
        cfg.kptr_restrict = value
        findings = _build_findings(cfg)
        assert not any(f['id'] == 'KRN-014' for f in findings), value


def test_ptrace_scope_1_2_3_all_produce_no_finding():
    for value in (1, 2, 3):
        cfg = _all_pass_config()
        cfg.yama_ptrace_scope = value
        findings = _build_findings(cfg)
        assert not any(f['id'] == 'KRN-015' for f in findings), value


# ===========================================================================
# suid_dumpable — the three-way branch (spec section 4.4)
# ===========================================================================

def test_suid_dumpable_0_produces_no_finding():
    cfg = _all_pass_config()
    cfg.suid_dumpable = 0
    findings = _build_findings(cfg)
    assert not any(f['id'] == 'KRN-016' for f in findings)


def test_suid_dumpable_1_and_2_both_produce_a_krn_016_finding():
    """Both non-zero values FAIL/partial-score, so both must produce a
    finding — but with different text (checked below), not just presence."""
    for value in (1, 2):
        cfg = _all_pass_config()
        cfg.suid_dumpable = value
        findings = {f['id']: f for f in _build_findings(cfg)}
        assert 'KRN-016' in findings, value


def test_suid_dumpable_1_and_2_produce_different_finding_text():
    """The core assertion for the graded control: value 1 (insecure,
    world-readable) and value 2 (suidsafe, root-only) must not share the
    same finding title/detail — collapsing them to identical text would
    be exactly the misreporting spec section 4.4 warns against."""
    cfg_1 = _all_pass_config()
    cfg_1.suid_dumpable = 1
    cfg_2 = _all_pass_config()
    cfg_2.suid_dumpable = 2

    finding_1 = next(f for f in _build_findings(cfg_1) if f['id'] == 'KRN-016')
    finding_2 = next(f for f in _build_findings(cfg_2) if f['id'] == 'KRN-016')

    assert finding_1['title'] != finding_2['title']
    assert finding_1['detail'] != finding_2['detail']


def test_suid_dumpable_1_finding_mentions_world_readable_leak():
    cfg = _all_pass_config()
    cfg.suid_dumpable = 1
    finding = next(f for f in _build_findings(cfg) if f['id'] == 'KRN-016')
    assert 'readable' in finding['detail'].lower()


def test_suid_dumpable_2_finding_mentions_no_leak():
    cfg = _all_pass_config()
    cfg.suid_dumpable = 2
    finding = next(f for f in _build_findings(cfg) if f['id'] == 'KRN-016')
    assert 'no cross-user' in finding['detail'].lower() or 'leak' in finding['detail'].lower()


def test_suid_dumpable_2_finding_severity_is_medium_not_high():
    """Even though 2 produces a finding, it should not carry the same
    weight-of-concern as 1 in its text — both happen to share severity
    'medium' per the spec (severity isn't graded, only the score is), but
    this test locks that in explicitly so a future edit doesn't
    accidentally bump 2's severity above 1's or vice versa without
    noticing the spec doesn't distinguish them by severity."""
    cfg_1 = _all_pass_config()
    cfg_1.suid_dumpable = 1
    cfg_2 = _all_pass_config()
    cfg_2.suid_dumpable = 2

    finding_1 = next(f for f in _build_findings(cfg_1) if f['id'] == 'KRN-016')
    finding_2 = next(f for f in _build_findings(cfg_2) if f['id'] == 'KRN-016')

    assert finding_1['severity'] == 'medium'
    assert finding_2['severity'] == 'medium'


# ===========================================================================
# ip_forward / ipv6_forwarding / send_redirects — finding text documents
# the v1 host-role limitation, per spec section 4.3
# ===========================================================================

def test_forwarding_findings_mention_no_router_auto_detection():
    """A router/NAT host will legitimately see these findings — the text
    should say so, so a reader isn't confused about whether this is a bug."""
    cfg = _all_pass_config()
    cfg.ip_forward = True
    cfg.ipv6_forwarding = True
    cfg.send_redirects = True
    findings = {f['id']: f for f in _build_findings(cfg)}

    for krn_id in ('KRN-008', 'KRN-009', 'KRN-010'):
        detail_lower = findings[krn_id]['detail'].lower()
        assert 'router' in detail_lower or 'auto-detect' in detail_lower, krn_id
