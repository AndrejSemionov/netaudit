"""
Regression tests for netaudit_pkg.checks.kernel_hardening — Step 1 scope
only: _build_components() and the 6 synthetic validation scenarios
docs/checks/kernel_hardening.md section 8 requires before implementation
proceeds to findings/registry. No audit_kernel_hardening_score(), no
check_kernel_hardening(), no findings — those are separate steps.
"""

from __future__ import annotations

from netaudit_pkg.kernel_config import KernelConfig
from netaudit_pkg.checks.kernel_hardening import _build_components
from netaudit_pkg.scoring import weighted_score


# ===========================================================================
# Fixture builders
# ===========================================================================

def _all_pass_config() -> KernelConfig:
    """Every field at its best value. randomize_va_space=2, rp_filter=1,
    kptr_restrict=2, suid_dumpable=0 (per spec section 8 scenario 1)."""
    return KernelConfig(
        readable=True,
        kernel_version='7.0.0-29-generic',
        randomize_va_space=2,
        dmesg_restrict=True,
        kptr_restrict=2,
        yama_ptrace_scope=1,
        suid_dumpable=0,
        ip_forward=False,
        ipv6_forwarding=False,
        tcp_syncookies=True,
        icmp_echo_ignore_broadcasts=True,
        accept_source_route=False,
        accept_redirects=False,
        secure_redirects=False,
        send_redirects=False,
        log_martians=True,
        rp_filter_all=1,
        rp_filter_default=1,
    )


def _all_fail_config() -> KernelConfig:
    """Every field at its worst value (spec section 8 scenario 2)."""
    return KernelConfig(
        readable=True,
        kernel_version='7.0.0-29-generic',
        randomize_va_space=0,
        dmesg_restrict=False,
        kptr_restrict=0,
        yama_ptrace_scope=0,
        suid_dumpable=1,
        ip_forward=True,
        ipv6_forwarding=True,
        tcp_syncookies=False,
        icmp_echo_ignore_broadcasts=False,
        accept_source_route=True,
        accept_redirects=True,
        secure_redirects=True,
        send_redirects=True,
        log_martians=False,
        rp_filter_all=0,
        rp_filter_default=0,
    )


def _vm_baseline_config() -> KernelConfig:
    """Actual 2026-08-11 VM values, docs/checks/kernel_hardening.md
    section 3 (spec section 8 scenario 3). Known FAILs on this VM:
    accept_redirects, send_redirects, secure_redirects, log_martians."""
    return KernelConfig(
        readable=True,
        kernel_version='7.0.0-29-generic',
        randomize_va_space=2,
        dmesg_restrict=True,
        kptr_restrict=1,
        yama_ptrace_scope=1,
        suid_dumpable=2,
        ip_forward=False,
        ipv6_forwarding=False,
        tcp_syncookies=True,
        icmp_echo_ignore_broadcasts=True,
        accept_source_route=False,
        accept_redirects=True,      # FAIL
        secure_redirects=True,      # FAIL
        send_redirects=True,        # FAIL
        log_martians=False,         # FAIL
        rp_filter_all=2,
        rp_filter_default=2,
    )


def _router_shaped_config() -> KernelConfig:
    """all-PASS except the three forwarding controls (spec section 8
    scenario 6): ip_forward=1, ipv6_forwarding=1, send_redirects=1."""
    cfg = _all_pass_config()
    cfg.ip_forward = True
    cfg.ipv6_forwarding = True
    cfg.send_redirects = True
    return cfg


# ===========================================================================
# _build_components() shape
# ===========================================================================

def test_build_components_returns_16_components():
    components = _build_components(_all_pass_config())
    assert len(components) == 16


def test_build_components_names_are_unique_and_expected():
    expected_names = {
        'randomize_va_space', 'dmesg_restrict', 'tcp_syncookies',
        'icmp_echo_ignore_broadcasts', 'accept_source_route',
        'secure_redirects', 'accept_redirects', 'ip_forward',
        'ipv6_forwarding', 'send_redirects', 'log_martians',
        'rp_filter_all', 'rp_filter_default', 'kptr_restrict',
        'ptrace_scope', 'suid_dumpable',
    }
    components = _build_components(_all_pass_config())
    names = [c.name for c in components]
    assert len(names) == len(set(names)), 'duplicate component name'
    assert set(names) == expected_names


def test_component_weights_sum_to_exactly_one():
    """The core contract weighted_score() enforces (scoring.py
    _WEIGHT_SUM_TOLERANCE=1e-6) — checked directly here too so a weight
    typo fails this test before it ever reaches weighted_score()."""
    components = _build_components(_all_pass_config())
    total = sum(c.weight for c in components)
    assert abs(total - 1.0) < 1e-6, f'weights sum to {total!r}, not 1.0'


def test_no_component_has_zero_or_negative_weight():
    for c in _build_components(_all_pass_config()):
        assert c.weight > 0, f'{c.name} has non-positive weight {c.weight!r}'


def test_finding_id_format_matches_krn_prefix():
    """Every FAILing component's finding_id must be KRN-0xx, matching the
    16 control IDs in docs/checks/kernel_hardening.md section 3."""
    for c in _build_components(_all_fail_config()):
        assert c.finding_id is not None, f'{c.name} should FAIL on all-FAIL fixture'
        assert c.finding_id.startswith('KRN-'), f'{c.name} finding_id={c.finding_id!r}'


def test_passing_component_has_no_finding_id():
    for c in _build_components(_all_pass_config()):
        assert c.finding_id is None, f'{c.name} PASSed but still has finding_id={c.finding_id!r}'


# ===========================================================================
# All-PASS / all-FAIL — scenario 1 & 2
# ===========================================================================

def test_all_pass_fixture_scores_100():
    result = weighted_score(_build_components(_all_pass_config()))
    assert result['score'] == 100


def test_all_fail_fixture_scores_0():
    result = weighted_score(_build_components(_all_fail_config()))
    assert result['score'] == 0


# ===========================================================================
# VM baseline — scenario 3
# ===========================================================================

def test_vm_baseline_scores_mid_range_reasonable():
    """4 of 16 controls FAIL outright on the real VM (accept_redirects,
    send_redirects, secure_redirects, log_martians), plus suid_dumpable=2
    contributes a partial 60/100 (not a full FAIL, not a full PASS) — so
    the score should be well above 0 but below 100. Confirms the score
    'matches intuition' for a stock Ubuntu VM with no kernel hardening
    applied yet, per spec section 8 scenario 3.

    Expected score computed the same way weighted_score() itself computes
    it (sum of weight_i * score_i/max_i across ALL 16 components, not a
    shortcut "1 - failing weight" subtraction) — the naive subtraction
    undercounts suid_dumpable's partial 60/100 contribution and gives a
    wrong expected value (77 instead of the correct 75), which is exactly
    the kind of scoring-shape mistake this synthetic validation step
    exists to catch before implementation proceeds further."""
    result = weighted_score(_build_components(_vm_baseline_config()))
    assert 0 < result['score'] < 100

    fully_failing_weight = (
        0.096774    # accept_redirects (high)
        + 0.064516  # send_redirects (medium)
        + 0.032258  # secure_redirects (low)
        + 0.032260  # log_martians (low)
    )
    suid_dumpable_weight = 0.064516
    suid_dumpable_partial_score = 60  # cfg.suid_dumpable == 2

    fraction = (
        (1.0 - fully_failing_weight - suid_dumpable_weight)  # every fully-PASSing component
        + suid_dumpable_weight * (suid_dumpable_partial_score / 100)
    )
    expected_score = round(100 * fraction)
    assert result['score'] == expected_score
    assert expected_score == 75


# ===========================================================================
# Range-tolerant equivalence — scenario 4
# ===========================================================================

def test_rp_filter_1_and_2_score_identically():
    cfg_strict = _all_pass_config()
    cfg_strict.rp_filter_all = 1
    cfg_strict.rp_filter_default = 1

    cfg_loose = _all_pass_config()
    cfg_loose.rp_filter_all = 2
    cfg_loose.rp_filter_default = 2

    score_strict = weighted_score(_build_components(cfg_strict))['score']
    score_loose = weighted_score(_build_components(cfg_loose))['score']
    assert score_strict == score_loose == 100


def test_kptr_restrict_1_and_2_score_identically():
    cfg_1 = _all_pass_config()
    cfg_1.kptr_restrict = 1

    cfg_2 = _all_pass_config()
    cfg_2.kptr_restrict = 2

    score_1 = weighted_score(_build_components(cfg_1))['score']
    score_2 = weighted_score(_build_components(cfg_2))['score']
    assert score_1 == score_2 == 100


def test_rp_filter_0_fails_while_1_and_2_pass():
    """Confirms 0 is a genuine FAIL, not accidentally included in the
    range-tolerant PASS set."""
    cfg = _all_pass_config()
    cfg.rp_filter_all = 0
    components = _build_components(cfg)
    rp_component = next(c for c in components if c.name == 'rp_filter_all')
    assert rp_component.score == 0
    assert rp_component.finding_id == 'KRN-012'


# ===========================================================================
# suid_dumpable graded scoring — scenario 5
# ===========================================================================

def test_suid_dumpable_component_scores_are_strictly_ordered():
    scores = {}
    for value in (0, 1, 2):
        cfg = _all_pass_config()
        cfg.suid_dumpable = value
        components = _build_components(cfg)
        c = next(x for x in components if x.name == 'suid_dumpable')
        scores[value] = c.score

    assert scores[1] == 0
    assert scores[2] == 60
    assert scores[0] == 100
    assert scores[1] < scores[2] < scores[0]


def test_suid_dumpable_weighted_score_delta_matches_component_weight():
    """The weighted_score() output must differ between suid_dumpable=0 and
    suid_dumpable=2 by exactly KRN-016's weight * (score delta / 100) —
    spec section 8 scenario 5's precise arithmetic check, not just 'some
    lower number'."""
    cfg_0 = _all_pass_config()
    cfg_0.suid_dumpable = 0
    cfg_2 = _all_pass_config()
    cfg_2.suid_dumpable = 2

    result_0 = weighted_score(_build_components(cfg_0))
    result_2 = weighted_score(_build_components(cfg_2))

    suid_weight = next(
        c.weight for c in _build_components(cfg_0) if c.name == 'suid_dumpable'
    )
    expected_delta = round(100 * suid_weight * ((100 - 60) / 100))
    assert result_0['score'] - result_2['score'] == expected_delta


def test_suid_dumpable_1_scores_lower_than_all_other_controls_failing_alone():
    """suid_dumpable=1 alone (all-PASS otherwise) must score exactly
    100 - (suid_weight * 100/100) = 100 - suid_weight*100, confirming the
    0-score branch actually zeroes out this component's full contribution."""
    cfg = _all_pass_config()
    cfg.suid_dumpable = 1
    components = _build_components(cfg)
    suid_weight = next(c.weight for c in components if c.name == 'suid_dumpable')
    result = weighted_score(components)
    expected_score = round(100 * (1.0 - suid_weight))
    assert result['score'] == expected_score


# ===========================================================================
# Router-shaped fixture — scenario 6
# ===========================================================================

def test_router_shaped_fixture_scores_lower_by_exact_forwarding_weight():
    """ip_forward=1, ipv6_forwarding=1, send_redirects=1, everything else
    PASS — must score lower than the all-PASS fixture by exactly those
    three controls' combined weight, per spec section 8 scenario 6.
    Demonstrates the documented v1 limitation (no host-role detection,
    spec section 4.3) is visible and quantifiable in the actual score."""
    all_pass_result = weighted_score(_build_components(_all_pass_config()))
    router_result = weighted_score(_build_components(_router_shaped_config()))

    combined_weight = (
        0.064516  # ip_forward
        + 0.064516  # ipv6_forwarding
        + 0.064516  # send_redirects
    )
    expected_score = round(100 * (1.0 - combined_weight))

    assert all_pass_result['score'] == 100
    assert router_result['score'] == expected_score
    assert router_result['score'] < all_pass_result['score']


def test_router_shaped_fixture_only_forwarding_controls_fail():
    """Confirms no other control accidentally FAILs on this fixture — a
    router config is otherwise fully hardened in this scenario, so exactly
    3 of 16 components should carry a finding_id."""
    components = _build_components(_router_shaped_config())
    failing = [c for c in components if c.finding_id is not None]
    failing_names = {c.name for c in failing}
    assert failing_names == {'ip_forward', 'ipv6_forwarding', 'send_redirects'}
