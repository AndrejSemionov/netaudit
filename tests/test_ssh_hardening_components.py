"""
Pure-function tests for netaudit_pkg.checks.ssh_hardening._build_components() -
no SSH mock needed, same pattern as test_nginx_hardening_components.py. Covers
each of the 14 Tier-1 controls' PASS/FAIL/N/A logic individually, then the 13
synthetic regression scenarios from docs/checks/ssh_hardening.md section 8.3,
run through the real weighted_score() to pin the exact final scores.
"""

from __future__ import annotations

import pytest

from netaudit_pkg.ssh_config import SSHConfig
from netaudit_pkg.checks.ssh_hardening import _build_components
from netaudit_pkg.scoring import weighted_score


def _cfg(**kwargs) -> SSHConfig:
    """SSHConfig with fully-hardened defaults, overridable per test - keeps
    each test focused on the one field it's actually exercising."""
    defaults = dict(
        readable=True,
        permit_root_login='no',
        password_authentication=False,
        permit_empty_passwords=False,
        pubkey_authentication=True,
        kbd_interactive_authentication=False,
        hostbased_authentication=False,
        max_auth_tries=4,
        login_grace_time=60,
        x11_forwarding=False,
        allow_tcp_forwarding='no',
        allow_agent_forwarding=False,
        ciphers=['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes256-ctr'],
        macs=['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com'],
        kex_algorithms=['curve25519-sha256', 'ecdh-sha2-nistp256'],
    )
    defaults.update(kwargs)
    return SSHConfig(**defaults)


def _by_name(components, name):
    return next(c for c in components if c.name == name)


# ===========================================================================
# SSH-AUTH-001 - permit_root_login (revised semantics, see ssh_hardening.py
# module docstring and docs/checks/ssh_hardening.md section 6.1)
# ===========================================================================

@pytest.mark.parametrize('value', ['no', 'prohibit-password', 'without-password', 'forced-commands-only'])
def test_permit_root_login_pass_values(value):
    c = _by_name(_build_components(_cfg(permit_root_login=value)), 'permit_root_login')
    assert c.score == 100 and c.finding_id is None


def test_permit_root_login_fail_on_yes():
    c = _by_name(_build_components(_cfg(permit_root_login='yes')), 'permit_root_login')
    assert c.score == 0 and c.finding_id == 'SSH-AUTH-001'


def test_permit_root_login_fail_on_none():
    # defensive: readable=True but the directive somehow didn't resolve
    c = _by_name(_build_components(_cfg(permit_root_login=None)), 'permit_root_login')
    assert c.score == 0 and c.finding_id == 'SSH-AUTH-001'


def test_permit_root_login_never_na():
    c = _by_name(_build_components(_cfg(permit_root_login='yes')), 'permit_root_login')
    assert c.applicable is True


def test_permit_root_login_weight():
    c = _by_name(_build_components(_cfg()), 'permit_root_login')
    assert c.weight == 0.0900


# ===========================================================================
# SSH-AUTH-002 - password_authentication
# ===========================================================================

def test_password_authentication_pass_when_false():
    c = _by_name(_build_components(_cfg(password_authentication=False)), 'password_authentication')
    assert c.score == 100 and c.finding_id is None


def test_password_authentication_fail_when_true():
    c = _by_name(_build_components(_cfg(password_authentication=True)), 'password_authentication')
    assert c.score == 0 and c.finding_id == 'SSH-AUTH-002'


def test_password_authentication_fail_when_none():
    c = _by_name(_build_components(_cfg(password_authentication=None)), 'password_authentication')
    assert c.score == 0 and c.finding_id == 'SSH-AUTH-002'


def test_password_authentication_weight():
    c = _by_name(_build_components(_cfg()), 'password_authentication')
    assert c.weight == 0.0600


# ===========================================================================
# SSH-AUTH-003 - permit_empty_passwords (critical severity)
# ===========================================================================

def test_permit_empty_passwords_pass_when_false():
    c = _by_name(_build_components(_cfg(permit_empty_passwords=False)), 'permit_empty_passwords')
    assert c.score == 100 and c.finding_id is None


def test_permit_empty_passwords_fail_when_true():
    c = _by_name(_build_components(_cfg(permit_empty_passwords=True)), 'permit_empty_passwords')
    assert c.score == 0 and c.finding_id == 'SSH-AUTH-003'


def test_permit_empty_passwords_weight_is_highest_in_catalogue():
    # critical severity - highest single-control weight of all 14
    c = _by_name(_build_components(_cfg()), 'permit_empty_passwords')
    assert c.weight == 0.1200
    all_weights = [comp.weight for comp in _build_components(_cfg())]
    assert c.weight == max(all_weights)


# ===========================================================================
# SSH-AUTH-004 - pubkey_authentication (PASS is True, inverted polarity)
# ===========================================================================

def test_pubkey_authentication_pass_when_true():
    c = _by_name(_build_components(_cfg(pubkey_authentication=True)), 'pubkey_authentication')
    assert c.score == 100 and c.finding_id is None


def test_pubkey_authentication_fail_when_false():
    c = _by_name(_build_components(_cfg(pubkey_authentication=False)), 'pubkey_authentication')
    assert c.score == 0 and c.finding_id == 'SSH-AUTH-004'


def test_pubkey_authentication_weight():
    c = _by_name(_build_components(_cfg()), 'pubkey_authentication')
    assert c.weight == 0.0900


# ===========================================================================
# SSH-AUTH-005 - kbd_interactive_authentication
# ===========================================================================

def test_kbd_interactive_pass_when_false():
    c = _by_name(_build_components(_cfg(kbd_interactive_authentication=False)),
                  'kbd_interactive_authentication')
    assert c.score == 100 and c.finding_id is None


def test_kbd_interactive_fail_when_true():
    c = _by_name(_build_components(_cfg(kbd_interactive_authentication=True)),
                  'kbd_interactive_authentication')
    assert c.score == 0 and c.finding_id == 'SSH-AUTH-005'


def test_kbd_interactive_weight():
    c = _by_name(_build_components(_cfg()), 'kbd_interactive_authentication')
    assert c.weight == 0.0600


# ===========================================================================
# SSH-AUTH-006 - hostbased_authentication
# ===========================================================================

def test_hostbased_pass_when_false():
    c = _by_name(_build_components(_cfg(hostbased_authentication=False)), 'hostbased_authentication')
    assert c.score == 100 and c.finding_id is None


def test_hostbased_fail_when_true():
    c = _by_name(_build_components(_cfg(hostbased_authentication=True)), 'hostbased_authentication')
    assert c.score == 0 and c.finding_id == 'SSH-AUTH-006'


def test_hostbased_weight():
    c = _by_name(_build_components(_cfg()), 'hostbased_authentication')
    assert c.weight == 0.0300


# ===========================================================================
# SSH-AUTH-007 - max_auth_tries (threshold-based)
# ===========================================================================

@pytest.mark.parametrize('value', [1, 2, 3, 4])
def test_max_auth_tries_pass_at_or_below_threshold(value):
    c = _by_name(_build_components(_cfg(max_auth_tries=value)), 'max_auth_tries')
    assert c.score == 100 and c.finding_id is None


@pytest.mark.parametrize('value', [5, 6, 10])
def test_max_auth_tries_fail_above_threshold(value):
    c = _by_name(_build_components(_cfg(max_auth_tries=value)), 'max_auth_tries')
    assert c.score == 0 and c.finding_id == 'SSH-AUTH-007'


def test_max_auth_tries_fail_when_none():
    c = _by_name(_build_components(_cfg(max_auth_tries=None)), 'max_auth_tries')
    assert c.score == 0 and c.finding_id == 'SSH-AUTH-007'


def test_max_auth_tries_weight():
    c = _by_name(_build_components(_cfg()), 'max_auth_tries')
    assert c.weight == 0.0500


# ===========================================================================
# SSH-AUTH-008 - login_grace_time (threshold-based)
# ===========================================================================

@pytest.mark.parametrize('value', [1, 30, 60])
def test_login_grace_time_pass_at_or_below_threshold(value):
    c = _by_name(_build_components(_cfg(login_grace_time=value)), 'login_grace_time')
    assert c.score == 100 and c.finding_id is None


@pytest.mark.parametrize('value', [61, 120, 300])
def test_login_grace_time_fail_above_threshold(value):
    c = _by_name(_build_components(_cfg(login_grace_time=value)), 'login_grace_time')
    assert c.score == 0 and c.finding_id == 'SSH-AUTH-008'


def test_login_grace_time_weight():
    c = _by_name(_build_components(_cfg()), 'login_grace_time')
    assert c.weight == 0.0500


# ===========================================================================
# SSH-FWD-001 - x11_forwarding
# ===========================================================================

def test_x11_forwarding_pass_when_false():
    c = _by_name(_build_components(_cfg(x11_forwarding=False)), 'x11_forwarding')
    assert c.score == 100 and c.finding_id is None


def test_x11_forwarding_fail_when_true():
    c = _by_name(_build_components(_cfg(x11_forwarding=True)), 'x11_forwarding')
    assert c.score == 0 and c.finding_id == 'SSH-FWD-001'


def test_x11_forwarding_weight():
    c = _by_name(_build_components(_cfg()), 'x11_forwarding')
    assert c.weight == 0.0400


# ===========================================================================
# SSH-FWD-002 - allow_tcp_forwarding (strict 'no' only, 'local'/'remote' FAIL too)
# ===========================================================================

def test_allow_tcp_forwarding_pass_when_no():
    c = _by_name(_build_components(_cfg(allow_tcp_forwarding='no')), 'allow_tcp_forwarding')
    assert c.score == 100 and c.finding_id is None


def test_allow_tcp_forwarding_fail_when_yes():
    c = _by_name(_build_components(_cfg(allow_tcp_forwarding='yes')), 'allow_tcp_forwarding')
    assert c.score == 0 and c.finding_id == 'SSH-FWD-002'


@pytest.mark.parametrize('value', ['local', 'remote'])
def test_allow_tcp_forwarding_fail_on_partial_modes(value):
    # spec section 6.3: partial forwarding modes are FAIL too, not a WARN -
    # no citable ranking between 'local'/'remote' and 'yes' was found
    c = _by_name(_build_components(_cfg(allow_tcp_forwarding=value)), 'allow_tcp_forwarding')
    assert c.score == 0 and c.finding_id == 'SSH-FWD-002'


def test_allow_tcp_forwarding_weight():
    c = _by_name(_build_components(_cfg()), 'allow_tcp_forwarding')
    assert c.weight == 0.0800


# ===========================================================================
# SSH-FWD-003 - allow_agent_forwarding
# ===========================================================================

def test_allow_agent_forwarding_pass_when_false():
    c = _by_name(_build_components(_cfg(allow_agent_forwarding=False)), 'allow_agent_forwarding')
    assert c.score == 100 and c.finding_id is None


def test_allow_agent_forwarding_fail_when_true():
    c = _by_name(_build_components(_cfg(allow_agent_forwarding=True)), 'allow_agent_forwarding')
    assert c.score == 0 and c.finding_id == 'SSH-FWD-003'


def test_allow_agent_forwarding_weight():
    c = _by_name(_build_components(_cfg()), 'allow_agent_forwarding')
    assert c.weight == 0.0800


# ===========================================================================
# SSH-CRYPTO-001 - ciphers (deny-list, substring match)
# ===========================================================================

def test_ciphers_pass_when_all_strong():
    c = _by_name(_build_components(_cfg(ciphers=['aes256-gcm@openssh.com', 'chacha20-poly1305@openssh.com'])),
                  'ciphers')
    assert c.score == 100 and c.finding_id is None


@pytest.mark.parametrize('weak_cipher', ['3des-cbc', 'aes128-cbc', 'aes256-cbc', 'blowfish-cbc',
                                          'cast128-cbc', 'twofish-cbc', 'arcfour', 'arcfour256'])
def test_ciphers_fail_on_weak_cipher_family(weak_cipher):
    c = _by_name(_build_components(_cfg(ciphers=['aes256-gcm@openssh.com', weak_cipher])), 'ciphers')
    assert c.score == 0 and c.finding_id == 'SSH-CRYPTO-001'


def test_ciphers_na_when_empty():
    c = _by_name(_build_components(_cfg(ciphers=[])), 'ciphers')
    assert c.applicable is False
    assert c.finding_id == 'SSH-CRYPTO-001'


def test_ciphers_weight():
    c = _by_name(_build_components(_cfg()), 'ciphers')
    assert c.weight == 0.09375


# ===========================================================================
# SSH-CRYPTO-002 - macs (deny-list, substring match, -etm variants included)
# ===========================================================================

def test_macs_pass_when_all_strong():
    c = _by_name(_build_components(_cfg(macs=['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512'])), 'macs')
    assert c.score == 100 and c.finding_id is None


@pytest.mark.parametrize('weak_mac', ['hmac-md5', 'hmac-md5-96', 'hmac-sha1', 'hmac-sha1-96',
                                       'hmac-sha1-etm@openssh.com', 'hmac-ripemd160',
                                       'hmac-sha2-256-96'])
def test_macs_fail_on_weak_mac_family(weak_mac):
    # explicitly includes the -etm@openssh.com variant (VM-realistic value
    # this catalogue's synthetic validation specifically checked) to confirm
    # the ETM wrapper doesn't exempt an otherwise-weak hash from matching
    c = _by_name(_build_components(_cfg(macs=['hmac-sha2-256-etm@openssh.com', weak_mac])), 'macs')
    assert c.score == 0 and c.finding_id == 'SSH-CRYPTO-002'


def test_macs_na_when_empty():
    c = _by_name(_build_components(_cfg(macs=[])), 'macs')
    assert c.applicable is False
    assert c.finding_id == 'SSH-CRYPTO-002'


def test_macs_weight():
    c = _by_name(_build_components(_cfg()), 'macs')
    assert c.weight == 0.0625


# ===========================================================================
# SSH-CRYPTO-003 - kex_algorithms (deny-list, substring match)
# ===========================================================================

def test_kex_pass_when_all_strong():
    c = _by_name(_build_components(_cfg(kex_algorithms=['curve25519-sha256', 'ecdh-sha2-nistp256'])),
                  'kex_algorithms')
    assert c.score == 100 and c.finding_id is None


@pytest.mark.parametrize('weak_kex', ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
                                       'diffie-hellman-group-exchange-sha1'])
def test_kex_fail_on_weak_kex_family(weak_kex):
    c = _by_name(_build_components(_cfg(kex_algorithms=['curve25519-sha256', weak_kex])), 'kex_algorithms')
    assert c.score == 0 and c.finding_id == 'SSH-CRYPTO-003'


def test_kex_group_exchange_sha256_is_not_weak():
    # spec section 6.4.1: the -sha256 variant of group-exchange must NOT
    # match the group-exchange-sha1 deny rule - this pins that distinction
    c = _by_name(_build_components(_cfg(kex_algorithms=['diffie-hellman-group-exchange-sha256'])),
                  'kex_algorithms')
    assert c.score == 100 and c.finding_id is None


def test_kex_na_when_empty():
    c = _by_name(_build_components(_cfg(kex_algorithms=[])), 'kex_algorithms')
    assert c.applicable is False
    assert c.finding_id == 'SSH-CRYPTO-003'


def test_kex_weight():
    c = _by_name(_build_components(_cfg()), 'kex_algorithms')
    assert c.weight == 0.09375


# ===========================================================================
# Component set shape
# ===========================================================================

def test_build_components_returns_fourteen_components():
    components = _build_components(_cfg())
    assert len(components) == 14
    assert {c.name for c in components} == {
        'permit_root_login', 'password_authentication', 'permit_empty_passwords',
        'pubkey_authentication', 'kbd_interactive_authentication', 'hostbased_authentication',
        'max_auth_tries', 'login_grace_time',
        'x11_forwarding', 'allow_tcp_forwarding', 'allow_agent_forwarding',
        'ciphers', 'macs', 'kex_algorithms',
    }


def test_build_components_weights_sum_to_one():
    components = _build_components(_cfg())
    assert abs(sum(c.weight for c in components) - 1.0) < 1e-9


def test_build_components_feeds_weighted_score_without_error():
    result = weighted_score(_build_components(_cfg()))
    assert result['score'] == 100
    assert result['max'] == 100


# ===========================================================================
# Synthetic validation scenarios (docs/checks/ssh_hardening.md section 8.3)
# ===========================================================================
# Exact input fields and expected scores are fixed in the spec - these tests
# are the executable form of that table, run through the real
# weighted_score() engine, matching the values the spike script produced
# before this module existed (see this session's working notes).

@pytest.mark.parametrize('name,kwargs,expected_score', [
    ('1_fully_hardened', {}, 100),
    ('2_password_auth_enabled', dict(password_authentication=True), 94),
    ('3_root_login_yes', dict(permit_root_login='yes'), 91),
    ('3b_root_login_prohibit_password', dict(permit_root_login='prohibit-password'), 100),
    ('3c_root_login_forced_commands_only', dict(permit_root_login='forced-commands-only'), 100),
    ('3d_root_login_no', dict(permit_root_login='no'), 100),
    ('4_all_forwarding_enabled', dict(
        x11_forwarding=True, allow_tcp_forwarding='yes', allow_agent_forwarding=True,
    ), 80),
    ('5a_weak_cipher', dict(ciphers=['aes256-gcm@openssh.com', '3des-cbc']), 91),
    ('5b_weak_mac', dict(macs=['hmac-sha2-256-etm@openssh.com', 'hmac-sha1-etm@openssh.com']), 94),
    ('5c_weak_kex', dict(kex_algorithms=['curve25519-sha256', 'diffie-hellman-group14-sha1']), 91),
    ('5d_all_crypto_weak', dict(
        ciphers=['3des-cbc', 'arcfour'],
        macs=['hmac-sha1', 'hmac-md5'],
        kex_algorithms=['diffie-hellman-group1-sha1'],
    ), 75),
    ('6_mixed_real_vm_config', dict(
        permit_root_login='prohibit-password', password_authentication=True,
        max_auth_tries=6, login_grace_time=120,
        x11_forwarding=True, allow_tcp_forwarding='yes', allow_agent_forwarding=True,
        macs=['umac-64-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'hmac-sha2-256'],
    ), 58),
    ('7_crypto_fields_empty', dict(ciphers=[], macs=[], kex_algorithms=[]), 100),
])
def test_synthetic_scenario_matches_spec(name, kwargs, expected_score):
    cfg = _cfg(**kwargs)
    result = weighted_score(_build_components(cfg))
    assert result['score'] == expected_score, (
        f'scenario {name}: expected {expected_score}, got {result["score"]} - '
        f'check docs/checks/ssh_hardening.md section 8.3 for the documented inputs'
    )


def test_scenario_7_all_crypto_components_are_na():
    # the specific regression this scenario exists to catch: empty crypto
    # lists must be N/A (not FAIL) - an empty list is either an upstream
    # collection gap or defensive coverage, not evidence of weak algorithms.
    cfg = _cfg(ciphers=[], macs=[], kex_algorithms=[])
    components = _build_components(cfg)
    for control_name in ('ciphers', 'macs', 'kex_algorithms'):
        assert _by_name(components, control_name).applicable is False


def test_scenario_3_permit_root_login_only_yes_fails():
    # confirms the revised SSH-AUTH-001 semantics against all four
    # documented values in one place, not just individually above
    for value, expected_pass in [
        ('no', True), ('prohibit-password', True),
        ('forced-commands-only', True), ('yes', False),
    ]:
        cfg = _cfg(permit_root_login=value)
        c = _by_name(_build_components(cfg), 'permit_root_login')
        assert (c.score == 100) == expected_pass, f'permit_root_login={value!r} unexpected result'
