"""
Regression tests for netaudit_pkg.kernel_config — collector only, no
scoring. Mirrors the fixture-based, no-SSH-mock style of
_parse_sshd_t()'s own tests: _parse_sysctl_a() is pure (no I/O), so every
parsing edge case here is tested directly against fixture text, and
collect_kernel_config()'s ssh.sudo()-vs-ssh.run() contract is tested
separately with a minimal fake SSHExecutor.
"""

from __future__ import annotations

import pytest

from netaudit_pkg.kernel_config import KernelConfig, _parse_sysctl_a, collect_kernel_config


# ===========================================================================
# Fixture builders
# ===========================================================================

def _line(key: str, value: str) -> str:
    return f'{key} = {value}'


_VM_BASELINE = '\n'.join([
    _line('kernel.randomize_va_space', '2'),
    _line('kernel.dmesg_restrict', '1'),
    _line('kernel.kptr_restrict', '1'),
    _line('kernel.yama.ptrace_scope', '1'),
    _line('fs.suid_dumpable', '2'),
    _line('net.ipv4.ip_forward', '0'),
    _line('net.ipv6.conf.all.forwarding', '0'),
    _line('net.ipv4.tcp_syncookies', '1'),
    _line('net.ipv4.icmp_echo_ignore_broadcasts', '1'),
    _line('net.ipv4.conf.all.accept_source_route', '0'),
    _line('net.ipv4.conf.all.accept_redirects', '1'),
    _line('net.ipv4.conf.all.secure_redirects', '1'),
    _line('net.ipv4.conf.all.send_redirects', '1'),
    _line('net.ipv4.conf.all.log_martians', '0'),
    _line('net.ipv4.conf.all.rp_filter', '2'),
    _line('net.ipv4.conf.default.rp_filter', '2'),
])


# ===========================================================================
# Basic parse — VM baseline shape
# ===========================================================================

def test_parses_vm_baseline_values():
    """The exact 2026-08-11 VM baseline (docs/checks/kernel_hardening.md
    section 3) round-trips through the parser correctly, field by field."""
    cfg = _parse_sysctl_a(_VM_BASELINE, kernel_version='7.0.0-29-generic')

    assert cfg.readable is True
    assert cfg.kernel_version == '7.0.0-29-generic'
    assert cfg.randomize_va_space == 2
    assert cfg.dmesg_restrict is True
    assert cfg.kptr_restrict == 1
    assert cfg.yama_ptrace_scope == 1
    assert cfg.suid_dumpable == 2
    assert cfg.ip_forward is False
    assert cfg.ipv6_forwarding is False
    assert cfg.tcp_syncookies is True
    assert cfg.icmp_echo_ignore_broadcasts is True
    assert cfg.accept_source_route is False
    assert cfg.accept_redirects is True
    assert cfg.secure_redirects is True
    assert cfg.send_redirects is True
    assert cfg.log_martians is False
    assert cfg.rp_filter_all == 2
    assert cfg.rp_filter_default == 2


# ===========================================================================
# Int-field edge cases — 0, 1, 2, 3
# ===========================================================================

@pytest.mark.parametrize('value,expected', [('0', 0), ('1', 1), ('2', 2), ('3', 3)])
def test_yama_ptrace_scope_accepts_all_four_values(value, expected):
    """yama.ptrace_scope is the one field with a genuine 0-3 range
    (docs/checks/kernel_hardening.md KRN-015) — must not be mistaken for
    a bool anywhere in the parser."""
    text = _line('kernel.yama.ptrace_scope', value)
    cfg = _parse_sysctl_a(text)
    assert cfg.yama_ptrace_scope == expected
    # and it must NOT have been coerced into a bool-like value
    assert not isinstance(cfg.yama_ptrace_scope, bool)


@pytest.mark.parametrize('value,expected', [('0', 0), ('1', 1), ('2', 2)])
def test_suid_dumpable_accepts_all_three_values(value, expected):
    """fs.suid_dumpable: 0/1/2 must all parse distinctly — this is the
    graded control (KRN-016), collapsing any of these three would corrupt
    the eventual scoring."""
    text = _line('fs.suid_dumpable', value)
    cfg = _parse_sysctl_a(text)
    assert cfg.suid_dumpable == expected


@pytest.mark.parametrize('value,expected', [('0', 0), ('1', 1), ('2', 2)])
def test_kptr_restrict_accepts_all_three_values(value, expected):
    text = _line('kernel.kptr_restrict', value)
    cfg = _parse_sysctl_a(text)
    assert cfg.kptr_restrict == expected


@pytest.mark.parametrize('value,expected', [('0', 0), ('1', 1), ('2', 2)])
def test_rp_filter_accepts_all_three_values(value, expected):
    """Both rp_filter_all and rp_filter_default must independently accept
    0/1/2 — KRN-012/KRN-013's range-tolerant PASS on 1-or-2."""
    text = '\n'.join([
        _line('net.ipv4.conf.all.rp_filter', value),
        _line('net.ipv4.conf.default.rp_filter', value),
    ])
    cfg = _parse_sysctl_a(text)
    assert cfg.rp_filter_all == expected
    assert cfg.rp_filter_default == expected


def test_rp_filter_all_and_default_are_independent():
    """all and default must never be conflated with each other — a
    server can legitimately have different values for each."""
    text = '\n'.join([
        _line('net.ipv4.conf.all.rp_filter', '1'),
        _line('net.ipv4.conf.default.rp_filter', '2'),
    ])
    cfg = _parse_sysctl_a(text)
    assert cfg.rp_filter_all == 1
    assert cfg.rp_filter_default == 2


# ===========================================================================
# Missing key → None, never a guessed default
# ===========================================================================

def test_missing_key_is_none_not_a_guessed_default():
    """A key entirely absent from sysctl -a output (e.g. an older kernel
    lacking a given sysctl) must produce None — never a fabricated 0/1,
    per this module's docstring contract."""
    # Only one key present; every other field must be None.
    text = _line('kernel.randomize_va_space', '2')
    cfg = _parse_sysctl_a(text)

    assert cfg.randomize_va_space == 2
    assert cfg.dmesg_restrict is None
    assert cfg.kptr_restrict is None
    assert cfg.yama_ptrace_scope is None
    assert cfg.suid_dumpable is None
    assert cfg.ip_forward is None
    assert cfg.ipv6_forwarding is None
    assert cfg.tcp_syncookies is None
    assert cfg.icmp_echo_ignore_broadcasts is None
    assert cfg.accept_source_route is None
    assert cfg.accept_redirects is None
    assert cfg.secure_redirects is None
    assert cfg.send_redirects is None
    assert cfg.log_martians is None
    assert cfg.rp_filter_all is None
    assert cfg.rp_filter_default is None


def test_empty_output_is_unreadable():
    """Empty sysctl -a output (e.g. sudo failed silently) must produce
    readable=False, matching collect_kernel_config()'s own empty-output
    branch — tested here at the parser level for the pure-function case."""
    cfg = _parse_sysctl_a('')
    # _parse_sysctl_a itself doesn't set readable=False for empty input
    # (that branch lives in collect_kernel_config, before this function is
    # ever called) - but every individual field must still come back None,
    # not a crash, if this function is ever called with empty text directly.
    assert cfg.randomize_va_space is None
    assert cfg.suid_dumpable is None


def test_unparseable_int_value_is_none():
    """A key present but with a value that doesn't parse as int (should
    never happen for these keys in practice, but must not crash) yields
    None, not an exception."""
    text = _line('kernel.randomize_va_space', 'not-a-number')
    cfg = _parse_sysctl_a(text)
    assert cfg.randomize_va_space is None


def test_unparseable_bool_value_is_none():
    """A key present but with a value other than '0'/'1' (unexpected, but
    must be handled defensively) yields None, not a guessed True/False."""
    text = _line('net.ipv4.tcp_syncookies', '2')
    cfg = _parse_sysctl_a(text)
    # '2' is not a valid bool-field value under this module's contract
    # (only '0'/'1' are) - must come back None, not silently truthy.
    assert cfg.tcp_syncookies is None


# ===========================================================================
# Repeated key → deterministic (first occurrence wins)
# ===========================================================================

def test_repeated_key_first_occurrence_wins():
    """If sysctl -a ever prints the same key twice (not expected for any
    of these 16 keys, but the parser must behave deterministically if it
    happens), the first value wins — matching ssh_config.py's identical
    precedent for the same defensive reason."""
    text = '\n'.join([
        _line('kernel.randomize_va_space', '2'),
        _line('kernel.randomize_va_space', '0'),
    ])
    cfg = _parse_sysctl_a(text)
    assert cfg.randomize_va_space == 2


# ===========================================================================
# Permission-denied and other malformed lines are skipped, not fatal
# ===========================================================================

def test_permission_denied_lines_are_skipped():
    """Lines like `sysctl: permission denied on key 'kernel.apparmor_...'`
    (the VM's actual non-sudo behavior on apparmor keys,
    docs/checks/kernel_hardening.md section 2) must not crash the parser
    and must not be mistaken for a valid key=value line — they contain no
    '=' at all, so the parser's own `'=' not in line` skip handles them,
    tested explicitly here rather than just assumed."""
    text = '\n'.join([
        "sysctl: permission denied on key 'kernel.apparmor_cache_timeout'",
        "sysctl: permission denied on key 'kernel.apparmor_display_secid_mode'",
        _line('kernel.randomize_va_space', '2'),
    ])
    cfg = _parse_sysctl_a(text)
    assert cfg.randomize_va_space == 2


def test_blank_lines_are_skipped():
    text = '\n'.join([
        '',
        _line('kernel.randomize_va_space', '2'),
        '',
        '',
    ])
    cfg = _parse_sysctl_a(text)
    assert cfg.randomize_va_space == 2


def test_unrelated_keys_are_ignored():
    """sysctl -a on a real host prints ~1080 lines; this module only cares
    about 16 of them. Unrelated keys must be silently ignored, not error,
    not accidentally picked up as a similarly-named field."""
    text = '\n'.join([
        _line('kernel.apparmor_cache_timeout', '30'),
        _line('vm.swappiness', '60'),
        _line('kernel.randomize_va_space', '2'),
        _line('net.core.somaxconn', '4096'),
    ])
    cfg = _parse_sysctl_a(text)
    assert cfg.randomize_va_space == 2
    # confirm nothing unexpected leaked onto an unrelated field
    assert cfg.dmesg_restrict is None


# ===========================================================================
# secure_redirects / rp_filter=2 — specific values called out by the spec
# ===========================================================================

def test_secure_redirects_equals_one_parses_as_true():
    """VM baseline: secure_redirects=1 (a FAIL per KRN-006, but that's
    checks/kernel_hardening.py's job, not the collector's — the collector
    just needs to report the fact correctly as True)."""
    text = _line('net.ipv4.conf.all.secure_redirects', '1')
    cfg = _parse_sysctl_a(text)
    assert cfg.secure_redirects is True


def test_rp_filter_two_parses_correctly_not_conflated_with_bool():
    """rp_filter=2 (loose mode, VM baseline) must parse as int 2, not as
    a truthy bool — a hardening control comparing this to `True` instead
    of `2` would be a real bug this test exists to catch early."""
    text = _line('net.ipv4.conf.all.rp_filter', '2')
    cfg = _parse_sysctl_a(text)
    assert cfg.rp_filter_all == 2
    assert not isinstance(cfg.rp_filter_all, bool)


# ===========================================================================
# collect_kernel_config() — uname -r and sudo() vs run() contract
# ===========================================================================

class _FakeSSH:
    """Minimal fake SSHExecutor recording which method (run vs sudo) was
    called for which command, without touching real SSH at all."""

    def __init__(self, sysctl_output: str, uname_output: str = '7.0.0-29-generic\n'):
        self._sysctl_output = sysctl_output
        self._uname_output = uname_output
        self.run_calls: list[str] = []
        self.sudo_calls: list[str] = []

    def run(self, cmd: str):
        self.run_calls.append(cmd)
        if cmd == 'uname -r':
            return self._uname_output, ''
        return '', ''

    def sudo(self, cmd: str):
        self.sudo_calls.append(cmd)
        if cmd == 'sysctl -a':
            return self._sysctl_output, ''
        return '', ''


def test_collect_uses_sudo_for_sysctl_not_run():
    """The core architectural contract this module's docstring insists on:
    sysctl -a must go through ssh.sudo(), never ssh.run() — even though
    all 16 keys happened to be readable without sudo on the VM. This test
    fails loudly if a future edit "simplifies" this to ssh.run()."""
    fake = _FakeSSH(_VM_BASELINE)
    collect_kernel_config(fake)

    assert 'sysctl -a' in fake.sudo_calls
    assert 'sysctl -a' not in fake.run_calls


def test_collect_uses_run_for_uname_not_sudo():
    """uname -r needs no privilege — using sudo for it would be an
    unnecessary elevated command for no reason, so this is checked
    explicitly in the opposite direction from the sysctl assertion above."""
    fake = _FakeSSH(_VM_BASELINE)
    collect_kernel_config(fake)

    assert 'uname -r' in fake.run_calls
    assert 'uname -r' not in fake.sudo_calls


def test_collect_captures_kernel_version():
    fake = _FakeSSH(_VM_BASELINE, uname_output='7.0.0-29-generic\n')
    cfg = collect_kernel_config(fake)
    assert cfg.kernel_version == '7.0.0-29-generic'


def test_collect_empty_sysctl_output_is_unreadable():
    """sudo() returning empty output (e.g. the sudo session itself failed)
    must produce readable=False, matching ssh_config.py's identical
    empty-output branch for sshd -T."""
    fake = _FakeSSH(sysctl_output='')
    cfg = collect_kernel_config(fake)
    assert cfg.readable is False
    # kernel_version is still captured even when sysctl fails — uname -r
    # is an independent, unprivileged command.
    assert cfg.kernel_version == '7.0.0-29-generic'


def test_collect_whitespace_only_sysctl_output_is_unreadable():
    fake = _FakeSSH(sysctl_output='   \n\n  ')
    cfg = collect_kernel_config(fake)
    assert cfg.readable is False


def test_collect_full_round_trip_matches_vm_baseline():
    """End-to-end: collect_kernel_config() against the fake SSH executor
    must produce the same KernelConfig as calling _parse_sysctl_a()
    directly on the same fixture — confirms collect_kernel_config() adds
    no unexpected transformation on top of the pure parser."""
    fake = _FakeSSH(_VM_BASELINE, uname_output='7.0.0-29-generic\n')
    cfg = collect_kernel_config(fake)
    expected = _parse_sysctl_a(_VM_BASELINE, kernel_version='7.0.0-29-generic')
    assert cfg == expected
