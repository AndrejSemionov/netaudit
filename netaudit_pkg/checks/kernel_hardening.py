"""
kernel sysctl hardening score: ASLR, kernel pointer/dmesg exposure, IP
forwarding, ICMP/redirect handling, reverse-path filtering, SYN flood
protection, and process-dump safety — scored 0-100 per
docs/checks/kernel_hardening.md.

Every control's PASS/FAIL condition, weight, and the one graded exception
(suid_dumpable) below is a direct transcription of
docs/checks/kernel_hardening.md sections 3 and 6 - this module implements
that spec, it does not re-derive it. In particular:

- rp_filter (KRN-012/013) and kptr_restrict (KRN-014) are range-tolerant:
  both their "strict" and "loose"/"stronger" values PASS identically. Do
  not narrow either back to a single exact-match value - see spec sections
  4.1/4.2 for why both values are equally valid hardening postures.
- suid_dumpable (KRN-016) is the one graded control in this catalogue:
  0->100, 2->60, 1->0. Do not simplify this to binary PASS/FAIL - spec
  section 4.4 explains why 2 ("suidsafe") is neither equivalent to 0 nor
  to 1, and collapsing it either way misstates what the value means. Its
  finding text below (_f_suid_dumpable) has three branches, not two, for
  the same reason - a finding that only distinguished "0 = fine" / "not 0 =
  bad" would misreport what 2 actually is.
- ip_forward, ipv6_forwarding, and send_redirects (KRN-008/009/010) are
  scored as plain binary controls with no host-role (router/NAT) detection
  in v1 - spec section 4.3. A real router will legitimately FAIL these
  three; this is a documented, deliberate scope cut, not a bug to "fix" by
  adding an N/A escape hatch here.
- rp_filter's finding text always states the actual observed value (spec
  section 4.1: "1 or 2 = PASS" must never be reported as a bare "PASS" that
  hides which of the two is in effect) - this only matters for the FAIL
  case (0) here, since PASS produces no finding at all, but the same
  discipline applies to Component.reason if that field is ever populated
  in a future revision of this module.
- N/A handling (spec section 5) is simpler than ssh_hardening's: there is
  only one group-level N/A case (KernelConfig.readable is False), no
  "tool not installed" branch like ssh_hardening's SSHConfig.version check
  - sysctl always exists on Linux, unlike sshd which may not be installed
  at all. See audit_kernel_hardening_score() below.
"""

from __future__ import annotations

from ..registry import register
from ..kernel_config import KernelConfig, collect_kernel_config
from ..findings import finding as _finding
from ..scoring import Component, weighted_score
from ..ssh import SSHExecutor, HostKeyMismatchError

try:
    import paramiko
except ImportError:
    paramiko = None

# ===========================================================================
# Per-control weights (docs/checks/kernel_hardening.md section 6)
# ===========================================================================
#
# Severity multiplier (high=1.5, medium=1.0, low=0.5) normalized so all 16
# weights sum to exactly 1.0 - transcribed here as literal float constants,
# same approach ssh_hardening.py and nginx_hardening.py already use (weights
# are a fixed policy decision from the spec, not recomputed at runtime).
# KRN-011 (log_martians) carries the rounding-remainder weight (0.032260
# instead of 0.032258) per spec section 6 - this is a deliberate arithmetic
# fit to land the sum inside weighted_score()'s 1e-6 tolerance, not a typo.

_W_RANDOMIZE_VA_SPACE = 0.096774        # high  — KRN-001
_W_DMESG_RESTRICT = 0.064516            # medium — KRN-002
_W_TCP_SYNCOOKIES = 0.096774            # high  — KRN-003
_W_ICMP_ECHO_IGNORE_BROADCASTS = 0.032258  # low — KRN-004
_W_ACCEPT_SOURCE_ROUTE = 0.096774       # high  — KRN-005
_W_SECURE_REDIRECTS = 0.032258          # low   — KRN-006
_W_ACCEPT_REDIRECTS = 0.096774          # high  — KRN-007
_W_IP_FORWARD = 0.064516                # medium — KRN-008
_W_IPV6_FORWARDING = 0.064516           # medium — KRN-009
_W_SEND_REDIRECTS = 0.064516            # medium — KRN-010
_W_LOG_MARTIANS = 0.032260              # low (absorbs rounding remainder) — KRN-011
_W_RP_FILTER_ALL = 0.064516             # medium — KRN-012
_W_RP_FILTER_DEFAULT = 0.032258         # low   — KRN-013
_W_KPTR_RESTRICT = 0.064516             # medium — KRN-014
_W_PTRACE_SCOPE = 0.032258              # low   — KRN-015
_W_SUID_DUMPABLE = 0.064516             # medium — KRN-016


# ===========================================================================
# Component builders — one per control, in docs/checks/kernel_hardening.md
# section 3 order (3.1 binary, 3.2 range-tolerant, 3.3 graded). None of
# these controls has an individual N/A condition (spec section 5: the only
# N/A case is the whole KernelConfig being unreadable, handled one level up
# in audit_kernel_hardening_score(), before any of these are ever called).
# ===========================================================================


def _c_randomize_va_space(cfg: KernelConfig) -> Component:
    # KRN-001 - full ASLR, weight 0.096774, severity high
    passed = cfg.randomize_va_space == 2
    score = 100 if passed else 0
    return Component(name='randomize_va_space', weight=_W_RANDOMIZE_VA_SPACE,
                      score=score, max=100, finding_id=None if passed else 'KRN-001')


def _c_dmesg_restrict(cfg: KernelConfig) -> Component:
    # KRN-002 - dmesg restricted to CAP_SYSLOG, weight 0.064516, severity medium
    passed = cfg.dmesg_restrict is True
    score = 100 if passed else 0
    return Component(name='dmesg_restrict', weight=_W_DMESG_RESTRICT,
                      score=score, max=100, finding_id=None if passed else 'KRN-002')


def _c_tcp_syncookies(cfg: KernelConfig) -> Component:
    # KRN-003 - SYN flood protection, weight 0.096774, severity high
    passed = cfg.tcp_syncookies is True
    score = 100 if passed else 0
    return Component(name='tcp_syncookies', weight=_W_TCP_SYNCOOKIES,
                      score=score, max=100, finding_id=None if passed else 'KRN-003')


def _c_icmp_echo_ignore_broadcasts(cfg: KernelConfig) -> Component:
    # KRN-004 - Smurf attack mitigation, weight 0.032258, severity low
    passed = cfg.icmp_echo_ignore_broadcasts is True
    score = 100 if passed else 0
    return Component(name='icmp_echo_ignore_broadcasts', weight=_W_ICMP_ECHO_IGNORE_BROADCASTS,
                      score=score, max=100, finding_id=None if passed else 'KRN-004')


def _c_accept_source_route(cfg: KernelConfig) -> Component:
    # KRN-005 - source-routed packets rejected, weight 0.096774, severity high
    passed = cfg.accept_source_route is False
    score = 100 if passed else 0
    return Component(name='accept_source_route', weight=_W_ACCEPT_SOURCE_ROUTE,
                      score=score, max=100, finding_id=None if passed else 'KRN-005')


def _c_secure_redirects(cfg: KernelConfig) -> Component:
    # KRN-006 - secure ICMP redirects rejected, weight 0.032258, severity low
    passed = cfg.secure_redirects is False
    score = 100 if passed else 0
    return Component(name='secure_redirects', weight=_W_SECURE_REDIRECTS,
                      score=score, max=100, finding_id=None if passed else 'KRN-006')


def _c_accept_redirects(cfg: KernelConfig) -> Component:
    # KRN-007 - ICMP redirects rejected, weight 0.096774, severity high.
    # Strict v1 policy, no router-in-trusted-network exception (spec 4.3's
    # reasoning extends here too — see this module's docstring).
    passed = cfg.accept_redirects is False
    score = 100 if passed else 0
    return Component(name='accept_redirects', weight=_W_ACCEPT_REDIRECTS,
                      score=score, max=100, finding_id=None if passed else 'KRN-007')


def _c_ip_forward(cfg: KernelConfig) -> Component:
    # KRN-008 - IPv4 forwarding disabled, weight 0.064516, severity medium.
    # No host-role auto-detection in v1 (spec section 4.3) — a real
    # router/NAT host will legitimately FAIL this, by design.
    passed = cfg.ip_forward is False
    score = 100 if passed else 0
    return Component(name='ip_forward', weight=_W_IP_FORWARD,
                      score=score, max=100, finding_id=None if passed else 'KRN-008')


def _c_ipv6_forwarding(cfg: KernelConfig) -> Component:
    # KRN-009 - IPv6 forwarding disabled, weight 0.064516, severity medium
    passed = cfg.ipv6_forwarding is False
    score = 100 if passed else 0
    return Component(name='ipv6_forwarding', weight=_W_IPV6_FORWARDING,
                      score=score, max=100, finding_id=None if passed else 'KRN-009')


def _c_send_redirects(cfg: KernelConfig) -> Component:
    # KRN-010 - ICMP redirects not sent, weight 0.064516, severity medium.
    # Same no-auto-detect policy as KRN-008/009 — kernel docs describe this
    # as "send redirects, if router"; v1 scores it as a plain host control.
    passed = cfg.send_redirects is False
    score = 100 if passed else 0
    return Component(name='send_redirects', weight=_W_SEND_REDIRECTS,
                      score=score, max=100, finding_id=None if passed else 'KRN-010')


def _c_log_martians(cfg: KernelConfig) -> Component:
    # KRN-011 - martian packets logged, weight 0.032260, severity low.
    # Detective, not preventive — lowest severity in the catalogue on purpose.
    passed = cfg.log_martians is True
    score = 100 if passed else 0
    return Component(name='log_martians', weight=_W_LOG_MARTIANS,
                      score=score, max=100, finding_id=None if passed else 'KRN-011')


def _c_rp_filter_all(cfg: KernelConfig) -> Component:
    # KRN-012 - reverse-path filtering enabled (all), weight 0.064516,
    # severity medium. Range-tolerant: 1 (strict) and 2 (loose) both PASS
    # equally — spec section 4.1. Only 0 (disabled) is a FAIL.
    passed = cfg.rp_filter_all in (1, 2)
    score = 100 if passed else 0
    return Component(name='rp_filter_all', weight=_W_RP_FILTER_ALL,
                      score=score, max=100, finding_id=None if passed else 'KRN-012')


def _c_rp_filter_default(cfg: KernelConfig) -> Component:
    # KRN-013 - reverse-path filtering enabled (default), weight 0.032258,
    # severity low. Same 1-or-2 PASS range as KRN-012, lower weight
    # (secondary to `all`, applies to interfaces created after boot).
    passed = cfg.rp_filter_default in (1, 2)
    score = 100 if passed else 0
    return Component(name='rp_filter_default', weight=_W_RP_FILTER_DEFAULT,
                      score=score, max=100, finding_id=None if passed else 'KRN-013')


def _c_kptr_restrict(cfg: KernelConfig) -> Component:
    # KRN-014 - kernel pointers restricted, weight 0.064516, severity
    # medium. Range-tolerant: 1 (unprivileged-only) and 2 (everyone
    # without CAP_SYSLOG, incl. root) both PASS equally — spec section 4.2.
    # Only 0 (unrestricted) is a FAIL.
    passed = cfg.kptr_restrict in (1, 2)
    score = 100 if passed else 0
    return Component(name='kptr_restrict', weight=_W_KPTR_RESTRICT,
                      score=score, max=100, finding_id=None if passed else 'KRN-014')


def _c_ptrace_scope(cfg: KernelConfig) -> Component:
    # KRN-015 - ptrace restricted, weight 0.032258, severity low.
    # Any of 1/2/3 counts as a real restriction relative to the
    # unrestricted default (0) — spec doesn't rank 1 vs 2 vs 3 against
    # each other in v1.
    passed = cfg.yama_ptrace_scope in (1, 2, 3)
    score = 100 if passed else 0
    return Component(name='ptrace_scope', weight=_W_PTRACE_SCOPE,
                      score=score, max=100, finding_id=None if passed else 'KRN-015')


# suid_dumpable score mapping (spec section 3.3 / 4.4) — the one graded
# control in this catalogue. Kept as an explicit dict, not an if/elif chain,
# so the 0->100 / 2->60 / 1->0 mapping is visually a table, matching how the
# spec itself presents it.
_SUID_DUMPABLE_SCORE = {0: 100, 2: 60, 1: 0}


def _c_suid_dumpable(cfg: KernelConfig) -> Component:
    # KRN-016 - SUID core dump safety, weight 0.064516, severity medium.
    # Graded, not binary: 0 (disabled, best) -> 100, 2 (suidsafe, dump
    # produced but root-only readable, no cross-user leak) -> 60, 1
    # (insecure, world-readable dump of a privileged process) -> 0.
    # See this module's docstring and spec section 4.4 for why collapsing
    # this to PASS/FAIL in either direction would misstate what value 2
    # actually means. A value outside {0, 1, 2} (including cfg.suid_dumpable
    # being None — unreadable field) is treated the same as the worst case
    # (0/100 score, not-applicable would require its own N/A branch that
    # the spec doesn't define for this control — see section 5: no
    # control-level N/A exists in this catalogue, only the whole-config
    # N/A handled one level up).
    score = _SUID_DUMPABLE_SCORE.get(cfg.suid_dumpable, 0)
    passed = score == 100
    return Component(name='suid_dumpable', weight=_W_SUID_DUMPABLE,
                      score=score, max=100, finding_id=None if passed else 'KRN-016')


def _build_components(cfg: KernelConfig) -> list[Component]:
    """All 16 Components, in docs/checks/kernel_hardening.md section 3
    order. Caller (audit_kernel_hardening_score(), below) is responsible
    for checking cfg.readable before calling this — this function assumes
    a readable, fully-populated KernelConfig and does not itself handle
    the group-level N/A case (spec section 5)."""
    return [
        _c_randomize_va_space(cfg),
        _c_dmesg_restrict(cfg),
        _c_tcp_syncookies(cfg),
        _c_icmp_echo_ignore_broadcasts(cfg),
        _c_accept_source_route(cfg),
        _c_secure_redirects(cfg),
        _c_accept_redirects(cfg),
        _c_ip_forward(cfg),
        _c_ipv6_forwarding(cfg),
        _c_send_redirects(cfg),
        _c_log_martians(cfg),
        _c_rp_filter_all(cfg),
        _c_rp_filter_default(cfg),
        _c_kptr_restrict(cfg),
        _c_ptrace_scope(cfg),
        _c_suid_dumpable(cfg),
    ]


# ===========================================================================
# Finding builders — self-generated findings for all 16 controls. Unlike
# ssh_hardening (which references audit_ssh_hardening()'s pre-existing
# findings for 3 of its 14 controls via Component.finding_id instead of
# re-deriving them), no pre-existing kernel-sysctl findings function exists
# in NetAudit today (docs/checks/kernel_hardening.md section 7) - every
# finding here is generated by this module alone. Each _f_*() returns None
# on PASS (no finding — same convention every other hardening module in
# this codebase uses) or a Finding dict on FAIL, always with the matching
# KRN-0xx id so Component.finding_id can reference it.
# ===========================================================================


def _f_randomize_va_space(cfg: KernelConfig) -> dict | None:
    if cfg.randomize_va_space == 2:
        return None
    value = cfg.randomize_va_space if cfg.randomize_va_space is not None else 'unresolved'
    return _finding('high', 'ASLR not fully enabled',
                    f'kernel.randomize_va_space is {value!r} — full address space layout '
                    'randomization (value 2) randomizes stack, heap, and mmap base; a lower '
                    'value leaves part of the address space predictable',
                    id='KRN-001')


def _f_dmesg_restrict(cfg: KernelConfig) -> dict | None:
    if cfg.dmesg_restrict is True:
        return None
    return _finding('medium', 'dmesg not restricted',
                    'kernel.dmesg_restrict is disabled — unprivileged users can read the kernel '
                    'ring buffer, which can leak kernel addresses/pointers used to defeat KASLR',
                    id='KRN-002')


def _f_tcp_syncookies(cfg: KernelConfig) -> dict | None:
    if cfg.tcp_syncookies is True:
        return None
    return _finding('high', 'SYN cookies disabled',
                    'net.ipv4.tcp_syncookies is disabled — the host has no SYN flood '
                    'mitigation for its TCP listeners',
                    id='KRN-003')


def _f_icmp_echo_ignore_broadcasts(cfg: KernelConfig) -> dict | None:
    if cfg.icmp_echo_ignore_broadcasts is True:
        return None
    return _finding('low', 'broadcast ICMP echo not ignored',
                    'net.ipv4.icmp_echo_ignore_broadcasts is disabled — the host will respond '
                    'to broadcast ping requests, enabling Smurf-style amplification',
                    id='KRN-004')


def _f_accept_source_route(cfg: KernelConfig) -> dict | None:
    if cfg.accept_source_route is False:
        return None
    return _finding('high', 'source-routed packets accepted',
                    'net.ipv4.conf.all.accept_source_route is enabled — a sender can dictate '
                    'the return path for its own packets, a classic spoofing/bypass vector',
                    id='KRN-005')


def _f_secure_redirects(cfg: KernelConfig) -> dict | None:
    if cfg.secure_redirects is False:
        return None
    return _finding('low', 'secure ICMP redirects accepted',
                    'net.ipv4.conf.all.secure_redirects is enabled — even redirects from '
                    'known gateways are still a MITM vector on an untrusted L2 segment',
                    id='KRN-006')


def _f_accept_redirects(cfg: KernelConfig) -> dict | None:
    if cfg.accept_redirects is False:
        return None
    return _finding('high', 'ICMP redirects accepted',
                    'net.ipv4.conf.all.accept_redirects is enabled — the host will update its '
                    'routing based on unauthenticated ICMP redirect messages, a MITM vector',
                    id='KRN-007')


def _f_ip_forward(cfg: KernelConfig) -> dict | None:
    if cfg.ip_forward is False:
        return None
    return _finding('medium', 'IPv4 forwarding enabled',
                    'net.ipv4.ip_forward is enabled — the host will route IPv4 traffic between '
                    'interfaces. Expected and required on a router/NAT gateway (this module '
                    'does not auto-detect host role in v1 — see docs/checks/kernel_hardening.md '
                    'section 4.3); unexpected on a plain host',
                    id='KRN-008')


def _f_ipv6_forwarding(cfg: KernelConfig) -> dict | None:
    if cfg.ipv6_forwarding is False:
        return None
    return _finding('medium', 'IPv6 forwarding enabled',
                    'net.ipv6.conf.all.forwarding is enabled — IPv6 equivalent of KRN-008; '
                    'expected on a router/NAT gateway, unexpected on a plain host (no '
                    'host-role auto-detection in v1)',
                    id='KRN-009')


def _f_send_redirects(cfg: KernelConfig) -> dict | None:
    if cfg.send_redirects is False:
        return None
    return _finding('medium', 'ICMP redirects sent',
                    'net.ipv4.conf.all.send_redirects is enabled — the kernel documentation '
                    'describes this as "send redirects, if router"; a plain (non-router) host '
                    'sending redirects has no legitimate reason to (no host-role '
                    'auto-detection in v1)',
                    id='KRN-010')


def _f_log_martians(cfg: KernelConfig) -> dict | None:
    if cfg.log_martians is True:
        return None
    return _finding('low', 'martian packets not logged',
                    'net.ipv4.conf.all.log_martians is disabled — packets with impossible '
                    'source/destination addresses (a spoofing/misconfiguration signal) are not '
                    'logged. Detective, not preventive: this control blocks nothing by itself',
                    id='KRN-011')


def _f_rp_filter_all(cfg: KernelConfig) -> dict | None:
    if cfg.rp_filter_all in (1, 2):
        return None
    value = cfg.rp_filter_all if cfg.rp_filter_all is not None else 'unresolved'
    return _finding('medium', 'reverse-path filtering disabled',
                    f'net.ipv4.conf.all.rp_filter is {value!r} — reverse-path source '
                    'validation (RFC 3704) is off. Either strict (1) or loose (2) mode is an '
                    'acceptable enabled state; only 0 (disabled) fails this control',
                    id='KRN-012')


def _f_rp_filter_default(cfg: KernelConfig) -> dict | None:
    if cfg.rp_filter_default in (1, 2):
        return None
    value = cfg.rp_filter_default if cfg.rp_filter_default is not None else 'unresolved'
    return _finding('low', 'reverse-path filtering disabled (default)',
                    f'net.ipv4.conf.default.rp_filter is {value!r} — applies to interfaces '
                    'created after boot; same strict-or-loose acceptance as KRN-012, only 0 fails',
                    id='KRN-013')


def _f_kptr_restrict(cfg: KernelConfig) -> dict | None:
    if cfg.kptr_restrict in (1, 2):
        return None
    value = cfg.kptr_restrict if cfg.kptr_restrict is not None else 'unresolved'
    return _finding('medium', 'kernel pointers not restricted',
                    f'kernel.kptr_restrict is {value!r} — /proc kernel pointer values are '
                    'exposed. Either restricting to unprivileged users only (1) or to '
                    'everyone without CAP_SYSLOG (2) is acceptable; only 0 fails',
                    id='KRN-014')


def _f_ptrace_scope(cfg: KernelConfig) -> dict | None:
    if cfg.yama_ptrace_scope in (1, 2, 3):
        return None
    value = cfg.yama_ptrace_scope if cfg.yama_ptrace_scope is not None else 'unresolved'
    return _finding('low', 'ptrace unrestricted',
                    f'kernel.yama.ptrace_scope is {value!r} — any process can attach to any '
                    'other via ptrace. Any restriction level (1=restricted, 2=admin-only, '
                    '3=no attach) is acceptable; only the unrestricted default (0) fails',
                    id='KRN-015')


def _f_suid_dumpable(cfg: KernelConfig) -> dict | None:
    # Three-way branch, not two — see this module's docstring for why a
    # bare PASS/FAIL text would misreport what value 2 actually is.
    if cfg.suid_dumpable == 0:
        return None
    if cfg.suid_dumpable == 2:
        return _finding('medium', 'SUID core dumps enabled (restricted mode)',
                        'fs.suid_dumpable is 2 (suidsafe) — SUID/privileged processes still '
                        'produce a core dump, but it is written to a defined, root-owned path '
                        'with no cross-user information leak. Safer than 1, but 0 (no dump at '
                        'all) is the strictest posture',
                        id='KRN-016')
    value = cfg.suid_dumpable if cfg.suid_dumpable is not None else 'unresolved'
    return _finding('medium', 'SUID core dumps world-readable',
                    f'fs.suid_dumpable is {value!r} — privileged (SUID) process core dumps are '
                    'dumpable and readable by the invoking unprivileged user, letting them '
                    "inspect that process's memory",
                    id='KRN-016')


def _build_findings(cfg: KernelConfig) -> list[dict]:
    """All 16 self-generated findings this module produces (see this
    module's docstring — no pre-existing kernel-sysctl findings function
    exists to reference via Component.finding_id instead). Returns only
    the findings for controls currently FAILing (or, for suid_dumpable,
    scoring below 100)."""
    findings = [
        _f_randomize_va_space(cfg),
        _f_dmesg_restrict(cfg),
        _f_tcp_syncookies(cfg),
        _f_icmp_echo_ignore_broadcasts(cfg),
        _f_accept_source_route(cfg),
        _f_secure_redirects(cfg),
        _f_accept_redirects(cfg),
        _f_ip_forward(cfg),
        _f_ipv6_forwarding(cfg),
        _f_send_redirects(cfg),
        _f_log_martians(cfg),
        _f_rp_filter_all(cfg),
        _f_rp_filter_default(cfg),
        _f_kptr_restrict(cfg),
        _f_ptrace_scope(cfg),
        _f_suid_dumpable(cfg),
    ]
    return [f for f in findings if f is not None]


# ===========================================================================
# Internal reusable API
# ===========================================================================

def audit_kernel_hardening_score(ssh: SSHExecutor) -> dict:
    """Scores kernel sysctl hardening (ASLR, pointer/dmesg exposure,
    forwarding, ICMP/redirect handling, reverse-path filtering, SYN flood
    protection, process-dump safety) from an already-connected
    SSHExecutor. Does NOT open or close the SSH session itself - same
    two-layer API rationale ssh_hardening.audit_ssh_hardening_score() and
    nginx_hardening.audit_nginx_hardening_score() already established.

    Unlike ssh_hardening (which references audit_ssh_hardening()'s
    pre-existing findings for 3 of its 14 controls), no pre-existing
    kernel-sysctl findings function exists to link to — this module's
    Components and Findings are both fully self-contained (spec section 7).

    N/A handling (spec section 5) is a single group-level case, simpler
    than ssh_hardening's two-case handling (tool-not-installed vs.
    resolved-but-empty): sysctl is a kernel interface, not an optional
    installed package, so there is no "kernel doesn't have sysctl"
    equivalent to sshd-not-installed. The only failure mode is
    KernelConfig.readable being False - sudo lacked access, or `sysctl -a`
    returned nothing usable - in which case no hardening score is
    produced at all, matching nginx_hardening's and ssh_hardening's
    identical handling of the same shape of failure (no partial score).
    """
    cfg = collect_kernel_config(ssh)
    if not cfg.readable:
        result = {'readable': False,
                   'error': 'sysctl -a requires root — no read access to the effective '
                            'kernel configuration'}
        if cfg.kernel_version:
            # uname -r needs no privilege and is collected independently of
            # sysctl -a (see kernel_config.py's collect_kernel_config()) -
            # still worth returning even when the hardening score can't be
            # computed, same as ssh_hardening returns cfg.version in its
            # equivalent N/A branch.
            result['kernel_version'] = cfg.kernel_version
        return result

    hardening = weighted_score(_build_components(cfg))
    findings = _build_findings(cfg)

    return {
        'readable': True,
        'kernel_version': cfg.kernel_version,
        'hardening': hardening,
        'findings': findings,
    }


# ===========================================================================
# Registry entrypoint
# ===========================================================================

@register(
    id='kernel_hardening', label='Kernel sysctl hardening (SSH)', category='hardening',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH port', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Key path', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Password (if not using a key)', 'default': ''},
    ],
    required_tools=[],
    risk_level='READ_ONLY',
    description='Scores Linux kernel sysctl hardening — ASLR, kernel pointer/dmesg '
                'exposure, IP forwarding, ICMP/redirect handling, reverse-path '
                'filtering, SYN flood protection, and process-dump safety — against '
                'docs/checks/kernel_hardening.md (16 controls, 0-100 hardening score). '
                'Read-only.',
)
def check_kernel_hardening(host='', user='root', port=22, key_path='', password='') -> dict:
    """Public registry entrypoint - opens its own SSH session when run
    standalone, then delegates to audit_kernel_hardening_score(). Callers
    that already hold an open SSHExecutor should call
    audit_kernel_hardening_score(ssh) directly instead, to avoid a second
    SSH connection to the same host. Mirrors check_ssh_hardening()'s and
    check_nginx_hardening()'s identical connect/delegate/close shape."""
    if paramiko is None:
        return {'error': 'paramiko not installed'}
    if not host:
        return {'error': 'host not specified'}

    try:
        ssh = SSHExecutor(host, user, port, key_path, password).connect()
    except HostKeyMismatchError as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': f'could not connect: {e}'}

    try:
        return audit_kernel_hardening_score(ssh)
    finally:
        ssh.close()
