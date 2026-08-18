"""
Logs Audit — Findings (Findings layer): turns a DetectionResult (facts:
counts, evidence, signals) into Finding objects (interpreted: severity,
confidence, recommendation) — the last step in the Discovery -> Collection
-> Parser -> Detection -> Findings chain. This module answers "what do
these facts mean for the audit", never re-derives or second-guesses the
facts themselves.

Scope (per Finding Contract freeze)
------------------------------------------------------------------
- One DetectionSignal produces exactly one Finding. No merging across
  signal types, even when they share a source_ip or username — see
  ssh_auth_detection.py's Rule 5 (overlapping evidence is expected) and
  this module's own decision not to add a second aggregation layer on
  top of Detection's.
- Finding.evidence contains ALL raw_line values belonging to the
  signal's events, newline-separated, with no truncation — evidence is
  the audit's source of truth (see ssh_auth_parser.py's raw_line
  docstring: "source of truth if parsing is partial or uncertain").
  Any display-size limiting is a presentation-layer concern, not this
  module's.
- coverage_uncertain=True downgrades confidence to 'medium' for ANY
  Finding whose evidence depends on it — it NEVER changes severity.
  Severity is a statement about what the evidence shows; confidence is
  a statement about how complete that evidence might be. Conflating
  them would let incomplete data quietly understate a real finding's
  severity.
- requires_manual_verification=True is a POLICY decision (not an
  automatic function of confidence): set when a HIGH-severity finding's
  confidence has been downgraded by coverage_uncertain. Lower-severity
  findings under the same coverage_uncertain condition still get
  confidence='medium', but requires_manual_verification stays False —
  see this module's docstring, "Test Matrix", cases 7-8.
- recommendation is only ever populated from KNOWN infrastructure state
  (e.g. whether fail2ban was found active/inactive by a separate audit
  contour already in this project). This module never asserts or
  implies fail2ban's state from SSH authentication findings alone.
  Iteration 4's scope does not yet wire in that cross-check — see this
  module's build_findings() signature for the (currently unused)
  extension point.
- Reference thresholds (SSHFindingPolicy) are attributed explicitly in
  every Finding.detail that uses one: Fail2Ban upstream jail.conf
  defaults are labeled as an external reference baseline, and
  NetAudit-only policy numbers (distributed_ip_threshold,
  invalid_username_diversity_threshold) are labeled as NetAudit
  engineering policy, not externally validated standards. See
  SSHFindingPolicy's own field docstrings.
- A successful Detection run with zero signals produces exactly one
  'ok' Finding ("no suspicious SSH authentication activity detected in
  the analyzed window"). An EMPTY DetectionResult is NOT automatically
  treated as "all clear" by this module — build_findings() takes an
  explicit detection_succeeded flag from its caller, who is the only
  layer that actually knows whether Collection/Detection ran
  successfully at all, as opposed to producing zero signals because the
  source was empty, unavailable, or a collection failure occurred. This
  module never infers success from the mere absence of signals.
"""

from __future__ import annotations

from dataclasses import dataclass

from .findings import finding as _finding
from .ssh_auth_detection import (
    DetectionResult,
    RepeatedFailuresForUsernameSignal,
    RepeatedFailuresFromIPSignal,
    SuccessAfterFailureSignal,
)


@dataclass(frozen=True)
class SSHFindingPolicy:
    reference_maxretry: int = 5
    """Source: Fail2Ban upstream jail.conf [DEFAULT]. An external
    reference baseline for interpreting repeated-failure counts — NOT a
    universal security threshold NetAudit asserts on its own authority.
    Fail2Ban jails may override this per-jail; this value is used only
    to give Finding.detail a documented, attributable comparison point."""

    reference_findtime_minutes: int = 10
    """Source: Fail2Ban upstream jail.conf [DEFAULT]. Same status as
    reference_maxretry — a reference window for the reference_maxretry
    comparison, not a claim about NetAudit's own DetectionContext.window
    (which is set independently by the caller)."""

    distributed_ip_threshold: int = 2
    """NetAudit engineering policy, NOT externally validated. Minimum
    number of distinct source IPs (for the same username) required to
    emit a distributed-source Finding at all. '2' is chosen as the
    minimum cardinality for which 'distinct sources' is a meaningful
    statement (one source cannot be 'distributed') — it is not a claim
    that 2 sources constitutes an attack."""

    invalid_username_diversity_threshold: int = 2
    """NetAudit engineering policy, NOT externally validated. Minimum
    number of distinct invalid usernames (from the same source_ip)
    required to treat the pattern as enumeration/diversity evidence
    rather than repeated attempts against a single guessed name. Same
    '2 is the minimum meaningful cardinality' reasoning as
    distributed_ip_threshold."""


DEFAULT_POLICY = SSHFindingPolicy()


def _cite_fail2ban(policy: SSHFindingPolicy) -> str:
    return (f'Fail2Ban upstream jail.conf [DEFAULT] reference baseline: '
            f'{policy.reference_maxretry} failures / {policy.reference_findtime_minutes}m. '
            f'This is an external reference for comparison, not a NetAudit-asserted universal threshold — '
            f'individual Fail2Ban jails may override these values.')


def _cite_netaudit_policy(field_name: str, value: int) -> str:
    return (f'NetAudit engineering policy ({field_name}={value}), not an externally validated security '
            f'standard — chosen as the minimum cardinality at which this evidence dimension becomes meaningful.')


def _evidence(events) -> str:
    """ALL raw_line values, newline-separated, no truncation — see this
    module's docstring on why evidence is never size-limited here."""
    return '\n'.join(e.raw_line for e in events)


def _apply_coverage(base_confidence: str, severity: str, coverage_uncertain: bool) -> tuple[str, bool]:
    """Returns (confidence, requires_manual_verification). coverage_uncertain
    downgrades confidence for ANY severity, but requires_manual_verification
    is only set True for 'high' severity findings — see this module's
    docstring, Rules on confidence vs requires_manual_verification."""
    if not coverage_uncertain:
        return base_confidence, False
    return 'medium', severity == 'high'


def _ip_signal_finding(signal: RepeatedFailuresFromIPSignal, policy: SSHFindingPolicy,
                        coverage_uncertain: bool) -> dict:
    total = signal.failed_password_count + signal.invalid_user_count
    diversity = len(signal.invalid_usernames)

    # Base severity from total repeated-failure count against the
    # Fail2Ban reference baseline (Scenario Matrix v1: 1=info, 2-4=low, >=5=high)
    if total <= 1:
        severity = 'info'
    elif total < policy.reference_maxretry:
        severity = 'low'
    else:
        severity = 'high'

    # Invalid-user diversity is an independent evidence dimension (per
    # this module's frozen rule): insufficient diversity caps
    # enumeration-driven severity at 'low' even when count alone would
    # reach 'high', but never suppresses the finding outright — the
    # underlying repeated-attempt signal (against a nonexistent account)
    # remains valid evidence on its own.
    if signal.invalid_user_count > 0 and diversity < policy.invalid_username_diversity_threshold:
        if severity == 'high' and signal.failed_password_count == 0:
            severity = 'low'

    detail_parts = [_cite_fail2ban(policy)]
    if signal.invalid_user_count > 0:
        detail_parts.append(
            f'{signal.invalid_user_count} invalid-user attempt(s) against {diversity} distinct username(s). ' +
            _cite_netaudit_policy('invalid_username_diversity_threshold', policy.invalid_username_diversity_threshold)
        )

    title = f'Repeated SSH authentication failures from {signal.source_ip}'
    confidence, manual = _apply_coverage('high', severity, coverage_uncertain)

    return _finding(
        severity, title, detail=' '.join(detail_parts), confidence=confidence,
        evidence=_evidence(signal.events), requires_manual_verification=manual,
        check='ssh_auth_findings',
    )


def _username_signal_finding(signal: RepeatedFailuresForUsernameSignal, policy: SSHFindingPolicy,
                              coverage_uncertain: bool) -> dict:
    distinct_ips = len(signal.source_ips)

    if distinct_ips < policy.distributed_ip_threshold:
        severity = 'info'
    elif signal.failed_password_count >= policy.reference_maxretry:
        severity = 'high'
    else:
        severity = 'low' if distinct_ips >= policy.distributed_ip_threshold else 'info'

    detail = (
        f'{signal.failed_password_count} failed password attempt(s) for username {signal.username!r} '
        f'from {distinct_ips} distinct source IP(s). ' +
        _cite_netaudit_policy('distributed_ip_threshold', policy.distributed_ip_threshold)
    )

    title = f'SSH authentication failures for username {signal.username!r} from multiple sources'
    confidence, manual = _apply_coverage('high', severity, coverage_uncertain)

    return _finding(
        severity, title, detail=detail, confidence=confidence,
        evidence=_evidence(signal.events), requires_manual_verification=manual,
        check='ssh_auth_findings',
    )


def _success_after_failure_finding(signal: SuccessAfterFailureSignal, policy: SSHFindingPolicy,
                                    coverage_uncertain: bool) -> dict:
    count = len(signal.failed_events)
    severity = 'high' if count >= policy.reference_maxretry else ('low' if count >= 2 else 'info')

    detail = (
        f'Successful SSH authentication for {signal.username!r} from {signal.source_ip} followed '
        f'{count} failed attempt(s). ' + _cite_fail2ban(policy)
    )

    title = f'Successful SSH login after repeated failures — {signal.username!r} from {signal.source_ip}'
    confidence, manual = _apply_coverage('high', severity, coverage_uncertain)

    all_events = signal.failed_events + [signal.accepted_event]
    return _finding(
        severity, title, detail=detail, confidence=confidence,
        evidence=_evidence(all_events), requires_manual_verification=manual,
        check='ssh_auth_findings',
    )


def build_findings(result: DetectionResult, detection_succeeded: bool,
                    policy: SSHFindingPolicy = DEFAULT_POLICY) -> list[dict]:
    """Turns a DetectionResult into a list of Finding dicts (via
    netaudit_pkg.findings.finding()).

    detection_succeeded must be supplied explicitly by the caller, who
    is the only layer with visibility into whether Collection/Detection
    actually ran to completion (as opposed to producing an empty
    DetectionResult because of a collection failure or an unavailable
    source). This module never infers success from an empty signal
    list — see this module's own docstring. When detection_succeeded is
    False, this function returns an empty list; it is the caller's
    responsibility to surface the underlying collection/availability
    problem as its own finding (already covered elsewhere in Logs Audit
    — see log_discovery_audit.py for the Discovery-level equivalent).
    """
    if not detection_succeeded:
        return []

    findings: list[dict] = []

    for signal in result.repeated_failures_by_ip:
        findings.append(_ip_signal_finding(signal, policy, result.coverage_uncertain))

    for signal in result.repeated_failures_by_username:
        findings.append(_username_signal_finding(signal, policy, result.coverage_uncertain))

    for signal in result.success_after_failure:
        findings.append(_success_after_failure_finding(signal, policy, result.coverage_uncertain))

    if not findings:
        findings.append(_finding(
            'ok', 'SSH authentication activity — no suspicious patterns detected',
            detail=(
                'SSH authentication logs were successfully collected and analyzed. No repeated-failure, '
                'distributed-source, invalid-user enumeration, or success-after-failure detection signals '
                'were identified within the analyzed window.'
            ),
            confidence='high', check='ssh_auth_findings',
        ))

    return findings
