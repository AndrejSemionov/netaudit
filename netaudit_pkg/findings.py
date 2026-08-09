"""
Shared Finding model.

Every check that produces a list of findings (docker_audit, backup_check,
aide_check, rootkit_check, lynis_audit, server_security, dns_audit,
breach_check, cert_transparency, ...) used to define its own private
`_finding(severity, title, detail='', confidence='high', id=None)` helper.
All nine copies were byte-for-byte identical - this module replaces them
with one implementation, so a future change (a new field, a stricter
validation rule) only has to happen once.

`Finding` is a dataclass rather than a plain dict for two reasons: (1) the
fields are enumerated in one place instead of implicitly by whatever keys
happen to get set, and (2) __post_init__ can validate severity/confidence
the moment a Finding is constructed, instead of letting a typo'd value
(e.g. 'hihg') silently flow all the way to the report JSON.

`.to_dict()` keeps the wire format identical to what checks/history/the web
UI already expect: a plain dict with only the keys that were actually set
(no `id` key at all when id wasn't given, matching the old helper's
`if id: f['id'] = id` behavior) - so this migration is a drop-in
replacement, not a breaking change to the report schema.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# 'ok' is not in the reviewer's suggested set (critical/high/medium/low/info)
# but is already used throughout the codebase (dns_audit, lynis_audit, etc.)
# to mean "checked, no issue found" - distinct from 'info' which would imply
# a neutral observation rather than a passed check. Kept here rather than
# renamed everywhere to avoid a breaking change to already-shipped reports.
SEVERITIES = ('critical', 'high', 'medium', 'low', 'info', 'ok')
CONFIDENCES = ('high', 'medium', 'low')


@dataclass
class Finding:
    """A single audit finding, in the shape every check/history/web UI already expects.

    id and check are optional because most existing call sites don't set them
    (findings are grouped by check ID at the report level already, in
    report['results'][check_id]) - required=True would force a mechanical
    migration of every call site with no benefit. New checks are encouraged
    to set both for tighter traceability (e.g. cross-referencing a specific
    finding from an AI analysis).
    """

    severity: str
    title: str
    detail: str = ''
    confidence: str = 'high'
    id: str | None = None
    check: str | None = None
    description: str = ''
    evidence: str = ''
    recommendation: str = ''
    requires_manual_verification: bool = False
    extra: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f'Finding: severity must be one of {SEVERITIES}, got {self.severity!r}')
        if self.confidence not in CONFIDENCES:
            raise ValueError(f'Finding: confidence must be one of {CONFIDENCES}, got {self.confidence!r}')

    def to_dict(self) -> dict:
        """Plain-dict form matching the historical _finding() output: only
        severity/title/detail/confidence are always present, everything else
        (id, check, description, evidence, recommendation,
        requires_manual_verification, extra) is included only when set, so
        old reports and new reports look the same unless a check opts into
        the richer fields."""
        d = {
            'severity': self.severity,
            'title': self.title,
            'detail': self.detail,
            'confidence': self.confidence,
        }
        if self.id:
            d['id'] = self.id
        if self.check:
            d['check'] = self.check
        if self.description:
            d['description'] = self.description
        if self.evidence:
            d['evidence'] = self.evidence
        if self.recommendation:
            d['recommendation'] = self.recommendation
        if self.requires_manual_verification:
            d['requires_manual_verification'] = self.requires_manual_verification
        if self.extra:
            d.update(self.extra)
        return d


def finding(severity: str, title: str, detail: str = '', confidence: str = 'high',
            id: str | None = None, **kwargs) -> dict:
    """Functional shortcut so existing call sites (`_finding('high', 'title', 'detail')`)
    convert to `finding('high', 'title', 'detail')` with a one-line import change and
    no other edits needed. Returns a dict, same as the old per-module helper did."""
    return Finding(severity=severity, title=title, detail=detail, confidence=confidence,
                    id=id, **kwargs).to_dict()
