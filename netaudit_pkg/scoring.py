"""
Hardening score contract: the single implementation of the weighted-average
math every hardening module (nginx_hardening, ssh_hardening, kernel_hardening,
docker_hardening, ...) uses to turn its sub-checks into a 0-100 score.

Full rationale and the JSON contract this implements: docs/scoring.md.

This module exists so a hardening module can't hand-roll its own weighted
average and silently produce a nonsensical score (weights that don't sum to
1.0, a sub-score above its own max, etc.) - weighted_score() validates the
input and raises ValueError rather than clamping or "fixing" bad data,
because a hardening module with a weight-sum bug should fail loudly the
first time it's run, not produce a plausible-looking wrong number forever.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# sum(weight) must equal 1.0 within this tolerance. Strict on purpose - see
# docs/scoring.md "weighted_score()" for why this isn't relaxed to "close enough".
_WEIGHT_SUM_TOLERANCE = 1e-6


@dataclass
class Component:
    """One weighted sub-check that feeds into a hardening score.

    `score`/`max` are the sub-check's own result on whatever scale makes
    sense for it (doesn't have to be 0-100) - weighted_score() normalizes
    each component to a 0-1 fraction of its own max before weighting, so
    components can mix scales (e.g. one component scored out of 10, another
    out of 100) without the caller doing any conversion.

    `applicable=False` marks a component the check couldn't evaluate (e.g. an
    SSH session that dropped mid-audit, or a control that doesn't apply to
    this build - "HTTP/2 config" when nginx was compiled without the http_v2
    module). Neither `score=0` (would look like "failed the check", falsely
    lowering the result) nor `score=max` (would look like "passed", hiding
    that part of the audit didn't run) is correct here - the component is
    excluded from the weighted average entirely, and weighted_score()
    redistributes its weight proportionally across the remaining applicable
    components, so a module's score is never silently inflated or deflated
    by a control it couldn't check. `score`/`max` are still required and
    still validated even when not applicable (use 0/100 as a neutral
    placeholder - see docs/scoring.md "Control score scale" for why hardening
    modules use a 0-100 scale for every control, binary or not) so the
    dataclass shape stays uniform for serialization.

    `finding_id` optionally links this component to a specific Finding (see
    findings.py) the same check produced for the same control - e.g. a
    'server_tokens' component links to the Finding titled "Server version
    disclosure enabled" that explains *why* it scored 0/100. This is an
    explicit link (a string id set by the calling module) rather than an
    implicit one (matching Component.name against Finding.title/id by
    string) - implicit matching is a naming convention that silently breaks
    the moment either side gets renamed, whereas a module that sets
    finding_id is making a deliberate, checkable connection. Findings and
    Components remain two separate lists in a check's result either way -
    finding_id doesn't merge them, it lets a reader (the web UI, the AI
    analysis) look up "which finding explains this component's score"
    without guessing.
    """

    name: str
    weight: float
    score: float
    max: float
    applicable: bool = True
    reason: str = ''
    finding_id: str | None = None

    def __post_init__(self):
        if not self.name or not isinstance(self.name, str):
            raise ValueError(f'Component: name must be a non-empty string, got {self.name!r}')
        if not isinstance(self.weight, (int, float)) or self.weight <= 0:
            raise ValueError(
                f'Component {self.name!r}: weight must be > 0, got {self.weight!r} '
                f'(a weight of 0 should be omitted from the components list entirely, '
                f'not included as dead weight)'
            )
        if not isinstance(self.max, (int, float)) or self.max <= 0:
            raise ValueError(f'Component {self.name!r}: max must be > 0, got {self.max!r}')
        if not isinstance(self.score, (int, float)) or not (0 <= self.score <= self.max):
            raise ValueError(
                f'Component {self.name!r}: score must satisfy 0 <= score <= max, '
                f'got score={self.score!r} max={self.max!r} - a sub-check that scored '
                f'outside its own declared range is a bug in that sub-check, not a value '
                f'to clamp and hide'
            )

    def to_dict(self) -> dict:
        d = {'name': self.name, 'weight': self.weight, 'score': self.score, 'max': self.max}
        if not self.applicable:
            d['applicable'] = False
            if self.reason:
                d['reason'] = self.reason
        if self.finding_id:
            d['finding_id'] = self.finding_id
        return d


@dataclass
class ScoreResult:
    score: int
    max: int
    components: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {'score': self.score, 'max': self.max, 'components': self.components}


def weighted_score(components: list[dict] | list[Component]) -> dict:
    """Combine weighted sub-check components into a single 0-100 hardening score.

    Input: a non-empty list of components, each either a Component instance
    or a dict with keys name/weight/score/max (dicts are converted to
    Component, which runs the same validation either way).

    Formula: components with applicable=False are excluded, and their weight
    is redistributed proportionally across the remaining applicable
    components (so their relative weighting to each other is unchanged, they
    just now cover the full 1.0). Each remaining component is normalized to
    a 0-1 fraction of its own max, multiplied by its (redistributed) weight,
    summed, then scaled to 0-100 and rounded to the nearest integer:

        score = round(100 * sum(weight_i' * (score_i / max_i) for each applicable component))

    where weight_i' = weight_i / sum(weight of applicable components).

    Raises ValueError (does not silently correct) when:
      - components is empty or not a list
      - any component fails its own validation (see Component.__post_init__:
        non-positive weight, non-positive max, score outside [0, max])
      - the weights across ALL components (applicable or not) don't sum to
        1.0 within 1e-6 - this validates the module author's original
        weighting is well-formed, before any N/A redistribution happens.
        Deliberately strict; see docs/scoring.md for why a module with a
        weight-sum bug should fail immediately rather than produce a
        plausible-looking wrong score.
      - every component is applicable=False - a score with zero applicable
        components is undefined, not zero (zero would look like "everything
        failed", which is a different, false claim - this must fail loudly
        so the caller changes its report shape entirely, e.g. skipping the
        hardening score for this run rather than showing a fake 0/100).

    Returns {'score': int, 'max': 100, 'components': [...]} - 'max' is always
    100 regardless of what scale individual components used internally, per
    the contract in docs/scoring.md. 'components' includes ALL components,
    including inapplicable ones (marked applicable: false), so the caller
    can still show what wasn't checked and why.
    """
    if not isinstance(components, list) or not components:
        raise ValueError(
            f'weighted_score: components must be a non-empty list, got {components!r}'
        )

    parsed: list[Component] = [
        c if isinstance(c, Component) else Component(**c) for c in components
    ]

    # validate the *original* weighting is well-formed before any N/A
    # redistribution - a module author's weights must sum to 1.0 regardless
    # of which components end up applicable at run time.
    weight_sum = sum(c.weight for c in parsed)
    if abs(weight_sum - 1.0) > _WEIGHT_SUM_TOLERANCE:
        names = ', '.join(f'{c.name}={c.weight}' for c in parsed)
        raise ValueError(
            f'weighted_score: component weights must sum to 1.0, got {weight_sum!r} '
            f'({names})'
        )

    applicable = [c for c in parsed if c.applicable]
    if not applicable:
        raise ValueError(
            'weighted_score: all components are applicable=False - a score with zero '
            'applicable components is undefined, not zero. The caller should omit the '
            'hardening score entirely for this run rather than call weighted_score().'
        )

    applicable_weight_sum = sum(c.weight for c in applicable)
    fraction = sum(
        (c.weight / applicable_weight_sum) * (c.score / c.max) for c in applicable
    )
    score = round(100 * fraction)

    return ScoreResult(score=score, max=100, components=[c.to_dict() for c in parsed]).to_dict()
