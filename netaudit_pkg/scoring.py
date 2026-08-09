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
    """

    name: str
    weight: float
    score: float
    max: float

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
        return {'name': self.name, 'weight': self.weight, 'score': self.score, 'max': self.max}


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

    Formula: each component is normalized to a 0-1 fraction of its own max,
    multiplied by its weight, summed across all components, then scaled to
    0-100 and rounded to the nearest integer:

        score = round(100 * sum(weight_i * (score_i / max_i) for each component))

    Raises ValueError (does not silently correct) when:
      - components is empty or not a list
      - any component fails its own validation (see Component.__post_init__:
        non-positive weight, non-positive max, score outside [0, max])
      - the weights across all components don't sum to 1.0 within 1e-6 -
        deliberately strict; see docs/scoring.md for why a module with a
        weight-sum bug should fail immediately rather than produce a
        plausible-looking wrong score.

    Returns {'score': int, 'max': 100, 'components': [...]} - 'max' is always
    100 regardless of what scale individual components used internally, per
    the contract in docs/scoring.md.
    """
    if not isinstance(components, list) or not components:
        raise ValueError(
            f'weighted_score: components must be a non-empty list, got {components!r}'
        )

    parsed: list[Component] = [
        c if isinstance(c, Component) else Component(**c) for c in components
    ]

    weight_sum = sum(c.weight for c in parsed)
    if abs(weight_sum - 1.0) > _WEIGHT_SUM_TOLERANCE:
        names = ', '.join(f'{c.name}={c.weight}' for c in parsed)
        raise ValueError(
            f'weighted_score: component weights must sum to 1.0, got {weight_sum!r} '
            f'({names})'
        )

    fraction = sum(c.weight * (c.score / c.max) for c in parsed)
    score = round(100 * fraction)

    return ScoreResult(score=score, max=100, components=[c.to_dict() for c in parsed]).to_dict()
