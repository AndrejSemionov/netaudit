"""
Tests for netaudit_pkg.scoring: Component validation and the weighted_score()
math, per the contract in docs/scoring.md.
"""

from __future__ import annotations

import pytest

from netaudit_pkg.scoring import Component, weighted_score


# ===========================================================================
# Component validation
# ===========================================================================

def test_component_valid_construction():
    c = Component(name='tls', weight=0.5, score=80, max=100)
    assert c.to_dict() == {'name': 'tls', 'weight': 0.5, 'score': 80, 'max': 100}


def test_component_rejects_empty_name():
    with pytest.raises(ValueError, match='non-empty string'):
        Component(name='', weight=0.5, score=50, max=100)


def test_component_rejects_zero_weight():
    with pytest.raises(ValueError, match='weight must be > 0'):
        Component(name='tls', weight=0, score=50, max=100)


def test_component_rejects_negative_weight():
    with pytest.raises(ValueError, match='weight must be > 0'):
        Component(name='tls', weight=-0.1, score=50, max=100)


def test_component_rejects_zero_max():
    with pytest.raises(ValueError, match='max must be > 0'):
        Component(name='tls', weight=0.5, score=0, max=0)


def test_component_rejects_score_above_max():
    with pytest.raises(ValueError, match='0 <= score <= max'):
        Component(name='tls', weight=0.5, score=150, max=100)


def test_component_rejects_negative_score():
    with pytest.raises(ValueError, match='0 <= score <= max'):
        Component(name='tls', weight=0.5, score=-5, max=100)


def test_component_allows_score_equal_to_max():
    c = Component(name='tls', weight=1.0, score=100, max=100)
    assert c.score == c.max


def test_component_allows_score_equal_to_zero():
    c = Component(name='tls', weight=1.0, score=0, max=100)
    assert c.score == 0


# ===========================================================================
# weighted_score() — happy path
# ===========================================================================

def test_weighted_score_single_full_component():
    result = weighted_score([{'name': 'tls', 'weight': 1.0, 'score': 100, 'max': 100}])
    assert result == {'score': 100, 'max': 100, 'components': [
        {'name': 'tls', 'weight': 1.0, 'score': 100, 'max': 100},
    ]}


def test_weighted_score_single_zero_component():
    result = weighted_score([{'name': 'tls', 'weight': 1.0, 'score': 0, 'max': 100}])
    assert result['score'] == 0


def test_weighted_score_from_docs_example():
    # exact example from docs/scoring.md
    components = [
        {'name': 'tls', 'weight': 0.30, 'score': 94, 'max': 100},
        {'name': 'security_headers', 'weight': 0.25, 'score': 80, 'max': 100},
        {'name': 'configuration', 'weight': 0.25, 'score': 75, 'max': 100},
        {'name': 'filesystem', 'weight': 0.10, 'score': 100, 'max': 100},
        {'name': 'exposure', 'weight': 0.10, 'score': 60, 'max': 100},
    ]
    result = weighted_score(components)
    # 0.30*94 + 0.25*80 + 0.25*75 + 0.10*100 + 0.10*60
    # = 28.2 + 20 + 18.75 + 10 + 6 = 82.95 -> rounds to 83
    assert result['score'] == 83
    assert result['max'] == 100
    assert len(result['components']) == 5


def test_weighted_score_normalizes_mixed_scales():
    # one component out of 10, one out of 100 - both should normalize correctly
    components = [
        {'name': 'a', 'weight': 0.5, 'score': 5, 'max': 10},   # 0.5 fraction
        {'name': 'b', 'weight': 0.5, 'score': 50, 'max': 100},  # 0.5 fraction
    ]
    result = weighted_score(components)
    assert result['score'] == 50


def test_weighted_score_accepts_component_instances():
    components = [Component(name='tls', weight=1.0, score=90, max=100)]
    result = weighted_score(components)
    assert result['score'] == 90


def test_weighted_score_result_max_always_100():
    components = [{'name': 'a', 'weight': 1.0, 'score': 5, 'max': 10}]
    result = weighted_score(components)
    assert result['max'] == 100


# ===========================================================================
# weighted_score() — error cases
# ===========================================================================

def test_weighted_score_rejects_empty_list():
    with pytest.raises(ValueError, match='non-empty list'):
        weighted_score([])


def test_weighted_score_rejects_non_list():
    with pytest.raises(ValueError, match='non-empty list'):
        weighted_score(None)


def test_weighted_score_rejects_weights_summing_below_one():
    components = [
        {'name': 'a', 'weight': 0.3, 'score': 50, 'max': 100},
        {'name': 'b', 'weight': 0.3, 'score': 50, 'max': 100},
        {'name': 'c', 'weight': 0.2, 'score': 50, 'max': 100},
    ]
    with pytest.raises(ValueError, match='must sum to 1.0'):
        weighted_score(components)


def test_weighted_score_rejects_weights_summing_above_one():
    components = [
        {'name': 'a', 'weight': 0.6, 'score': 50, 'max': 100},
        {'name': 'b', 'weight': 0.6, 'score': 50, 'max': 100},
    ]
    with pytest.raises(ValueError, match='must sum to 1.0'):
        weighted_score(components)


def test_weighted_score_propagates_component_validation_error():
    # a bad component (score > max) should fail even before weight-sum is checked
    components = [{'name': 'a', 'weight': 1.0, 'score': 200, 'max': 100}]
    with pytest.raises(ValueError, match='0 <= score <= max'):
        weighted_score(components)


def test_weighted_score_tolerates_float_rounding_noise():
    # 0.1 + 0.2 + 0.7 in floating point is 0.9999999999999999, not exactly 1.0 -
    # this must NOT raise, since it's within the documented 1e-6 tolerance.
    components = [
        {'name': 'a', 'weight': 0.1, 'score': 100, 'max': 100},
        {'name': 'b', 'weight': 0.2, 'score': 100, 'max': 100},
        {'name': 'c', 'weight': 0.7, 'score': 100, 'max': 100},
    ]
    result = weighted_score(components)
    assert result['score'] == 100
