"""
Tests for netaudit_pkg.timing: decide_mode() with legacy single-instance
('params') and multi-instance ('instances') selected items.

decide_mode() had no dedicated test file before this - these tests lock down
both the pre-existing 'params' behavior (so the multi-instance change can't
silently break it) and the new 'instances' behavior in the same place.
"""

from __future__ import annotations

from netaudit_pkg import timing


def test_decide_mode_legacy_params_unchanged(monkeypatch):
    """Existing single-instance 'params' form: total = sum of per-check estimates."""
    monkeypatch.setattr(timing, 'estimate', lambda check_id, params: {
        'a': 1.0, 'b': 2.0,
    }[check_id])

    mode, total = timing.decide_mode([
        {'id': 'a', 'params': {}},
        {'id': 'b', 'params': {}},
    ], threshold=10.0)
    assert total == 3.0
    assert mode == 'sync'


def test_decide_mode_instances_uses_max_within_check(monkeypatch):
    """One check with 3 instances -> contributes max(estimates), not sum."""
    estimates_by_host = {'h1': 1.0, 'h2': 5.0, 'h3': 2.0}
    monkeypatch.setattr(timing, 'estimate',
                         lambda check_id, params: estimates_by_host[params['host']])

    mode, total = timing.decide_mode([
        {'id': 'cve', 'instances': [
            {'host': 'h1'}, {'host': 'h2'}, {'host': 'h3'},
        ]},
    ], threshold=10.0)
    assert total == 5.0  # max, not 1+5+2=8


def test_decide_mode_sums_across_checks_even_with_instances(monkeypatch):
    """Different checks still sum relative to each other; only instances
    *within* one check are collapsed via max."""
    def fake_estimate(check_id, params):
        table = {
            ('cve', 'h1'): 3.0, ('cve', 'h2'): 7.0,
            ('dns', None): 1.5,
        }
        return table[(check_id, params.get('host'))]

    monkeypatch.setattr(timing, 'estimate', fake_estimate)

    mode, total = timing.decide_mode([
        {'id': 'cve', 'instances': [{'host': 'h1'}, {'host': 'h2'}]},
        {'id': 'dns', 'params': {}},
    ], threshold=100.0)
    assert total == 7.0 + 1.5  # max(3,7) + 1.5, not 3+7+1.5


def test_decide_mode_mixed_legacy_and_instances_items(monkeypatch):
    """A single request can mix legacy 'params' checks and 'instances' checks."""
    def fake_estimate(check_id, params):
        table = {
            ('mtr', None): 4.0,
            ('cve', 'a'): 2.0, ('cve', 'b'): 6.0,
        }
        return table[(check_id, params.get('host'))]

    monkeypatch.setattr(timing, 'estimate', fake_estimate)

    mode, total = timing.decide_mode([
        {'id': 'mtr', 'params': {}},
        {'id': 'cve', 'instances': [{'host': 'a'}, {'host': 'b'}]},
    ], threshold=100.0)
    assert total == 4.0 + 6.0


def test_decide_mode_single_instance_list_behaves_like_legacy(monkeypatch):
    """A check with exactly one instance in 'instances' form gives the same
    total as the equivalent 'params' form (no special-casing needed, max of
    one value is just that value)."""
    monkeypatch.setattr(timing, 'estimate', lambda check_id, params: 3.5)

    _, total_instances = timing.decide_mode([
        {'id': 'cve', 'instances': [{'host': 'a'}]},
    ], threshold=100.0)
    _, total_params = timing.decide_mode([
        {'id': 'cve', 'params': {'host': 'a'}},
    ], threshold=100.0)
    assert total_instances == total_params == 3.5


def test_decide_mode_empty_instances_list_contributes_zero(monkeypatch):
    """Defensive: a check with an empty instances list shouldn't crash max()
    on an empty sequence - contributes 0 to the total."""
    monkeypatch.setattr(timing, 'estimate', lambda check_id, params: 99.0)

    mode, total = timing.decide_mode([
        {'id': 'cve', 'instances': []},
    ], threshold=100.0)
    assert total == 0.0


def test_decide_mode_force_async_still_returns_correct_total(monkeypatch):
    monkeypatch.setattr(timing, 'estimate',
                         lambda check_id, params: estimates_by_host[params['host']])
    estimates_by_host = {'h1': 1.0, 'h2': 5.0}

    mode, total = timing.decide_mode([
        {'id': 'cve', 'instances': [{'host': 'h1'}, {'host': 'h2'}]},
    ], force_async=True)
    assert mode == 'async'
    assert total == 5.0


def test_decide_mode_threshold_boundary_with_instances(monkeypatch):
    monkeypatch.setattr(timing, 'estimate', lambda check_id, params: 5.0)

    mode_at, _ = timing.decide_mode([
        {'id': 'cve', 'instances': [{'host': 'a'}, {'host': 'b'}]},
    ], threshold=5.0)
    assert mode_at == 'sync'

    mode_over, _ = timing.decide_mode([
        {'id': 'cve', 'instances': [{'host': 'a'}, {'host': 'b'}]},
    ], threshold=4.99)
    assert mode_over == 'async'
