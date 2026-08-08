"""Tests for netaudit_pkg.registry: CheckSpec, risk_level validation, the
@register decorator, and Registry lookup/grouping."""

from __future__ import annotations

import pytest

from netaudit_pkg.registry import CheckSpec, Registry, RISK_LEVELS, register


def _dummy_func():
    return {}


def test_checkspec_default_risk_level():
    spec = CheckSpec(id='t1', label='Test', category='test', func=_dummy_func)
    assert spec.risk_level == 'READ_ONLY'


def test_checkspec_explicit_risk_level():
    spec = CheckSpec(id='t2', label='Test', category='test', func=_dummy_func,
                      risk_level='PASSIVE')
    assert spec.risk_level == 'PASSIVE'


def test_checkspec_rejects_invalid_risk_level():
    with pytest.raises(ValueError, match='risk_level'):
        CheckSpec(id='t3', label='Test', category='test', func=_dummy_func,
                  risk_level='BOGUS')


def test_all_risk_levels_are_accepted():
    for level in RISK_LEVELS:
        spec = CheckSpec(id=f'level-{level}', label='Test', category='test',
                          func=_dummy_func, risk_level=level)
        assert spec.risk_level == level


def test_registry_register_and_get():
    reg = Registry()
    spec = CheckSpec(id='foo', label='Foo', category='test', func=_dummy_func)
    reg.register(spec)
    assert reg.get('foo') is spec
    assert reg.get('missing') is None


def test_registry_rejects_duplicate_id():
    reg = Registry()
    reg.register(CheckSpec(id='dup', label='A', category='test', func=_dummy_func))
    with pytest.raises(ValueError, match='already registered'):
        reg.register(CheckSpec(id='dup', label='B', category='test', func=_dummy_func))


def test_registry_all_and_by_category():
    reg = Registry()
    reg.register(CheckSpec(id='a', label='A', category='network', func=_dummy_func))
    reg.register(CheckSpec(id='b', label='B', category='network', func=_dummy_func))
    reg.register(CheckSpec(id='c', label='C', category='server', func=_dummy_func))

    assert {s.id for s in reg.all()} == {'a', 'b', 'c'}

    by_cat = reg.by_category()
    assert {s.id for s in by_cat['network']} == {'a', 'b'}
    assert {s.id for s in by_cat['server']} == {'c'}


def test_register_decorator_defaults_to_read_only():
    reg = Registry()

    def deco(**kw):
        # mirror the module-level register() but target our isolated registry
        def decorator(func):
            reg.register(CheckSpec(
                id=kw['id'], label=kw['label'], category=kw['category'], func=func,
                params=kw.get('params') or [], required_tools=kw.get('required_tools') or [],
                description=kw.get('description', ''), risk_level=kw.get('risk_level', 'READ_ONLY'),
            ))
            return func
        return decorator

    @deco(id='decorated', label='Decorated', category='test')
    def check_something():
        return {}

    spec = reg.get('decorated')
    assert spec is not None
    assert spec.risk_level == 'READ_ONLY'
    assert spec.func is check_something


def test_register_decorator_with_explicit_risk_level():
    """The real module-level register() from registry.py, exercised directly -
    registers into the real global registry, so we clean up after ourselves
    to avoid polluting other tests that inspect the global registry."""
    from netaudit_pkg.registry import registry as global_registry

    @register(id='__test_only_active_check__', label='Test', category='test',
              risk_level='ACTIVE')
    def check_test_active():
        return {}

    try:
        spec = global_registry.get('__test_only_active_check__')
        assert spec is not None
        assert spec.risk_level == 'ACTIVE'
    finally:
        global_registry._checks.pop('__test_only_active_check__', None)
