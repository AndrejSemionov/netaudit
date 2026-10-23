"""
Check registry — the heart of the modularity. Each check registers itself via the
@register decorator and automatically becomes available in the CLI and the web UI.

Adding a new check = write a function with the @register(...) decorator. That's it.
Nothing else needs to change — not the CLI, not the web, not the UI.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

# What a check actually does to the target, in increasing order of consequence.
# This isn't decoration - it's meant to let the CLI/web UI warn appropriately
# before a check runs, and let future callers (scripts, CI) filter checks by
# how much they're willing to risk touching a target.
#
#   PASSIVE     external/local observation with zero interaction with the target
#               beyond what a normal DNS/TLS/HTTP client already does (dns_audit,
#               cert_transparency, ssl, http, breach_check)
#   READ_ONLY   reads the target over SSH/API but changes nothing (server_audit,
#               lynis_audit, docker_audit, aide_check in 'check' mode, backup_check)
#   ACTIVE      actively probes/tests the target beyond passive observation, in a
#               way that could be logged, rate-limited, or trip alerting on the
#               other end (sql_injection active mode, port scans)
#   MODIFYING   installs packages, writes files, changes configuration on the
#               target (auto_install=True paths, aide_check mode='init')
#   DESTRUCTIVE could plausibly damage data or availability if something goes
#               wrong (not currently used by any check - reserved for anything
#               like this added later, so it's flagged loudly rather than
#               silently defaulting to something safer-sounding)
RISK_LEVELS = ('PASSIVE', 'READ_ONLY', 'ACTIVE', 'MODIFYING', 'DESTRUCTIVE')

# Shared confirmation string for any param that gates a MODIFYING action
# (installing a package, initializing a database, etc). Using one shared
# string/param shape everywhere means every such gate looks and behaves the
# same in the CLI and the web UI, instead of each check inventing its own
# wording (see sql_injection's separate AUTH_CONFIRM before this existed).
CONFIRM_MODIFY = 'yes — modify the target system'


def confirm_param(label: str = 'Confirm system modification', default: str = 'no') -> dict:
    """A ready-made 'select' param spec for gating a MODIFYING action. Add
    this to a check's params list, then check `<param_name> == CONFIRM_MODIFY`
    in the check function before doing anything that installs/writes/changes
    state on the target - exactly the same shape sql_injection's
    'authorization' param already uses for ACTIVE scans."""
    return {
        'name': 'confirm_modify', 'type': 'select', 'label': label,
        'options': ['no', CONFIRM_MODIFY], 'default': default,
    }


# what a checkbox may be given as on the command line or in an API request;
# anything else is refused (docs/research/param_value_types.md)
CHECKBOX_WORDS = {'true': True, 'yes': True, '1': True, 'on': True,
                  'false': False, 'no': False, '0': False, 'off': False}
WHOLE_NUMBER = re.compile(r'[+-]?[0-9]+')

# what a text parameter with a `format` holds (docs/research/a4_1_param_audit.md):
# a value a local tool reads as its last argument must never start with "-"
# (dig -f <file> read a local file), and a URL must be http(s)
_HOST = re.compile(r'[\w.:-]{1,253}')        # host name (any script), IPv4, IPv6
_ZONE = re.compile(r'[\w.-]{1,64}')           # an interface name or number (fe80::1%eth0)
_INTERFACE = re.compile(r'[\w.:-]{1,64}')
_EMAIL = re.compile(r'[^@\s/?#\\,]+@([^@\s/?#\\,]+)')
FORMAT_EXPECTS = {
    'host': 'takes a host name or an IP address',
    'domains': 'takes host names separated by commas',
    'url': 'takes an http:// or https:// URL',
    'emails': 'takes email addresses separated by commas',
    'interface': 'takes a network interface name',
}


def _is_host(text: str) -> bool:
    if text.startswith('-'):
        return False
    if '%' in text:
        # only a link-local IPv6 address takes a zone (review #53 R1)
        address, _, zone = text.partition('%')
        try:
            ipaddress.IPv6Address(address)
        except ValueError:
            return False
        return bool(_ZONE.fullmatch(zone)) and not zone.startswith('-')
    return bool(_HOST.fullmatch(text))


def _is_url(text: str) -> bool:
    """http(s) only, after the `https://` the URL checks add when there is no
    scheme; the host must pass the host rule."""
    if text.startswith('-') or any(c.isspace() for c in text):
        return False
    try:
        parsed = urlparse(text if '://' in text else f'https://{text}')
    except ValueError:
        return False
    return parsed.scheme in ('http', 'https') and bool(parsed.hostname) and _is_host(parsed.hostname)


def _format_ok(form: str, text: str) -> bool:
    items = [item.strip() for item in text.split(',') if item.strip()]
    if form == 'host':
        return _is_host(text)
    if form == 'domains':
        return all(_is_host(item) for item in items)
    if form == 'url':
        return _is_url(text)
    if form == 'emails':
        return all((m := _EMAIL.fullmatch(item)) and _is_host(m.group(1)) for item in items)
    if form == 'interface':
        return bool(_INTERFACE.fullmatch(text)) and not text.startswith('-')
    raise ValueError(f'unknown format {form!r}')


def param_value(param: dict, value):
    """`value` as the check expects it for the type of `param`, so a word
    from the command line or a string from an API request never reaches a
    check as truthy text ('false') or as a shell fragment ('5; id').

    checkbox -> bool, number -> int (whole) or float within the float
    range (trends compare numbers as floats) and within the spec's
    `min`/`max`, select -> one of `options` (a name from `aliases` becomes
    its option), text with a `format` -> unchanged when it has that form
    (an empty value is left to the check). Other values are returned
    unchanged.
    Raises ValueError saying what the parameter takes - never with the value
    in it, a mistyped secret must not end up in a log."""
    kind = param.get('type')
    if kind == 'checkbox':
        if isinstance(value, bool):
            return value
        if type(value) is int and value in (0, 1):
            return bool(value)
        if isinstance(value, str) and value.strip().lower() in CHECKBOX_WORDS:
            return CHECKBOX_WORDS[value.strip().lower()]
        raise ValueError('takes true or false (also yes/no, 1/0, on/off)')
    if kind == 'number':
        number = None
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            number = value
        elif isinstance(value, str):
            text = value.strip()
            try:
                number = int(text) if WHOLE_NUMBER.fullmatch(text) else float(text)
            except ValueError:
                number = None
        try:
            finite = number is not None and math.isfinite(number)
        except OverflowError:  # an int beyond the float range (review #49 R1)
            finite = False
        if not finite:
            raise ValueError('takes a number')
        low, high = param.get('min'), param.get('max')
        if (low is not None and number < low) or (high is not None and number > high):
            raise ValueError(f'takes a number from {low} to {high}')
        return int(number) if number == int(number) else number
    if kind == 'select' and param.get('options'):
        if isinstance(value, str):
            if value in param['options']:
                return value
            if value in param.get('aliases', {}):
                return param['aliases'][value]
        raise ValueError('takes one of: ' + ', '.join(f'"{o}"' for o in param['options']))
    if kind == 'text' and param.get('format'):
        if value == '':
            return value  # not given: the check says what is missing
        if not isinstance(value, str) or not _format_ok(param['format'], value):
            raise ValueError(FORMAT_EXPECTS[param['format']])
    return value


@dataclass
class CheckSpec:
    """Description of a single check."""
    id: str                          # unique identifier (e.g. 'mtr')
    label: str                       # human-readable name for the UI
    category: str                    # group: network / site / server / performance / security
    func: Callable[..., Any]         # the executor function
    params: list[dict] = field(default_factory=list)  # UI params (name/type/label/default)
    required_tools: list[str] = field(default_factory=list)  # which binaries are needed
    description: str = ''             # hint shown in the UI
    risk_level: str = 'READ_ONLY'     # see RISK_LEVELS above; READ_ONLY is the most
                                       # common case among existing checks, so it's
                                       # the default rather than forcing every
                                       # @register(...) call to specify one

    def __post_init__(self):
        if self.risk_level not in RISK_LEVELS:
            raise ValueError(f'{self.id}: risk_level must be one of {RISK_LEVELS}, got {self.risk_level!r}')


class Registry:
    """Storage for all registered checks."""

    def __init__(self) -> None:
        self._checks: dict[str, CheckSpec] = {}

    def register(self, spec: CheckSpec) -> None:
        if spec.id in self._checks:
            raise ValueError(f'Check with id={spec.id} is already registered')
        self._checks[spec.id] = spec

    def get(self, check_id: str) -> CheckSpec | None:
        return self._checks.get(check_id)

    def all(self) -> list[CheckSpec]:
        return list(self._checks.values())

    def by_category(self) -> dict[str, list[CheckSpec]]:
        result: dict[str, list[CheckSpec]] = {}
        for spec in self._checks.values():
            result.setdefault(spec.category, []).append(spec)
        return result


# Global registry
registry = Registry()


def register(id: str, label: str, category: str, params: list[dict] | None = None,
             required_tools: list[str] | None = None, description: str = '',
             risk_level: str = 'READ_ONLY'):
    """Decorator for registering a check."""
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        registry.register(CheckSpec(
            id=id, label=label, category=category, func=func,
            params=params or [], required_tools=required_tools or [],
            description=description, risk_level=risk_level,
        ))
        return func
    return decorator
