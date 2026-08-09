"""
Check registry — the heart of the modularity. Each check registers itself via the
@register decorator and automatically becomes available in the CLI and the web UI.

Adding a new check = write a function with the @register(...) decorator. That's it.
Nothing else needs to change — not the CLI, not the web, not the UI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Any

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
