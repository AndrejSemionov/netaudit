"""
Check registry — the heart of the modularity. Each check registers itself via the
@register decorator and automatically becomes available in the CLI and the web UI.

Adding a new check = write a function with the @register(...) decorator. That's it.
Nothing else needs to change — not the CLI, not the web, not the UI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Any


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
             required_tools: list[str] | None = None, description: str = ''):
    """Decorator for registering a check."""
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        registry.register(CheckSpec(
            id=id, label=label, category=category, func=func,
            params=params or [], required_tools=required_tools or [],
            description=description,
        ))
        return func
    return decorator
