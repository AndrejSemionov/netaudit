"""
Реестр проверок — сердце модульности. Каждая проверка регистрируется декоратором
@register и автоматически становится доступна в CLI и веб-интерфейсе.

Добавить новую проверку = создать функцию с декоратором @register(...). Всё.
Ничего больше менять не нужно — ни CLI, ни веб, ни UI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Any


@dataclass
class CheckSpec:
    """Описание одной проверки."""
    id: str                          # уникальный идентификатор (например 'mtr')
    label: str                       # человекочитаемое имя для UI
    category: str                    # группа: network / site / server / performance / security
    func: Callable[..., Any]         # функция-исполнитель
    params: list[dict] = field(default_factory=list)  # параметры для UI (name/type/label/default)
    required_tools: list[str] = field(default_factory=list)  # какие бинарники нужны
    description: str = ''             # подсказка для UI


class Registry:
    """Хранилище всех зарегистрированных проверок."""

    def __init__(self) -> None:
        self._checks: dict[str, CheckSpec] = {}

    def register(self, spec: CheckSpec) -> None:
        if spec.id in self._checks:
            raise ValueError(f'Проверка с id={spec.id} уже зарегистрирована')
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


# Глобальный реестр
registry = Registry()


def register(id: str, label: str, category: str, params: list[dict] | None = None,
             required_tools: list[str] | None = None, description: str = ''):
    """Декоратор для регистрации проверки."""
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        registry.register(CheckSpec(
            id=id, label=label, category=category, func=func,
            params=params or [], required_tools=required_tools or [],
            description=description,
        ))
        return func
    return decorator
