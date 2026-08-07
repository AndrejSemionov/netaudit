"""Движок: выполняет выбранные проверки с их параметрами, замеряет время каждой."""

from __future__ import annotations

import time
from datetime import datetime

from .registry import registry
from .utils import log, missing_tools
from . import timing

# импорт регистрирует все проверки
from . import checks  # noqa: F401


def run_checks(selected: list[dict]) -> dict:
    """
    selected: список {'id': 'mtr', 'params': {'target': '8.8.8.8', 'count': 15}}
    Возвращает отчёт со временем выполнения каждой проверки.
    """
    report = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'results': {},
        'timing': {},
        'meta': {},
    }

    for item in selected:
        check_id = item['id']
        params = item.get('params', {})
        spec = registry.get(check_id)
        if spec is None:
            report['results'][check_id] = {'error': f'проверка {check_id} не найдена'}
            continue

        missing = missing_tools(spec.required_tools)
        if missing:
            report['results'][check_id] = {'error': f'нужны инструменты: {", ".join(missing)}'}
            report['timing'][check_id] = 0.0
            continue

        log.info(f'Running: {spec.label} ({check_id})...')
        start = time.monotonic()
        try:
            result = spec.func(**params)
        except Exception as e:
            result = {'error': f'исключение: {type(e).__name__}: {e}'}
        elapsed = round(time.monotonic() - start, 2)

        # обучаем адаптивную систему на реальном времени (только успешные прогоны,
        # чтобы ошибки инструмента не искажали оценку)
        if not (isinstance(result, dict) and result.get('error')):
            timing.record(check_id, params, elapsed)

        report['results'][check_id] = result
        report['timing'][check_id] = elapsed
        report['meta'][check_id] = {'label': spec.label, 'category': spec.category}

    report['total_time'] = round(sum(report['timing'].values()), 2)
    return report


def list_available() -> list[dict]:
    """Список всех проверок для UI/CLI: id, label, category, params, доступность инструментов."""
    out = []
    for spec in registry.all():
        out.append({
            'id': spec.id, 'label': spec.label, 'category': spec.category,
            'description': spec.description, 'params': spec.params,
            'required_tools': spec.required_tools,
            'missing_tools': missing_tools(spec.required_tools),
        })
    return out
