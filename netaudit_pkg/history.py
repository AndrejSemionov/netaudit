"""Report history + AI analysis. Storage backed by SQLite (storage module)."""

from __future__ import annotations

import json
import os

from .utils import log
from . import storage

MODEL = 'claude-sonnet-4-6'
DEFAULT_AI_LANGUAGE = 'en'

_PROMPT_INSTRUCTIONS = {
    'en': (
        "You are a senior network and security engineer. Analyze the JSON network audit "
        "report and return STRICTLY valid JSON (no markdown, no ```), format:\n"
        '{"summary": "brief 2-3 sentence summary", '
        '"problems": [{"severity": "high|medium|low", "title": "...", "detail": "..."}], '
        '"recommendations": [{"priority": 1, "action": "what exactly to do", "why": "why"}]}\n\n'
        "Pay special attention to:\n"
        "- if mtr (ICMP) and tcptraceroute (TCP) disagree - this matters for disputing with the ISP;\n"
        "- loss at hop 2+ = ISP problem, at hop 1 = local;\n"
        "- open ports without a firewall, outdated SSL, PermitRootLogin yes, PasswordAuthentication yes - risks;\n"
        "- high CPU/RAM/disk - performance problems;\n"
        "- if traffic analysis is present (destinations with risk_level): assess destinations flagged "
        "high/suspicious, explain where traffic is going and why it's suspicious, but do NOT panic over "
        "legitimate services (Google, CDN). Direct IP without DNS + unusual port + persistent connections "
        "= possible C2/spyware;\n"
        "- if server_audit or web_security_external is present (findings with severity): roll all high/medium "
        "into prioritized recommendations, explain each finding in plain language and what exactly to fix "
        "(which directive, where).\n"
        "- if cve_audit is present (findings with package/version/cve/severity): for each CVE found, check its "
        "summary against the actual service config if present in the report (e.g. nginx.conf from server_audit) - "
        "if the vulnerable module/directive isn't in use, explicitly say 'no risk, not applicable'; if it is, "
        "give a CONCRETE action: 'upgrade nginx to X.Y.Z' (use fixed_versions) or 'workaround without upgrading: "
        "...'. Don't just restate the raw CVSS score without a conclusion on what to do.\n"
        "Write in English, concretely and to the point.\n\n"
        "REPORT:\n{report_json}"
    ),
    'ru': (
        "Ты старший сетевой инженер и специалист по безопасности. Проанализируй JSON-отчёт "
        "сетевого аудита и верни СТРОГО валидный JSON (без markdown, без ```), формат:\n"
        '{"summary": "краткое резюме 2-3 предложения", '
        '"problems": [{"severity": "high|medium|low", "title": "...", "detail": "..."}], '
        '"recommendations": [{"priority": 1, "action": "что конкретно сделать", "why": "почему"}]}\n\n'
        "Обрати особое внимание:\n"
        "- если mtr (ICMP) и tcptraceroute (TCP) расходятся - это важно для спора с провайдером;\n"
        "- потери на хопе 2+ = проблема провайдера, на хопе 1 = локальная;\n"
        "- открытые порты без firewall, устаревший SSL, PermitRootLogin yes, PasswordAuthentication yes - риски;\n"
        "- высокий CPU/RAM/диск - проблемы производительности;\n"
        "- если есть анализ трафика (destinations с risk_level): оцени назначения помеченные high/suspicious, "
        "объясни куда уходит трафик и почему это подозрительно, но НЕ паникуй по легитимным сервисам (Google, CDN). "
        "Прямой IP без DNS + необычный порт + постоянные соединения = возможный C2/шпионское ПО;\n"
        "- если есть server_audit или web_security_external (findings с severity): собери все high/medium в приоритетные "
        "рекомендации, объясни каждую находку простым языком и что конкретно исправить (какую директиву, где).\n"
        "- если есть cve_audit (findings с package/version/cve/severity): для каждой найденной CVE посмотри на её "
        "summary и сопоставь с реальным конфигом сервиса, если он есть в отчёте (например nginx.conf из server_audit) - "
        "если уязвимый модуль/директива не используется, явно скажи 'риск отсутствует, не критично'; если применимо - "
        "дай КОНКРЕТНОЕ действие: 'обновить nginx до X.Y.Z' (используй fixed_versions) или 'временный workaround без "
        "обновления: ...'. Не пересказывай голый CVSS-score без вывода что делать.\n"
        "Пиши на русском, конкретно, по делу.\n\n"
        "ОТЧЁТ:\n{report_json}"
    ),
}


def save_report(report: dict) -> int:
    return storage.save_report(report)


def list_reports(limit: int = 50) -> list[dict]:
    return storage.list_reports(limit)


def load_report(report_id: int) -> dict | None:
    return storage.load_report(int(report_id))


def _resolve_api_key(explicit: str | None = None) -> str | None:
    """Priority: explicit arg -> DB setting -> environment variable."""
    if explicit:
        return explicit
    from_db = storage.setting_get('anthropic_api_key')
    if from_db:
        return from_db
    return os.environ.get('ANTHROPIC_API_KEY')


def _resolve_ai_language(explicit: str | None = None) -> str:
    """Priority: explicit arg -> DB setting -> default ('en')."""
    lang = explicit or storage.setting_get('ai_language') or DEFAULT_AI_LANGUAGE
    return lang if lang in _PROMPT_INSTRUCTIONS else DEFAULT_AI_LANGUAGE


def ai_analyze(report: dict, api_key: str | None = None, language: str | None = None,
                history: list[dict] | None = None) -> dict:
    """AI analysis: problems + recommendations on what to do.

    history: optional list of past reports about the same object (see
    storage.find_related_reports()), each shaped {'timestamp', 'checks',
    'results'}. When None or empty, behavior is unchanged from before this
    parameter existed - the prompt is built from `report` alone. When
    given, a "PREVIOUS REPORTS" section is appended to the prompt so the
    model can compare trends; `report` itself is never mutated to include
    history - the history list is used only for prompt construction here,
    not merged into the object the caller will save/display.
    """
    api_key = _resolve_api_key(api_key)
    if not api_key:
        return {'error': 'API key not set (Settings -> Anthropic API key, or ANTHROPIC_API_KEY env var)'}

    try:
        import httpx
    except ImportError:
        return {'error': 'httpx is not installed'}

    lang = _resolve_ai_language(language)
    report_json = json.dumps(report, ensure_ascii=False, indent=2)
    # .replace(), not .format() - _PROMPT_INSTRUCTIONS itself contains a
    # literal JSON example of the expected response format (e.g.
    # '{"summary": "...", "problems": [...]}'), and str.format() parses
    # EVERY brace-delimited token in the string as a placeholder, not just
    # the intended {report_json} one - raising KeyError on the literal
    # '{"summary"...}' text. .replace() only touches the exact
    # '{report_json}' substring and leaves the rest of the template alone.
    prompt = _PROMPT_INSTRUCTIONS[lang].replace('{report_json}', report_json)

    if history:
        # Appended after the current report, not interleaved into the
        # {report_json} placeholder itself - keeps the existing prompt
        # (and every no-history call) byte-for-byte unchanged, and keeps
        # find_related_reports()'s output format (a list of reduced
        # {timestamp, checks, results} dicts) as the only thing this
        # function needs to know about "history" - no separate schema.
        history_json = json.dumps(history, ensure_ascii=False, indent=2)
        prompt += (
            f'\n\nPREVIOUS REPORTS FOR THE SAME OBJECT (most recent first, '
            f'for trend comparison):\n{history_json}'
        )

    try:
        resp = httpx.post(
            'https://api.anthropic.com/v1/messages',
            headers={'x-api-key': api_key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'},
            json={'model': MODEL, 'max_tokens': 2000, 'messages': [{'role': 'user', 'content': prompt}]},
            timeout=45,
        )
        resp.raise_for_status()
        data = resp.json()
        text = '\n'.join(b['text'] for b in data.get('content', []) if b.get('type') == 'text')
        cleaned = text.replace('```json', '').replace('```', '').strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return {'summary': text, 'problems': [], 'recommendations': [], 'raw': True}
    except httpx.HTTPError as e:
        log.error(f'Anthropic API: {e}')
        return {'error': str(e)}


def verify_api_key(api_key: str) -> dict:
    """Checks that the key works - sends a minimal request to the API."""
    if not api_key:
        return {'ok': False, 'error': 'empty key'}
    try:
        import httpx
    except ImportError:
        return {'ok': False, 'error': 'httpx is not installed'}
    try:
        resp = httpx.post(
            'https://api.anthropic.com/v1/messages',
            headers={'x-api-key': api_key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'},
            json={'model': MODEL, 'max_tokens': 5, 'messages': [{'role': 'user', 'content': 'hi'}]},
            timeout=15,
        )
        if resp.status_code == 200:
            return {'ok': True}
        if resp.status_code == 401:
            return {'ok': False, 'error': 'key rejected (401)'}
        return {'ok': False, 'error': f'HTTP {resp.status_code}'}
    except httpx.HTTPError as e:
        return {'ok': False, 'error': str(e)}
