"""
Проверка на SQL-инъекции. Два уровня:
  ПАССИВНЫЙ (всегда) — находит точки ввода (GET-параметры, формы), где инъекция теоретически
                       возможна. Ничего не атакует, только разведка. Безопасно и легально.
  АКТИВНЫЙ (sqlmap)   — реальное тестирование через sqlmap. Требует ОБЯЗАТЕЛЬНОГО подтверждения,
                       что пользователь — владелец сайта или имеет письменное разрешение.

⚠️ ВАЖНО: активное сканирование чужого сайта без разрешения незаконно (в ЕС/Литве —
противоправный доступ). Плагин НЕ запускает sqlmap без явного подтверждения авторизации.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs

from ..registry import register
from ..utils import run_cmd, tool_available


def _fetch_html(url: str) -> str | None:
    if tool_available('curl'):
        code, out, _ = run_cmd(['curl', '-s', '-L', '--max-time', '15', url], timeout=20)
        if code == 0:
            return out
    try:
        import httpx
        with httpx.Client(follow_redirects=True, timeout=15) as c:
            return c.get(url).text
    except Exception:
        return None


def _find_injection_points(url: str, html: str | None) -> dict:
    """Пассивно находит точки ввода: GET-параметры в URL и поля форм."""
    points = {'get_params': [], 'forms': []}

    # GET-параметры прямо в URL
    q = parse_qs(urlparse(url).query)
    points['get_params'] = list(q.keys())

    if not html:
        return points

    # формы и их поля
    for form_m in re.finditer(r'<form\b([^>]*)>(.*?)</form>', html, re.IGNORECASE | re.DOTALL):
        attrs, body = form_m.group(1), form_m.group(2)
        action_m = re.search(r'action\s*=\s*["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
        method_m = re.search(r'method\s*=\s*["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
        inputs = re.findall(r'<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["\']?([^"\'\s>]+)', body, re.IGNORECASE)
        points['forms'].append({
            'action': action_m.group(1) if action_m else '(текущий URL)',
            'method': (method_m.group(1).upper() if method_m else 'GET'),
            'inputs': inputs,
        })
    return points


def _run_sqlmap(url: str, crawl: bool, level: int = 1, risk: int = 1) -> dict:
    """Запускает sqlmap ограниченно и парсит результат."""
    if not tool_available('sqlmap'):
        return {'error': 'sqlmap не установлен (apt install sqlmap или pip install sqlmap)'}

    cmd = ['sqlmap', '-u', url, '--batch', '--disable-coloring',
           f'--level={level}', f'--risk={risk}', '--timeout=10', '--retries=1',
           '--forms']
    if crawl:
        cmd += ['--crawl=1']

    code, out, err = run_cmd(cmd, timeout=240)
    combined = out + '\n' + err

    findings = []
    vulnerable = False

    if 'sqlmap identified the following injection point' in combined or 'is vulnerable' in combined:
        vulnerable = True
        # вытащим параметры и типы
        params = re.findall(r'Parameter:\s*(.+)', combined)
        types = re.findall(r'Type:\s*(.+)', combined)
        dbms_m = re.search(r'back-end DBMS:\s*(.+)', combined)
        for p in params:
            findings.append({'severity': 'high', 'title': f'SQL-инъекция: параметр {p.strip()}',
                             'detail': 'параметр уязвим для инъекции'})
        if types:
            findings.append({'severity': 'high', 'title': 'типы инъекций',
                             'detail': ', '.join(t.strip() for t in dict.fromkeys(types))})
        if dbms_m:
            findings.append({'severity': 'medium', 'title': f'СУБД раскрыта: {dbms_m.group(1).strip()}',
                             'detail': 'sqlmap определил тип базы данных'})
    elif 'all tested parameters do not appear to be injectable' in combined:
        findings.append({'severity': 'ok', 'title': 'sqlmap: инъекций не найдено',
                         'detail': 'протестированные параметры не уязвимы (на заданном уровне)'})
    elif 'no parameter' in combined.lower() or 'not able to find' in combined.lower():
        findings.append({'severity': 'low', 'title': 'sqlmap: не нашёл параметров для теста',
                         'detail': 'нет GET-параметров/форм для проверки на этом URL'})
    else:
        tail = combined.strip()[-400:]
        findings.append({'severity': 'low', 'title': 'sqlmap завершился без явного вердикта',
                         'detail': tail})

    return {'vulnerable': vulnerable, 'findings': findings}


AUTH_CONFIRM = 'да — я владелец / есть письменное разрешение'


@register(
    id='sql_injection', label='Проверка SQL-инъекций', category='site',
    params=[
        {'name': 'url', 'type': 'text', 'label': 'URL (с параметрами, напр. ?id=1)', 'default': ''},
        {'name': 'authorization', 'type': 'select', 'label': 'Авторизация на тест',
         'options': ['нет', AUTH_CONFIRM], 'default': 'нет'},
        {'name': 'mode', 'type': 'select', 'label': 'Режим',
         'options': ['пассив (только точки ввода)', 'пассив + sqlmap'], 'default': 'пассив (только точки ввода)'},
        {'name': 'crawl', 'type': 'select', 'label': 'Обход ссылок (sqlmap crawl)',
         'options': ['нет', 'да'], 'default': 'нет'},
    ],
    required_tools=[],
    description='Пассивный поиск точек ввода всегда; активное тестирование через sqlmap — только с подтверждением авторизации.',
)
def check_sql_injection(url='', authorization='нет', mode='пассив (только точки ввода)', crawl='нет') -> dict:
    if not url:
        return {'error': 'укажи URL'}
    full = url if '://' in url else f'https://{url}'

    # ПАССИВНО — всегда
    html = _fetch_html(full)
    points = _find_injection_points(full, html)

    findings = []
    n_points = len(points['get_params']) + sum(len(f['inputs']) for f in points['forms'])
    if n_points == 0:
        findings.append({'severity': 'ok', 'title': 'точек ввода не найдено',
                         'detail': 'нет GET-параметров и полей форм — инъекция маловероятна здесь'})
    else:
        findings.append({'severity': 'low', 'title': f'найдено точек ввода: {n_points}',
                         'detail': f"GET-параметры: {', '.join(points['get_params']) or '—'}; "
                                   f"форм: {len(points['forms'])}"})

    result = {
        'url': full,
        'injection_points': points,
        'findings': findings,
        'mode': 'passive',
    }

    # АКТИВНО — только с подтверждением
    wants_active = (mode == 'пассив + sqlmap')
    if wants_active:
        if authorization != AUTH_CONFIRM:
            result['findings'].append({
                'severity': 'medium',
                'title': '⛔ активное сканирование НЕ запущено',
                'detail': 'нет подтверждения авторизации. Тестировать SQL-инъекции можно только на '
                          'своём сайте или с письменного разрешения владельца — иначе это незаконно. '
                          'Подтверди авторизацию, чтобы запустить sqlmap.',
            })
            result['active_blocked'] = True
        else:
            sqlmap_res = _run_sqlmap(full, crawl=(crawl == 'да'))
            result['mode'] = 'active'
            result['sqlmap'] = sqlmap_res
            if sqlmap_res.get('error'):
                result['findings'].append({'severity': 'low', 'title': 'sqlmap недоступен',
                                           'detail': sqlmap_res['error']})
            else:
                result['findings'].extend(sqlmap_res.get('findings', []))

    # сводка severity
    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for f in result['findings']:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1
    result['summary'] = counts
    return result
