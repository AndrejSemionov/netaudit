"""
SQL injection check. Two levels:
  PASSIVE (always) — finds input points (GET params, forms) where injection is
                     theoretically possible. Doesn't attack anything, reconnaissance only.
                     Safe and legal.
  ACTIVE (sqlmap)   — real testing via sqlmap. Requires EXPLICIT confirmation
                     that the user is the site owner or has written permission.

⚠️ IMPORTANT: actively scanning someone else's site without permission is
illegal (in the EU/Lithuania — unauthorized access). This plugin does NOT run
sqlmap without explicit authorization confirmation.
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
    """Passively finds input points: GET params in the URL and form fields."""
    points = {'get_params': [], 'forms': []}

    # GET params directly in the URL
    q = parse_qs(urlparse(url).query)
    points['get_params'] = list(q.keys())

    if not html:
        return points

    # forms and their fields
    for form_m in re.finditer(r'<form\b([^>]*)>(.*?)</form>', html, re.IGNORECASE | re.DOTALL):
        attrs, body = form_m.group(1), form_m.group(2)
        action_m = re.search(r'action\s*=\s*["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
        method_m = re.search(r'method\s*=\s*["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
        inputs = re.findall(r'<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["\']?([^"\'\s>]+)', body, re.IGNORECASE)
        points['forms'].append({
            'action': action_m.group(1) if action_m else '(current URL)',
            'method': (method_m.group(1).upper() if method_m else 'GET'),
            'inputs': inputs,
        })
    return points


def _run_sqlmap(url: str, crawl: bool, level: int = 1, risk: int = 1) -> dict:
    """Runs sqlmap in a constrained mode and parses the result."""
    if not tool_available('sqlmap'):
        return {'error': 'sqlmap is not installed (apt install sqlmap or pip install sqlmap)'}

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
        # pull out parameters and types
        params = re.findall(r'Parameter:\s*(.+)', combined)
        types = re.findall(r'Type:\s*(.+)', combined)
        dbms_m = re.search(r'back-end DBMS:\s*(.+)', combined)
        for p in params:
            findings.append({'severity': 'high', 'title': f'SQL injection: parameter {p.strip()}',
                             'detail': 'the parameter is vulnerable to injection'})
        if types:
            findings.append({'severity': 'high', 'title': 'injection types',
                             'detail': ', '.join(t.strip() for t in dict.fromkeys(types))})
        if dbms_m:
            findings.append({'severity': 'medium', 'title': f'DBMS disclosed: {dbms_m.group(1).strip()}',
                             'detail': 'sqlmap identified the database type'})
    elif 'all tested parameters do not appear to be injectable' in combined:
        findings.append({'severity': 'ok', 'title': 'sqlmap: no injections found',
                         'detail': 'the tested parameters aren\'t vulnerable (at the given level)'})
    elif 'no parameter' in combined.lower() or 'not able to find' in combined.lower():
        findings.append({'severity': 'low', 'title': 'sqlmap: found no parameters to test',
                         'detail': 'no GET params/forms to check on this URL'})
    else:
        tail = combined.strip()[-400:]
        findings.append({'severity': 'low', 'title': 'sqlmap finished with no clear verdict',
                         'detail': tail})

    return {'vulnerable': vulnerable, 'findings': findings}


AUTH_CONFIRM = 'yes — I\'m the owner / I have written permission'


@register(
    id='sql_injection', label='SQL injection check', category='site',
    params=[
        {'name': 'url', 'type': 'text', 'label': 'URL (with params, e.g. ?id=1)', 'default': ''},
        {'name': 'authorization', 'type': 'select', 'label': 'Authorization to test',
         'options': ['no', AUTH_CONFIRM], 'default': 'no'},
        {'name': 'mode', 'type': 'select', 'label': 'Mode',
         'options': ['passive (input points only)', 'passive + sqlmap'], 'default': 'passive (input points only)'},
        {'name': 'crawl', 'type': 'select', 'label': 'Follow links (sqlmap crawl)',
         'options': ['no', 'yes'], 'default': 'no'},
    ],
    required_tools=[],
    description='Passive input-point discovery always runs; active testing via sqlmap only with authorization confirmed.',
)
def check_sql_injection(url='', authorization='no', mode='passive (input points only)', crawl='no') -> dict:
    if not url:
        return {'error': 'provide a URL'}
    full = url if '://' in url else f'https://{url}'

    # PASSIVE — always
    html = _fetch_html(full)
    points = _find_injection_points(full, html)

    findings = []
    n_points = len(points['get_params']) + sum(len(f['inputs']) for f in points['forms'])
    if n_points == 0:
        findings.append({'severity': 'ok', 'title': 'no input points found',
                         'detail': 'no GET params or form fields — injection is unlikely here'})
    else:
        findings.append({'severity': 'low', 'title': f'input points found: {n_points}',
                         'detail': f"GET params: {', '.join(points['get_params']) or '—'}; "
                                   f"forms: {len(points['forms'])}"})

    result = {
        'url': full,
        'injection_points': points,
        'findings': findings,
        'mode': 'passive',
    }

    # ACTIVE — only with confirmation
    wants_active = (mode == 'passive + sqlmap')
    if wants_active:
        if authorization != AUTH_CONFIRM:
            result['findings'].append({
                'severity': 'medium',
                'title': '⛔ active scan NOT started',
                'detail': 'authorization not confirmed. SQL injection testing is only allowed on '
                          'your own site or with the owner\'s written permission — otherwise it\'s illegal. '
                          'Confirm authorization to run sqlmap.',
            })
            result['active_blocked'] = True
        else:
            sqlmap_res = _run_sqlmap(full, crawl=(crawl == 'yes'))
            result['mode'] = 'active'
            result['sqlmap'] = sqlmap_res
            if sqlmap_res.get('error'):
                result['findings'].append({'severity': 'low', 'title': 'sqlmap unavailable',
                                           'detail': sqlmap_res['error']})
            else:
                result['findings'].extend(sqlmap_res.get('findings', []))

    # severity summary
    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for f in result['findings']:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1
    result['summary'] = counts
    return result
