"""
Telegram notifications for scheduled audits (C2,
docs/research/c1_schedule_notifications.md §3-§4).

collect_changes() reads the history and builds the FULL change set of one
saved report; decide() and render() are pure functions of that data; only
send_telegram() talks to the network. The decision is never taken on the AI
context of trends.trend_context(), which cuts units and ids before any
severity filter (review pass 1).

The bot token is part of the Bot API URL, and httpx writes that URL into its
INFO request log and into HTTPStatusError. So no httpx log line is emitted
while sending, no message here is built from an httpx exception, and every
NotifyError is raised `from None` - a traceback never prints the chained
httpx error either.
"""

from __future__ import annotations

import logging
import re
import time
from contextlib import contextmanager

import httpx

from . import host_summary, storage, trends

TELEGRAM_API = 'https://api.telegram.org'
SEVERITIES = trends.PROBLEM_SEVERITIES  # most severe first
DEFAULT_THRESHOLD = 'medium'
HISTORY_WINDOW = storage.RELATED_REPORTS_SEARCH_WINDOW
MAX_TEXT = 4096  # Telegram's limit for one message
MAX_TITLE = 120
SEND_TIMEOUT = 10.0
MAX_RETRY_AFTER = 30
_TARGET_KEYS = ('host', 'url', 'domain', 'target')
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_HINTS = {400: ' (check the chat ID)', 401: ' (the bot token was rejected)',
          403: ' (the bot cannot write to this chat)', 404: ' (the bot token was rejected)'}


class NotifyError(Exception):
    """A notification problem. Its text never contains the bot token."""


def telegram_config() -> tuple[str, str]:
    """(token, chat id) from settings, or NotifyError naming what is missing."""
    token = storage.setting_get('telegram_token') or ''
    chat = storage.setting_get('telegram_chat') or ''
    if not token or not chat:
        missing = ' and '.join(name for name, value in (('bot token', token), ('chat ID', chat)) if not value)
        raise NotifyError(f'Telegram is not configured: set the {missing} (Web UI -> Settings)')
    return token, chat


def redact(text: str, token: str) -> str:
    """Last barrier for any text NetAudit prints about sending."""
    return text.replace(token, '<redacted>') if token else text


def at_or_above(severity, threshold: str) -> bool:
    return severity in SEVERITIES and SEVERITIES.index(severity) <= SEVERITIES.index(threshold)


# --- the full change set -----------------------------------------------------

def _target(params: dict) -> str:
    for key in _TARGET_KEYS:
        value = params.get(key)
        if isinstance(value, str) and value:
            return value
    return ''


def _instances(report: dict):
    """(check_id, instance key, params, result) of every check instance, the
    ones without a result included."""
    contexts = report.get('execution_context') or {}
    results = report.get('results') or {}
    for check_id in dict.fromkeys([*results, *contexts]):
        result, ctx = results.get(check_id), contexts.get(check_id)
        if isinstance(result, dict) and result.get('_multi_host') and isinstance(ctx, dict):
            by_host = result.get('by_host') if isinstance(result.get('by_host'), dict) else {}
            for key, params in ctx.items():
                yield check_id, key, params if isinstance(params, dict) else {}, by_host.get(key)
        else:
            yield check_id, None, ctx if isinstance(ctx, dict) else {}, result


def _status(check_id: str, key, params: dict, result) -> str:
    if not isinstance(result, dict):
        return 'error'  # no result at all: this instance was not audited
    return host_summary._check_row(check_id, key, _target(params), params, result)['status']


def _titles(report: dict, check_id: str, key: str, value) -> dict:
    """id -> title of the unit's findings in this report."""
    ctx = (report.get('execution_context') or {}).get(check_id)
    titles = {}
    for params, result in trends._result_param_pairs(check_id, ctx, report.get('results') or {}):
        if params.get(key) != value:
            continue
        for findings in (trends._scoped_findings(result) or {}).values():
            for f in findings:
                if isinstance(f, dict) and f.get('id'):
                    titles.setdefault(f['id'], f.get('title') or '')
    return titles


def _severity_count(finding_ids: dict, severity: str) -> int:
    return sum(1 for s in finding_ids.values() if s == severity)


def _unit_change(snap: dict, prev: dict, titles: dict) -> dict:
    change = trends._change(prev, snap)
    cur_ids, prev_ids = snap['finding_ids'], prev['finding_ids']
    idless = {}
    for s in SEVERITIES:
        # what the count moved by, minus what findings with an id explain
        delta = change['counts_delta'][s] - (_severity_count(cur_ids, s) - _severity_count(prev_ids, s))
        if delta > 0:
            idless[s] = delta
    raised = [{'id': fid, 'severity': cur_ids[fid], 'was': prev_ids[fid]} for fid in change['persisting']
              if cur_ids[fid] in SEVERITIES and prev_ids[fid] in SEVERITIES
              and SEVERITIES.index(cur_ids[fid]) < SEVERITIES.index(prev_ids[fid])]
    return {
        'counts_delta': change['counts_delta'],
        'new': [{'id': fid, 'severity': cur_ids[fid], 'title': titles.get(fid, '')} for fid in change['new']],
        'idless': idless,
        'raised': raised,
        # the current report has no title for these, only the previous snapshot's severity
        'resolved': [{'id': fid, 'severity': prev_ids.get(fid)} for fid in change['resolved']],
        'not_checked': [{'id': fid, 'severity': prev_ids.get(fid)} for fid in change['not_evaluated']],
    }


def collect_changes(report: dict, report_id: int | None, window: int | None = None) -> dict:
    """Everything decide() and render() need, for every instance and id of
    `report`, against the reports saved strictly before it (the same window
    as trends, without the AI context's unit and id limits)."""
    window = HISTORY_WINDOW if window is None else window
    # a scheduled job (`run --notify --job`) compares with its own runs, so a
    # manual or Web run in between cannot cancel its alert; a unit the job
    # has never seen falls back to any run (docs/research/a4_6_job_baseline.md)
    job = report.get('job')
    history: dict[tuple, list] = {}
    job_history: dict[tuple, list] = {}
    for past in reversed(storage.report_data_before(report, report_id, window)):
        same_job = job is not None and past.get('job') == job
        for snap in trends.snapshots_from_report(past):
            unit = (snap['check_id'], snap['key'], snap['value'])
            history.setdefault(unit, []).append(snap)
            if same_job:
                job_history.setdefault(unit, []).append(snap)

    problems, no_findings = [], []
    for check_id, key, params, result in _instances(report):
        status = _status(check_id, key, params, result)
        if status in ('error', 'incomplete'):
            problems.append({'check_id': check_id, 'target': _target(params), 'status': status})
        elif status == 'unknown':
            no_findings.append({'check_id': check_id, 'target': _target(params)})

    units = []
    for snap in trends.snapshots_from_report(report):
        # an errored run is a problem above; event checks never get a diff (2d)
        if snap['error'] is not None or trends._kind(snap['check_id']) != 'state':
            continue
        unit = (snap['check_id'], snap['key'], snap['value'])
        earlier = job_history.get(unit) or history.get(unit, [])
        good = [s for s in earlier if s['error'] is None and s['counts'] is not None]
        entry = {'check_id': unit[0], 'key': unit[1], 'target': str(unit[2]), 'counts': snap['counts']}
        if good:
            entry.update(_unit_change(snap, good[-1], _titles(report, *unit)))
        else:
            entry['baseline'] = True  # no earlier successful run within the window
        units.append(entry)

    hosts = [{'host': row['host'], 'counts': row['observed_counts']}
             for row in host_summary.host_summary(report)['hosts']]
    return {'problems': problems, 'no_findings': no_findings, 'units': units, 'hosts': hosts,
            'window': window}


def decide(changes: dict, threshold: str = DEFAULT_THRESHOLD) -> bool:
    """Whether this run needs a message (§3.2)."""
    if changes['problems']:
        return True
    for unit in changes['units']:
        relevant = [s for s in SEVERITIES if at_or_above(s, threshold)]
        if unit.get('baseline'):
            if any(unit['counts'][s] > 0 for s in relevant):
                return True
            continue
        # a new id, or an id that got worse: A low -> high while another HIGH
        # was fixed leaves the HIGH count as it was (review C2 pass 1)
        if any(at_or_above(f['severity'], threshold) for f in unit['new'] + unit['raised']):
            return True
        # an id-less finding shows only as a count that went up
        if any(unit['counts_delta'][s] > 0 for s in relevant):
            return True
    return False


# --- the text ----------------------------------------------------------------

def _clean(text, limit: int = MAX_TITLE) -> str:
    """One line of plain text: a control character never starts a new line."""
    text = _CONTROL.sub(' ', str(text or '')).strip()
    return text if len(text) <= limit else text[:limit - 1] + '…'


def _where(item: dict) -> str:
    return f"{item['check_id']} @ {_clean(item['target']) or '-'}"


def _sev(severity) -> str:
    return str(severity or '?').upper()


def _top(severity) -> bool:
    return severity in ('critical', 'high')


def _count_text(counts: dict | None) -> str:
    if counts is None:
        return 'counts unknown'
    parts = [f'{s} {counts[s]}' for s in SEVERITIES if counts.get(s)]
    return ', '.join(parts) or 'no problems'


def render(changes: dict, report_id, job: str | None) -> str:
    """The message (§3.3): plain text, at most MAX_TEXT characters. When it
    is too long, per-host counts go first, then resolved and not-checked
    lists, then new findings below HIGH; errors, incomplete checks and
    CRITICAL/HIGH lines are cut last."""
    header = f'NetAudit: {job} - report #{report_id}' if job else f'NetAudit - report #{report_id}'
    problems, top, other, resolved, not_checked, no_findings, counts = ([] for _ in range(7))

    by_target: dict[tuple, list] = {}
    for p in changes['problems']:
        by_target.setdefault((p['target'], p['status']), []).append(p['check_id'])
    for (target, status), check_ids in by_target.items():
        word = 'error' if status == 'error' else 'collection incomplete'
        problems.append(f"! {_clean(target) or '-'}: {word} - {_clean(', '.join(check_ids), 300)}")

    for unit in changes['units']:
        where = _where(unit)
        if unit.get('baseline'):
            line = (f'= baseline {where}: no earlier run in the last {changes["window"]} reports - '
                    f'{_count_text(unit["counts"])}')
            (top if any(unit['counts'][s] for s in ('critical', 'high')) else other).append(line)
            continue
        for f in sorted(unit['new'], key=lambda f: SEVERITIES.index(f['severity'])
                        if f['severity'] in SEVERITIES else len(SEVERITIES)):
            (top if _top(f['severity']) else other).append(
                f"+ {_sev(f['severity'])} {_clean(f['id'])}: {_clean(f['title'])} - {where}")
        for s, n in unit['idless'].items():
            (top if _top(s) else other).append(f'+ {n} {_sev(s)} without id - {where}')
        for f in unit['raised']:
            (top if _top(f['severity']) else other).append(
                f"^ {_sev(f['severity'])} {_clean(f['id'])} (was {f['was']}) - {where}")
        for f in unit['resolved']:
            resolved.append(f"- resolved {_sev(f['severity'])} {_clean(f['id'])} - {where}")
        for f in unit['not_checked']:
            not_checked.append(f"? not checked this time {_sev(f['severity'])} {_clean(f['id'])} - {where}")

    for item in changes['no_findings']:
        no_findings.append(f'. no findings to compare - {_where(item)}')
    for row in changes['hosts']:
        counts.append(f"# {_clean(row['host'])}: {_count_text(row['counts'])}")

    groups = [  # (lines, cut priority: higher goes first, what the "+N more" line says)
        (problems, 0, 'problem lines'),
        (top, 0, 'CRITICAL/HIGH lines'),
        (other, 1, 'lines below HIGH'),
        (resolved, 2, 'resolved'),
        (not_checked, 2, 'not checked this time'),
        (no_findings, 3, 'checks without findings'),
        (counts, 3, 'host counts'),
    ]
    return _fit(header, groups)


def _more(n: int, label: str) -> str:
    return f'... +{n} more {label}'


def _fit(header: str, groups: list, limit: int = MAX_TEXT) -> str:
    kept = [list(lines) for lines, _, _ in groups]
    dropped = [0] * len(groups)
    total = len(header) + sum(len(line) + 1 for lines in kept for line in lines)
    for priority in (3, 2, 1, 0):
        for i in reversed(range(len(groups))):
            if groups[i][1] != priority:
                continue
            while kept[i] and total > limit:
                line = kept[i].pop()
                old_more = len(_more(dropped[i], groups[i][2])) + 1 if dropped[i] else 0
                dropped[i] += 1
                total += len(_more(dropped[i], groups[i][2])) + 1 - old_more - (len(line) + 1)
        if total <= limit:
            break
    out = [header]
    for i, lines in enumerate(kept):
        out.extend(lines)
        if dropped[i]:
            out.append(_more(dropped[i], groups[i][2]))
    text = '\n'.join(out)
    return text if len(text) <= limit else text[:limit - 1] + '…'


# --- sending -----------------------------------------------------------------

@contextmanager
def _quiet_http_logs():
    """httpx logs every request URL - with the token in it - at INFO."""
    loggers = [logging.getLogger(name) for name in ('httpx', 'httpcore')]
    levels = [lg.level for lg in loggers]
    for lg in loggers:
        lg.setLevel(logging.WARNING)
    try:
        yield
    finally:
        for lg, level in zip(loggers, levels, strict=True):
            lg.setLevel(level)


def _retry_after(response: httpx.Response):
    try:
        value = response.json()['parameters']['retry_after']
    except (ValueError, KeyError, TypeError):
        return None
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def send_telegram(text: str, token: str, chat_id: str, *, client: httpx.Client | None = None,
                  sleep=time.sleep) -> None:
    """One message, best effort (§3.3). A second attempt only when the first
    certainly did not reach Telegram: a connection error, or HTTP 429 with a
    short retry_after. A read timeout or a 5xx is not retried - Telegram may
    already have the message, and a retry could send it twice."""
    url = f'{TELEGRAM_API}/bot{token}/sendMessage'
    body = {'chat_id': chat_id, 'text': text, 'link_preview_options': {'is_disabled': True}}
    own_client = client is None
    client = client or httpx.Client(timeout=SEND_TIMEOUT)
    try:
        with _quiet_http_logs():
            _post(client, url, body, sleep)
    finally:
        if own_client:
            client.close()


def _post(client: httpx.Client, url: str, body: dict, sleep) -> None:
    for attempt in (1, 2):
        try:
            response = client.post(url, json=body, timeout=SEND_TIMEOUT)
        except (httpx.ConnectError, httpx.ConnectTimeout):
            continue  # the request never reached Telegram
        except httpx.HTTPError as e:
            raise NotifyError(f'Telegram: {type(e).__name__}, not retried: '
                              'the message may have been delivered') from None
        if response.status_code == 200:
            return
        wait = _retry_after(response) if response.status_code == 429 else None
        if attempt == 1 and wait is not None and wait <= MAX_RETRY_AFTER:
            sleep(wait)
            continue
        raise NotifyError(f'Telegram: HTTP {response.status_code}{_HINTS.get(response.status_code, "")}') from None
    raise NotifyError('Telegram: could not deliver the message in two attempts') from None
