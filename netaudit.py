#!/usr/bin/env python3
"""
NetAudit — modular, universal network audit tool.
Runs from the console and as a web service.

Console:
    netaudit.py list                        - show all available checks
    netaudit.py run mtr ping                 - run checks (default params)
    netaudit.py run mtr --target 5.20.136.3   - with params
    netaudit.py run ssl http --url https://example.com
    netaudit.py run --quick --url https://example.com --domain example.com - default site bundle
    netaudit.py run --quick --host 1.2.3.4 --user root  - default server bundle
    netaudit.py history                       - list reports
    netaudit.py analyze <report_id>            - AI analysis of a saved report (see history)

Web:
    netaudit.py web                            - start the web UI on 127.0.0.1:8000
    netaudit.py web --host 0.0.0.0 --port 8080  - on all interfaces
    netaudit.py setup-nginx --domain audit.local - generate an nginx config + basic auth

Installing tools:
    sudo apt install mtr-tiny tcptraceroute dnsutils iputils-arping iperf3 -y
    pip install psutil httpx paramiko fastapi "uvicorn[standard]" --break-system-packages
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import pwd
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from netaudit_pkg import __version__, host_summary, hosts, notify, storage, trends
from netaudit_pkg.engine import (
    DEFAULT_MAX_PARALLEL,
    list_available,
    run_checks,
    run_checks_multi,
    validate_multi_request,
)
from netaudit_pkg.history import ai_analyze, list_reports, load_report, save_report
from netaudit_pkg.redaction import SECRET_PARAM_NAMES
from netaudit_pkg.registry import param_value
from netaudit_pkg.utils import log, run_cmd

QUICK_BUNDLE_SITE = ['ssl', 'security_headers', 'web_security_external', 'dns_audit']
# remote checks only: `ports`/`firewall` audit the NetAudit machine itself
# (docs/research/quick_bundle_targets.md)
QUICK_BUNDLE_SERVER = ['server_audit', 'ssh_audit', 'lynis_audit', 'cve_audit']
# what a bundle check audits: the first of these params it declares
QUICK_TARGET_PARAMS = ('url', 'domain', 'host')
# checks that run on the NetAudit machine itself (checks/system.py)
LOCAL_CHECKS = frozenset({'ports', 'firewall', 'performance'})
# a target default that is only a documentation example (RFC 2606): such a
# target must be named on the command line (docs/research/cli_example_targets.md)
EXAMPLE_TARGETS = frozenset({'example.com', 'https://example.com'})

# setup-timer (C2): values that go into a systemd unit are validated, not
# escaped - systemd expands % specifiers and $VARIABLES in ExecStart= and
# splits it on spaces, so anything outside these sets is refused
JOB_NAME = re.compile(r'[a-z0-9][a-z0-9-]{0,31}')
UNIT_PATH = re.compile(r'/[A-Za-z0-9._/@+-]*')
UNIT_TIMEOUT = re.compile(r'[1-9][0-9]{0,4}(s|min|h)')
UNIX_USER = re.compile(r'[a-z_][a-z0-9_-]{0,31}')
CALENDAR_FORBIDDEN = re.compile(r'[\x00-\x1f\x7f%$\\]')

BANNER = f"""\
NetAudit v{__version__} — modular network & security audit
https://github.com/AndrejSemionov/netaudit

  netaudit run ssl web_security_external --url https://example.com
  netaudit run --quick --url https://example.com --domain example.com
  netaudit run --quick --host 1.2.3.4 --user root
  netaudit run kernel_hardening --host 1.2.3.4 --sudo_password -   (asks, no echo)
  netaudit list
  netaudit trend ssh_hardening 1.2.3.4
  netaudit web

Full flag list: netaudit --detailed / netaudit <command> -h
"""


def cmd_list(args):
    for c in list_available():
        miss = f"  [missing: {', '.join(c['missing_tools'])}]" if c['missing_tools'] else ''
        print(f"[{c['category']:12}] {c['id']:18} {c['label']}{miss}")
        if c['params']:
            for p in c['params']:
                default = 'required' if _example_target(p) else f"default={p['default']}"
                kind = p['type']
                if kind == 'select' and p.get('options'):
                    kind = f"select: {' | '.join(p['options'])}"
                print(f"                 └─ --{p['name']} ({kind}, {default})")


def _parse_run_params(tokens: list[str]) -> tuple[dict, set[str]]:
    """`--name value` pairs after `netaudit run` (the last value of a repeated
    name wins, as before) and the names given more than once - each form
    decides what a repeat means (B2.2)."""
    extra, repeated = {}, set()
    i = 0
    while i < len(tokens):
        if tokens[i].startswith('--'):
            key = tokens[i][2:]
            if key in extra:
                repeated.add(key)
            extra[key] = tokens[i + 1] if i + 1 < len(tokens) else ''
            i += 2
        else:
            i += 1
    return extra, repeated


def _refuse(message: str):
    log.error(message)
    sys.exit(1)


def _quick_bundle(bundle: list[str], extra: dict) -> list[str]:
    """The bundle checks whose target was given. The others are skipped with a
    hint rather than run on their default target (dns_audit on example.com);
    the domain is never guessed from --url."""
    avail = {c['id']: {p['name'] for p in c['params']} for c in list_available()}
    picked = []
    for check_id in bundle:
        target = next(name for name in QUICK_TARGET_PARAMS if name in avail[check_id])
        if target in extra:
            picked.append(check_id)
        else:
            log.warning(f'--quick: skipping {check_id}: add --{target} <value> to include it')
    return picked


def _flag_names(keys) -> str:
    """Flags for a message: the name only, cut before "=" - in `--password=VALUE`
    the parser keeps the whole text as the name (review #46)."""
    return ", ".join(dict.fromkeys("--" + key.split("=", 1)[0] for key in sorted(keys)))


def _refuse_unused_flags(check_ids: list[str], extra: dict, avail: dict) -> None:
    """A flag that no selected check takes is refused before anything runs.
    It used to be dropped without a word, so the check ran on another target:
    this computer (`ports --host X`) or its default (`dns_audit --url U`
    audited example.com) - docs/research/cli_unused_flags.md. Only flag names
    are printed, never their values."""
    taken = {p['name'] for check_id in check_ids if check_id in avail for p in avail[check_id]['params']}
    unused = sorted(set(extra) - taken)
    if not unused:
        return
    hint = ''
    if set(unused) & storage.IDENTITY_PARAM_KEYS:
        targets = sorted(taken & storage.IDENTITY_PARAM_KEYS)
        local = [c for c in check_ids if c in LOCAL_CHECKS]
        if targets:
            hint = f' The selected checks take their target as {", ".join("--" + t for t in targets)}.'
        elif local:
            hint = f' {", ".join(local)} always check this computer.'
        else:
            hint = ' None of the selected checks takes a target.'
    _refuse(f'{_flag_names(unused)}: not used by any of the selected checks '
            f'({", ".join(check_ids)}).{hint} Drop the flag or pick checks that take it')


def _example_target(param: dict) -> bool:
    """A target parameter whose default is only the example.com placeholder."""
    return param['name'] in storage.IDENTITY_PARAM_KEYS and param['default'] in EXAMPLE_TARGETS


def _refuse_example_targets(check_ids: list[str], extra: dict, avail: dict) -> None:
    """A check whose target was not given would audit example.com, its
    default, and the report would look like one about the user's site
    (docs/research/cli_example_targets.md). Refused before anything runs."""
    missing = [(check_id, p) for check_id in check_ids if check_id in avail
               for p in avail[check_id]['params'] if _example_target(p) and p['name'] not in extra]
    if not missing:
        return
    needs = ", ".join(f"{check_id} needs --{p['name']} (otherwise it checks the example {p['default']})"
                      for check_id, p in missing)
    _refuse(f'No target given: {needs}. Add the flag with your own site or domain')


def _refuse_wrong_values(check_ids: list[str], extra: dict, avail: dict) -> None:
    """A checkbox, number or select value the check would misread is refused
    before the first password prompt and before anything runs: `false` used
    to reach the check as the true string 'false', and `--lines '5; id'` a
    remote shell as a second command (docs/research/param_value_types.md).
    Each (check, flag) pair is checked - `--mode` takes other values in
    another check. Values are never printed."""
    wrong = []
    for check_id in check_ids:
        for p in avail[check_id]['params'] if check_id in avail else []:
            if p['name'] in extra:
                try:
                    param_value(p, extra[p['name']])
                except ValueError as e:
                    wrong.append(f'--{p["name"]} ({check_id}) {e}')
    if wrong:
        _refuse(f'Wrong value: {"; ".join(wrong)}. Nothing was run')


def _single_selection(args, extra: dict) -> list[dict]:
    check_ids = args.checks or []
    if args.quick:
        if not check_ids:
            if 'url' in extra:
                check_ids = _quick_bundle(QUICK_BUNDLE_SITE, extra)
            elif 'host' in extra:
                check_ids = _quick_bundle(QUICK_BUNDLE_SERVER, extra)
            else:
                log.error('--quick needs --url <site> or --host <server> to pick a check bundle.')
                sys.exit(1)
        log.info(f"--quick: running {', '.join(check_ids)}")

    if not check_ids:
        log.error("No checks given. Use 'netaudit run <check_id> ...' or 'netaudit run --quick --url/--host ...'.")
        sys.exit(1)

    avail = {c['id']: c for c in list_available()}
    _refuse_unused_flags(check_ids, extra, avail)
    _refuse_example_targets(check_ids, extra, avail)
    _refuse_wrong_values(check_ids, extra, avail)

    selected = []
    # a password-type param given as "-" is asked for (no echo) instead of
    # being typed on the command line, where ps and shell history see it;
    # asked once per param name for the whole run (task 10)
    asked: dict[str, str] = {}
    for check_id in check_ids:
        spec_params = {}
        if check_id in avail:
            for p in avail[check_id]['params']:
                if p['name'] in extra:
                    v = extra[p['name']]
                    if p['type'] == 'password' and v == '-':
                        if p['name'] not in asked:
                            asked[p['name']] = getpass.getpass(f'{p["name"]} for {check_id}: ')
                        v = asked[p['name']]
                    spec_params[p['name']] = param_value(p, v)
        selected.append({'id': check_id, 'params': spec_params})
    return selected


def _max_parallel(raw) -> int:
    """--max-parallel for a group run: an integer the engine accepts
    (B2.1: 1-16, default 4)."""
    if raw is None:
        return DEFAULT_MAX_PARALLEL
    if not raw.isdigit():
        _refuse(f'--max-parallel must be a whole number, got {raw!r}')
    return int(raw)


def _group_selection(args, extra: dict, hosts_file: str, max_parallel: int = DEFAULT_MAX_PARALLEL) -> list[dict]:
    """One instance per host record for every selected check (B2.2,
    docs/research/b2_2_cli_hosts_file.md). Everything is validated before
    the first password prompt and before anything runs."""
    refuse = _refuse
    if args.quick:
        refuse('--quick cannot be combined with --hosts-file; name the checks to run on every host')
    if 'host' in extra:
        refuse('--host cannot be combined with --hosts-file; the hosts come from the file')
    check_ids = args.checks or []
    if not check_ids:
        refuse("No checks given. Use 'netaudit run <check_id> ... --hosts-file <json>'.")

    try:
        records = hosts.load_hosts_file(hosts_file)
        for record in records:
            if 'key_path' in record:
                record['key_path'] = hosts.readable_key_path(record['key_path'])
        if extra.get('key_path'):
            extra['key_path'] = hosts.readable_key_path(extra['key_path'])
    except hosts.HostRecordError as e:
        refuse(str(e))

    avail = {c['id']: c for c in list_available()}
    no_host = [c for c in check_ids
               if c not in avail or not any(p['name'] == 'host' for p in avail[c]['params'])]
    if no_host:
        refuse(f'{", ".join(no_host)}: no host parameter; run without --hosts-file')
    _refuse_unused_flags(check_ids, extra, avail)
    _refuse_wrong_values(check_ids, extra, avail)
    # B2.1 limits (max_parallel, 64 hosts per check, 256 per run), checked
    # here so an oversized run is refused before any password prompt
    try:
        validate_multi_request([{'id': c, 'instances': records} for c in check_ids], max_parallel)
    except ValueError as e:
        refuse(f'{e} (--max-parallel / hosts file)')

    # a secret typed on the command line is visible in ps and shell history
    # (review #35); a secret flag no selected check takes was refused above
    secret_names = SECRET_PARAM_NAMES | {p['name'] for c in avail.values()
                                         for p in c['params'] if p['type'] == 'password'}
    for name in sorted(secret_names & extra.keys()):
        if extra[name] != '-':
            refuse(f'--{name}: in a group run give it as "--{name} -" to be asked without echo')

    selected = []
    asked: dict[str, str] = {}
    for check_id in check_ids:
        names = {p['name'] for p in avail[check_id]['params']}
        common = {}
        for p in avail[check_id]['params']:
            if p['name'] not in extra:
                continue
            v = extra[p['name']]
            if p['type'] == 'password':  # always "-" here, checked above
                if p['name'] not in asked:
                    asked[p['name']] = getpass.getpass(f'{p["name"]} (all hosts): ')
                v = asked[p['name']]
            common[p['name']] = param_value(p, v)
        instances = [{**common, **{k: v for k, v in record.items() if k in names}} for record in records]
        selected.append({'id': check_id, 'instances': instances})
    return selected


def _run_selected(args, extra: dict, repeated: set) -> dict:
    hosts_file = extra.pop('hosts-file', None)
    max_parallel = extra.pop('max-parallel', None)
    if hosts_file is not None:
        if repeated:
            _refuse(f'{_flag_names(repeated)} given more than once')
        parallel = _max_parallel(max_parallel)
        return run_checks_multi(_group_selection(args, extra, hosts_file, parallel), max_parallel=parallel)
    if max_parallel is not None:
        _refuse('--max-parallel only applies to a group run (--hosts-file)')
    # the single form keeps last-wins for a repeated parameter, except
    # --host: two hosts there can only be a mistake (B1 §3.1)
    if 'host' in repeated:
        _refuse('--host given more than once; to audit several hosts use --hosts-file <json>')
    return run_checks(_single_selection(args, extra))


def _notify_options(args, extra: dict) -> dict | None:
    """--notify and its options (C2, docs/research/c1_schedule_notifications.md).
    All checked before anything runs: a scheduled job must not run and then
    find out that it cannot report."""
    threshold = extra.pop('notify-min-severity', None)
    job = extra.pop('job', None)
    if not getattr(args, 'notify', False):
        if threshold is not None or job is not None:
            _refuse('--notify-min-severity and --job only apply with --notify')
        return None
    threshold = threshold or notify.DEFAULT_THRESHOLD
    if threshold not in notify.SEVERITIES:
        _refuse(f'--notify-min-severity must be one of: {", ".join(notify.SEVERITIES)}')
    if job is not None and not JOB_NAME.fullmatch(job):
        _refuse('--job: 1-32 lowercase letters, digits and "-", starting with a letter or a digit')
    try:
        token, chat = notify.telegram_config()
    except notify.NotifyError as e:
        _refuse(f'--notify: {e}')
    return {'threshold': threshold, 'job': job, 'token': token, 'chat': chat}


def _send(opts: dict, text: str) -> bool:
    try:
        notify.send_telegram(text, opts['token'], opts['chat'])
    except notify.NotifyError as e:
        log.error(f'--notify: {notify.redact(str(e), opts["token"])}')
        return False
    log.info('--notify: message sent')
    return True


def _notify_failure(opts: dict, what: str) -> None:
    head = f'NetAudit: {opts["job"]}' if opts['job'] else 'NetAudit'
    _send(opts, f'{head} - {what}. See the journal of the NetAudit host.')


def _notify_report(opts: dict, report: dict, report_id: int) -> bool:
    """True when nothing had to be sent or the message was delivered."""
    try:
        changes = notify.collect_changes(report, report_id)
        if not notify.decide(changes, opts['threshold']):
            log.info('--notify: nothing to report')
            return True
        text = notify.render(changes, report_id, opts['job'])
    except Exception as e:  # noqa: BLE001 - the report is saved; say so instead of staying silent
        log.error(f'--notify: could not build the message: {type(e).__name__}')
        _notify_failure(opts, f'report #{report_id} was saved, but its summary failed ({type(e).__name__})')
        return False
    return _send(opts, text)


def cmd_run(args):
    extra, repeated = _parse_run_params(args.rest)
    opts = _notify_options(args, extra)
    try:
        report = _run_selected(args, extra, repeated)
        if opts and opts['job']:
            # a scheduled job's next notification compares with this run
            # (docs/research/a4_6_job_baseline.md)
            report['job'] = opts['job']
        saved = save_report(report)
    except SystemExit as e:
        if opts and e.code not in (0, None):
            _notify_failure(opts, 'the run was refused before it started')
        raise
    except Exception as e:
        if opts:
            _notify_failure(opts, f'the run failed before its report was saved ({type(e).__name__})')
        raise
    log.info(f'Report saved: {saved}')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    # the report is saved first: a failed send never loses it
    delivered = _notify_report(opts, report, saved) if opts else True

    if args.ai:
        log.info('Running AI analysis...')
        # anchored on this run's id: history and trend are strictly before it
        related = storage.find_related_reports(report, limit=3, report_id=saved)
        analysis = ai_analyze(report, history=related,
                              trends=trends.trend_context(report, report_id=saved))
        print('\n=== AI ANALYSIS ===')
        print(json.dumps(analysis, ensure_ascii=False, indent=2))
    if not delivered:
        sys.exit(1)


def cmd_history(args):
    items = list_reports()
    if not items:
        print('No reports yet.')
        return
    for it in items:
        print(f"#{it['id']}  {it['timestamp']}  [{', '.join(it['checks'])}]  {it['total_time']}s")


def cmd_summary(args):
    """Read-only host summary or same-check comparison for one saved report."""
    report_id = int(args.id)
    report = load_report(report_id)
    if report is None:
        print(f'Report #{report_id} not found.')
        return
    data = (host_summary.compare_hosts(report, args.check) if args.check
            else host_summary.host_summary(report))
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return
    if args.check:
        print(f'Report #{report_id}, check {args.check}:')
        for row in data['hosts']:
            counts = row['observed_counts']
            observed = ('no comparable findings' if counts is None
                        else f'{sum(counts.values())} observed findings')
            if row['status'] == 'incomplete':
                observed += ' (collection incomplete)'
            print(f"  {json.dumps(row['host'], ensure_ascii=False)} "
                  f"[{row['instance_key'] or 'single'}]: {row['status']}; {observed}")
    else:
        print(f'Report #{report_id}, hosts:')
        for row in data['hosts']:
            counts = row['observed_counts']
            observed = ('no comparable findings' if counts is None
                        else f'{sum(counts.values())} observed findings')
            if row['incomplete_checks']:
                observed += ' (collection incomplete)'
            print(f"  {json.dumps(row['host'], ensure_ascii=False)}: "
                  f"{row['completed_checks']} completed, {row['errored_checks']} errors; {observed}")
            for field in ('error_checks', 'incomplete_checks', 'unknown_checks', 'duplicate_checks'):
                if row[field]:
                    print(f"    {field}: {', '.join(row[field])}")


def cmd_analyze(args):
    report_id = int(args.id)
    report = load_report(report_id)
    if report is None:
        print(f'Report #{args.id} not found.')
        return
    related = storage.find_related_reports(report, limit=3, report_id=report_id)
    analysis = ai_analyze(report, history=related,
                          trends=trends.trend_context(report, report_id=report_id))
    print(json.dumps(analysis, ensure_ascii=False, indent=2))


def _signed(n) -> str:
    return f'+{n}' if n > 0 else str(n)


def _print_trend(trend: dict) -> None:
    runs = len(trend['points'])
    print(f"{trend['check_id']}  {trend['key']}={trend['value']}  ({runs} run{'s' if runs != 1 else ''})\n")
    if trend.get('kind') == 'event_observation':
        print('Log observations (bounded collection slices; no state change inferred):')
        for p in trend['points']:
            if p['error']:
                label = ('AMBIGUOUS: ' + p['error'][len('ambiguous: '):]
                         if p['error'].startswith('ambiguous: ') else f"ERROR: {p['error']}")
                print(f"  {p['timestamp']}  {label}")
                continue
            obs = p.get('observation') or {}
            label = obs.get('label') or 'coverage unknown'
            source = obs.get('source') or 'source unknown'
            coverage = obs.get('coverage')
            contours = (f"access={obs.get('access_coverage') or 'unknown'}, "
                        f"error={obs.get('error_coverage') or 'unknown'}") if obs.get('access_coverage') or obs.get('error_coverage') else None
            coverage_text = contours or (f'coverage={coverage}' if coverage else label)
            count = p['total'] if p['total'] is not None else 'unknown'
            c = p['counts']
            severities = (f"critical={c['critical']}, high={c['high']}, medium={c['medium']}, low={c['low']}"
                          if c is not None else 'severity counts unknown')
            limits = ', '.join(f'{name}={obs[name]}' for name in ('requested_lines', 'window_hours')
                               if obs.get(name) is not None)
            print(f"  {p['timestamp']}  observed problems={count} ({severities})  "
                  f"{source}; {coverage_text}; {label}" + (f'; {limits}' if limits else ''))
        return
    print(f"  {'timestamp':<20} {'crit':>4} {'high':>4} {'med':>4} {'low':>4} {'total':>6} {'score':>6}")
    for p in trend['points']:
        if p['error']:
            # Contract v1.1: 'ambiguous: ...' is not a failed check.
            label = 'AMBIGUOUS: ' + p['error'][len('ambiguous: '):] \
                if p['error'].startswith('ambiguous: ') else f"ERROR: {p['error']}"
            print(f"  {p['timestamp']:<20} {label}")
            continue
        c = p['counts']
        score = p['hardening_score'] if p['hardening_score'] is not None else '-'
        print(f"  {p['timestamp']:<20} {c['critical']:>4} {c['high']:>4} {c['medium']:>4} "
              f"{c['low']:>4} {p['total']:>6} {score:>6}")

    ch = trend['latest_change']
    if ch is None:
        print('\nNot enough successful runs to compare.')
        return
    # By position, not by timestamp: two different reports can share a
    # timestamp (seconds resolution). latest_change compares exactly the last
    # two non-error points, so those are the ones to print.
    prev, cur = [p for p in trend['points'] if not p['error']][-2:]
    print(f"\nLatest change ({ch['from']} -> {ch['to']}):")
    # observed counts: a run that could not look everywhere sees fewer problems
    print(f"  observed problems: {prev['total']} -> {cur['total']} ({_signed(ch['total_delta'])})")
    if ch['score_delta'] is not None:
        print(f"  hardening score: {prev['hardening_score']} -> {cur['hardening_score']} "
              f"({_signed(ch['score_delta'])})")
    if ch['params_changed']:
        print(f"  check settings changed: {', '.join(ch['params_changed'])} - missing findings are not evaluated")
    for field, label in (('new', 'new'), ('resolved', 'resolved'),
                         ('not_evaluated', 'not evaluated'), ('persisting', 'persisting')):
        print(f"  {label}: {', '.join(ch[field]) or '-'}")


def cmd_trend(args):
    if not args.check_id:
        units = trends.list_units()
        if args.json:
            print(json.dumps(units, ensure_ascii=False, indent=2))
        elif not units:
            print('No trend history yet.')
        else:
            for u in units:
                kind_label = ' (log observations)' if u.get('kind') == 'event_observation' else ''
                print(f"{u['check_id']:<22} {u['key']}={u['value']:<30} "
                      f"{u['runs']} run{'s' if u['runs'] != 1 else ''}, last {u['last_timestamp']}{kind_label}")
        return

    if args.value is None:
        if args.json:
            print(json.dumps({'error': 'missing_value', 'check_id': args.check_id}, ensure_ascii=False))
        else:
            print('Usage: netaudit trend <check_id> <value> [--key KEY]')
        sys.exit(2)

    key = args.key
    if key is None:
        keys = sorted({u['key'] for u in trends.list_units()
                       if u['check_id'] == args.check_id and u['value'] == args.value})
        if len(keys) > 1:
            if args.json:
                print(json.dumps({'error': 'ambiguous_key', 'check_id': args.check_id,
                                  'value': args.value, 'keys': keys}, ensure_ascii=False))
            else:
                print(f"{args.check_id} {args.value} matches several identity keys ({', '.join(keys)}) "
                      f"- pass --key.")
            sys.exit(2)
        key = keys[0] if keys else None

    trend = trends.trend_for(args.check_id, key, args.value) if key else None
    if args.json:
        print(json.dumps(trend, ensure_ascii=False, indent=2))
    elif trend is None:
        print(f'No trend history for {args.check_id} {args.value}.')
    else:
        _print_trend(trend)


def cmd_tools(args):
    from netaudit_pkg import tools as toolsmod
    for t in toolsmod.tools_status():
        mark = '✓' if t['installed'] else '✗'
        used = f" ← {', '.join(t['used_by'])}" if t['used_by'] else ''
        pkg = f" (package: {t['package']})" if t['package'] and not t['installed'] else ''
        print(f"{mark} {t['tool']:15}{pkg}{used}")


def cmd_install(args):
    from netaudit_pkg import tools as toolsmod
    r = toolsmod.install_tool(args.tool)
    if r.get('ok'):
        print(f"✓ {args.tool}: " + ('already installed' if r.get('already') else 'installed'))
    else:
        print(f"✗ {r.get('error')}")
        if r.get('manual_command'):
            print(f"  Manual install: {r['manual_command']}")


def cmd_web(args):
    try:
        import uvicorn
    except ImportError:
        log.error('uvicorn not installed: pip install "uvicorn[standard]" fastapi --break-system-packages')
        sys.exit(1)
    log.info(f'Web UI: http://{args.host}:{args.port}')
    os.environ['NETAUDIT_WEB_HOST'] = args.host
    uvicorn.run('web.app:app', host=args.host, port=args.port, reload=args.reload,
                app_dir=str(Path(__file__).resolve().parent))


def cmd_setup_nginx(args):
    project_dir = Path(__file__).resolve().parent
    conf = f"""# NetAudit — nginx config with basic auth
# 1. Create a user:         sudo htpasswd -c /etc/nginx/.netaudit_htpasswd {args.user}
# 2. Copy this file:        sudo cp netaudit.nginx.conf /etc/nginx/sites-available/netaudit
# 3. Enable it:             sudo ln -s /etc/nginx/sites-available/netaudit /etc/nginx/sites-enabled/
# 4. Test and reload:       sudo nginx -t && sudo systemctl reload nginx
# 5. Start the backend:     python3 netaudit.py web --host 127.0.0.1 --port {args.backend_port}

server {{
    listen 80;
    server_name {args.domain};

    # For HTTPS, uncomment after getting a certificate (certbot):
    # listen 443 ssl;
    # ssl_certificate     /etc/letsencrypt/live/{args.domain}/fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/{args.domain}/privkey.pem;

    auth_basic "NetAudit";
    auth_basic_user_file /etc/nginx/.netaudit_htpasswd;

    location / {{
        proxy_pass http://127.0.0.1:{args.backend_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
        proxy_connect_timeout 75s;
        proxy_buffering off;
        proxy_cache off;
        proxy_set_header Connection '';
        proxy_http_version 1.1;
    }}
}}
"""
    out_path = project_dir / 'netaudit.nginx.conf'
    out_path.write_text(conf)
    print(f'nginx config saved: {out_path}\n')
    print('Next steps:')
    print('  1. sudo apt install nginx apache2-utils -y')
    print(f'  2. sudo htpasswd -c /etc/nginx/.netaudit_htpasswd {args.user}')
    print(f'  3. sudo cp {out_path} /etc/nginx/sites-available/netaudit')
    print('  4. sudo ln -s /etc/nginx/sites-available/netaudit /etc/nginx/sites-enabled/')
    print('  5. sudo nginx -t && sudo systemctl reload nginx')
    print(f'  6. python3 netaudit.py web --host 127.0.0.1 --port {args.backend_port}')
    print(f'\nThen open http://{args.domain} (will prompt for login/password).')


def _systemd_calendar_ok(spec: str):
    """systemd's own verdict on an OnCalendar= value: its normalized form, or
    False when rejected; None when systemd-analyze is not installed."""
    if shutil.which('systemd-analyze') is None:
        return None
    code, out, _err = run_cmd(['systemd-analyze', 'calendar', '--', spec], timeout=15)
    if code != 0:
        return False
    match = re.search(r'Normalized form: (.+)', out)
    return match.group(1).strip() if match else spec


def _unit_path(raw, what: str, resolve: bool = True) -> str:
    # the interpreter is not resolved: a venv's python is a symlink to the
    # system one, and resolving it would lose the venv
    path = Path(raw).expanduser()
    path = path.resolve() if resolve else Path(os.path.abspath(path))
    if not UNIT_PATH.fullmatch(str(path)):
        _refuse(f'{what}: {path}: only letters, digits and . _ / @ + - are allowed in a path '
                'that goes into a systemd unit (it expands % and $ and splits on spaces); '
                'rename or move it')
    return str(path)


def cmd_setup_timer(args):
    """Writes netaudit-audit-<name>.service/.timer to the current directory
    (docs/research/c1_schedule_notifications.md §4.3). Never installs them."""
    if args.rest:
        # option names only, cut before "=": a value - a password in
        # --password=... - is never echoed (review C2 pass 1)
        flags = list(dict.fromkeys(t.split('=', 1)[0] for t in args.rest if t.startswith('--')))
        secret_names = SECRET_PARAM_NAMES | {p['name'] for c in list_available()
                                             for p in c['params'] if p['type'] == 'password'}
        secret = [f for f in flags if f[2:] in secret_names]
        if secret:
            _refuse(f'{", ".join(secret)}: a unit file is no place for a secret; scheduled runs use a key '
                    'without a passphrase and sudo -n (README, "Scheduled audits")')
        _refuse(f'unknown options: {", ".join(flags) or "(values without an option)"}')
    name = args.name
    if not JOB_NAME.fullmatch(name):
        _refuse('--name: 1-32 lowercase letters, digits and "-", starting with a letter or a digit')
    if os.geteuid() == 0:
        _refuse("setup-timer must not run as root: root's ~/.netaudit is another database. "
                'Run it as the account of netaudit.service')
    account = pwd.getpwuid(os.geteuid())
    if not UNIX_USER.fullmatch(account.pw_name):
        _refuse(f'the account name {account.pw_name!r} cannot go into User= of a unit')
    home = _unit_path(account.pw_dir, 'the home directory')
    if not UNIT_TIMEOUT.fullmatch(args.timeout):
        _refuse('--timeout: a number with s, min or h, e.g. 1h or 90min')
    spec = args.on_calendar
    if not spec.strip() or CALENDAR_FORBIDDEN.search(spec):
        _refuse('--on-calendar: no control characters, %, $ or \\ allowed')
    normalized = _systemd_calendar_ok(spec)
    if normalized is None:
        _refuse('setup-timer needs systemd-analyze (systemd) to check --on-calendar')
    if not normalized:
        _refuse('--on-calendar: systemd-analyze calendar rejected it, see `man systemd.time`')

    hosts_path = _unit_path(args.hosts_file, '--hosts-file')
    python = _unit_path(sys.executable, 'the Python interpreter', resolve=False)
    script = _unit_path(Path(__file__), 'netaudit.py')
    workdir = _unit_path(Path(__file__).resolve().parent, 'the NetAudit directory')
    try:
        notify.telegram_config()
    except notify.NotifyError as e:
        _refuse(f'{e}; every scheduled run sends through it')
    # the unit runs in the NetAudit directory, not in this one: a relative
    # key_path would point to another file there (review C2 pass 1)
    try:
        records = hosts.load_hosts_file(hosts_path)
    except hosts.HostRecordError as e:
        _refuse(str(e))
    relative = [r['host'] for r in records
                if 'key_path' in r and not Path(r['key_path']).expanduser().is_absolute()]
    if relative:
        _refuse(f'--hosts-file: key_path of {", ".join(relative)} is relative; the timer runs in '
                f'{workdir}, so write it as an absolute path (or ~/...)')
    # the same checks as the run itself: a readable hosts file without
    # secrets, checks with a host parameter, readable key files, the B2.1 limits
    _group_selection(argparse.Namespace(checks=args.checks, quick=False), {}, hosts_path)

    service_name = f'netaudit-audit-{name}.service'
    exec_start = ' '.join([python, script, 'run', *args.checks, '--hosts-file', hosts_path,
                           '--notify', '--job', name, '--notify-min-severity', args.notify_min_severity])
    service = f"""# NetAudit scheduled audit "{name}", generated by `netaudit setup-timer`.
# Runs as {account.pw_name}: the database, the Telegram settings and known_hosts
# are that account's ~/.netaudit, the same as netaudit.service's.
[Unit]
Description=NetAudit scheduled audit {name}
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User={account.pw_name}
WorkingDirectory={workdir}
Environment=PATH={home}/.local/bin:/usr/local/bin:/usr/bin:/bin
ExecStart={exec_start}
# a oneshot has no start timeout by default: a hung audit would keep the unit
# active, and the timer would never start it again
TimeoutStartSec={args.timeout}
"""
    timer = f"""# Timer for {service_name}, generated by `netaudit setup-timer`.
[Unit]
Description=Run NetAudit scheduled audit {name}

[Timer]
OnCalendar={spec}
Persistent=true
RandomizedDelaySec=5min
Unit={service_name}

[Install]
WantedBy=timers.target
"""
    service_path = Path.cwd() / service_name
    timer_path = Path.cwd() / f'netaudit-audit-{name}.timer'
    service_path.write_text(service, encoding='utf-8')
    timer_path.write_text(timer, encoding='utf-8')
    print(f'Saved: {service_path}')
    print(f'Saved: {timer_path}')
    print(f'OnCalendar: {spec} (systemd: {normalized if isinstance(normalized, str) else spec})\n')
    print('Install (from an account with sudo):')
    print(f'  sudo cp {service_path} {timer_path} /etc/systemd/system/')
    print('  sudo systemctl daemon-reload')
    print(f'  sudo systemctl enable --now netaudit-audit-{name}.timer')
    print('Check:')
    print(f'  systemctl list-timers netaudit-audit-{name}.timer')
    print(f'  sudo systemctl start {service_name}     # one run now')
    print(f'  journalctl -u {service_name}')
    print('\nNo message means: nothing new at or above the threshold, OR the timer is not running.')


def build_parser(detailed: bool = True):
    p = argparse.ArgumentParser(prog='netaudit', description='Modular universal network audit.')
    p.add_argument('--version', action='version', version=f'netaudit {__version__}')
    sub = p.add_subparsers(dest='command')

    p_list = sub.add_parser('list', help='Show all available checks')
    p_list.set_defaults(func=cmd_list)

    p_run = sub.add_parser('run', help='Run checks')
    p_run.add_argument('checks', nargs='*', help='Check IDs (see list). Omit with --quick.')
    p_run.add_argument('--ai', action='store_true', help='AI analysis after the run')
    p_run.add_argument(
        '--quick', '--simple', dest='quick', action='store_true',
        help='Run a sensible default bundle for --url (site) or --host (server) '
             'without picking individual check IDs. The site bundle audits DNS '
             'only with --domain.',
    )
    p_run.add_argument(
        '--notify', action='store_true',
        help='Send a Telegram message when something failed or new problems appeared '
             '(--notify-min-severity, default medium; --job NAME). Needs the bot token '
             'and chat ID in settings.',
    )
    p_run.set_defaults(func=cmd_run)

    p_hist = sub.add_parser('history', help='List reports')
    p_hist.set_defaults(func=cmd_history)

    p_summary = sub.add_parser('summary', help='Per-host summary of one saved report')
    p_summary.add_argument('id', help='Report ID from history')
    p_summary.add_argument('--check', help='Compare hosts for one check in this report')
    p_summary.add_argument('--json', action='store_true', help='Machine-readable output')
    p_summary.set_defaults(func=cmd_summary)

    p_an = sub.add_parser('analyze', help='AI analysis of a report by id (see history)')
    p_an.add_argument('id', help='Report ID from history')
    p_an.set_defaults(func=cmd_analyze)

    p_trend = sub.add_parser('trend', help='Finding/score trend of one audited object over saved reports')
    p_trend.add_argument('check_id', nargs='?', help='Check ID; omit to list objects with history')
    p_trend.add_argument('value', nargs='?', help='Identity value (host, url, domain, ...)')
    p_trend.add_argument('--key', help='Identity key (host, url, domain, ...) if the value is ambiguous')
    p_trend.add_argument('--json', action='store_true', help='Machine-readable output')
    p_trend.set_defaults(func=cmd_trend)

    p_tools = sub.add_parser('tools', help='Status of external tools')
    p_tools.set_defaults(func=cmd_tools)

    p_install = sub.add_parser('install', help='Install a tool (apt, allow-list)')
    p_install.add_argument('tool', help='Tool name (see tools)')
    p_install.set_defaults(func=cmd_install)

    p_web = sub.add_parser('web', help='Start the web interface')
    p_web.add_argument('--host', default='127.0.0.1')
    p_web.add_argument('--port', type=int, default=8000)
    p_web.add_argument('--reload', action='store_true', help='Auto-reload (development)')
    p_web.set_defaults(func=cmd_web)

    p_nginx = sub.add_parser('setup-nginx', help='Generate an nginx config with basic auth')
    p_nginx.add_argument('--domain', default='netaudit.local')
    p_nginx.add_argument('--user', default='admin', help='Basic auth username')
    p_nginx.add_argument('--backend-port', type=int, default=8000)
    p_nginx.set_defaults(func=cmd_setup_nginx)

    p_timer = sub.add_parser('setup-timer',
                             help='Generate a systemd timer that audits hosts and notifies via Telegram')
    p_timer.add_argument('checks', nargs='+', help='Check IDs with a host parameter (see list)')
    p_timer.add_argument('--name', required=True, help='Job name: netaudit-audit-<name>.service/.timer')
    p_timer.add_argument('--on-calendar', dest='on_calendar', required=True,
                         help='systemd OnCalendar=, e.g. daily or "Mon *-*-* 03:00:00"')
    p_timer.add_argument('--hosts-file', dest='hosts_file', required=True, help='JSON hosts file (see run)')
    p_timer.add_argument('--timeout', default='1h', help='TimeoutStartSec= of one run (default 1h)')
    p_timer.add_argument('--notify-min-severity', dest='notify_min_severity',
                         default=notify.DEFAULT_THRESHOLD, choices=notify.SEVERITIES)
    p_timer.set_defaults(func=cmd_setup_timer)

    return p


def main():
    if len(sys.argv) == 1:
        print(BANNER)
        return

    if '--detailed' in sys.argv:
        sys.argv.remove('--detailed')
        parser = build_parser()
        parser.parse_args(['--help'])
        return

    parser = build_parser()

    if len(sys.argv) > 1 and sys.argv[1] == 'run':
        known_run_flags = {'--ai', '--quick', '--simple', '--notify', '-h', '--help'}
        run_argv = []
        rest = []
        i = 2
        while i < len(sys.argv):
            tok = sys.argv[i]
            if tok in known_run_flags:
                run_argv.append(tok)
                i += 1
            elif tok.startswith('--'):
                rest.append(tok)
                if i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith('--'):
                    rest.append(sys.argv[i + 1])
                    i += 2
                else:
                    i += 1
            else:
                run_argv.append(tok)
                i += 1
        args = parser.parse_args(['run'] + run_argv)
    else:
        args, rest = parser.parse_known_args()

    if args.command is None:
        print(BANNER)
        sys.exit(1)
    args.rest = rest
    args.func(args)


if __name__ == '__main__':
    main()
