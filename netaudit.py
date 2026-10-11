#!/usr/bin/env python3
"""
NetAudit — modular, universal network audit tool.
Runs from the console and as a web service.

Console:
    netaudit.py list                        - show all available checks
    netaudit.py run mtr ping                 - run checks (default params)
    netaudit.py run mtr --target 5.20.136.3   - with params
    netaudit.py run ssl http --url https://example.com
    netaudit.py run --quick --url https://example.com   - default site bundle
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
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from netaudit_pkg import __version__, host_summary, hosts, storage, trends
from netaudit_pkg.engine import (
    DEFAULT_MAX_PARALLEL,
    list_available,
    run_checks,
    run_checks_multi,
    validate_multi_request,
)
from netaudit_pkg.history import ai_analyze, list_reports, load_report, save_report
from netaudit_pkg.redaction import SECRET_PARAM_NAMES
from netaudit_pkg.utils import log

QUICK_BUNDLE_SITE = ['ssl', 'security_headers', 'web_security_external', 'dns_audit']
QUICK_BUNDLE_SERVER = ['server_audit', 'ports', 'firewall', 'lynis_audit', 'cve_audit']

BANNER = f"""\
NetAudit v{__version__} — modular network & security audit
https://github.com/AndrejSemionov/netaudit

  netaudit run ssl web_security_external --url https://example.com
  netaudit run --quick --url https://example.com
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
                print(f"                 └─ --{p['name']} ({p['type']}, default={p['default']})")


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


def _typed(param: dict, value):
    return int(value) if param['type'] == 'number' and str(value).isdigit() else value


def _single_selection(args, extra: dict) -> list[dict]:
    check_ids = args.checks or []
    if args.quick:
        if not check_ids:
            if 'url' in extra:
                check_ids = QUICK_BUNDLE_SITE
            elif 'host' in extra:
                check_ids = QUICK_BUNDLE_SERVER
            else:
                log.error('--quick needs --url <site> or --host <server> to pick a check bundle.')
                sys.exit(1)
        log.info(f"--quick: running {', '.join(check_ids)}")

    if not check_ids:
        log.error("No checks given. Use 'netaudit run <check_id> ...' or 'netaudit run --quick --url/--host ...'.")
        sys.exit(1)

    selected = []
    # a password-type param given as "-" is asked for (no echo) instead of
    # being typed on the command line, where ps and shell history see it;
    # asked once per param name for the whole run (task 10)
    asked: dict[str, str] = {}
    for check_id in check_ids:
        spec_params = {}
        avail = {c['id']: c for c in list_available()}
        if check_id in avail:
            for p in avail[check_id]['params']:
                if p['name'] in extra:
                    v = extra[p['name']]
                    if p['type'] == 'password' and v == '-':
                        if p['name'] not in asked:
                            asked[p['name']] = getpass.getpass(f'{p["name"]} for {check_id}: ')
                        v = asked[p['name']]
                    spec_params[p['name']] = _typed(p, v)
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
    # B2.1 limits (max_parallel, 64 hosts per check, 256 per run), checked
    # here so an oversized run is refused before any password prompt
    try:
        validate_multi_request([{'id': c, 'instances': records} for c in check_ids], max_parallel)
    except ValueError as e:
        refuse(f'{e} (--max-parallel / hosts file)')

    # every secret flag, used or not: a value typed on the command line is
    # visible in ps and shell history, and a flag no selected check takes
    # would be silently ignored (review #35)
    secret_names = SECRET_PARAM_NAMES | {p['name'] for c in avail.values()
                                         for p in c['params'] if p['type'] == 'password'}
    used = {p['name'] for check_id in check_ids for p in avail[check_id]['params']}
    for name in sorted(secret_names & extra.keys()):
        if extra[name] != '-':
            refuse(f'--{name}: in a group run give it as "--{name} -" to be asked without echo')
        if name not in used:
            refuse(f'--{name} is not used by any of the selected checks; drop it')

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
            common[p['name']] = _typed(p, v)
        instances = [{**common, **{k: v for k, v in record.items() if k in names}} for record in records]
        selected.append({'id': check_id, 'instances': instances})
    return selected


def cmd_run(args):
    extra, repeated = _parse_run_params(args.rest)
    hosts_file = extra.pop('hosts-file', None)
    max_parallel = extra.pop('max-parallel', None)
    if hosts_file is not None:
        if repeated:
            _refuse(f'{", ".join("--" + k for k in sorted(repeated))} given more than once')
        parallel = _max_parallel(max_parallel)
        report = run_checks_multi(_group_selection(args, extra, hosts_file, parallel), max_parallel=parallel)
    else:
        if max_parallel is not None:
            _refuse('--max-parallel only applies to a group run (--hosts-file)')
        # the single form keeps last-wins for a repeated parameter, except
        # --host: two hosts there can only be a mistake (B1 §3.1)
        if 'host' in repeated:
            _refuse('--host given more than once; to audit several hosts use --hosts-file <json>')
        report = run_checks(_single_selection(args, extra))
    saved = save_report(report)
    log.info(f'Report saved: {saved}')
    print(json.dumps(report, ensure_ascii=False, indent=2))

    if args.ai:
        log.info('Running AI analysis...')
        # anchored on this run's id: history and trend are strictly before it
        related = storage.find_related_reports(report, limit=3, report_id=saved)
        analysis = ai_analyze(report, history=related,
                              trends=trends.trend_context(report, report_id=saved))
        print('\n=== AI ANALYSIS ===')
        print(json.dumps(analysis, ensure_ascii=False, indent=2))


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
             'without picking individual check IDs.',
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
        known_run_flags = {'--ai', '--quick', '--simple', '-h', '--help'}
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
