#!/usr/bin/env python3
"""
NetAudit — modular, universal network audit tool.
Runs from the console and as a web service.

Console:
    netaudit.py list                        - show all available checks
    netaudit.py run mtr ping                 - run checks (default params)
    netaudit.py run mtr --target 5.20.136.3   - with params
    netaudit.py run ssl http --url https://example.com
    netaudit.py history                       - list reports
    netaudit.py analyze <path>                 - AI analysis of a report (what to do)

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
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from netaudit_pkg.engine import list_available, run_checks
from netaudit_pkg.history import save_report, list_reports, load_report, ai_analyze
from netaudit_pkg.utils import log


def cmd_list(args):
    for c in list_available():
        miss = f"  [missing: {', '.join(c['missing_tools'])}]" if c['missing_tools'] else ''
        print(f"[{c['category']:12}] {c['id']:18} {c['label']}{miss}")
        if c['params']:
            for p in c['params']:
                print(f"                 └─ --{p['name']} ({p['type']}, default={p['default']})")


def cmd_run(args):
    # collect shared params from --key value for all selected checks
    extra = {}
    i = 0
    unknown = args.rest
    while i < len(unknown):
        if unknown[i].startswith('--'):
            key = unknown[i][2:]
            val = unknown[i + 1] if i + 1 < len(unknown) else ''
            extra[key] = val
            i += 2
        else:
            i += 1

    selected = []
    for check_id in args.checks:
        spec_params = {}
        avail = {c['id']: c for c in list_available()}
        if check_id in avail:
            for p in avail[check_id]['params']:
                if p['name'] in extra:
                    v = extra[p['name']]
                    spec_params[p['name']] = int(v) if p['type'] == 'number' and str(v).isdigit() else v
        selected.append({'id': check_id, 'params': spec_params})

    report = run_checks(selected)
    saved = save_report(report)
    log.info(f'Report saved: {saved}')
    print(json.dumps(report, ensure_ascii=False, indent=2))

    if args.ai:
        log.info('Running AI analysis...')
        analysis = ai_analyze(report)
        print('\n=== AI ANALYSIS ===')
        print(json.dumps(analysis, ensure_ascii=False, indent=2))


def cmd_history(args):
    items = list_reports()
    if not items:
        print('No reports yet.')
        return
    for it in items:
        print(f"#{it['id']}  {it['timestamp']}  [{', '.join(it['checks'])}]  {it['total_time']}s")


def cmd_analyze(args):
    report = load_report(int(args.id))
    if report is None:
        print(f'Report #{args.id} not found.')
        return
    analysis = ai_analyze(report)
    print(json.dumps(analysis, ensure_ascii=False, indent=2))


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
    # app.py reads host from this env var at import time, to decide whether to
    # enable mandatory Basic Auth (see netaudit_pkg/web_auth.py)
    os.environ['NETAUDIT_WEB_HOST'] = args.host
    uvicorn.run('web.app:app', host=args.host, port=args.port, reload=args.reload,
                app_dir=str(Path(__file__).resolve().parent))


def cmd_setup_nginx(args):
    """Generates an nginx config with basic auth and prints the install commands."""
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
        # long-running checks (mtr/iperf) - extended timeouts
        proxy_read_timeout 3600s;
        proxy_connect_timeout 75s;
        # for streaming responses (SSE, the live chart) - disable buffering
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


def build_parser():
    p = argparse.ArgumentParser(prog='netaudit', description='Modular universal network audit.')
    sub = p.add_subparsers(dest='command', required=True)

    p_list = sub.add_parser('list', help='Show all available checks')
    p_list.set_defaults(func=cmd_list)

    p_run = sub.add_parser('run', help='Run checks')
    p_run.add_argument('checks', nargs='+', help='Check IDs (see list)')
    p_run.add_argument('--ai', action='store_true', help='AI analysis after the run')
    p_run.set_defaults(func=cmd_run)

    p_hist = sub.add_parser('history', help='List reports')
    p_hist.set_defaults(func=cmd_history)

    p_an = sub.add_parser('analyze', help='AI analysis of a report by id (see history)')
    p_an.add_argument('id', help='Report ID from history')
    p_an.set_defaults(func=cmd_analyze)

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
    parser = build_parser()
    args, rest = parser.parse_known_args()
    args.rest = rest  # for cmd_run: free-form --key value
    args.func(args)


if __name__ == '__main__':
    main()
