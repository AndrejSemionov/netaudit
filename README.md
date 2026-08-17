# NetAudit — modular universal network audit

[![Donate](https://img.shields.io/badge/Donate-PayPal-00457C?logo=paypal&logoColor=white)](https://paypal.me/AndrejSemionov)
[![Bitcoin](https://img.shields.io/badge/Bitcoin-BTC-f7931a?logo=bitcoin&logoColor=white)](#support-the-project)
[![Zcash](https://img.shields.io/badge/Zcash-ZEC-ecb244?logo=zcash&logoColor=white)](#support-the-project)

**BTC:** `bc1qhla2r3nucfr3j8mz49xsmztk50wzrmc35tmjwm`
**ZEC:** `t1Wd9Xh6EMWQvBGJzsYQPmbUG1SW7XwGz5S`

[🇷🇺 Русский](README.ru.md) · 🇬🇧 English

A diagnostics tool for networks, websites and servers. Works from the **console** and via a
**web interface**. Modular architecture: every check is a plugin, registered with a decorator
and automatically appearing both in the CLI and the web. AI analysis of the report gives
concrete "what to do" recommendations.

> ⚠️ **Use only on your own systems or with the owner's explicit permission.**
> Some checks (SQL injection via sqlmap, traffic capture, port scanning) are active security
> testing. Without the owner's permission this may be illegal in your jurisdiction. The SQL
> injection check requires explicit authorization confirmation in the UI before active
> scanning — this is a real barrier, not a formality.

## Quick install

```bash
./install.sh
```

Or manually:
```bash
sudo apt install mtr-tiny tcptraceroute dnsutils iputils-arping iperf3 -y
pip install -r requirements.txt --break-system-packages
```

Or as an installed package, giving you a `netaudit` command instead of `python3 netaudit.py`:
```bash
pip install . --break-system-packages
netaudit list
```
Both ways work identically — the commands below use `python3 netaudit.py` since that's the
more common way to run it straight from a git checkout, but every one of them also works as
`netaudit ...` if you installed the package.

## Getting started (2 minutes)

The fastest way to see what NetAudit actually does — no server setup, no config, just run one check against a public site:

```bash
python3 netaudit.py run ssl web_security_external --url https://example.com
```

This runs two checks (SSL certificate + external web security headers) against a real target and
prints a JSON report to your terminal. Replace `example.com` with any site you're allowed to test.

Add AI analysis of the results — plain-language findings and what to fix — if you've set an
Anthropic API key (see below):
```bash
python3 netaudit.py run ssl web_security_external --url https://example.com --ai
```

See every available check and what it needs:
```bash
python3 netaudit.py list
```

Prefer clicking over typing? Start the web UI and open it in a browser:
```bash
python3 netaudit.py web --host 127.0.0.1 --port 8000
```
Then go to `http://127.0.0.1:8000`, tick some checks in the left sidebar (start with the
"🔒 Site audit (external)" preset if you're not sure), and click "Run Audit". The web UI has its
own in-app "Help" tab covering every single check in detail, with exact terminal equivalents.

**Set up your Anthropic API key** (for "AI analysis: what to do" in both CLI and web) either via
the web UI (Settings tab → Anthropic API) or as an environment variable:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

**Recommended first real audit**, if you have SSH access to a server you're allowed to test:
```bash
python3 netaudit.py run server_audit lynis_audit cve_audit --host 1.2.3.4 --user root --ai
```
This combines a general security audit, a Lynis hardening score, and a CVE check against
installed software versions — then has the AI cross-reference the findings and tell you what
actually needs fixing versus what's not critical.

## Full server install (from scratch)

Step by step, for deploying on a dedicated machine/VM (tested on Ubuntu 24.04+).

### 1. Get the code and install dependencies

```bash
git clone https://github.com/AndrejSemionov/netaudit.git
cd netaudit
sudo apt update
sudo apt install -y python3 python3-pip unzip
chmod +x install.sh
./install.sh
```

Add `~/.local/bin` to PATH (pip installs uvicorn etc. there):
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

Verify everything imports and checks are listed:
```bash
python3 -c "import fastapi, uvicorn, psutil, paramiko, httpx; print('OK')"
python3 netaudit.py list
```

### 2. Capabilities for mtr (required)

`mtr` sends raw ICMP packets and hangs when run from a service without privileges. Grant it a capability:
```bash
sudo setcap cap_net_raw+ep $(which mtr)
getcap $(which mtr)   # should show cap_net_raw=ep
```

### 3. Autostart via systemd

Create `/etc/systemd/system/netaudit.service` (adjust the path/user):
```ini
[Unit]
Description=NetAudit web interface
After=network.target

[Service]
Type=simple
User=netaudit
WorkingDirectory=/home/netaudit/netaudit
ExecStart=/usr/bin/python3 /home/netaudit/netaudit/netaudit.py web --host 127.0.0.1 --port 8000
Restart=on-failure
RestartSec=5
Environment=PATH=/home/netaudit/.local/bin:/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=multi-user.target
```

`Environment=PATH` is required — otherwise systemd won't find uvicorn/fastapi in `~/.local/bin`.

```bash
sudo systemctl daemon-reload
sudo systemctl enable netaudit
sudo systemctl start netaudit
sudo systemctl status netaudit   # active (running)
```

### 4. nginx + basic auth (external access)

The backend listens on localhost only — expose it via nginx with a password:
```bash
sudo apt install -y nginx apache2-utils
python3 netaudit.py setup-nginx --domain <IP-or-domain> --user admin
sudo htpasswd -c /etc/nginx/.netaudit_htpasswd admin      # set a password
sudo cp netaudit.nginx.conf /etc/nginx/sites-available/netaudit
sudo ln -s /etc/nginx/sites-available/netaudit /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

Done — open `http://<IP-or-domain>`, log in with your username/password. Port 8000 is not exposed.
The generated config already includes `proxy_buffering off` — needed for the live chart (SSE stream).

### 5. Updating

```bash
cd ~/netaudit
git pull
find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null
sudo systemctl restart netaudit
```
Then hard-refresh the browser (Ctrl+Shift+R), since the frontend is cached.

### Service management

```bash
sudo systemctl status netaudit      # status
sudo systemctl restart netaudit     # restart after update
sudo journalctl -u netaudit -f      # live logs
```

## Web interface

```bash
python3 netaudit.py web
```
Open http://127.0.0.1:8000 — pick checks with checkboxes on the left and set parameters,
click "Run audit". Checks with a duration (mtr, ping, tcptraceroute) draw a **live chart**
in real time, and any of them can be **stopped early** with a button. Results render as tables
with loss highlighting. The "AI analysis: what to do" button sends the report to Claude and
returns a list of issues + prioritized recommendations.

The interface is in **Russian and English** — RU/EN switch in the header, and the language is
also auto-detected from the browser.

## CLI

```bash
python3 netaudit.py list                 # list all checks
python3 netaudit.py run mtr --target 8.8.8.8   # run a check
python3 netaudit.py history              # past reports
python3 netaudit.py install <tool>       # install a missing tool (nmap, tshark, ...)
```

### Common examples

Every check takes its params as `--key value` after the check ID(s). `netaudit.py list` shows
each check's exact param names and defaults.

**Audit a public website (no server access needed):**

```bash
python3 netaudit.py run ssl security_headers web_security_external dns_audit --url https://example.com
```

**Quick default bundle** — same idea, without picking check IDs by hand:

```bash
python3 netaudit.py run --quick --url https://example.com          # site bundle
python3 netaudit.py run --quick --host 1.2.3.4 --user root         # server bundle
```

**Audit a server you have SSH access to** (key-based, the common case):

```bash
python3 netaudit.py run server_audit lynis_audit docker_audit \
    --host 1.2.3.4 --user root --key_path ~/.ssh/id_rsa
```

Password-based instead of a key — read it interactively so it never lands in shell history:

```bash
read -s -p "Password: " NA_PASS && echo
python3 netaudit.py run server_audit --host 1.2.3.4 --user root --password "$NA_PASS"
unset NA_PASS
```

**Fail2Ban status on a key-only connection (no sudo password)** — most servers work fine with
the default `client` mode:

```bash
python3 netaudit.py run server_audit --host 1.2.3.4 --user root \
    --key_path ~/.ssh/id_rsa --fail2ban_mode client
```

If that server's `sudoers` is scoped to a narrow status-only wrapper instead of the raw
`fail2ban-client` binary (see "Checks" above for why and an example wrapper script), switch to
`status-wrapper` — otherwise the fail2ban section of the report comes back as `low: could not
determine fail2ban status` instead of real jail data:

```bash
python3 netaudit.py run server_audit --host 1.2.3.4 --user root \
    --key_path ~/.ssh/id_rsa --fail2ban_mode status-wrapper
```

To check on the target itself which mode you actually need, before running the audit:

```bash
# does this user's sudoers allow the raw binary without a password?
ssh youruser@1.2.3.4 'sudo -n fail2ban-client status; echo "exit=$?"'

# or only the wrapper?
ssh youruser@1.2.3.4 'sudo -n /usr/local/bin/fail2ban-status-only; echo "exit=$?"'
```

`exit=0` on the first one → use `client` (the default, no need to pass `--fail2ban_mode` at
all). `exit=0` only on the second → use `status-wrapper`. If a password is supplied for this
check (see the password example just above), `fail2ban_mode` doesn't matter at all — both
produce identical results, since `sudo -S` with a real password doesn't depend on `sudoers`
scoping the way `sudo -n` does.

**Add AI analysis** (needs an Anthropic API key, see "Getting started" above) — append `--ai`
to any `run`:

```bash
python3 netaudit.py run server_audit lynis_audit cve_audit --host 1.2.3.4 --user root --ai
```

**Checks that modify the target** (`lynis_audit`/`rootkit_check`/`aide_check` with
`auto_install=true`, or `aide_check` with `mode=init`) refuse to run without an explicit
confirmation — this is enforced the same way in the CLI and the web UI, and the check
never even connects over SSH until it's given:

```bash
# without confirmation - refused immediately, no SSH connection made
python3 netaudit.py run lynis_audit --host 1.2.3.4 --user root --auto_install true

# with confirmation - proceeds
python3 netaudit.py run lynis_audit --host 1.2.3.4 --user root --auto_install true \
    --confirm_modify "yes — modify the target system"
```

**File Integrity Monitoring** (`aide_check`) needs a one-time database initialization before
`mode=check` has anything to compare against. Both `--init` and `--check` do a full filesystem
scan, so budget several minutes on a real server (a first-hand test took ~7 minutes on a
modest VM — the check's internal timeouts (600s/900s) already account for this):

```bash
# one-time setup - creates the reference database (requires confirmation, see above)
python3 netaudit.py run aide_check --host 1.2.3.4 --user root --mode init --auto_install true \
    --confirm_modify "yes — modify the target system"

# routine use afterwards - compares current state against that database, read-only
python3 netaudit.py run aide_check --host 1.2.3.4 --user root --mode check
```

## Checks

29 checks across 6 categories: network (mtr, tcptraceroute, ping, dig, arping),
site (ssl, http, security headers, external web audit, SQL injection, DNS audit,
Certificate Transparency monitoring), security (open ports, firewall, CVE audit,
data breach check), performance (CPU/RAM/disk, iperf3), server via SSH (SSH audit,
full security audit, Lynis hardening audit, systemd sandboxing audit, kernel sysctl
hardening audit, rootkit check, file integrity monitoring, backup verification,
Docker container audit), traffic capture (tshark, MikroTik) with threat scoring of
destinations.

**Full server security audit** (`server_audit`, SSH) — a complete security audit of a server
in one connection:
- **nginx**: `server_tokens`, outdated TLS 1.0/1.1, security headers in the config, autoindex,
  version
- **Fail2Ban**: active jails, SSH coverage, ban counts, or a warning if it's not installed. The
  `fail2ban_mode` parameter controls which command is used to read the status (needs root, so
  this matters specifically when connecting **without a sudo password** — key-only auth):
    - `client` (default) — plain `fail2ban-client status`. Works for most servers, where sudo
      is either passwordless for everything (`NOPASSWD: ALL`) or a password is supplied in the
      check's params.
    - `status-wrapper` — for servers where, for security reasons, sudo isn't granted on the
      whole `fail2ban-client` binary (it has dangerous subcommands like `unban`/`set`/`stop`),
      only on a narrow wrapper script that can exclusively read status. Example wrapper and
      matching `sudoers` rule:
      ```bash
      # /usr/local/bin/fail2ban-status-only
      #!/bin/sh
      exec /usr/bin/fail2ban-client status "$@"
      ```
      ```
      # /etc/sudoers.d/netaudit-fail2ban
      your_username ALL=(root) NOPASSWD: /usr/local/bin/fail2ban-status-only
      ```
      **Important:** if a password is supplied for this host (the "Password (if not using a
      key)" field), `fail2ban_mode` doesn't matter — both modes behave identically, because
      sudo uses the password directly and doesn't depend on how `sudoers` is scoped. The
      difference between `client` and `status-wrapper` only matters when connecting **by SSH
      key with no password** — then `sudo -n` is used, and the mode you pick has to match
      whatever is actually permitted in that server's `sudoers`. See "Common examples" below
      for exact CLI invocations of both modes, and how to check which one you need on a given
      server before running the audit.
- **firewall**: actual parsing of ufw/nftables/iptables, detecting "effectively open" (ACCEPT
  with no rules)
- **MySQL/MariaDB**: whether it's listening on 0.0.0.0 (reachable from outside), bind-address
  in the config
- **SSH hardening**: `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, port,
  `MaxAuthTries`

**External web security audit** (`web_security_external`, no server access needed) — audits a
site the way an attacker would see it: security headers, server version leaks, outdated TLS
1.0/1.1 support, and exposure of sensitive paths (`.git/config`, `.env`,
`wp-config.php.bak`, `server-status`, SQL backups, etc.).

Every finding has a severity (high/medium/low/ok) and an explanation of what to fix. Summary at
the top, color-coded in the dashboard. AI analysis rolls up every high/medium finding into
prioritized, concrete recommendations (which directive, where).

**Lynis audit** (`lynis_audit`, SSH) — runs `lynis audit system` on the remote host and parses
`/var/log/lynis-report.dat`: hardening index (0–100), warnings mapped to `high` severity,
suggestions mapped to `low`. Can auto-install lynis, with confirmation (see Security below).
Otherwise read-only, same as all other SSH-based checks; full coverage requires passwordless
sudo (or root) on the target.

**DNS audit** (`dns_audit`, DNS-only) — SPF (lookup-count limit, `+all` risk), DKIM (common
selector probing), DMARC (policy, missing reports), DNSSEC (signed zone + DS chain), and
dangling CNAME detection (subdomain takeover risk) across a configurable subdomain list.

**systemd sandboxing audit** (`systemd_hardening`, SSH) — runs `systemd-analyze security
<unit>` on the target and maps every unrestricted sandboxing directive (`ProtectSystem=`,
`NoNewPrivileges=`, `PrivateNetwork=`, capability bounding set entries, syscall filters,
etc.) to a finding, severity-scaled by the directive's exposure weight. Also fetches the
official overall exposure score (0.0–10.0) and predicate (OK/MEDIUM/EXPOSED/UNSAFE) via a
second plain-text invocation, since `--json=short` doesn't expose the values needed to
recompute that score exactly. Defaults to `nginx.service` but works with any systemd unit.
Read-only; requires systemd >= 246 (Ubuntu 20.04+, Debian 11+) on the target.

**Kernel sysctl hardening audit** (`kernel_hardening`, SSH) — reads the running kernel's
sysctl values via `sysctl -a` (sudo required for a complete, error-free read) and scores 16
controls: ASLR, kernel pointer/dmesg exposure, IP/IPv6 forwarding, ICMP redirect handling,
reverse-path filtering, SYN flood protection, and SUID core-dump safety. Two controls
(`rp_filter`, `kptr_restrict`) accept a range of values as equally valid rather than a single
exact match; `fs.suid_dumpable` is graded (not binary) since its three possible values
represent genuinely different security postures, not just "more" or "less" secure. No
router-role auto-detection in this version — a genuine NAT/router host will legitimately
score lower on the three forwarding-related controls; see `docs/checks/kernel_hardening.md`
for the full control list and scoring rationale. Read-only.

## Security

- The web listens on localhost by default; external access only via nginx + basic auth (+ HTTPS via certbot).
- All external commands run through `subprocess` without `shell=True`, argument lists only.
- SSH checks are read-only by default. Optional operations that modify the target system —
  automatically installing a missing tool (`lynis_audit`, `rootkit_check`, `aide_check`) or
  reinitializing the AIDE reference database (`aide_check` with `mode=init`) — require an
  explicit confirmation ("yes — modify the target system") before they run, in both the CLI
  and the web UI. Without it, the check reports what it would have done and stops.
- The Anthropic API key is read from an environment variable / local DB, never stored in code or reports.

## Support the project

If you find the tool useful, you can support the author:

- PayPal: [paypal.me/AndrejSemionov](https://paypal.me/AndrejSemionov)
- Bitcoin (BTC): `bc1qhla2r3nucfr3j8mz49xsmztk50wzrmc35tmjwm`
- Zcash (ZEC): `t1Wd9Xh6EMWQvBGJzsYQPmbUG1SW7XwGz5S`

## License

AGPL-3.0. Free to use, modify and distribute — including commercially — but if you deploy a
modified version as a network service, you must make your changes' source available to the
users of that service. See the `LICENSE` file.
