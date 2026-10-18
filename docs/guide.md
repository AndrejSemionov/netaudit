# NetAudit — step-by-step guide

🇬🇧 English · [🇷🇺 Русский](guide.ru.md) · [README](../README.md)

Step by step, from installation to scheduled audits with notifications. For what each check
does, see the [README](../README.md) and the "Help" tab in the interface.

> ⚠️ Audit only your own systems, or systems whose owner gave you explicit permission.

## Contents

1. [How it fits together](#1-how-it-fits-together)
2. [Installation](#2-installation)
3. [First run in the console](#3-first-run-in-the-console)
4. [Web interface: how to open it in a browser](#4-web-interface-how-to-open-it-in-a-browser)
5. [What is where in the interface](#5-what-is-where-in-the-interface)
6. [Audit a website](#6-audit-a-website)
7. [Prepare SSH access to a server](#7-prepare-ssh-access-to-a-server)
8. [Audit a server](#8-audit-a-server)
9. [Several servers at once](#9-several-servers-at-once)
10. [Settings: AI, Telegram, Web password](#10-settings-ai-telegram-web-password)
11. [Scheduled audits with notifications](#11-scheduled-audits-with-notifications)
12. [History, summary and trends](#12-history-summary-and-trends)
13. [Updating](#13-updating)
14. [Where the data is and how to back it up](#14-where-the-data-is-and-how-to-back-it-up)
15. [Common errors](#15-common-errors)

## 1. How it fits together

- **The NetAudit machine** is the computer or server NetAudit is installed on. It keeps the
  reports, the settings, the SSH keys used to log in to audited servers, and their host keys.
- **Audited targets** are websites (checked from outside, no access needed) and servers (checked
  over SSH, read-only).
- You can work **in the console** (`python3 netaudit.py …`) and **in a browser** (the Web
  interface). Both are the same tool and write reports to the same database.

Every SSH key path you type, in the console or in the browser, is a path **on the NetAudit
machine**, not on the computer your browser runs on.

## 2. Installation

You need Linux (tested on Ubuntu 24.04; Ubuntu 22.04+ and Debian 12 work), Python 3.11+, `git`
and `sudo`.

### 2.1 Try it on your own computer

```bash
git clone https://github.com/AndrejSemionov/netaudit.git
```

```bash
cd netaudit
```

```bash
./install.sh
```

`install.sh` installs the system tools (mtr, tcptraceroute, dig, arping, iperf3, curl, openssl,
Speedtest CLI) and the Python dependencies. Check that everything imports:

```bash
python3 -c "import fastapi, uvicorn, psutil, paramiko, httpx; print('OK')"
```

It should print `OK`. If `pip` put programs into `~/.local/bin`, add that directory to `PATH`:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
```

```bash
source ~/.bashrc
```

### 2.2 Install it on a server as a service

This way NetAudit runs all the time and the Web interface is always available.

**Step 1. A dedicated user** (from an account with sudo):

```bash
sudo adduser netaudit
```

```bash
sudo usermod -aG sudo netaudit
```

```bash
sudo -iu netaudit
```

Run all the following steps as `netaudit`.

**Step 2. Code and dependencies:**

```bash
sudo apt update
```

```bash
sudo apt install -y git python3 python3-pip unzip
```

```bash
git clone https://github.com/AndrejSemionov/netaudit.git ~/netaudit
```

```bash
cd ~/netaudit && ./install.sh
```

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

**Step 3. ICMP permission for mtr** (without it mtr hangs inside the service):

```bash
sudo setcap cap_net_raw+ep $(which mtr)
```

**Step 4. Start on boot with systemd.** Create `/etc/systemd/system/netaudit.service`:

```bash
sudo nano /etc/systemd/system/netaudit.service
```

Content:

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

Enable and start it:

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now netaudit
```

```bash
sudo systemctl status netaudit
```

The output should say `active (running)`. The service listens on `127.0.0.1:8000` only, so it is
not visible from outside. To open it in a browser on your own computer, see
[section 4](#4-web-interface-how-to-open-it-in-a-browser).

## 3. First run in the console

All checks and their parameters:

```bash
python3 netaudit.py list
```

The first website audit (use your own site's address):

```bash
python3 netaudit.py run ssl web_security_external --url https://example.com
```

At the end you see a line like `Report saved: 1`, and the report as JSON. The report number
(`1`) is how you open it again later. All saved reports:

```bash
python3 netaudit.py history
```

The ready-made website bundle (DNS is checked only with `--domain`):

```bash
python3 netaudit.py run --quick --url https://example.com --domain example.com
```

## 4. Web interface: how to open it in a browser

### 4.1 Which address to open

One rule: **NetAudit opens at the address of the computer it is installed on.**

- NetAudit and the browser on the **same** computer — open `http://127.0.0.1:8000`.
- NetAudit on a **server**, the browser on **your** computer — open the server's address, e.g.
  `http://192.168.88.20` or `http://192.168.88.20:8000`. Which of the two is yours, the command
  in section 4.2 shows.

`example.com` in this guide is only an **example of a site NetAudit checks**. You don't open it in
the browser. In the check commands you put your own site's address in its place.

### 4.2 How to find your server's address

Run this on the server where NetAudit is installed:

```bash
systemctl cat netaudit | grep ExecStart; ls /etc/nginx/sites-enabled/ 2>/dev/null
```

Find what the output shows in this table:

| What the output shows | What to open in the browser |
|---|---|
| The `ExecStart` line has `--host 0.0.0.0` | `http://<server-IP>:8000`. If another number follows `--port`, use it instead of `8000` |
| The `ExecStart` line has `--host 127.0.0.1` (or no `--host` at all), and a line `netaudit` follows | `http://<server-IP>` |
| The `ExecStart` line has `--host 127.0.0.1` (or no `--host` at all), and no line `netaudit` follows | It does not open from another computer this way. Pick a way from section 4.4; way A is the simplest |
| `No files found for netaudit.service.` | NetAudit is not installed as a service on this computer. Start it by hand as in section 4.3 |

`<server-IP>` is the server's address in your network. This command on the server shows it (take
the first number):

```bash
hostname -I
```

If the browser asks for a login and password, that is fine: where they come from is in ways B and
C of section 4.4.

### 4.3 NetAudit and the browser on the same computer

Start the Web interface:

```bash
python3 netaudit.py web
```

The terminal shows a line `Web UI: http://127.0.0.1:8000`. That is the address: open it in the
browser. No password is needed, because the server listens to this computer only. Stop the server
with `Ctrl+C` in the terminal.

If port 8000 is taken, start it on another port and open `http://127.0.0.1:8080`:

```bash
python3 netaudit.py web --port 8080
```

### 4.4 How to open NetAudit from another computer: ways A, B, C

You need this only if the table in section 4.2 said "it does not open from another computer", or
if you want to set up access differently. One way is enough.

**Way A — an SSH tunnel.** In the browser: `http://127.0.0.1:8000` on your computer. The simplest:
nothing changes on the server and nothing opens to the network.

On **your own** computer (Linux, macOS, or Windows 10+ in PowerShell), with the server's address:

```bash
ssh -L 8000:127.0.0.1:8000 netaudit@<server-IP>
```

While this window stays open, open `http://127.0.0.1:8000` on your computer: you see the server's
Web interface, carried over SSH. Close the window and the access is gone. If port 8000 is taken on
your computer, use `-L 8080:127.0.0.1:8000` and open `http://127.0.0.1:8080`.

**Way B — nginx with a password.** In the browser: `http://<server-IP>`. Good for permanent access.

On the server, as `netaudit`, from `~/netaudit`:

```bash
sudo apt install -y nginx apache2-utils
```

```bash
python3 netaudit.py setup-nginx --domain <server-IP> --user admin
```

```bash
sudo htpasswd -c /etc/nginx/.netaudit_htpasswd admin
```

`htpasswd` asks you to choose a password: this is the password you log in with in the browser.

```bash
sudo cp netaudit.nginx.conf /etc/nginx/sites-available/netaudit
```

```bash
sudo ln -s /etc/nginx/sites-available/netaudit /etc/nginx/sites-enabled/
```

```bash
sudo rm -f /etc/nginx/sites-enabled/default
```

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Open `http://<server-IP>` and log in as `admin` with that password. To change the password:

```bash
sudo htpasswd /etc/nginx/.netaudit_htpasswd admin
```

The connection is plain HTTP, without encryption. For access from the internet get a certificate
(certbot): `netaudit.nginx.conf` already has commented-out lines for HTTPS. The address then starts
with `https://`.

**Way C — directly, in your own local network only.** In the browser: `http://<server-IP>:8000`.

If NetAudit runs as a service, switch it to all addresses and restart it:

```bash
sudo sed -i 's/--host 127.0.0.1/--host 0.0.0.0/' /etc/systemd/system/netaudit.service
```

```bash
sudo systemctl daemon-reload && sudo systemctl restart netaudit
```

Check with the command from section 4.2: the `ExecStart` line must now have `--host 0.0.0.0`.

If you start it by hand, do it like this:

```bash
python3 netaudit.py web --host 0.0.0.0 --port 8000
```

On the first such start NetAudit creates the login `admin` and a password and prints the password
to the log **once**, inside a frame of `=`. The line looks like `password: <password>`. For the
service, the password is in the journal:

```bash
sudo journalctl -u netaudit | grep -A1 "user:"
```

If a login was set before, there is no new password: the log shows only the user name, and the
password stays as it was. Forgot it? See the reset in section 10.3.

Open `http://<server-IP>:8000` and log in. You can change the password in the "Settings" tab →
"Web UI access". The password travels over the network unencrypted, so this way is only for your
own local network. Otherwise use A or B.

## 5. What is where in the interface

At the top: the **"Audit"**, **"Trends"**, **"Settings"** and **"Help"** tabs, and the RU/EN
language switch.

**"Audit".**
- On the left are the **presets** (ready-made sets such as "🔒 Site audit (external)" and
  "🖥️ Server audit (SSH)") and the list of checks. Tick a check to see its parameters.
- **"+ Add host"** adds another server to the same check.
- The button at the bottom shows the estimated time and mode, e.g. "Run · ~1min · in
  background". While a run is going, the same button reads "■ Stop".
- The report is on the right. Above it are the **"History"** tab (past reports, with an "open"
  link) and **"AI analysis: what to do"** (needs an AI key, section 10.1).
- "Save as preset" remembers the ticked checks and their parameters, without passwords.

**"Trends".** How each object's findings and score changed between runs, plus a chart of mtr
loss per target.

**"Settings".**
- Anthropic API, HaveIBeenPwned API;
- Web UI access;
- Sync / async mode;
- Telegram alerts;
- Traffic history (MikroTik);
- Default targets;
- SSH hosts;
- Reputation lists;
- System tools;
- Presets.

"Save settings" saves the Anthropic and HaveIBeenPwned keys, the sync/async mode and Telegram.
Web UI access, traffic history, targets, SSH hosts and presets have buttons of their own.

**"Help".** Every check: what it does, what it needs, and how to run the same thing in the
terminal.

## 6. Audit a website

No access to the site's server is needed.

**In the browser:**
1. "Audit" tab → the "🔒 Site audit (external)" preset. It ticks `ssl`,
   `web_security_external` and `security_headers`.
2. In each of them enter the site's address (`url`, with `https://`), e.g.
   `https://example.com`.
3. Want the DNS check too (SPF, DKIM, DMARC, DNSSEC)? Also tick `dns_audit` and enter the domain
   (`domain`, without `https://`), e.g. `example.com`.
4. Click "Run".

**In the console:**

```bash
python3 netaudit.py run --quick --url https://example.com --domain example.com
```

Every finding has a severity: `critical`, `high`, `medium`, `low`, `info` or `ok`. A
`requires_manual_verification` mark means the check could not confirm it on its own, so look at
it yourself.

## 7. Prepare SSH access to a server

To audit a server, NetAudit logs in over SSH and only reads. You prepare this once per server.

**Step 1. A key on the NetAudit machine.** Run this as the user NetAudit runs as: `netaudit` for
the service.

```bash
ssh-keygen -t ed25519 -f ~/.ssh/netaudit_audit -N '' -C netaudit-audit
```

The key has no passphrase (`-N ''`). The service and scheduled audits need that: they have no
ssh-agent and nobody to type a passphrase. What protects the key is that only this user can read
the file (`-rw-------`).

**Step 2. A user on the audited server.** Logging in as `root` is the simplest. Safer is a
separate `audit` user with limited sudo rights; which commands to allow is in the
[README, "SSH and sudo"](../README.md#ssh-and-sudo). Create it **on the audited server**:

```bash
sudo adduser audit
```

**Step 3. Put the key on the server** — back on the NetAudit machine. The command asks for the
`audit` user's password once. If password login is disabled on the server, append the content of
`~/.ssh/netaudit_audit.pub` to `~audit/.ssh/authorized_keys` on the server by hand.

```bash
ssh-copy-id -i ~/.ssh/netaudit_audit.pub audit@<server-IP>
```

**Step 4. Check the key login** (it must not ask for a password):

```bash
ssh -i ~/.ssh/netaudit_audit audit@<server-IP> true
```

**About the host key.** On the first connection NetAudit remembers the server's key in
`~/.netaudit/known_hosts` and checks every later connection against it. If the key changes, the
connection is refused (see [section 15](#15-common-errors)). This is how NetAudit protects you
from a substituted server.

**sudo.** Some checks read what only root can: `nginx -T`, `sshd -T`, `sysctl -a`, firewall rules.
If sudo on the server asks for a password, you have two options:
- type it at run time: the "Sudo password (if sudo asks for one)" field in the browser, or
  `--sudo_password -` in the console, which asks without echoing;
- allow the needed commands without a password (NOPASSWD). For scheduled audits this is the only
  way. The exact sudoers lines are in the [README, "SSH and sudo"](../README.md#ssh-and-sudo).

Passwords are never saved: not in reports, not in presets, not in data sent to AI.

## 8. Audit a server

**In the browser:**
1. "Audit" tab → the "🖥️ Server audit (SSH)" preset (that is `server_audit`: nginx, fail2ban,
   firewall, MySQL, SSH). Tick more checks if you want, e.g. `ssh_hardening`,
   `kernel_hardening`, `lynis_audit`.
2. In each check's block enter:
   - `host` — the server's address;
   - `user` — e.g. `audit`;
   - `key_path` — the key's path on the NetAudit machine, e.g. `/home/netaudit/.ssh/netaudit_audit`;
   - "Sudo password", if sudo asks for one.
3. Click "Run". You can see which check is running.

**In the console** (`--sudo_password -` means "ask without echoing"):

```bash
python3 netaudit.py run server_audit ssh_hardening kernel_hardening --host <server-IP> --user audit --key_path ~/.ssh/netaudit_audit --sudo_password -
```

The ready-made server bundle:

```bash
python3 netaudit.py run --quick --host <server-IP> --user audit --key_path ~/.ssh/netaudit_audit
```

If a check could not connect or lacked rights, the report shows an error with the reason, such
as `could not connect: …` or `sudo: a password is required`. Such a check means "not checked",
not "all clean".

## 9. Several servers at once

**In the browser:**
1. "Settings" → "SSH hosts": add the servers (label, host, user, port, key path). There are no
   passwords there.
2. "Audit": tick the SSH checks. In the "Saved hosts" block tick the servers and click "Apply to
   selected checks": every check gets one block per server.
3. Click "Run". The report has a per-host summary, where errors and incomplete collection stay
   separate from finding counts.

**In the console.** Create `~/hosts.json` (no passwords go into it):

```json
[
  {"host": "192.168.88.20", "user": "audit", "key_path": "/home/netaudit/.ssh/netaudit_audit"},
  {"host": "192.168.88.21", "user": "audit", "port": 2222, "key_path": "/home/netaudit/.ssh/netaudit_audit"}
]
```

```bash
python3 netaudit.py run ssh_hardening kernel_hardening --hosts-file ~/hosts.json
```

4 servers are audited at a time; change it with `--max-parallel N` (1 to 16). A per-host summary
of a saved report:

```bash
python3 netaudit.py summary <report-number>
```

## 10. Settings: AI, Telegram, Web password

### 10.1 AI analysis (Anthropic)

1. Get an API key at `console.anthropic.com`.
2. "Settings" → "Anthropic API" → paste the key → "Verify key" → "Save settings".
3. After an audit click "AI analysis: what to do". In the console, add `--ai`:

```bash
python3 netaudit.py run ssl web_security_external --url https://example.com --ai
```

The report goes to Anthropic (without passwords). The key is stored in the database on the
NetAudit machine and is never sent back to the browser.

### 10.2 Telegram

1. In Telegram open `@BotFather` → `/newbot` → choose a name. BotFather sends a **token** like
   `123456789:AA…`.
2. Send your bot any message (otherwise it cannot write to you).
3. Find the **chat ID**: open the address below in a browser (with your token) and look for
   `"chat":{"id":…}`. For a group: add the bot to the group, send `/start@your_bot_name` there (by
   default a bot does not see plain text in a group), and open the address again. Take the `id` of
   the entry whose `"type"` is `"group"` or `"supergroup"`; a group's ID is negative.

```text
https://api.telegram.org/bot<TOKEN>/getUpdates
```

4. "Settings" → "Telegram alerts" → token and chat ID → "Save settings".
5. Test it. An audit of a port that is certainly closed always gives an error, so a message is
   sent:

```bash
python3 netaudit.py run ssh_hardening --host 127.0.0.1 --port 1 --notify --job test
```

Like the AI key, the token is never sent back to the browser.

### 10.3 The Web interface password

It is needed only for way C in section 4.4; with way B, `htpasswd` in nginx sets the password.
"Settings" → "Web UI access": login and a new password (8 characters or more) → "Save access".

If you forgot it, reset it as the NetAudit user:

```bash
python3 -c "import sqlite3, pathlib; c = sqlite3.connect(pathlib.Path.home() / '.netaudit' / 'netaudit.db'); c.execute(\"DELETE FROM settings WHERE key IN ('web_auth_user', 'web_auth_password_hash')\"); c.commit()"
```

Then restart NetAudit: a new password appears in the log, as in way C of section 4.4.

## 11. Scheduled audits with notifications

For example: audit the servers every night, and get a Telegram message if something failed or
new problems appeared.

You need first:
- Telegram configured (section 10.2);
- an SSH key without a passphrase (section 7);
- sudo without a password for the needed commands (section 7);
- a hosts file with absolute key paths (section 9).

**Step 1.** As the service user (`netaudit`, not root), from `~/netaudit`:

```bash
python3 netaudit.py setup-timer --name daily --on-calendar daily --hosts-file /home/netaudit/hosts.json server_audit ssh_hardening kernel_hardening
```

It checks everything and writes two files into the current directory:
`netaudit-audit-daily.service` and `netaudit-audit-daily.timer`. It installs nothing itself.
`--on-calendar` is a systemd schedule, e.g. `daily`, `Mon..Fri *-*-* 03:30:00`, `weekly`.

**Step 2.** Install them with the commands it printed:

```bash
sudo cp netaudit-audit-daily.service netaudit-audit-daily.timer /etc/systemd/system/
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now netaudit-audit-daily.timer
```

**Step 3.** Check when the next run is, and run it once now:

```bash
systemctl list-timers netaudit-audit-daily.timer
```

```bash
sudo systemctl start netaudit-audit-daily.service
```

```bash
journalctl -u netaudit-audit-daily.service -n 50
```

**When a message is sent:**
- a check failed, a server could not be reached, or data was collected only in part;
- new problems of `medium` or higher appeared (change the threshold with
  `--notify-min-severity`);
- the first run found problems.

**Important:**
- **No message does not mean "all fine".** A stopped timer looks the same, so look at
  `systemctl list-timers` now and then.
- The message goes to Telegram's servers. It contains host names, finding ids and titles, without
  passwords or details.
- Daily is a good cadence: trends read the latest 200 reports of the whole database.

The detailed rules are in the
[README, "Scheduled audits and Telegram notifications"](../README.md#scheduled-audits-and-telegram-notifications).

## 12. History, summary and trends

```bash
python3 netaudit.py history
```

```bash
python3 netaudit.py summary <report-number>
```

```bash
python3 netaudit.py trend
```

```bash
python3 netaudit.py trend ssh_hardening <server-IP>
```

- `history` lists the reports.
- `summary` is the per-host summary of one report.
- `trend` shows which objects have been run several times.
- `trend <check> <object>` shows what changed. "not evaluated" means it could not be checked this
  time, not that the problem was fixed.

In the browser, the same is under "History" on the "Audit" tab and in the "Trends" tab.

## 13. Updating

On the server, as `netaudit`:

```bash
cd ~/netaudit && git pull origin main && sudo systemctl restart netaudit
```

Then reload the page in the browser without the cache: `Ctrl+Shift+R`. If the update changed
`requirements.txt`, run `pip install -r requirements.txt --break-system-packages` before the
restart. Reports and settings live outside the code directory; `git pull` does not touch them.

## 14. Where the data is and how to back it up

Everything is in `~/.netaudit/` of the user NetAudit runs as:
- `netaudit.db` — reports and settings, including the AI key and the Telegram token;
- `known_hosts` — host keys of the audited servers.

Only the owner can open the directory (`700`) and the database (`600`).

### 14.1 Backup

Run this as the NetAudit user. You do not need to stop the service: SQLite makes the copy, and it
stays consistent. Each run creates a **new** file `~/netaudit-backup-YYYYMMDD-HHMMSS.db` with mode
`600`. The mode is set before any secret goes into the file, and existing files are never touched.

```bash
python3 - <<'EOF'
import os, sqlite3, sys, time
db = os.path.expanduser('~/.netaudit/netaudit.db')
copy = os.path.expanduser(time.strftime('~/netaudit-backup-%Y%m%d-%H%M%S.db'))
if not os.path.isfile(db):
    sys.exit(f'no database at {db}')
try:  # a new file that only you can read, before any secret goes into it
    os.close(os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
except FileExistsError:
    sys.exit(f'{copy} already exists; run again in a second')
src, dst = sqlite3.connect(db), sqlite3.connect(copy)
src.backup(dst)
print(copy, '-', dst.execute('SELECT count(*) FROM reports').fetchone()[0], 'reports')
dst.close(); src.close()
EOF
```

At the end the script prints the file name and the number of reports in the copy. The copy holds
the same secrets as the database: keep it just as private.

### 14.2 Restore from a backup

While you restore, nothing may use the database: not the Web service, not scheduled audits, not
commands started by hand.

**Step 1.** Note which audit timers you have: you start them again after the restore.

```bash
systemctl list-timers --all 'netaudit-audit-*'
```

**Step 2.** Stop the timers, the scheduled audits and the Web service. A scheduled audit that is
running right now is interrupted without a report, so better wait for it to finish.

```bash
sudo systemctl stop 'netaudit-audit-*.timer' 'netaudit-audit-*.service' netaudit
```

**Step 3.** Make sure NetAudit runs nowhere else. The command must print nothing. If it prints
something, end those processes, e.g. with `Ctrl+C` in their terminal. The script in step 4
checks this again by itself.

```bash
pgrep -af netaudit.py
```

**Step 4.** Restore the database. Put your backup file on the first line.

```bash
python3 - ~/netaudit-backup-20261017-030000.db <<'EOF'
import glob, os, shutil, sqlite3, sys, time
backup, db = sys.argv[1], os.path.expanduser('~/.netaudit/netaudit.db')
files = [db, db + '-wal', db + '-shm']
new = db + '.restoring'
saved = os.path.expanduser(time.strftime('~/netaudit-before-restore-%Y%m%d-%H%M%S'))
# 1. the backup must be a usable NetAudit database
if not os.path.isfile(backup):
    sys.exit(f'no backup at {backup}; nothing was changed')
try:
    b = sqlite3.connect(f'file:{backup}?mode=ro', uri=True)
    ok = b.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    reports = b.execute('SELECT count(*) FROM reports').fetchone()[0]
except sqlite3.DatabaseError:
    ok = False
if not ok:
    sys.exit(f'{backup} is not a usable NetAudit database; nothing was changed')
# 2. no process may have the database open
real = {os.path.realpath(f) for f in files}
busy = set()
for fd in glob.glob('/proc/[0-9]*/fd/*'):
    try:
        if os.path.realpath(fd) in real:
            busy.add(fd.split('/')[2])
    except OSError:
        pass
if busy:
    sys.exit(f'the database is still open by process {", ".join(sorted(busy))}; stop it first; nothing was changed')
if os.path.exists(new) or os.path.exists(saved):
    sys.exit(f'{new} or {saved} already exists; nothing was changed')
# 3. the current files, byte for byte, into a folder only you can open
try:
    os.mkdir(saved, 0o700)
    for f in files:
        if os.path.exists(f):
            shutil.copy2(f, saved)
except OSError as e:
    sys.exit(f'could not save the current files to {saved}: {e.strerror}; nothing was changed')
# 4. a new private database from the backup, checked before it replaces anything
os.close(os.open(new, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
try:
    n = sqlite3.connect(new)
    b.backup(n)
    good = n.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    n.close()
except sqlite3.Error:
    good = False
if not good:
    os.remove(new)
    sys.exit(f'the restored copy failed its check; nothing was changed (current files also kept in {saved})')
# 5. swap; the old -wal/-shm belong to the old database and are kept in the folder above
for f in files[1:]:
    if os.path.exists(f):
        os.remove(f)
os.replace(new, db)
print(f'restored {reports} reports from {backup}; the previous files are in {saved}')
EOF
```

What the script does:
- if the backup is missing, damaged or not a NetAudit database, it refuses and changes nothing;
- if any process still has the database open, it refuses and changes nothing;
- it saves the current database files as they are, byte for byte, into a new folder
  `~/netaudit-before-restore-…` (mode `700`). This works even when the current database is
  damaged: it does not have to be read;
- it builds a new database from the backup (mode `600`), checks it, and only then puts it in
  place of the old one. The old `-wal` and `-shm` go with the old database into that folder.

If anything goes wrong, the previous files are in that folder.

**Step 5.** Start everything again: the Web service, and each timer from the list in step 1.

```bash
sudo systemctl start netaudit
```

```bash
sudo systemctl start netaudit-audit-daily.timer
```

## 15. Common errors

| What you see | Why | What to do |
|---|---|---|
| The page does not open from another computer | The service listens on `127.0.0.1` only | Find your address (section 4.2); if it does not open that way, an SSH tunnel or nginx (section 4.4) |
| The browser asks for a login and password you don't know | With nginx, `htpasswd` sets it; with `--host 0.0.0.0`, NetAudit does | `sudo htpasswd /etc/nginx/.netaudit_htpasswd admin`, or the reset in section 10.3 |
| `Auth not configured. Restart the server to generate credentials.` | The Web login was removed from the database while the server ran | Restart NetAudit; a new password appears in the log |
| `[Errno 98] … address already in use` | The port is taken (for example, a second instance runs) | Stop the old one, or start with `--port 8080` |
| The old interface after an update | The browser used a cached page | `Ctrl+Shift+R` |
| `could not connect: timed out` / `Unable to connect to port …` | Wrong address or port, the server is off, or a firewall blocks it | Try `ssh -i ~/.ssh/netaudit_audit audit@<server-IP> true` from the NetAudit machine |
| `… presented a different SSH host key than the one NetAudit has on file …` | The server was reinstalled, or substituted | Make sure it is your server and the key changed legitimately, then `ssh-keygen -R <server-IP> -f ~/.netaudit/known_hosts` (for a port other than 22: `ssh-keygen -R '[<server-IP>]:2222' -f ~/.netaudit/known_hosts`) |
| `the private key … is encrypted` | The key has a passphrase and ssh-agent does not hold it | In the console, `ssh-add`; for the service and schedules, a key without a passphrase (section 7) |
| `sudo: a password is required` | sudo on the server wants a password | Enter "Sudo password" / `--sudo_password -`, or set up NOPASSWD (section 7) |
| `… is open to other accounts and its mode could not be changed …` | The files in `~/.netaudit` belong to another user | Run NetAudit as their owner, or run the `chmod` the message names |
| mtr hangs when NetAudit runs as a service | mtr has no ICMP permission | `sudo setcap cap_net_raw+ep $(which mtr)` |
| `--notify: Telegram is not configured …` | The token or the chat ID is missing | Section 10.2 |
| `Telegram: HTTP 401 (the bot token was rejected)` / `HTTP 400 (check the chat ID)` / `HTTP 403 …` | Wrong token, wrong chat ID, or the bot cannot write to that chat | Check the token with BotFather and the chat ID via `getUpdates`, and write to the bot first |
| "Set ANTHROPIC_API_KEY on the server running netaudit." | No AI key | Section 10.1 |
| `uvicorn not installed` | The Web dependencies are not installed | `pip install -r requirements.txt --break-system-packages` |
