# C1: scheduled audits and notifications — research and contract

Status: **DRAFT for USER approval.** USER 2026-10-17: «этап C: только research и
контракт по расписанию и уведомлениям, без кода. Контракт утверждаю я.»
Implementer: Claude. Reviewer: GPT/Codex. No code in C1. Implementation (C2) starts
only after USER approves this contract and its decisions (§5).

Base: `main` `85f5bd5`. FACT = checked in code or run with a temporary HOME;
the real database was not opened.

## 1. What exists now

1. **One periodic job, inside the Web process.** `history_capture` (MikroTik
   traffic history) is a daemon thread started by the FastAPI lifespan
   (`web/app.py` `_lifespan`). It reads its settings from SQLite on each pass,
   sleeps `interval_sec` (at least 10 s), and keeps `last_run`/`last_error`
   in memory only. The status is lost on restart, and the thread runs only
   while the Web service runs. It stores the router password in plain text in
   the `settings` table (`history_capture_password`). That key is not in
   `SECRET_KEYS`, so the general `GET /api/settings` returns it in clear,
   while `/api/history_capture/settings` drops it. GPT/Codex reproduced this
   with a fake value (`FINDINGS.md` 2026-10-17). Nothing else runs on a
   schedule.
2. **An unattended audit is already possible from the CLI.**
   `netaudit run <checks> --hosts-file hosts.json` (B2.2) asks nothing unless a
   password is given as `-`. It uses bounded workers (default 4), saves one
   report per run, and redacts secrets. FACT: `run` exits **0** even when every
   check failed (the `--quick` run on `127.0.0.1:1` on 2026-10-17: four
   "could not connect", exit 0). So the exit code cannot tell systemd or cron
   that an audit failed.
3. **No secrets are kept for unattended runs, by design.** The host inventory
   (B2.3) has no column for a secret, presets are scrubbed (task 8), and
   passwords are asked only at run time. An unattended run therefore needs:
   - an SSH key without a passphrase, readable only by the service account
     (README, "SSH and sudo");
   - `sudo -n`: scoped `NOPASSWD` lines for the argv-style commands (README
     table), and full sudo or a root login for the checks that still pass shell
     strings to sudo.

   When sudo refuses, the report already shows sudo's own message (A1/F3).
4. **Telegram is half-prepared.** Settings `telegram_token` (in `SECRET_KEYS`,
   masked by `GET /api/settings`) and `telegram_chat`. The UI hint says "for
   future background monitoring" (`index.html`). No code sends anything.
   `httpx` is already a runtime dependency.
5. **Change detection exists.** `trends.trend_context(report, report_id)` gives,
   per unit `(check_id, identity key, value)`, the change from the previous run
   to this one: `new`, `resolved`, `persisting` and `not_evaluated`
   (tri-state, Contract v1.2). Event-log checks have no diff (2d: observations
   only). The first run of a unit has no `latest_change`.
   `host_summary.host_summary(report)` gives per host `errors`, `incomplete`,
   `unknown` and observed counts (B2.4).
6. **History window.** Trends and AI history read the latest **200 reports of
   the whole database** (`storage.RELATED_REPORTS_SEARCH_WINDOW`,
   `recent_report_data()`). A frequent schedule pushes older reports of other
   units out of that window. Reports are never pruned.
7. **Process model.** The Web UI runs as one uvicorn process under systemd
   (`netaudit.service`, `User=netaudit`, `Restart=on-failure`, README). SQLite
   uses WAL with `busy_timeout` 10 s. The instance limit of 8 is per process.
   The `known_hosts` lock works across processes (TOFU, #34). A CLI process can
   run next to the Web process on the same database.
8. **Database file permissions.** FACT (temporary HOME, umask 0002): a fresh
   `~/.netaudit/netaudit.db` is `0644` and `~/.netaudit` is `0775`. The file
   holds the AI key, the Telegram token, the MikroTik password and the Web
   login hash. Any local account that can enter the home directory can read
   them. This already holds today (`FINDINGS.md` 2026-10-17); it matters more
   once a token is used unattended.
9. **A token in a URL leaks through error text.** The Bot API URL is
   `https://api.telegram.org/bot<token>/<method>`. FACT (httpx 0.28.1): the
   text of `HTTPStatusError` contains the whole URL, token included.
   `ConnectError` text does not, but its `request.url` does. Logging an httpx
   error as-is would write the token to the journal.

## 2. Where the schedule runs

| | A. systemd timer → CLI | B. Thread in the Web process | C. Schedules in the DB, a timer runs `netaudit schedule run-due` |
|---|---|---|---|
| Runs when the Web is down or restarting | yes | no | yes |
| Missed run after reboot | `Persistent=true` catches up | lost, unless we write catch-up logic | same as A |
| Two runs of the same job at once | impossible: systemd does not start an active unit again | needs our own lock | needs our own lock per schedule |
| Long audit competes with interactive Web runs | separate process (own limit of 8) | same process, shares the limit of 8 | separate process |
| Logs, failures | journald, `systemctl status`, `OnFailure=` | in-memory status, like history capture | journald + `last_run` in the DB |
| Managed from the Web UI | no: unit files, installed with sudo | yes | yes |
| Install effort | once per schedule: copy two files with sudo | none | once: one timer |
| New code | small: message builder, `--notify`, unit-file generator | thread, scheduler, catch-up, lock, UI, API | table, CLI command, UI, API, lock |
| Time zone, DST | systemd `OnCalendar` | ours | ours (due check) |

Cron is A without catch-up, overlap protection and journald; not proposed.

**Recommendation: A.** The existing `run --hosts-file` already is the job; C2
adds only notification and a generator, `netaudit setup-timer`. It prints the
`.service`/`.timer` pair and the `sudo` steps, the same way `setup-nginx`
prints an nginx config, and never installs anything itself. B repeats the
weak points of history capture: no run while the Web is down, status lost on
restart, audits inside the Web process. C is the path if Web management is
needed later. It can reuse A's message builder and `--notify` unchanged.

## 3. Notifications

### 3.1 Channel

- **Telegram (recommended):** the settings already exist, there is one fixed
  HTTPS host, and httpx is already a dependency.
- Email (SMTP): one more secret, a host, a port and TLS settings. Not in C2.
- Webhook: a URL from settings, and content goes to an endpoint the code does
  not know. Not in C2.

The message leaves the machine for a third party: hostnames and finding ids
of the user's servers go to Telegram's servers. This is the same kind of
decision as AI analysis (Anthropic), and it is USER's (D2).

### 3.2 When a message is sent

Per run, at most **one** message (cut to fit, §3.3):

1. **Always**, when anything did not complete:
   - a check `error`, including a host that could not be reached;
   - a check `incomplete` in the host summary;
   - a run that crashed before saving a report.

   Silence must never hide a failed audit. `unknown` alone does not send a
   message: the host summary also gives it to checks that return raw data
   without findings, such as `ssh_audit` in the `--quick` server bundle, so it
   would fire on every run. When a message is sent anyway, such checks are
   listed as "no findings to compare".
2. **New problems:** ids in `latest_change.new` with a severity at or above the
   threshold (D3; default `medium`, from `critical, high, medium, low`).
3. **Resolved** ids are listed in the same message, but never trigger one on
   their own.
4. `not_evaluated` ids are shown as "not checked this time" whenever a message
   is sent. They are never called resolved.
5. `persisting` ids are not repeated.
6. **First run of a unit** (no `latest_change`): a one-time "baseline: N
   problems by severity" line instead of listing every finding as new.
7. **Event-log checks** (`EVENT_CHECK_IDS`): no diff and no "new" claims (2d).
   Only coverage problems (case 1) send a message.
8. **Nothing to report:** no message, unless a heartbeat is enabled (D4).
   Without a heartbeat, a schedule that stopped running looks the same as one
   with nothing to report. The docs must say this plainly.

### 3.3 Content and safety

- Plain text, no `parse_mode`, so text from a scanned target (finding titles
  can carry cookie names or headers of an external site) cannot become
  formatting or links.
- Link previews off (`link_preview_options: {"is_disabled": true}`), so
  Telegram never fetches a URL found in that text.
- At most 4096 characters (the Telegram limit). Lists are cut with "+N more",
  and each title is cut to 120 characters.
- Contains: the job name, report id (to open it in the Web UI), each host with
  its errors and incomplete checks, new/resolved/not-checked ids with severity
  and title, and per-host counts.
- Never contains: params, passwords (the report is already redacted, and the
  builder takes only the redacted report), `detail`, raw command output, AI
  text, or the token.
- Errors from sending are logged without the token: built from the HTTP
  status or the exception type only, never `str(exc)` or the URL (§1.9). A
  test checks this with a fake token.
- Timeout 10 s, one retry. The report is saved **before** sending, so a
  failed send never loses it.
- With `--notify`, the exit code is non-zero when the report could not be
  saved or the message could not be delivered. Then systemd marks the unit
  failed, and `OnFailure=` can act on it. Without `--notify`, the exit code
  stays as it is now (compatibility).

### 3.4 Token

The token stays in the `settings` table, as now, masked in the API. C2 adds no
new secret setting: `telegram_token` is already in `SECRET_KEYS`, and
`telegram_chat`, the job name and the threshold are not secrets. A secret
added later must go into `SECRET_KEYS`, or `GET /api/settings` returns it in
clear (§1.1). C2 also
creates the database file `0600` and `~/.netaudit` `0700`, and tightens
existing ones (D6). An environment variable or systemd `LoadCredential=`
would keep the token out of SQLite, but it would split configuration between
two places. Not proposed.

## 4. C2 scope, if the recommended options are approved

1. `netaudit_pkg/notify.py`:
   - `build_message(report, report_id, job)` — pure, deterministic text, from
     the redacted report, `trends.trend_context()` and
     `host_summary.host_summary()`;
   - `send_telegram(text)` — httpx, plain text, previews off, timeout and one
     retry, errors without the token.
2. CLI: `run … --notify [--notify-min-severity medium] [--job NAME]`, for
   single-host and `--hosts-file` runs. `--notify` with an unconfigured
   Telegram is refused before anything runs.
3. CLI: `netaudit setup-timer --name N --on-calendar SPEC --hosts-file PATH <checks>`.
   It prints `netaudit-audit-N.service` (`Type=oneshot`, `User=netaudit`, the
   README's `WorkingDirectory`/`PATH`, `ExecStart=… run <checks> --hosts-file
   PATH --notify --job N`) and `netaudit-audit-N.timer` (`OnCalendar=SPEC`,
   `Persistent=true`, `RandomizedDelaySec=` a few minutes), plus the `sudo`
   install steps. It refuses any password flag, since a unit file is no place
   for a secret. It refuses a hosts file it cannot read. It validates the
   checks the same way `run --hosts-file` does (B2.2), before printing.
4. Database file permissions (D6).
5. Docs: README EN/RU, "Scheduled audits" — the key and sudo requirements
   (§1.3), what silence means (§3.2 p. 8), the 200-report window (§1.6), the
   data that goes to Telegram (§3.1). CHANGELOG.
6. Not in C2: schedules in the Web UI (option C), email and webhooks, stored
   passwords, report retention, AI in scheduled runs (`--ai` keeps working,
   but it is not added to generated units), MikroTik history capture changes.

Tests (RED first, in C2): message builder on fixed reports for every case in
§3.2 (error, unreachable host, incomplete, `unknown` alone sends nothing,
new above and below the threshold, resolved only, not_evaluated, persisting, first run, event check,
nothing to report); cutting at 4096 characters and 120-character titles;
request body: no `parse_mode`, previews off; a fake token never in logs or
exception text on HTTP 401, 500 or connect errors (`httpx.MockTransport`, no
network); the report saved before sending, exit codes with and without
`--notify`; `setup-timer` output for a valid job, and refusals for a password
flag, an unreadable hosts file and a check without `host`; database
permissions on a fresh and an existing temporary HOME.

## 5. Decisions for USER

- **D1. Where the schedule runs:** A systemd timer + CLI (recommended) / B
  thread in the Web / C schedules in the DB + one timer.
- **D2. Channel:** Telegram only (recommended), and that the message content
  (§3.3) may go to Telegram.
- **D3. Threshold for "new problems":** `medium` and above (recommended) /
  `high` and above / every problem severity.
- **D4. Heartbeat:** none (recommended for C2, documented) / a short "no
  changes" message on every run / a daily summary.
- **D5. Unattended credentials:** key without a passphrase and `sudo -n` only,
  with no stored passwords (recommended) / store a sudo password for
  schedules (not recommended: it reverses B2.3).
- **D6. Database permissions** `0600`/`0700` in C2: yes (recommended) / a
  separate task.
- **D7. Default cadence in the docs and the generator example:** daily
  (recommended, because of the 200-report window) / hourly / no default.
