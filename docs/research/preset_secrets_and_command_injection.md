# Preset secrets and command injection — fix contract proposal (task 8)

Status: **APPROVED by USER rev.1** (2026-10-08). USER: «делай задачу 8» (the
two findings recorded during task 7, E1–E2); D1 = **all three** extra findings
(E3–E5) in scope; D2 = **D2-A** (scrub tool covers presets); MODE: AUTONOMOUS,
GPT/Codex reviews the contract together with the code.
Implementer: Claude. Reviewer: GPT/Codex.
Branch: `fix/preset-secrets-shell-injection`, stacked on `fix/sudo-privilege`
(PR #8), because both change `checks/systemd_hardening.py`.

## Evidence

- **E1. Web presets store the SSH password and serve it back.**
  `saveCurrentAsPreset()` sends `getSelected()` (`web/static/index.html`),
  which reads every `input[data-param]`, including `type=password`.
  `storage.preset_save()` writes `checks` as is and `presets_list()` returns it,
  so does `GET /api/presets`. Redaction (task 3) covers `execution_context`
  only; the scrub tool (task 5) covers the `reports` table only.
  Reproduced on a temporary HOME with TestClient: POST a preset with
  `password='FAKE-TEST-PW'` → the GET body and the raw `presets.checks` row both
  contain it.
- **E2. `systemd_hardening`: `unit` reaches a shell unquoted.**
  `ssh.run(f'systemctl status {unit} --no-pager 2>&1 | head -1')`. The sudo
  call no longer has this problem after task 7 (argv), but a unit that starts
  with `-` is still parsed as an option by `systemd-analyze` running as root
  (`--root=`, `--security-policy=` …).
- **E3. `cve_audit`: paths found on the target reach a shell unquoted.**
  `base` is cut from `find /var/www -maxdepth 3 -iname wp-includes` and used in
  `grep … {base}/wp-includes/version.php`; `lock_path` comes from
  `find /var/www /home … composer.lock` and is used in `cat {lock_path}`. Anyone
  who can create a directory there (a web application running as `www-data`,
  a hosting user) chooses the name, e.g. `site$(…)`. The command then runs as
  the audit SSH user, which defaults to `root`. Reproduced with the exact
  command strings in a temporary directory: `$(touch …)` in the WordPress path
  and `;touch …;` in the composer path both created their files.
- **E4. `backup_check`: `directory` goes through `repr()`.**
  `find {directory!r} …` and `df -P {directory!r} …`. Python `repr` is not
  shell quoting: a name with `'` is printed in double quotes, so `$(…)` expands
  (reproduced). A directory starting with `-` is parsed by `find` as an
  expression: `-delete` would make it delete files under the SSH user's home.
- **E5. MikroTik `target_ip` reaches a RouterOS command unvalidated.**
  `capture.check_mikrotik_sniffer()` and `history_capture` build
  `/ip firewall connection print terse where src-address~"{target_ip}"`.
  A `"` ends the string and `;` starts another RouterOS command. In the Web UI
  `history_capture` keeps the value in settings and runs it periodically.

E2, E4 and E5 need someone who can already run checks (CLI user or Web user
behind Basic Auth). E3 does not: the target's own unprivileged users control the
input, and the result is code execution as the audit user.

## Design

### P1. Presets never hold secret params

- `redaction.redact_preset_checks(checks)`: a copy of the preset's check list
  with every key from `SECRET_PARAM_NAMES` removed from any dict inside each
  item (`params`, every `instances[*]`). One source of truth for what counts as
  a secret, same as reports. The input is not modified.
- `storage.preset_save()` strips before INSERT (last barrier for every caller),
  `storage.presets_list()` strips on read (rows saved before the fix).
  `GET /api/presets` therefore never returns a secret.
- Web: `saveCurrentAsPreset()` leaves out `type=password` inputs before sending
  (the secret is not sent for a save at all), and the status line says that
  passwords are not saved. Applying a preset leaves password fields as they are.
- Existing rows (decision D2): see below.

### P2. Operator-supplied values

- `systemd_hardening`: reject `unit` unless it matches systemd's unit-name
  characters `[A-Za-z0-9:_.@\\-]`, length 1–256, and does not start with `-`
  → `{'error': 'invalid systemd unit name'}` before connecting. The
  `systemctl status` line also gets `shlex.quote(unit)`.
- `backup_check`: every directory must be an absolute path (start with `/`) →
  otherwise a per-directory error, no command is run for it. `find` and `df`
  use `shlex.quote(directory)` instead of `repr`.
- MikroTik: `target_ip` must parse with `ipaddress.ip_address()` →
  otherwise `{'error': …}` before connecting (`capture.py`), a `RuntimeError`
  in the history-capture run (`history_capture.py`), and `save_settings()`
  refuses to store it (the API returns 400). An empty value stays allowed in
  settings (capture disabled).

### P3. Values read from the target (`cve_audit`)

- `base` and `lock_path` are passed through `shlex.quote()`.
- `dpkg-query … {dpkg_name}` and `apt-cache show {dpkg_name}={version}` also
  get `shlex.quote()`. Their sources (dpkg names/versions, `uname -r`) are
  constrained, so this is hardening only; package names made only of safe
  characters come out unchanged, so existing command strings stay the same.

### D2. Preset rows saved before the fix

- **D2-A (recommended):** extend `scrub_legacy_secrets` to the `presets` table.
  Dry-run prints `presets=N presets_affected=M` next to the report counts;
  `--apply` rewrites both tables in the same transaction, behind the same
  private backup, verification, `VACUUM` and checkpoint. A malformed preset row
  blocks `--apply`, like a malformed report. Nothing runs automatically.
  Read-side stripping (P1) already stops the API from returning old secrets.
- **D2-B:** a one-time automatic cleanup at startup (storage migration). Simple,
  but it rewrites the user's database without a backup, which tasks 3 and 5
  ruled out for reports.
- **D2-C:** read-side stripping only. Old secrets stay in the file.

## Out of scope

- Other `ssh.sudo('<shell string>')` calls (task 7 finding).
- `src-address~` is a regular-expression match in RouterOS; a valid IP still
  matches `.` loosely. Unchanged.
- Settings that are secrets by design (`anthropic_api_key`,
  `history_capture_password`, `telegram_token`, `hibp_api_key`) stay in
  settings; their GET already hides them.

## Tests (RED first, temporary HOME, no real SSH)

1. P1: `redact_preset_checks` for flat `params` and `instances`; input not
   mutated; `preset_save()` + raw SQLite row has no secret; `presets_list()`
   strips a row written directly with a secret; TestClient POST → GET has no
   secret; the existing preset round trip for non-secret params still works.
2. P1 Web: the saved preset request from `saveCurrentAsPreset()` excludes
   password inputs (checked on the JS source, the same way the 2f XSS guard
   tests read `index.html`).
3. P2: invalid units (`x; id`, `-x`, `--root=/`, empty after validation, 257
   characters) → error and no SSH connection; valid units (`nginx.service`,
   `getty@tty1.service`, `nginx`) pass; the `systemctl status` command is quoted.
   `backup_check`: relative path or `-delete` → error, no command; a directory
   with `'` and `$(…)` reaches `find`/`df` as one quoted argument and is not
   executed (real `/bin/sh` with a local executor, as in task 7). MikroTik:
   `1.1.1.1"; /system reboot` → error before connecting, in both paths;
   settings refuse it; IPv4 and IPv6 pass.
4. P3: WordPress and composer paths with `$(…)` and `;` are quoted; run through
   a real `/bin/sh` they are not executed.
5. D2-A: scrub dry-run counts presets; `--apply` removes secrets from presets
   and reports in one transaction; the backup keeps the originals; a malformed
   preset row blocks `--apply`; a database without a `presets` table still
   works.

Verification: full pytest including Web, full Ruff, bandit, pip-audit,
`git diff --check`; browser check that saving and applying a preset works and
the password field is not filled from a preset.
