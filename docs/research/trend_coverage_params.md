# Trends: a changed check setting is not a fix

Status: USER approved as an autonomous task (2026-10-19: «начинай», «работайте
автономно с codex» for the finding "«Динамика» может ложно показать
«исправлено»"; contract → RED → GREEN → review → PR; merge by USER).
Implementer: Claude. Reviewer: GPT/Codex.

## Evidence

`main` `24adec4`, `netaudit_pkg/trends.py`.

A trend unit is `(check_id, identity key, value)`, for example
`(dns_audit, domain, site.example)`. `_change()` calls an id that is gone
from the latest run `resolved` unless its scope had a collection gap
(Contract v1.2). The other parameters of the run are not looked at.

So a run that simply **did not look** at something reports it as fixed:

| Run 1 | Run 2 | Shown today |
|---|---|---|
| `dns_audit`, `subdomains_to_check=www,blog`, dangling CNAME on `blog` | `subdomains_to_check=www` | the `blog` finding is `resolved` |
| `backup_check`, `directories=/var/backups,/srv/backup`, a problem in `/srv/backup` | `directories=/var/backups` | `resolved` |
| `systemd_hardening`, `unit=nginx.service` | `unit=ssh.service` | every nginx finding `resolved` |
| `backup_check`, `max_age_hours=26`, "backup too old" | `max_age_hours=1000` | `resolved` |

The same `_change()` feeds the CLI and Web trends, the AI context
(`trend_context`) and the Telegram notification (`notify.collect_changes`:
"resolved" lines). All four show the false "resolved".

## Design

1. **Check settings.** For each check instance, a snapshot records the
   settings that decide *what is checked and by which rule*: every registry
   parameter of the check except
   - the identity keys (`storage.IDENTITY_PARAM_KEYS`: they are the unit),
   - how to connect: `user`, `port`, `key_path`, and the secrets
     (`password`, `sudo_password`, never saved anyway),
   - permission switches: `auto_install`, `confirm_modify`.

   Everything else counts, so a new parameter is a check setting by default.
   A parameter saved in an old report but no longer in the registry counts
   too.
2. **Effective values.** CLI saves only the flags given; Web saves every
   field. A missing parameter takes its registry default, so a CLI run and a
   Web run with the same values compare equal. Values are compared as the
   check uses them: `checkbox` → `bool(value)`, `number` → a number when it
   parses (`26` and `"26"` are equal), anything else → its text.
3. **Rule.** When the settings of the two compared runs differ, **no** gone
   id is `resolved`: all of them are `not_evaluated`. `new` and `persisting`
   are unchanged. The change gets `params_changed`: the sorted names of the
   settings that differ (names only, no values); `[]` when none.
   - This is per instance: in a group run, a host whose settings did not
     change keeps its `resolved`.
   - Coarse on purpose: for `dns_audit` a changed subdomain list also stops
     an SPF fix from showing as `resolved` in that one comparison. The next
     run with the same settings compares normally. Wrong "not evaluated" is
     safe; wrong "resolved" is not.
4. **One report, two instances of one unit** with different settings: the
   snapshot is `ambiguous` (not compared), like instances with different
   results (Contract v1.1).
5. **Where it shows:**
   - CLI `trend`: a line `check settings changed: <names> - missing findings are not evaluated`
     when `params_changed` is not empty.
   - Web trends: the same line (RU/EN i18n).
   - AI prompt: one sentence saying what `params_changed` means.
   - Telegram: no change in the text; these ids are already listed as
     "not checked" instead of "resolved".
6. **Unchanged:** event-log checks (no state diff), metric checks (no
   snapshot), the report format, `execution_context`, identity keys, stored
   data. Snapshots built by hand without the new field (old tests) are
   compared as before.

Known limit: an old CLI report that relied on a default which has since
changed is compared with the current default.

## Tests (RED first)

- `dns_audit`: `subdomains_to_check` `www,blog` → `www`; the `blog` id is
  `not_evaluated`, not `resolved`; `params_changed == ['subdomains_to_check']`.
- `backup_check` `directories`, `max_age_hours`; `systemd_hardening` `unit`:
  same result.
- Same settings → `resolved` as before, `params_changed == []`.
- A CLI-shaped run (setting missing) vs a Web-shaped run (setting = default,
  number as int vs text, checkbox `False` vs missing) → equal, `resolved`.
- `user`, `port`, `key_path`, `auto_install` changed → still `resolved`.
- Group run: host A changes its settings, host B does not → only A's ids are
  `not_evaluated`.
- Two instances of one unit with different settings in one report →
  `ambiguous`.
- `trend_context` and `notify.collect_changes` put the id in
  `not_evaluated` / "not checked", not "resolved".
- CLI `trend` prints the settings line; Web has the i18n key in both
  languages and renders it; the AI prompt explains `params_changed`.
