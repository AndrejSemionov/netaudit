# `run`: a check whose default target is `example.com` needs its target named

Status: USER approved as an autonomous task (2026-10-18: «Дальше: проверка
без указанной цели идёт по цели по умолчанию (example.com). Контракт → RED →
GREEN → ревью Codex → PR, автономно. Слияние — я.»). Implementer: Claude.
Reviewer: GPT/Codex.

## Evidence

`main` `bcd7ff8`, `netaudit._single_selection()`, no network:

| Command line | What the check gets | What it audits |
|---|---|---|
| `run dns_audit` | `{}` | `example.com` (function default) |
| `run ssl` | `{}` | `https://example.com` |
| `run cert_transparency` | `{}` | `example.com` |
| `run ssl dns_audit --url https://site.example` | `ssl` gets the URL, `dns_audit` gets `{}` | the site's TLS, and the DNS of `example.com` |

No message says that the target is a placeholder. The report looks like a
report about "your" site. PR #46 refuses a flag that no check takes, but here
no flag is given at all, so that rule does not apply.

Six checks have such a default (`netaudit list`, registry):

| Check | Target flag | Default |
|---|---|---|
| `ssl` | `--url` | `https://example.com` |
| `http` | `--url` | `https://example.com` |
| `security_headers` | `--url` | `https://example.com` |
| `web_security_external` | `--url` | `https://example.com` |
| `dns_audit` | `--domain` | `example.com` |
| `cert_transparency` | `--domain` | `example.com` |

`example.com` is a name reserved for documentation (RFC 2606). It is never
the user's site, so auditing it is never what the user wanted.

## Design

1. A target parameter (`storage.IDENTITY_PARAM_KEYS`) whose registry default
   is `example.com` or `https://example.com` is **required** on the command
   line. The list of such defaults is one constant in `netaudit.py`.
2. `run` (single form, including `--quick` and explicit check ids) refuses a
   selected check whose required target was not given:

   `No target given: ssl needs --url (otherwise it checks the example https://example.com), dns_audit needs --domain (otherwise it checks the example example.com). Add the flag with your own site or domain`

   - All such checks are named in one message, in the order given.
   - Exit code is non-zero; nothing runs; no password prompt comes first.
   - The check runs after `_refuse_unused_flags()` (#46): `run dns_audit --url U`
     keeps its #46 message, which already says to use `--domain`.
3. `--quick --url U` is unchanged: the site bundle gives `--url` to `ssl`,
   `security_headers`, `web_security_external`, and skips `dns_audit` with a
   hint unless `--domain` is given (#40).
4. `netaudit list` shows such a parameter as `required` instead of
   `default=https://example.com`, so the list matches what `run` accepts.
5. Unchanged:
   - **Group form** (`--hosts-file`): it takes only checks with a `host`
     parameter, so these six checks are already refused there.
   - **Web**: the form shows the default in the field, so the user sees the
     address before pressing Run. Not in scope.
   - **Network diagnostics** (`ping`, `mtr`, `tcptraceroute` → `8.8.8.8`,
     `dig` → `google.com`, `arping` → `192.168.88.1`, `mikrotik_sniffer`
     router `192.168.88.1`): these are real reachable targets. `ping 8.8.8.8`
     is a useful default ("is the internet reachable?"), and the report
     names the address.
   - **Empty defaults** (`host=''` of SSH checks, `url=''` of
     `sql_injection`, `emails=''`, `server=''` of `iperf`): these checks
     already return an explicit error ("host not specified"), so no wrong
     target is audited.
   - The check functions keep their defaults; only the CLI asks for the
     target.

## Tests (RED first)

- `run ssl`, `run dns_audit`, `run cert_transparency` (each alone): refused,
  nothing runs, the message names the check, its flag and the example.
- `run ssl dns_audit --url U`: refused, names `dns_audit` and `--domain`;
  nothing runs (not even `ssl`).
- Several checks without a target are named in one message, in the order
  given.
- The refusal comes before any password prompt
  (`run ssl server_audit --host H --password -`).
- The set of checks with an example default is exactly the six above, and
  every registry default containing `example.` is in that set (a new check
  with such a default needs a decision).
- `run ssl --url U`, `run dns_audit --domain D`, a mixed run where every
  target is given, `--quick --url U` (with and without `--domain`), and
  `run ping` (default `8.8.8.8`) work as before.
- `netaudit list` prints `required` for these six parameters and still prints
  `default=8.8.8.8` for `ping`.
