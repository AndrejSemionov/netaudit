# `run`: a flag that no selected check takes is refused, not ignored

Status: USER approved as an autonomous task (2026-10-18: contract → RED →
GREEN → review → PR; merge by USER; «работайте автономно»). Implementer:
Claude. Reviewer: GPT/Codex.

## Evidence

`main` `2f1fb87`, `netaudit._single_selection()`, no network:

| Command line (flags) | What runs |
|---|---|
| `run ports firewall --host 192.0.2.10` | `ports` and `firewall` with `{}`: `ss`/`ufw` on the NetAudit machine, while the user asked about `192.0.2.10` |
| `run dns_audit --url https://github.com` | `dns_audit` with `{}`: the DNS of `example.com` (its default) |
| `run ssh_hardening --hots 192.0.2.10` (typo) | `ssh_hardening` with `{}`: "host not specified" at best |
| `run --quick --url https://example.org --host 192.0.2.10` | the site bundle; `--host` is dropped |

In all four cases `_single_selection()` hands each check only the flags it
declares and drops the rest, with no message. The group form
(`--hosts-file`, B2.2) refuses an unused *secret* flag but drops any other
unused flag in the same way.

## Design

1. After the checks are chosen (explicit ids, or the `--quick` bundle), and
   **before** any password prompt and anything that runs, `run` collects the
   parameter names of all selected checks. A flag outside that set is
   refused:

   `--host: not used by any of the selected checks (ports, firewall). Checks without --host audit this computer; drop the flag or pick checks that take it.`

   - The message names the flags only, never their values.
   - The extra sentence about this computer appears only for `--host` when
     none of the selected checks takes it.
   - Several unused flags are refused in one message, sorted.
2. A flag is fine if **at least one** selected check takes it. Mixed runs
   keep working as before, e.g. `run ssl server_audit --url U --host H`.
3. The run's own flags are taken off first, as now, and never count as
   unused: `--hosts-file`, `--max-parallel`, `--notify-min-severity`,
   `--job`, and the argparse flags `--ai`, `--quick`, `--notify`.
4. **Group form** (`--hosts-file`): the same rule, after the existing
   `--host` refusal and before the secret-flag rules. The existing
   "`--name` is not used by any of the selected checks" for a secret becomes
   part of the general rule.
5. **`--quick` with both `--url` and `--host`:** `--url` still picks the site
   bundle, which takes no `--host`, so the run is refused. Before, `--host`
   was silently dropped. The `--quick` test for this case changes from
   "site bundle runs" to "refused".
6. Unknown check ids keep their current behaviour (the report says "check …
   not found"); they declare no parameters, so a flag meant only for them is
   refused, and the message lists the selected ids, typo included.
7. Not in scope: a check that runs on its own default target when no flag is
   given at all (e.g. `run dns_audit` alone audits `example.com`). That is an
   explicit default shown by `netaudit list`, recorded in `FINDINGS.md`.

## Tests (RED first)

- `run ports firewall --host X`: refused, nothing runs, the message names
  `--host` and both checks.
- `run dns_audit --url U`: refused, names `--url`.
- A typo (`--hots`) is refused; a value given with an unused flag never
  appears in the log or on stdout/stderr.
- `run ports --host X --password -`: refused before any password prompt.
- A mixed run where every flag is taken by some check works, and each check
  gets only its own flags (unchanged).
- `--quick --url U --host H`: refused. `--quick --url U --domain D` and
  `--quick --host H --user u --key_path k` work (unchanged).
- Group form: `run ssh_hardening --hosts-file F --url U` → refused; the
  existing group tests stay green.
- The run's own flags (`--job`, `--notify-min-severity` with `--notify`,
  `--max-parallel`) are not reported as unused.
