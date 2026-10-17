# `--quick` bundles audit the target the user named

Status: USER approved as an autonomous task (2026-10-17: contract → RED →
GREEN → review → PR; merge by USER). Bundle choices are USER decisions of the
same day (see "Design"). Implementer: Claude. Reviewer: GPT/Codex.

## Evidence

Both cases reproduced on `main` `8534320` with a temporary HOME.

- **Server bundle.** `QUICK_BUNDLE_SERVER` (`netaudit.py`) is
  `server_audit, ports, firewall, lynis_audit, cve_audit`. `ports` and
  `firewall` have no parameters: `check_ports()` runs `ss -tulnp` and
  `check_firewall()` runs `ufw status` / `nft list ruleset` through `run_cmd`
  on the machine NetAudit runs on (`checks/system.py`).
  `netaudit run --quick --host 192.0.2.10 --port 1 --user nobody`: every SSH
  check fails with "could not connect: timed out", but the saved report has
  `results.ports.open_ports` with this machine's sockets (`192.168.88.12:…`)
  and `results.firewall` with its own ufw/nft errors. Nothing in the report
  says that these two results are about another machine. Their
  `execution_context` is `{}`, so the host summary (B2.4) does not show them
  under the host either; the JSON report and `--ai` do.
- **Site bundle.** `QUICK_BUNDLE_SITE` is
  `ssl, security_headers, web_security_external, dns_audit`. `--quick --url`
  passes `url` to the first three; `dns_audit` takes `domain`, which was not
  given, so it runs with its default `example.com`.
  `_single_selection(quick=True, extra={'url': 'https://github.com'})` →
  `dns_audit` params `{}`; `engine.run_checks()` → `results.dns_audit.domain
  == 'example.com'`. The report for github.com contains SPF/DKIM/DMARC
  findings of example.com, and `--ai` would analyse them as the site's.
- Neither result reaches trends: trends need an identity param
  (`storage.IDENTITY_PARAM_KEYS`), and both have empty params. So no stored
  trend history depends on the old bundles.

## Design

1. **Server bundle** (USER: «Заменить на ssh_audit»):
   `QUICK_BUNDLE_SERVER = ['server_audit', 'ssh_audit', 'lynis_audit', 'cve_audit']`.
   `ssh_audit` is the existing remote check: listening ports (`ss`),
   ufw/nft and fail2ban (through `sudo`), failed SSH logins, OS, disk, memory
   and load of the target. It takes the same SSH parameters as the other
   three, so `--user`, `--port`, `--key_path`, `--password -` and
   `--sudo_password -` reach it as they reach them (a `-` password is still
   asked once per parameter name for the whole run).
2. **Every bundle check audits the named target.** A bundle check's target
   parameter is the first of `url`, `domain`, `host` that it declares. When
   the user gave that parameter, the check runs. When not, it is left out of
   the run and the CLI logs, as a warning:
   `--quick: skipping <check_id>: add --<param> <value> to include it`.
   Only `dns_audit` (`domain`) can be skipped today: the site bundle is
   chosen by `--url`, the server bundle by `--host`.
3. **No guessing of the domain** (USER: «Да: без --domain пропустить»).
   `dns_audit` is not given a domain derived from `--url`: SPF and DMARC are
   often legitimately absent on a subdomain such as `shop.example.com`, so a
   guessed domain would report false problems.
   `--quick --url https://example.com --domain example.com` runs all four.
4. Unchanged:
   - `--quick` with explicit check IDs runs exactly those checks (the bundle
     is not used, nothing is skipped);
   - `--url` still takes precedence over `--host` when both are given;
   - `--quick` without `--url`/`--host` is refused as before; `--quick` with
     `--hosts-file` is refused as before (B2.2);
   - `netaudit run ports firewall …` and the Web UI still run `ports` and
     `firewall` locally when the user picks them by name. That is an explicit
     choice and out of scope here (`FINDINGS.md`).
   - No check module, report format, trend, Web or API code changes.

## Tests (RED first)

- every check in `QUICK_BUNDLE_SERVER` declares `host`, and every check in
  `QUICK_BUNDLE_SITE` declares `url` or `domain` (so no bundle check runs on
  the local machine or on a default target);
- `--quick --host H` selects `server_audit, ssh_audit, lynis_audit,
  cve_audit`, each with `host == H` and the shared SSH params;
- `--quick --host H --password -` asks once and gives the same password to
  all four;
- `--quick --url U` selects `ssl, security_headers, web_security_external`
  with `url == U`, no `dns_audit`, and logs the skip hint naming `--domain`;
- `--quick --url U --domain D` also selects `dns_audit` with `domain == D`;
- `--quick ssl --url U` selects only `ssl` (explicit IDs win, no hint).
