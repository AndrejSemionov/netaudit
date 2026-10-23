# Stable finding IDs — second migration (the remaining state checks)

Status: USER asked to finish the remaining list autonomously (2026-10-22:
«докончим уже все и закроем дыры работаем автономно»); this is item 5 of
it (`FINDINGS.md` 2026-09-26: findings without an id; titles with changing
numbers). It applies the approved contract
`docs/research/stable_finding_ids_research.md` (rev.3, USER 2026-09-27) to
the checks its first migration left out. Implementer: Claude. Reviewer:
GPT/Codex.

## Evidence

`main` `5d23f27`, AST over `netaudit_pkg/checks`: every problem finding
(severity critical/high/medium/low) of these state checks has no `id`:

| Check | Problem findings without an id |
|---|---|
| `aide_check` | files added / removed / changed (counts in the title) |
| `cert_transparency` | sensitive hostnames, unexpected issuer, wildcard certificates (counts in the title) |
| `cve_audit` | one per vulnerability of an installed package (dict findings) |
| `log_discovery` | core source missing, source empty, no logrotate, no nginx logs, journal state unknown |
| `lynis_audit` | each Lynis warning and suggestion |
| `rootkit_check` | rkhunter warnings, chkrootkit INFECTED / vulnerable but disabled, scan incomplete |
| `sql_injection` | input points, injectable parameter, injection types, DBMS, scan not started, sqlmap results (dict findings) |

The trend layer diffs findings by id only, so for these checks a trend,
the AI context and the Telegram notification can say "one fewer high" but
not which problem was fixed. The titles with changing numbers
(`files changed: 12`) are a problem only for findings without an id: once a
finding has one, its title is not compared.

## Design

Same format, rules and catalogue as the first migration; only an `id` key
is added. Titles, details, severities, order and the shape of every finding
stay as they are (the existing tests are not changed).

| Control id | Severities | Subject | Control |
|---|---|---|---|
| AIDE-FILE-001 | medium | — | files were added |
| AIDE-FILE-002 | medium | — | files were removed |
| AIDE-FILE-003 | high | — | files were changed |
| CT-HOST-001 | medium | — | potentially sensitive hostnames in the CT logs |
| CT-ISS-001 | high | — | certificates from an unexpected issuer |
| CT-WILD-001 | low | — | wildcard certificates in use |
| CVE-VULN-001 | critical, high, medium, low | package, vulnerability id | a known vulnerability affects an installed package |
| LOG-SRC-001 | medium | source type | a core system log source is missing |
| LOG-SRC-002 | low | source type | a log source exists but is empty |
| LOG-ROT-001 | low | source type | a log source has no logrotate configuration |
| LOG-NGX-001 | medium | — | no active nginx logs and no rotation history |
| LOG-JRN-001 | medium | — | could not determine the systemd journal state |
| LYN-WARN-001 | high | Lynis test id | a Lynis warning |
| LYN-SUGG-001 | low | Lynis test id | a Lynis suggestion |
| RKT-RKH-001 | medium | — | an rkhunter warning |
| RKT-CHK-001 | high | chkrootkit test | chkrootkit reports INFECTED |
| RKT-CHK-002 | low | chkrootkit test | chkrootkit: vulnerable but disabled |
| RKT-SCAN-001 | low | — | the rootkit scan is incomplete |
| SQLI-PNT-001 | low | — | input points found |
| SQLI-INJ-001 | high | parameter | a parameter is injectable |
| SQLI-INJ-002 | high | — | injection types |
| SQLI-DBMS-001 | medium | — | the DBMS was identified |
| SQLI-SCAN-001 | medium | — | the active scan was not started (authorization not confirmed) |
| SQLI-SCAN-002 | low | — | sqlmap found no parameters to test |
| SQLI-SCAN-003 | low | — | sqlmap finished with no clear verdict |
| SQLI-SCAN-004 | low | — | sqlmap is unavailable |

Subjects follow the first contract: only the object the check names, never
a value that changes while the problem stays.

- `CVE-VULN-001:<package>:<vulnerability id>`: the installed version is not
  part of it, so an upgrade that still leaves the package vulnerable keeps
  the id. The id is the OSV id the check already reports (`CVE-…`,
  `UBUNTU-CVE-…`, `GHSA-…`).
- `LYN-*:<test id>` (`SSH-7408`). Known limit: Lynis can report several
  suggestions for one test; they share the id (counts stay exact), as the
  report line keeps only the test id and the text.
- `RKT-CHK-*:<test name>` (`bindshell`): the rest of the chkrootkit line
  (`INFECTED (PORTS: 465)`) is not part of it.
- `RKT-RKH-001` has **no** subject: rkhunter warning text carries run
  details such as `(PID 1022)`, so a per-text id would read as "fixed + new"
  on every run. All rkhunter warnings share the control id.
- `LOG-*:<source type>` (`auth_log`, `syslog`, `kern_log`, `mail_log`,
  `fail2ban_log`, ...): the value of `SourceType`, not the label.
- `SQLI-INJ-001:<parameter>`: the parameter as sqlmap prints it
  (`id (GET)`).

Not in scope:

- the event log checks (`ssh_auth_audit`, `nginx_logs_audit`,
  `kern_log_audit`, `fail2ban_logs_audit`), as in the first contract;
- the `server_audit` nginx and sshd sections' "no access" and "could not
  determine whether installed" findings: their own contract keeps them
  without an id on purpose (`audit_nginx()` docstring);
- `breach_check`, which reports per address and has no findings list.

## Tests (RED first)

- The static guard of `tests/test_finding_ids.py` covers the seven modules:
  every `_finding(...)` call and every finding dict literal (`severity` and
  `title` keys) whose severity is not `ok`/`info`/`not_supported`/
  `third_party_repo` has an `id`; every literal control is catalogued with a
  compatible severity; catalogue and code name the same controls.
- Behaviour: Lynis warning/suggestion ids; chkrootkit ids by test name
  (the `PORTS` part ignored); one shared rkhunter id; `cve_audit` per
  vulnerability `CVE-VULN-001:nginx:CVE-2023-44487` and two vulnerabilities
  of one package → two ids; `log_discovery` source ids; the sqlmap parameter
  id; ids match the id regex.
- Trends: a `cve_audit` run in which one CVE disappeared reports it as
  `resolved` and the other as `persisting`.
- Existing tests pass unchanged.
