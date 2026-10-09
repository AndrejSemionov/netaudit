# F3 — confirmed execution for rootkit, Lynis, AIDE

Status: implemented locally; awaiting Claude's independent review. USER approved
F1–F7 autonomous follow-up to A2 on 2026-10-09.
Implementer: GPT/Codex; independent reviewer: Claude. Base: `origin/main` @
`ea68f97`. Scope: RA-13, RA-15, RA-18 in
`docs/research/result_reliability_audit.md`. No automatic installation or
new sudoers rules are introduced.

## Current failure

- `rootkit_check`: `sudo ... 2>&1` can return `sudo: a password is required`
  in stdout; the parser sees zero rootkit warnings and reports `ok`.
  A second tool failure can also be hidden by a clean `ok` from the first.
- `lynis_audit`: the return value of `lynis audit system` is ignored; an old
  `/var/log/lynis-report.dat` is accepted when the current audit failed.
- `aide_check` check mode: successful-looking text is accepted without a
  confirmed exit status; unlike its init/database paths it still uses
  `ssh.sudo()`.

## Contract

1. Run the actual fixed binary and arguments through
   `run_sudo_with_exit_code()`; this preserves scoped sudoers behavior and
   keeps any password on stdin. Do not use a second shell under sudo or
   include `2>&1` in argv. On no completion or `sudo_error`, return an
   explicit error or incomplete status, never `ok`.
2. `rootkit_check`: parse tool output even on a nonzero exit, because
   `rkhunter` can use nonzero for a warning. Preserve positive findings.
   A nonzero exit without a recognized finding is a tool failure. A clean
   finding requires every selected tool to have completed successfully
   (or the result must explicitly name the unrun tool as incomplete).
3. `lynis_audit`: only read the report after a confirmed successful audit
   command. A failed, refused or unconfirmed audit must not read an old
   report. Read the report itself with a confirmed command result too.
   Conservatively reject a nonzero Lynis exit; exit 78 can mean warnings
   under `error-on-warnings=yes`, so report that limitation rather than
   presenting a stale report as current.
4. `aide_check`: accept exit 0 as a clean check. AIDE's 1/2/4 change bits
   (or combinations) can represent detected changes and must still be
   parsed as findings. Error codes 14–23, an unknown exit, no completion,
   or sudo refusal are errors. A text-only `no differences`/`looks okay`
   is clean only with confirmed exit 0. A parsed summary claiming zero
   changes with a change-bit exit is inconsistent, not clean.
5. Keep existing finding titles/IDs and successful result shapes where
   possible. Report bounded stderr/detail; never echo password material.

## RED cases

- Both rootkit tools return a sudo refusal; no clean finding. One tool fails
  and the other is clean; result says incomplete, not fully clean. A warning
  with nonzero rkhunter status remains visible.
- Lynis audit refused or failed while an old report is readable: no report
  read and no hardening score. Successful audit + failed report read: error.
- AIDE check output says `no differences` but exit is unknown/nonzero:
  no clean result. Exit 4 with changed files still yields a finding;
  exit 0 and a clean summary remains OK.

## References

- [rkhunter manual: nonzero on error or warning](https://man.archlinux.org/man/extra/rkhunter/rkhunter.8.en)
- [Lynis manual: exit codes, including 78 with error-on-warnings](https://man.archlinux.org/man/extra/lynis/lynis.8.en)
- Existing AIDE bitmask/error mapping: `netaudit_pkg/checks/aide_check.py`.

## Verification

RED `0f69dcc`: all eight F3 cases failed for the expected false-result paths.
GREEN: 67 focused tests passed; broad suite excluding eight files using Web
TestClient: 2150 passed with a temporary HOME. Full Ruff, compileall,
Bandit and `git diff --check` passed. The Codex environment's Web TestClient
hang is unrelated to these three SSH checks; Claude will run the full suite
as part of independent review.
