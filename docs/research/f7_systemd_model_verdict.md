# F7 part 2 — confirmed systemd unit and directive model (RA-19)

Status: implemented locally, awaiting independent review. USER approved
F1–F7 autonomous follow-up on 2026-10-09.
Implementer: GPT/Codex. Reviewer: Claude. Base: `origin/main` @ `ea68f97`.
Claude's F7 part 1 branch owns RA-07/08/09/20 in other modules. This branch
owns only RA-19 (`systemd_hardening`) and its tests; the F7 PR delivery plan
will be coordinated at handoff.

## Problem

`systemctl status UNIT | head -1` always returns `head`'s status. If the
status command fails or its output is empty, the check still runs
`systemd-analyze`. Separately, a successful `--json=short` containing `[]`
produces an `ok` "looks reasonably hardened" finding from zero directives.

## Contract

1. Query unit `LoadState` with `systemctl show --property=LoadState --value
   UNIT` through an exit-marked, unprivileged SSH command. `systemctl show`
   is the machine-readable interface documented by systemd
   (https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).
   Exit 0 and
   `not-found` means the existing "unit not found" result; exit 0 and a
   nonempty other state may proceed to the actual analysis. Missing marker,
   nonzero exit, or empty output returns an explicit unknown/error and does
   not pretend the unit exists. Do not use sudo for this preflight.
2. A successful `systemd-analyze security --json=short` must parse to a
   nonempty list of directive objects. Empty or malformed models cannot
   produce `ok` or a hardening score; report an explicit error. Existing
   nonempty model findings and separate overall-score handling stay intact.
3. Unit names remain validated and passed as one shell-quoted argument.

## RED cases

- No completion marker, nonzero `systemctl show`, or empty LoadState:
  no security analysis, explicit error.
- `LoadState=not-found`: specific unit-not-found error; `loaded` and
  `masked` still reach `systemd-analyze` (which decides whether it can
  evaluate the unit).
- JSON `[]` or `{"entries": []}` with command exit 0: no `ok` finding.
- Valid nonempty directive model still yields its findings/overall score.

Contract → RED → GREEN are separate commits. Run focused and broad tests,
Ruff, compileall, Bandit and diff check. Claude performs independent review
and full Web TestClient pytest. Merge remains USER.
