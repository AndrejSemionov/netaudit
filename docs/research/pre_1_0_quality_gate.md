# Pre-1.0 quality gate — research proposal

Status: **DRAFT**, to be revisited after feature branches merge. Date:
2026-10-08. No automated rewrite has been applied.

## Current evidence

On `codex/roadmap-1-0` after five feature merges, full Ruff reports 243
findings; CI's `E9,F` subset passes. 180 findings have a Ruff-supplied
fix. The largest groups are `I001` 73, `BLE001` 37, `RUF059` 27, `C408`
26, `UP017` 23, `DTZ005` 19 and `ISC004` 12. Most findings are distributed
across project and test files; the top project files are `storage.py` and
`streaming.py` with 10 each.

`pyproject.toml` and `netaudit.py` still declare 0.2.0. The five earlier
branches have local independent reviews and a combined test run, but no
published PRs. Fresh install, upgrade, and rollback on a disposable test
host have not been verified for this integrated code. The real server with
280+ reports is not available in this workspace.

## Proposed gate

1. Freeze feature behavior first. Re-run full Ruff on the final feature
   integration, because file/rule counts can change.
2. Apply Ruff-supplied mechanical fixes in small, reviewable commits
   (`I001`, `RUF059`, `C408`, `UP017`, and similarly safe rules), with the
   full test suite and diff checks after each group. Avoid blanket
   `--fix` on all rules.
3. Review `BLE001` by call path. Many checks deliberately catch external
   command or SSH failures to return an audit result; broad catches may be
   appropriate at those boundaries. Retain only evidence-backed exceptions
   with local explanation; narrow accidental catches with tests.
4. Review `DTZ005/DTZ007` against storage timestamp formats, report
   ordering, and UI parsing before changing timezone semantics. Replacing
   naive `now()` mechanically could reorder or reformat persisted data.
5. Aim for full Ruff clean on project code. Any remaining finding needs a
   documented reason and bounded suppression; do not silently disable an
   entire rule family. CI keeps `E9,F` at minimum, and can expand only after
   the corrected tree is stable across Python 3.11/3.12/3.13.
6. Run tests with an isolated HOME and a Web-capable environment. Verify
   dependency audit and security scan. Exercise fresh install, update and
   rollback only on an authorized disposable host; document commands and
   observed outcomes. Do not infer server behavior from local unit tests.
7. Correct English/Russian CLI/API instructions and add release notes.
   Set version 1.0.0 only when tests, review, operational checks, and
   documentation are complete. Merge to `main` remains the user's action.

## Open inputs

- Which disposable host or VM may be used for operational checks?
- Should full Ruff clean be a hard release gate, or are individually
  documented intentional `BLE001`/timezone suppressions acceptable?
- Which release artifact and upgrade path does the user expect for 1.0?
