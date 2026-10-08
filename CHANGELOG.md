# Changelog

## 1.0.0 — 2026-10-08

- Add deterministic history for state findings, server audit sections, and
  hardening scores in the CLI and web interface. A missing finding is marked
  **not evaluated** when its area could not be checked.
- Show SSH authentication, Nginx, kernel, and Fail2Ban log results as bounded
  observations without state-style resolved/new claims.
- Add stable IDs to supported findings. Findings without an ID still count
  toward observed severity totals but are not matched across runs.
- Add strictly prior report history and deterministic changes to AI context.
- Save execution context for web runs and redact SSH password parameters on
  report write, read, and AI egress. Add an opt-in legacy SQLite scrub tool;
  no existing database is rewritten automatically.
- Escape saved report, AI, and history data in the web interface to prevent
  stored script execution. Correct SSH log source failure handling and replace
  deprecated FastAPI lifecycle hooks.
- AI analysis of a saved report no longer receives that same report as its own
  "previous" run, and analysing an older report never uses later runs.
- Report one version everywhere: the web API said 2.0 while the CLI said 0.2.0.
- CI lints with the full Ruff rule set of a pinned Ruff version; remaining
  exceptions are point-in-place `noqa` with a reason.

Upgrading an existing server: see [docs/upgrade_to_1_0.md](docs/upgrade_to_1_0.md)
(database backup, checks, optional removal of old SSH passwords, rollback).
