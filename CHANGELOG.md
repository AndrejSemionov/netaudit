# Changelog

## Unreleased — 1.0 preparation

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

The 1.0 version number and release date will be set after the release checks
and independent review are complete.
