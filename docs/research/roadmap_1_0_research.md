# Roadmap to 1.0 — research and proposed execution contract

Status: **DRAFT**. The user chose the whole roadmap on 2026-10-08. This
document records evidence and a proposed order; it does not claim product
decisions or approval of the detailed contracts below.

## Verified starting point

The five previously reviewed branches have been merged locally, in order,
into `codex/roadmap-1-0` without conflicts. On this integration branch,
2001 tests passed with `tests/test_web_app.py` and
`tests/test_web_app_health_version.py` excluded. The full test run reached
the Web TestClient tests and timed out after 90 seconds in the Codex
environment. Ruff E9/F, Bandit (exit 0), and `git diff --check` passed.
Claude independently ran the full suite (2023 passed, including Web tests)
and security checks on the five-merge integration HEAD `133c904`; see
`.ai/STATUS.md`. Later roadmap commits still need their own review.

`pyproject.toml` and `netaudit.py` still report version 0.2.0. GitHub
search returned no matching remote branches for the five local branches
and no open PRs on 2026-10-08. Real database cleanup and live server
verification have not been performed. Full Ruff reports 243 findings on
this integration branch (73 `I001`, 37 `BLE001`, 27 `RUF059`, 26 `C408`,
23 `UP017`, 19 `DTZ005`, and others); the CI E9/F subset passes.

## Proposed release sequence

1. Deliver the five reviewed changes as separate PRs, in their agreed
   order: redaction, Web execution context, trend layer, stable finding IDs,
   legacy scrub utility. Publishing requires the project's explicit push
   authorization; merging into `main` is reserved for the user.
2. Complete deterministic state trends. `server_audit` has section-level
   findings and currently produces no trend snapshot. Define how section
   findings and duplicate IDs map to one snapshot, then implement with
   tests. Preserve the raw report and existing trend contract for other
   checks.
3. Define event-observation semantics for `ssh_auth_audit`,
   `nginx_logs_audit`, `kern_log_audit`, and `fail2ban_logs_audit` before
   adding finding IDs or showing a resolved/new diff. These checks read
   bounded tails or rolling windows. An event absent from a later slice
   may simply have aged out. Recommendation: treat their results as
   observations with counts and coverage, without "resolved" claims, until
   a reliable non-overlapping interval contract exists. Keep them out of
   the state-trend diff in the meantime.
4. Expose deterministic trends in the Web UI and pass the validated
   `latest_change` to `ai_analyze()` for the same trend unit. Decide API
   shapes, identity selection, unavailable/ambiguous states, and prompt
   size limits in a focused contract before RED/GREEN implementation.
5. Investigate log-analysis quality against representative, authorized
   fixtures. Correlation remains deferred until evidence shows a
   specific cross-source relationship that can be tested. This is an
   explicit decision gate, not a promise to invent correlations.
6. Release hardening: resolve or explicitly triage the remaining full
   Ruff findings; run CI and isolated database tests; verify deployment,
   upgrade and rollback on an authorized test environment; update English
   and Russian documentation; align version and release notes only after
   the acceptance gates pass.

## Decisions needed before code

- Should 1.0 explicitly exclude event-level resolved/new claims and show
  observation counts only, or must it implement a new interval-based event
  history model? The latter needs reliable interval, source, and coverage
  metadata that the current reports do not consistently preserve.
- Which deployment or test server may be used for operational checks?
  No live target is implied by approval of the roadmap.
- Should release delivery retain five separate PRs plus later roadmap PRs,
  or use one integration PR? The existing reviews were performed per
  branch; separate PRs preserve that evidence.

## Proposed acceptance gates for 1.0

- All approved contracts implemented with RED/GREEN commits and independent
  Claude/Codex review, within the protocol's three-pass limit.
- No known high-severity secret leak or false "resolved" trend.
- Full CI, security checks, isolated database tests, and Web e2e pass in
  an environment that can run TestClient.
- Upgrade, fresh install, and rollback documented and exercised on an
  authorized test environment; real user data changed only by a separate
  explicit instruction.
- Public docs match CLI/API behavior, and 1.0 version is set only at the
  release gate.
