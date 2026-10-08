# NetAudit 1.0 quality gate

Status: **in progress** (2026-10-08). This records local evidence and the
remaining release gates; it does not claim the server upgrade or GitHub CI
has run.

## Decisions

- Full Ruff must pass. Intentional broad exception handlers and local naive
  timestamps have point-in-place `noqa` with a reason. No rule family is
  disabled globally. CI pins Ruff to the version used for the local baseline.
- The release version is `1.0.0` in `pyproject.toml` and
  `netaudit_pkg.__version__`; the CLI and Web OpenAPI read the package value.
- Build and exercise a clean wheel locally. The user will update the server
  following `docs/upgrade_to_1_0.md`; agents do not apply the secret scrub to
  the real database. Tag `v1.0.0` and create the GitHub release after the user
  merges the PRs.

## Local evidence so far

- The five earlier feature branches were integrated and independently
  reviewed. Roadmap features 2a–2f passed cross-review; the combined branch
  is `codex/roadmap-1-0`.
- Full Ruff on the integrated source and tests reports zero findings. Claude
  ran the complete test suite on the integration at `53ddb8f`: **2094 passed**,
  with a temporary HOME and Web TestClient. Codex independently ran the
  non-Web suite on that commit: **2039 passed, 55 deselected**. Web TestClient
  hangs in the Codex execution environment; Claude's full run is the Web
  evidence. Bandit was clean in Claude's run.
- From a clean `git archive` of `53ddb8f`, Codex built a wheel and installed
  it in a temporary venv with runtime dependencies. `netaudit --version`,
  `list`, `run performance`, `history`, and `trend` worked with a temporary
  HOME. The installed Web app returned HTTP 200 for `/api/health`,
  `/api/trends`, `/`, and `/static/i18n.js` on loopback.
- On another temporary HOME, an old wheel built from `main` wrote a
  `performance` report. The integrated wheel read it with `history` and
  `trend`; the old wheel read it again after rollback. SQLite
  `integrity_check` returned `ok` and the report count stayed 1. One old
  report without trend identity correctly produced “No trend history yet.”
- Claude's branch `c196309` added version-consistency tests and reported
  **2097 passed** plus full Ruff, Bandit, and pip-audit clean on Python 3.12.
  Codex independently ran its three version tests: **3 passed**. This branch
  is awaiting integration and the final version bump.

## Remaining gates

1. Resolve review of the two-layout upgrade guide, including the database
   path under the systemd service account's HOME.
2. Integrate CI and version-consistency changes. Set `1.0.0`, date the
   changelog, and run the complete suite, full Ruff, Bandit, pip-audit, and
   wheel/CLI/Web smoke on that exact final commit. Verify the independent
   review of the release bump.
3. Open the five feature PRs and the roadmap PR after GitHub authorization is
   configured. GitHub CI will then provide the Python 3.11/3.12/3.13 matrix;
   only Python 3.12 has been checked locally.
4. The user runs the upgrade on the real server and inspects the dry-run on
   its database. Any `--apply` to the real database needs a separate explicit
   instruction. Merge, tag, and GitHub release remain user-controlled as
   agreed.

The local compatibility and wheel checks use disposable state. They do not
establish the state or contents of the user's server database.
