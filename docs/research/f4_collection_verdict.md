# F4 — confirmed collection for Docker, backups and log discovery

Status: implemented locally, awaiting independent review. USER approved F1–F7
autonomous follow-up to A2 on 2026-10-09.
Implementer: GPT/Codex; reviewer: Claude. Base: `origin/main` @ `ea68f97`.
Scope: RA-14, RA-16, RA-17 of the A2 audit. No changes to target systems.

## Contract

1. `docker_audit`: `docker ps` must have a recovered exit 0 before an empty
   list means zero containers. Retry under sudo only for a confirmed access
   denial. Other failures, including dropped commands and daemon/API errors,
   return an explicit `error`. Every ID from a successful `ps` must have a
   successful, parseable `inspect`; otherwise report incomplete coverage and
   never issue a global clean finding. Preserve findings from successfully
   inspected containers. Existing scoped sudoers semantics remain: sudo
   runs `docker` itself, not `sh -c`.
2. `backup_check`: `find` exit 0 and parsed output means an existing directory
   with that file list, including a genuinely empty one. Exit nonzero with
   explicit `No such file or directory` for the queried directory means
   absent. Other nonzero or no completion means unknown; do not issue
   `no backup files` or `directory does not exist` for it. If any directory
   is unknown, no global clean finding. Archive checks distinguish a
   completed corrupt archive test from tool missing, permissions denied or
   incomplete collection. Unknown integrity is not `integrity_ok=False`
   and must not be called `corrupted`.
3. `log_discovery`: preserve confirmed absence separately from unavailable
   metadata. `stat` exit nonzero with `No such file or directory` is absent;
   any other code/output, no completion, or unparseable success is unknown.
   Findings for unknown sources say collection could not confirm presence,
   not `not found` / `not present`. Existing `available` bool remains for
   downstream collectors; add an explicit unknown flag in the verdict.
   Nginx aggregate findings also avoid a missing/empty conclusion when a
   discovered file's stat is unknown.

## RED cases

- Docker `ps` API error and uncompleted command never produce zero-container
  OK. One `inspect` fails while another succeeds: retain the first one's
  findings and name incomplete coverage, without an OK finding.
- Backup `find` permission error and uncompleted command never produce
  empty-directory finding; truly empty successful listing still does.
  Missing `gzip`/`tar`/`unzip` does not report a corrupt archive.
- Fixed log source `stat` permission error or no completion produces an
  unknown-source finding, not an absence finding; confirmed ENOENT still
  uses the existing optional/core severity mapping.

## Verification

RED and GREEN are separate commits. Run focused tests for all three checks,
broader pytest excluding the known Web TestClient hang in Codex, full Ruff,
compileall, Bandit and diff check. Claude repeats an independent review and
full pytest including Web in his environment.

## Remaining limit

The separate Docker daemon socket grep still uses `|| true`; a failed socket
probe can miss an exposed daemon while the container configuration verdict is
otherwise complete. The F4 correction covers `docker ps` and every `inspect`
result, as specified by RA-14. A socket probe verdict needs a separate task.
