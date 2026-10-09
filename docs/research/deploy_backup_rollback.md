# deploy.sh backup and rollback — fix contract proposal (task 9)

Status: **APPROVED by USER rev.1** (2026-10-09, «давай» on the recommended
options): D1 = deploy everything since the last deployed commit and remove
deleted files; D2 = back up the database always, restore it only by hand;
D3 = HTTP 401 in the smoke test is success with a warning. MODE: AUTONOMOUS.
Implementer: Claude. Reviewer: GPT/Codex.

Scope: layout B only (`deploy.sh`: git mirror `~/netaudit-git` copied into the
runtime directory `~/netaudit`, see `docs/upgrade_to_1_0.md`). Layout A (a git
checkout) rolls back with `git checkout` and is not changed.

## Evidence (`deploy.sh` on `main` @ `be1decc`)

- **E1. No backup, no rollback.** Files are copied into `~/netaudit` first
  (step 3), pytest runs after that (step 4). On a test failure the script says
  the runtime directory "is in a mixed state" and exits. A failed restart or an
  inactive service also only exits. `docs/upgrade_to_1_0.md` §5 tells the
  operator not to roll back with `deploy.sh` and to swap a manual snapshot.
- **E2. Only the last pull is deployed.** The file list is
  `git diff HEAD@{1} HEAD` (reflog). Two `git pull`s without a deploy in
  between → the first pull's changes never reach `~/netaudit`.
- **E3. Deleted files stay.** A file deleted in git is skipped
  (`[skip] … deleted`), so old modules and tests remain in the runtime
  directory; the pytest step then runs tests the repository no longer has.
- **E4. A working service behind Basic Auth fails the smoke test.**
  Step 9 requests `/api/checks` without credentials; when the service listens
  beyond localhost, `web_auth` answers 401 and the deploy is reported as
  failed after a successful restart (documented in `docs/upgrade_to_1_0.md` §2).
- **E5. The database is not backed up.** It lives in the service account's
  `~/.netaudit/netaudit.db`; a new version may migrate it on start
  (`PRAGMA user_version`).

## Design

### S1. What gets deployed (decision D1)

The base is the last deployed commit: `DEPLOYED_COMMIT` from
`~/netaudit/.deployed_manifest`, resolved with
`git rev-parse --verify "$DEPLOYED_COMMIT^{commit}"`. The list comes from
`git diff --name-status --no-renames <base> HEAD`: `A`/`M` files are copied,
`D` files are removed from `~/netaudit`. When there is no manifest or the
commit is unknown, the script stops and asks for an explicit file list (the
existing `./deploy.sh file1 file2 …` form, which never deletes). The reflog
fallback is removed. The manifest format does not change (`/api/health` reads
it).

### S2. Backup before anything changes

A new private directory `~/netaudit-deploy-backups/<UTC time>-<previous
commit>/` (mode `0700`) holds:

- `files/` — the current runtime copy of every file the deploy will overwrite
  or delete, with its relative path;
- `added.txt` — files the deploy creates (they do not exist yet), to delete on
  rollback;
- `manifest` — the current `.deployed_manifest`, if any;
- `netaudit.db` — a consistent copy of `~/.netaudit/netaudit.db` made with
  SQLite's online backup API (the service keeps running), only if the
  database exists.

The database copy and the lists are `0600`. Code files keep their original
mode (a rollback must restore it); the `0700` directory keeps them private.
The backup is written and verified (`PRAGMA integrity_check` on the database
copy) before step 3 copies anything. The last **5** backups are kept; older
ones are deleted after a successful deploy. The database copy can hold old SSH
passwords (see the scrub tool), which is why the directory is private and
retention is short.

### S3. Automatic rollback on failure

Any failure after the first file is copied — pytest, restart, the restart
freshness check, inactive service, smoke test (except S5) — triggers the same
rollback: restore `files/`, delete everything in `added.txt`, restore the
manifest, `sudo systemctl restart`, check that the service is active. The
script prints `=== DEPLOYMENT FAILED — ROLLED BACK TO <commit> ===` and exits
with status 1. If the rollback itself fails, it prints
`=== ROLLBACK FAILED ===`, the backup path and the manual steps, and exits with
status 2.

### S4. Manual rollback

`./deploy.sh --rollback` restores the newest backup the same way (files,
`added.txt`, manifest, restart, active check) and renames that backup to
`<name>.rolled-back`, so the next `--rollback` goes one deploy further back and
the database copy stays available for a manual restore (retention counts these
directories too). It does not touch the git mirror; the script prints the
`git checkout <commit>` to run there.

### S5. Smoke test behind Basic Auth (decision D3)

HTTP 401 from `/api/checks` means the service is up and requires
credentials: the deploy succeeds and prints a warning to check with
`curl -u user:pass`. Any other non-200 status or no answer is a failure
(→ S3).

### Database on rollback (decision D2)

The database is **never** restored automatically: reports written after the
restart would be lost, and the database is not code. The rollback output prints
the exact restore command for the backup copy. A future schema change would
need its own downgrade note; 1.0 has none.

### Unchanged

The NotImplementedError guard, pytest on the runtime copy, the restart
freshness check, the manifest contents, the smoke test URL. `sudo` is used
only for `systemctl`, as now.

## Decisions for USER

- **D1:** deploy everything since the last deployed commit and remove deleted
  files (recommended), or keep "last pull only" and skip deletions.
- **D2:** database: back up always, restore only by hand (recommended), or
  restore automatically on rollback.
- **D3:** HTTP 401 in the smoke test counts as success with a warning
  (recommended), or as failure (today's behaviour, now with rollback).

## Tests (RED first; temporary HOME, no real service)

`tests/test_deploy_sh.py` runs the real `deploy.sh` with `HOME` set to a
temporary directory holding a git mirror with commits and a runtime copy.
Fake `sudo`, `systemctl` (state kept in a file, restart updates the start
time), `curl` (status code from an environment variable) and a `python3`
wrapper whose `-m pytest` exit code comes from an environment variable (every
other `python3` call goes to the real interpreter) are first in `PATH`.

1. Success: added and modified files copied, deleted files removed, manifest
   updated, a backup with `files/`, `added.txt`, `manifest` and a valid
   `netaudit.db` copy, modes `0700`/`0600`.
2. Two commits since the last deploy: files from both are deployed.
3. No manifest and no file list: exits before changing anything.
4. pytest fails: runtime tree byte-identical to before (added files gone,
   deleted files back), manifest unchanged, exit 1, "ROLLED BACK".
5. Service inactive after restart: same restore, a second restart, exit 1.
6. Smoke 500 → rollback; smoke 401 → success with a warning, no rollback.
7. `--rollback` after a successful deploy: tree and manifest as before that
   deploy, service restarted, backup marked `.rolled-back` with its database
   copy kept; file modes are restored.
8. Retention: after 6 successful deploys, 5 backups remain.
9. The NotImplementedError guard still stops before any copy or backup.

Verification: the tests above, full pytest, Ruff, bandit, `bash -n deploy.sh`,
`shellcheck` if it is installed locally (not a CI dependency). A real deploy
on the server is a USER step; `docs/upgrade_to_1_0.md` §1, §2 and §5 for
layout B are updated to the automatic backup and rollback.
