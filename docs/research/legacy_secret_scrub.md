# Legacy report secret scrub — proposed contract

Status: APPROVED by USER on 2026-09-27 for implementation/testing on temporary databases only; Claude review approved the contract.
Date: 2026-09-27
Owner: GPT/Codex (implementation); reviewer: Claude.

## Goal and boundary

Older NetAudit reports may contain SSH `password` in the JSON
`reports.data.execution_context`. Current code redacts this field on write,
read, Web output, and AI egress, but does not change old SQLite rows. Provide
an explicit maintenance utility that can remove the already-stored field.
This is **not** a schema migration or an automatic startup action.

No operation on the real `~/.netaudit/netaudit.db`, its WAL, existing backups,
or credentials is part of implementation/testing. The utility is tested only
against newly created temporary databases. Running it on real data is a
separate USER decision.

## Interface

Standalone invocation (not a routine `netaudit` check):

```text
python -m netaudit_pkg.scrub_legacy_secrets --database ABSOLUTE_PATH
python -m netaudit_pkg.scrub_legacy_secrets --database ABSOLUTE_PATH --apply --backup ABSOLUTE_PATH
```

- Both modes require an explicit absolute database path; never default to
  `storage.DB_PATH`. No glob, directory, symlink, or nonexistent source is
  accepted. The backup path is explicit and must not exist, equal the DB,
  name one of the source database's `-wal`/`-shm`/`-journal` sidecars, or be
  a symlink. Its parent must exist.
- Without `--apply`, run a preflight scan only. Print aggregate report and
  affected-row counts, malformed-row count, and whether this DB is eligible
  for apply. Separately count rows with a `SECRET_PARAM_NAMES` key outside
  `execution_context` (advisory only; this tool does not delete those keys).
  Never print report JSON, secret values, or SQL containing data.
  Dry-run does no SQL UPDATE, backup, VACUUM, or checkpoint.
- `--apply` requires `--backup`. The backup is a sensitive plaintext copy,
  created with mode 0600 and no overwrite **before any SQLite write**:
  reserve the path with `os.open(O_CREAT|O_EXCL, 0o600)` before opening it
  via sqlite3, not `connect()` followed by `chmod`. Temporarily set process
  umask to `0o077` for the entire apply (restore it in `finally`) so any
  utility-created SQLite sidecar is also private. The utility is a
  standalone single-threaded process; it must not run inside the Web
  server. Check the file modes of backup and utility-created sidecars before
  reporting success. Display the backup location and explain that it must
  be protected, retained only as needed, and disposed of under the
  operator's backup policy. Do not auto-delete it after success or error.
- The CLI returns nonzero on malformed JSON, unsupported shape, lock/busy,
  backup failure, integrity failure, or verification failure. No generic
  exception text containing data values is printed.
- Operator must stop NetAudit and other writers before `--apply`; the tool
  also requires the database to be in WAL mode, acquires a SQLite writer
  lock (`BEGIN IMMEDIATE`), and fails closed when it cannot obtain one. It
  does not proceed by silently racing live writers. Readers may still run
  in WAL mode; they can observe the pre-scrub snapshot until they finish.

## Scope of transformation

Only JSON in `reports.data` is changed, and only `execution_context` secret
keys recognized by `netaudit_pkg.redaction.redact_report()` are removed. No
other JSON field, row metadata (`id`, `timestamp`, `checks`, `total_time`),
table, setting, or report order changes **semantically**. Re-serialization
may change JSON whitespace/escaping in affected rows; untouched rows keep
their original bytes. `redact_report()` remains the single source of truth
for normal flat/multi-host contexts.

Preflight reads every report row directly via SQL (never `load_report()`,
which masks legacy values). It parses each JSON object, produces a redacted
copy, and counts rows where the object differs. It aborts apply before any
UPDATE if a row is not valid JSON/object or if a key from
`SECRET_PARAM_NAMES` remains anywhere under `execution_context` after
redaction (unsupported legacy shape). Do not silently call this "clean".
Preflight does not display secret values, even on errors.

When there are no affected rows and no malformed/unsupported rows, `--apply`
is a no-op (no backup or VACUUM required). This is idempotent.

## Apply and recovery

1. Require maintenance window, verify WAL mode, and acquire a writer lock
   on the source connection with `BEGIN IMMEDIATE`. Use a bounded busy
   timeout; if another writer prevents the lock, fail without changing rows.
   Revalidate the preflight result under this lock so a stale dry-run cannot
   be used as authority. A WAL writer lock allows concurrent readers but
   prevents a competing writer while the backup and UPDATE proceed.
2. Make a consistent backup with SQLite's backup API into a newly created
   0600 file, using a **separate read-only source connection** while the
   first connection holds the writer lock. Backing up from the same
   connection with `BEGIN IMMEDIATE` open can hang (verified on local
   SQLite), so it is forbidden. Verify backup integrity
   (`PRAGMA integrity_check`) and row count before changing source. The
   backup includes legacy plaintext and must never be placed in git or
   logged.
3. Enable SQLite `secure_delete=ON`. Update all affected `reports.data`
   rows in one transaction, preserving all other fields. If validation or
   UPDATE fails before commit, roll back and leave source logically
   unchanged. Commit only after in-transaction verification that no supported
   secret key remains under `execution_context`.
4. After commit, run `VACUUM` and `PRAGMA wal_checkpoint(TRUNCATE)` and check
   their outcomes. `VACUUM` is needed because UPDATE alone may leave old
   bytes in unused database pages; WAL truncation is needed because old
   frames can remain in a reused WAL. Then run `PRAGMA integrity_check`
   and a fresh direct SQL read/parse of **raw** `reports.data` for the same
   postcondition. Do not use `load_report()` as proof. Preflight reports a
   conservative free-space warning for backup + VACUUM; it cannot guarantee
   space remains available. If VACUUM fails (e.g. disk full), or checkpoint
   reports busy=1 because of an active reader, report which step is
   incomplete rather than claiming physical cleanup.
5. A failure after commit is **not** presented as rollback: the logical JSON
   may be clean while VACUUM/checkpoint failed. Return a distinct incomplete
   status and keep the backup for operator recovery. Never auto-restore a
   backup over a potentially live or more recent database.

The test suite should additionally use a unique fake sentinel and raw SQL
`SELECT data FROM reports` assertions to show its absence from new stored
JSON; aggregate production verification cannot prove that unknown secret
values are absent from unrelated result fields.

## Security limits

- This cleans the live SQLite database's report JSON, not historical
  filesystem blocks, snapshots, old backup files, logs, or credentials
  already sent to Anthropic. Even `VACUUM` + checkpoint is not a guarantee
  of forensic erasure on SSD/COW filesystems.
- The freshly created backup necessarily contains the original secrets.
  Encryption at rest may protect this backup from media theft, but is not a
  substitute for deleting the secret from report JSON.
- If credentials may have been disclosed, rotate them. The utility cannot
  undo past disclosure.
- New secret parameter names not in `SECRET_PARAM_NAMES` are outside this
  version; the runtime and scrub policy must be extended together.

## RED/GREEN and acceptance

RED tests on temporary SQLite files only: dry-run non-mutation; flat and
multi-host contexts; exact preservation of unrelated JSON/metadata; unknown
or malformed row abort; no-op idempotency; backup mode 0600/no overwrite;
backup integrity; backup and every utility-created sidecar are 0600 or
stricter **before data is written**, including with umask 022; raw-SQL
postcondition with fake sentinel; locked database failure; forced failure
before commit rolls back; simulated failure after commit returns incomplete
status; WAL mode/checkpoint busy=1 result handling; free-space warning;
out-of-scope secret-key count; no secret values in CLI output/errors.
GREEN implementation is a separate
commit. Existing test suite, Ruff E9/F, Bandit, pip-audit as relevant;
Claude independently reviews code and failure paths.

## Sources

- SQLite official [backup API](https://www.sqlite.org/backup.html): consistent
  SQLite backup rather than copying a live main database file.
- SQLite official [PRAGMA documentation](https://www.sqlite.org/pragma.html):
  `secure_delete`, `wal_checkpoint(TRUNCATE)`, and their limitations.
- SQLite official [WAL documentation](https://www.sqlite.org/wal.html): WAL
  frames/checkpoint behavior.
