# Upgrading a server to NetAudit 1.0

Two install layouts are covered: **A** - a git checkout in `~/netaudit` run
by the `netaudit` systemd service (README, "Full server install"); **B** - the
`deploy.sh` layout, a git mirror `~/netaudit-git` copied into a runtime
directory `~/netaudit`. The database is `~/.netaudit/netaudit.db` in both.

What 1.0 does **not** change: no new Python dependencies, no database schema
change, no automatic rewrite of saved reports. New modules: `redaction`,
`trends`, `scrub_legacy_secrets`.

What to know first: reports saved before 1.0 may contain SSH passwords inside
the SQLite file. 1.0 hides them on every read and never sends them to the AI
provider, but they stay in the file until you run the optional scrub (step 4).

## 1. Before the upgrade

```bash
git -C ~/netaudit rev-parse HEAD             # A: the rollback point
cat ~/netaudit/.deployed_manifest            # B: note DEPLOYED_COMMIT - the rollback point
cp -a ~/netaudit ~/netaudit-pre-1.0          # B only: runtime snapshot for rollback (step 5)
umask 077
python3 -c "import sqlite3, os; s = sqlite3.connect(os.path.expanduser('~/.netaudit/netaudit.db')); d = sqlite3.connect(os.path.expanduser('~/netaudit-pre-1.0.db')); s.backup(d); d.close(); s.close()"
```

The database backup is a full copy, old passwords included. Keep it private
(`umask 077` makes it `0600`) and delete it when you no longer need it.

## 2. Upgrade

A - git checkout:

```bash
cd ~/netaudit
git pull
find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null
sudo systemctl restart netaudit
```

B - `deploy.sh`:

```bash
cd ~/netaudit-git
git pull
./deploy.sh
```

`deploy.sh` copies the changed files, runs the full test suite in
`~/netaudit` and only then restarts and verifies the service.

Hard-refresh the browser afterwards (Ctrl+Shift+R): the page is cached.

## 3. Check it works

```bash
curl -s http://127.0.0.1:8000/api/health        # your service's port (8000 by default); -u user:pass if Basic Auth is on
cd ~/netaudit
python3 netaudit.py trend                         # objects with history from the existing reports
python3 netaudit.py trend server_audit <host>     # one object: points and the latest change
```

In the web interface: **Trends** tab → **Changes and observations per object**.
`resolved` is shown only where the latest run could evaluate the area;
otherwise the id is listed as **not evaluated**. The four log checks
(`ssh_auth_audit`, `nginx_logs_audit`, `kern_log_audit`, `fail2ban_logs_audit`)
show observations only, never resolved/new.

## 4. Optional: remove old passwords from the database file

Dry run - reads only and prints counts, never report contents (SQLite may
create empty `-wal`/`-shm` files next to the database):

```bash
cd ~/netaudit
python3 -m netaudit_pkg.scrub_legacy_secrets --database "$HOME/.netaudit/netaudit.db"
```

If it prints `affected=N` with N > 0 and `eligible=True`:

```bash
sudo systemctl stop netaudit
python3 -m netaudit_pkg.scrub_legacy_secrets --database "$HOME/.netaudit/netaudit.db" \
    --apply --backup "$HOME/netaudit-scrub-backup.db"
sudo systemctl start netaudit
```

Exit code `0` and `status=complete`: the rows are clean and the file was vacuumed
(`status=noop`: there was nothing to remove).
Exit code `3` (`incomplete`, with the failed `stage`): the rows are already
clean, but `VACUUM` or the WAL checkpoint did not finish, so old bytes may
still be on free pages. Running the tool again does nothing (no rows left to
change). With NetAudit still stopped, finish the physical cleanup yourself -
it should print `(0, 0, 0)`:

```bash
python3 -c "import sqlite3, os; c = sqlite3.connect(os.path.expanduser('~/.netaudit/netaudit.db')); c.execute('VACUUM'); print(c.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()); c.close()"
```

The scrub backup still contains the passwords, and older backups or
filesystem snapshots are not touched - see
[the scrub contract](research/legacy_secret_scrub.md).

Passwords used in reports before the fix may also have reached the AI
provider during AI analysis - rotate them.

## 5. Rollback

The database schema did not change, so the previous version reads the same
database, including reports saved by 1.0.

A - git checkout:

```bash
cd ~/netaudit
git checkout <commit from step 1>
sudo systemctl restart netaudit
```

B - do not roll back with `deploy.sh` alone: files added in 1.0 (tests included)
would stay in `~/netaudit`, and its test run would fail against the old code.
Swap the runtime snapshot instead:

```bash
sudo systemctl stop netaudit
mv ~/netaudit ~/netaudit-1.0-failed
mv ~/netaudit-pre-1.0 ~/netaudit
sudo systemctl start netaudit
cd ~/netaudit-git && git checkout <DEPLOYED_COMMIT from step 1>
```

Restore the database backup from step 1 only if you need the pre-upgrade data
back. Reports saved after the upgrade are then lost.
