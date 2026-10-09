#!/usr/bin/env bash
# deploy.sh — run on VM (netaudit@192.168.88.20), from ~/netaudit-git.
#
# Copies what changed since the last deployed commit from the pulled git
# mirror (~/netaudit-git) into the live runtime copy (~/netaudit, not a git
# repo by design), restarts the service, verifies the restart, and writes a
# deployment manifest. Before it changes anything it backs up every file it
# will overwrite or delete, plus the SQLite database; when a later step
# fails it restores those files and restarts the service by itself.
#
# Usage:
#   cd ~/netaudit-git
#   git pull
#   ./deploy.sh                    # everything since DEPLOYED_COMMIT in ~/netaudit/.deployed_manifest
#   ./deploy.sh file1.py file2.py  # explicit file list (never deletes anything)
#   ./deploy.sh --rollback         # restore the newest backup by hand
#
# Backups: ~/netaudit-deploy-backups/<UTC time>-<previous commit>/ (mode 0700):
#   files/      runtime copies of the files the deploy overwrote or deleted
#   added.txt   files the deploy created (deleted on rollback)
#   manifest    the previous .deployed_manifest
#   netaudit.db online SQLite backup of ~/.netaudit/netaudit.db (0600); it can
#               hold old SSH passwords, see scrub_legacy_secrets
# The newest 5 are kept. The database is never restored automatically: the
# rollback output prints the command. See docs/research/deploy_backup_rollback.md.
#
# What this does NOT do: it does not decide *what* is safe to deploy — that
# judgment (which commits, whether tests passed elsewhere) stays with you.

set -Eeuo pipefail

GIT_DIR="$HOME/netaudit-git"
RUNTIME_DIR="$HOME/netaudit"
SERVICE_NAME="netaudit"
MANIFEST_PATH="$RUNTIME_DIR/.deployed_manifest"
BACKUP_ROOT="$HOME/netaudit-deploy-backups"
DB_PATH="$HOME/.netaudit/netaudit.db"
KEEP_BACKUPS=5
RESTART_WAIT="${DEPLOY_RESTART_WAIT:-2}"
ROLLED_BACK_SUFFIX=".rolled-back"

BACKUP_DIR=""
PREV_COMMIT=""

manifest_commit() {
    # $1: manifest file; prints DEPLOYED_COMMIT or nothing (never fails)
    [ -f "$1" ] || return 0
    sed -n 's/^DEPLOYED_COMMIT=//p' "$1" | head -1 | tr -d '[:space:]' || true
}

restart_and_check() {
    sudo systemctl restart "$SERVICE_NAME" || return 1
    sleep "$RESTART_WAIT"
    systemctl is-active --quiet "$SERVICE_NAME"
}

restore_backup() {
    # $1: backup dir. Puts back the saved files, removes files the deploy
    # added, restores the manifest. Returns non-zero on the first failure.
    local dir="$1" rel
    while IFS= read -r -d '' rel; do
        rel="${rel#./}"
        mkdir -p "$RUNTIME_DIR/$(dirname "$rel")" || return 1
        cp -p "$dir/files/$rel" "$RUNTIME_DIR/$rel" || return 1
    done < <(cd "$dir/files" && find . -type f -print0)
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        rm -f -- "$RUNTIME_DIR/$rel" || return 1
    done < "$dir/added.txt"
    if [ -f "$dir/manifest" ]; then
        cp "$dir/manifest" "$MANIFEST_PATH" || return 1
        chmod 644 "$MANIFEST_PATH" || return 1
    else
        rm -f "$MANIFEST_PATH" || return 1
    fi
}

print_db_note() {
    # $1: backup dir
    [ -f "$1/netaudit.db" ] || return 0
    echo "[deploy] The database was NOT restored. To go back to the pre-deploy database"
    echo "[deploy] (reports saved since then are lost):"
    echo "  sudo systemctl stop $SERVICE_NAME"
    echo "  rm -f $DB_PATH-wal $DB_PATH-shm"
    echo "  cp $1/netaudit.db $DB_PATH"
    echo "  sudo systemctl start $SERVICE_NAME"
}

rollback_and_exit() {
    # $1: why the deploy failed. Exit 1 after a clean rollback, 2 otherwise.
    trap - ERR
    set +e
    echo "[deploy] FAILED: $1"
    echo "[deploy] Rolling back from $BACKUP_DIR ..."
    if restore_backup "$BACKUP_DIR" && restart_and_check; then
        echo ""
        echo "=== DEPLOYMENT FAILED — ROLLED BACK TO ${PREV_COMMIT:-the previous files} ==="
        print_db_note "$BACKUP_DIR"
        exit 1
    fi
    echo ""
    echo "=== ROLLBACK FAILED ==="
    echo "Backup: $BACKUP_DIR"
    echo "Restore by hand: copy $BACKUP_DIR/files/* back into $RUNTIME_DIR, delete the files"
    echo "listed in $BACKUP_DIR/added.txt, copy $BACKUP_DIR/manifest to $MANIFEST_PATH, then"
    echo "  sudo systemctl restart $SERVICE_NAME && systemctl status $SERVICE_NAME --no-pager"
    print_db_note "$BACKUP_DIR"
    exit 2
}

on_error() {
    rollback_and_exit "unexpected error at deploy.sh line $1"
}

backup_dirs() {
    # newest last; $1 = "all" or "usable" (not rolled back yet)
    local d
    while IFS= read -r d; do
        if [ "$1" = usable ] && [[ "$d" == *"$ROLLED_BACK_SUFFIX" ]]; then
            continue
        fi
        printf '%s\n' "$d"
    done < <(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
}

manual_rollback() {
    local -a usable
    mapfile -t usable < <(backup_dirs usable)
    if [ "${#usable[@]}" -eq 0 ]; then
        echo "[deploy] FAILED: no deploy backup to roll back to in $BACKUP_ROOT."
        exit 1
    fi
    BACKUP_DIR="${usable[${#usable[@]}-1]}"
    local mirror_head
    mirror_head=$(git rev-parse --short HEAD)
    echo "[deploy] Rolling back by hand from $BACKUP_DIR ..."
    if ! restore_backup "$BACKUP_DIR" || ! restart_and_check; then
        echo ""
        echo "=== ROLLBACK FAILED ==="
        echo "Backup: $BACKUP_DIR"
        systemctl status "$SERVICE_NAME" --no-pager | head -20 || true
        exit 2
    fi
    mv "$BACKUP_DIR" "$BACKUP_DIR$ROLLED_BACK_SUFFIX"
    PREV_COMMIT=$(manifest_commit "$MANIFEST_PATH")
    echo ""
    echo "=== ROLLED BACK TO ${PREV_COMMIT:-the previous files} ==="
    echo "The git mirror still has $mirror_head: the next ./deploy.sh deploys it again."
    echo "To keep the old version in the mirror too: git -C $GIT_DIR checkout ${PREV_COMMIT:-<commit>}"
    print_db_note "$BACKUP_DIR$ROLLED_BACK_SUFFIX"
}

make_backup() {
    # Saves what the deploy will change. Runs before anything is copied; on
    # failure the caller removes the partial backup and nothing has changed yet.
    local old_umask rel
    old_umask=$(umask)
    umask 077
    mkdir -p "$BACKUP_ROOT" || return 1
    chmod 700 "$BACKUP_ROOT" || return 1
    BACKUP_DIR="$BACKUP_ROOT/$(date -u +%Y%m%dT%H%M%S.%NZ)-${PREV_COMMIT:-none}"
    mkdir "$BACKUP_DIR" "$BACKUP_DIR/files" || return 1
    : > "$BACKUP_DIR/added.txt" || return 1
    for rel in "${DEPLOY[@]}" "${DELETE[@]}"; do
        if [ -e "$RUNTIME_DIR/$rel" ]; then
            mkdir -p "$BACKUP_DIR/files/$(dirname "$rel")" || return 1
            cp -p "$RUNTIME_DIR/$rel" "$BACKUP_DIR/files/$rel" || return 1  # -p: rollback restores the mode too
        elif [ -f "$GIT_DIR/$rel" ]; then
            printf '%s\n' "$rel" >> "$BACKUP_DIR/added.txt" || return 1
        fi
    done
    if [ -f "$MANIFEST_PATH" ]; then
        cp "$MANIFEST_PATH" "$BACKUP_DIR/manifest" || return 1
    fi
    if [ -f "$DB_PATH" ]; then
        python3 - "$DB_PATH" "$BACKUP_DIR/netaudit.db" <<'PY' || return 1
import sqlite3
import sys

source = sqlite3.connect(f'file:{sys.argv[1]}?mode=ro', uri=True, timeout=10)
target = sqlite3.connect(sys.argv[2])
source.backup(target)
ok = target.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
target.close()
source.close()
sys.exit(0 if ok else 1)
PY
    fi
    umask "$old_umask"
}

prune_backups() {
    local -a all
    mapfile -t all < <(backup_dirs all)
    local extra=$(( ${#all[@]} - KEEP_BACKUPS )) i
    for (( i = 0; i < extra; i++ )); do
        rm -rf -- "${all[$i]}"
    done
}

cd "$GIT_DIR"

if [ "${1:-}" = "--rollback" ]; then
    manual_rollback
    exit 0
fi

PREV_COMMIT=$(manifest_commit "$MANIFEST_PATH")

# --- Step 1: determine which files to deploy ---
DEPLOY=()
DELETE=()
if [ "$#" -gt 0 ]; then
    DEPLOY=("$@")
    echo "[deploy] Using explicit file list (${#DEPLOY[@]} files)."
else
    BASE=""
    if [ -n "$PREV_COMMIT" ]; then
        BASE=$(git rev-parse --verify --quiet "$PREV_COMMIT^{commit}" || true)
    fi
    if [ -z "$BASE" ]; then
        echo "[deploy] FAILED: $MANIFEST_PATH has no DEPLOYED_COMMIT that this git mirror knows."
        echo "[deploy] Nothing changed. Pass an explicit file list: ./deploy.sh file1 file2 ..."
        exit 1
    fi
    while IFS= read -r -d '' status && IFS= read -r -d '' path; do
        if [[ "$path" == *$'\n'* ]]; then
            echo "[deploy] FAILED: a changed path contains a newline. Nothing changed."
            exit 1
        fi
        if [ "$status" = D ]; then
            DELETE+=("$path")
        else
            DEPLOY+=("$path")
        fi
    done < <(git diff -z --name-status --no-renames "$BASE" HEAD)
    echo "[deploy] Changes since DEPLOYED_COMMIT $PREV_COMMIT: ${#DEPLOY[@]} to copy, ${#DELETE[@]} to delete."
    [ "${#DEPLOY[@]}" -eq 0 ] || printf '  copy   %s\n' "${DEPLOY[@]}"
    [ "${#DELETE[@]}" -eq 0 ] || printf '  delete %s\n' "${DELETE[@]}"
fi

if [ $(( ${#DEPLOY[@]} + ${#DELETE[@]} )) -eq 0 ]; then
    echo "[deploy] No files to deploy. Nothing to do."
    exit 0
fi

# --- Step 2: NotImplementedError guard on every file about to be deployed
# (checked on the git-mirror source, before anything touches runtime) ---
echo ""
echo "[deploy] Checking for NotImplementedError in files to deploy ..."
GUARD_FAILED=0
for f in "${DEPLOY[@]}"; do
    [ -f "$f" ] || continue  # skip missing files
    case "$f" in
        *.py)
            count=$(grep -c "raise NotImplementedError" "$f" 2>/dev/null) || true
            count=${count:-0}
            if [ "$count" -gt 0 ]; then
                echo "  [GUARD FAIL] $f contains $count NotImplementedError raise(s)."
                GUARD_FAILED=1
            fi
            ;;
    esac
done
if [ "$GUARD_FAILED" -eq 1 ]; then
    echo "[deploy] FAILED: one or more files still contain NotImplementedError. Aborting — nothing copied."
    exit 1
fi
echo "[deploy] Guard OK — no NotImplementedError found in deployed files."

# --- Step 3: back up what will change, before changing it ---
echo ""
echo "[deploy] Backing up files and database ..."
if ! make_backup; then
    echo "[deploy] FAILED: backup could not be made. Nothing changed."
    [ -z "$BACKUP_DIR" ] || rm -rf -- "$BACKUP_DIR"
    exit 1
fi
echo "[deploy] Backup: $BACKUP_DIR"

# From here on every failure restores the backup.
trap 'on_error $LINENO' ERR

# --- Step 4: copy changed files, delete removed ones ---
echo ""
echo "[deploy] Updating $RUNTIME_DIR ..."
for f in "${DEPLOY[@]}"; do
    [ -f "$f" ] || { echo "  [skip] $f (missing in the mirror or not a regular file)"; continue; }
    mkdir -p "$(dirname "$RUNTIME_DIR/$f")"
    cp "$f" "$RUNTIME_DIR/$f"
    echo "  [copied] $f"
done
for f in "${DELETE[@]}"; do
    rm -f -- "$RUNTIME_DIR/$f"
    echo "  [deleted] $f"
done

# --- Step 5: pytest MUST pass on the runtime copy (~/netaudit) — this is
# where the venv with httpx/paramiko lives, per project convention;
# ~/netaudit-git is a pull-only mirror and its own venv is intentionally
# incomplete, not a valid place to run the test suite. ---
echo ""
echo "[deploy] Running pytest on $RUNTIME_DIR ..."
cd "$RUNTIME_DIR"
if ! python3 -m pytest -q; then
    rollback_and_exit "pytest did not pass on $RUNTIME_DIR after copy."
fi
echo "[deploy] pytest OK."
cd "$GIT_DIR"

# --- Step 6: restart ---
echo ""
echo "[deploy] Restarting $SERVICE_NAME ..."
if ! sudo systemctl restart "$SERVICE_NAME"; then
    rollback_and_exit "systemctl restart $SERVICE_NAME failed."
fi
sleep "$RESTART_WAIT"

# --- Step 7: verify the restart actually happened AFTER the file copy ---
ACTIVE_ENTER=$(systemctl show "$SERVICE_NAME" --property=ActiveEnterTimestamp --value)
ACTIVE_ENTER_EPOCH=$(date -d "$ACTIVE_ENTER" +%s 2>/dev/null || echo 0)
NOW_EPOCH=$(date +%s)

echo "[deploy] Service ActiveEnterTimestamp: $ACTIVE_ENTER"

if [ "$ACTIVE_ENTER_EPOCH" -eq 0 ]; then
    echo "[deploy] WARNING: could not parse ActiveEnterTimestamp — skipping freshness check."
elif [ $((NOW_EPOCH - ACTIVE_ENTER_EPOCH)) -gt 30 ]; then
    rollback_and_exit "service ActiveEnterTimestamp is more than 30s old — the restart did not take effect."
fi
echo "[deploy] Restart verified fresh."

# --- Step 8: is the service actually up? ---
if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    sudo systemctl status "$SERVICE_NAME" --no-pager | head -20 || true
    rollback_and_exit "$SERVICE_NAME is not active after restart."
fi
echo "[deploy] Service is active."

# --- Step 9: E2E smoke test — /api/checks responds with a non-empty list.
# 401 means the service is up behind NetAudit's Basic Auth (it listens
# beyond localhost): not a reason to roll back. ---
echo ""
echo "[deploy] Running smoke test against http://127.0.0.1:8000/api/checks ..."
if ! SMOKE_RESPONSE=$(curl -s -w '\n%{http_code}' http://127.0.0.1:8000/api/checks 2>&1); then
    rollback_and_exit "could not reach /api/checks."
fi
SMOKE_CODE=$(echo "$SMOKE_RESPONSE" | tail -1)
if [ "$SMOKE_CODE" = "401" ]; then
    echo "[deploy] WARNING: /api/checks answered 401 — Basic Auth is on. The service is up;"
    echo "[deploy] check it by hand: curl -u user:pass http://127.0.0.1:8000/api/checks"
elif [ "$SMOKE_CODE" != "200" ]; then
    rollback_and_exit "/api/checks returned HTTP $SMOKE_CODE."
else
    CHECK_COUNT=$(echo "$SMOKE_RESPONSE" | head -n -1 | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "?")
    echo "[deploy] Smoke test OK — /api/checks returned $CHECK_COUNT registered check(s)."
fi

trap - ERR

# --- Step 10: write deployment manifest ---
COMMIT=$(git rev-parse --short HEAD)
DEPLOYED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cat > "$MANIFEST_PATH" << EOF
DEPLOYED_COMMIT=$COMMIT
DEPLOYED_AT=$DEPLOYED_AT
SERVICE_STARTED_AT=$ACTIVE_ENTER
FILES_DEPLOYED=$(( ${#DEPLOY[@]} + ${#DELETE[@]} ))
EOF
echo ""
echo "[deploy] Manifest written to $MANIFEST_PATH:"
cat "$MANIFEST_PATH"

prune_backups

echo ""
echo "=== DEPLOYMENT SUCCESS ==="
echo "Commit: $COMMIT (previous: ${PREV_COMMIT:-none})"
echo "Deployed at: $DEPLOYED_AT"
echo "Files: ${#DEPLOY[@]} copied, ${#DELETE[@]} deleted"
echo "Backup: $BACKUP_DIR (roll back with ./deploy.sh --rollback)"
