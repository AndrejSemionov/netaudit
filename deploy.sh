#!/usr/bin/env bash
# deploy.sh — run on VM (netaudit@192.168.88.20), from ~/netaudit-git.
#
# Copies changed files from the pulled git mirror (~/netaudit-git) into
# the live runtime copy (~/netaudit, not a git repo by design), restarts
# the service, writes a deployment manifest, and verifies the restart
# actually happened after the file copy — closing the exact class of
# bug hit twice: files updated on disk, but the running process still
# executing the old code because no restart followed.
#
# Usage:
#   cd ~/netaudit-git
#   git pull
#   ./deploy.sh                    # auto-detects changed files from last pull
#   ./deploy.sh file1.py file2.py  # explicit file list, if you want control
#
# What this does NOT do: it does not decide *what* changed is safe to
# deploy — that judgment (which files, whether tests passed on VM
# already) stays with you. This script only makes the mechanical part
# (copy -> restart -> verify) atomic and self-checking instead of
# relying on remembering to restart.

set -euo pipefail

GIT_DIR="$HOME/netaudit-git"
RUNTIME_DIR="$HOME/netaudit"
SERVICE_NAME="netaudit"
MANIFEST_PATH="$RUNTIME_DIR/.deployed_manifest"

cd "$GIT_DIR"

# --- Step 1: determine which files to deploy ---
if [ "$#" -gt 0 ]; then
    FILES=("$@")
    echo "[deploy] Using explicit file list (${#FILES[@]} files)."
else
    # Files changed by the most recent pull (comparing HEAD to its
    # previous position via reflog). If this is the first pull in this
    # session or reflog is unavailable, falls back to files changed in
    # the single most recent commit.
    PREV_HEAD=$(git reflog show -1 --format='%H' HEAD@{1} 2>/dev/null || echo "")
    if [ -n "$PREV_HEAD" ] && [ "$PREV_HEAD" != "$(git rev-parse HEAD)" ]; then
        mapfile -t FILES < <(git diff --name-only "$PREV_HEAD" HEAD)
    else
        mapfile -t FILES < <(git diff --name-only HEAD~1 HEAD)
    fi
    echo "[deploy] Auto-detected ${#FILES[@]} changed file(s) from last pull:"
    printf '  %s\n' "${FILES[@]}"
fi

if [ "${#FILES[@]}" -eq 0 ]; then
    echo "[deploy] No files to deploy. Nothing to do."
    exit 0
fi

# --- Step 2: NotImplementedError guard on every file about to be deployed
# (checked on the git-mirror source, before anything touches runtime) ---
echo ""
echo "[deploy] Checking for NotImplementedError in files to deploy ..."
GUARD_FAILED=0
for f in "${FILES[@]}"; do
    [ -f "$f" ] || continue  # skip deleted files
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

# --- Step 3: copy each file individually, mirroring the manual workflow ---
echo ""
echo "[deploy] Copying files to $RUNTIME_DIR ..."
for f in "${FILES[@]}"; do
    [ -f "$f" ] || { echo "  [skip] $f (deleted or not a regular file)"; continue; }
    dest="$RUNTIME_DIR/$f"
    mkdir -p "$(dirname "$dest")"
    cp "$f" "$dest"
    echo "  [copied] $f"
done

# --- Step 4: pytest MUST pass on the runtime copy (~/netaudit) — this is
# where the venv with httpx/paramiko lives, per project convention;
# ~/netaudit-git is a pull-only mirror and its own venv is intentionally
# incomplete, not a valid place to run the test suite. ---
echo ""
echo "[deploy] Running pytest on $RUNTIME_DIR ..."
cd "$RUNTIME_DIR"
if ! python3 -m pytest -q; then
    echo "[deploy] FAILED: pytest did not pass on $RUNTIME_DIR after copy."
    echo "[deploy] Files are already copied — runtime dir is in a mixed state relative to the last known-good deploy. Investigate before restarting the service."
    exit 1
fi
echo "[deploy] pytest OK."
cd "$GIT_DIR"

# --- Step 5: restart ---
echo ""
echo "[deploy] Restarting $SERVICE_NAME ..."
sudo systemctl restart "$SERVICE_NAME"
sleep 2

# --- Step 6: verify the restart actually happened AFTER the file copy ---
# This is the check that would have caught the 09:53 copy / 10:03 restart
# gap immediately, instead of only surfacing as "check not found" on the
# next E2E run.
ACTIVE_ENTER=$(systemctl show "$SERVICE_NAME" --property=ActiveEnterTimestamp --value)
ACTIVE_ENTER_EPOCH=$(date -d "$ACTIVE_ENTER" +%s 2>/dev/null || echo 0)
NOW_EPOCH=$(date +%s)

echo "[deploy] Service ActiveEnterTimestamp: $ACTIVE_ENTER"

if [ "$ACTIVE_ENTER_EPOCH" -eq 0 ]; then
    echo "[deploy] WARNING: could not parse ActiveEnterTimestamp — skipping freshness check."
elif [ $((NOW_EPOCH - ACTIVE_ENTER_EPOCH)) -gt 30 ]; then
    echo "[deploy] FAILED: service ActiveEnterTimestamp is more than 30s old — restart may not have taken effect."
    echo "[deploy] Check 'systemctl status $SERVICE_NAME' manually before trusting this deployment."
    exit 1
fi
echo "[deploy] Restart verified fresh."

# --- Step 7: is the service actually up? ---
if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "[deploy] FAILED: $SERVICE_NAME is not active after restart."
    sudo systemctl status "$SERVICE_NAME" --no-pager | head -20
    exit 1
fi
echo "[deploy] Service is active."

# --- Step 8: write deployment manifest ---
COMMIT=$(git rev-parse --short HEAD)
DEPLOYED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cat > "$MANIFEST_PATH" << EOF
DEPLOYED_COMMIT=$COMMIT
DEPLOYED_AT=$DEPLOYED_AT
SERVICE_STARTED_AT=$ACTIVE_ENTER
FILES_DEPLOYED=${#FILES[@]}
EOF
echo ""
echo "[deploy] Manifest written to $MANIFEST_PATH:"
cat "$MANIFEST_PATH"

# --- Step 9: E2E smoke test — confirm /api/checks responds and returns a non-empty list ---
echo ""
echo "[deploy] Running smoke test against http://127.0.0.1:8000/api/checks ..."
SMOKE_RESPONSE=$(curl -s -w '\n%{http_code}' http://127.0.0.1:8000/api/checks 2>&1) || {
    echo "[deploy] FAILED: could not reach /api/checks."
    exit 1
}
SMOKE_CODE=$(echo "$SMOKE_RESPONSE" | tail -1)
if [ "$SMOKE_CODE" != "200" ]; then
    echo "[deploy] FAILED: /api/checks returned HTTP $SMOKE_CODE."
    exit 1
fi
CHECK_COUNT=$(echo "$SMOKE_RESPONSE" | head -n -1 | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "?")
echo "[deploy] Smoke test OK — /api/checks returned $CHECK_COUNT registered check(s)."

echo ""
echo "=== DEPLOYMENT SUCCESS ==="
echo "Commit: $COMMIT"
echo "Deployed at: $DEPLOYED_AT"
echo "Files: ${#FILES[@]}"
