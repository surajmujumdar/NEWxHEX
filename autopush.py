#!/usr/bin/env python3
"""
========================================================================
   🔄 VAJRA + SENTINEL | AUTO-GIT SYNC & CONTINUOUS PUSHER
========================================================================
Monitors the workspace for local changes, automatically commits, and pushes
cleanly to https://github.com/surajmujumdar/vajraxsentinal.
"""

import os
import sys
import time
import subprocess
from datetime import datetime
from pathlib import Path

WORKSPACE_DIR = Path(__file__).resolve().parent
SYNC_INTERVAL_SECONDS = int(os.getenv("AUTOPUSH_INTERVAL", "30"))

def run_git(args):
    try:
        res = subprocess.run(
            ["git"] + args,
            cwd=str(WORKSPACE_DIR),
            capture_output=True,
            text=True
        )
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except Exception as e:
        return 1, "", str(e)

def has_changes():
    code, out, _ = run_git(["status", "--porcelain"])
    return code == 0 and len(out) > 0

def push_changes():
    # 1. Stage all tracked and new non-ignored files
    code, _, err = run_git(["add", "."])
    if code != 0:
        print(f"[AUTOPUSH ERROR] Failed to stage files: {err}")
        return False

    # 2. Check if anything actually staged
    code, staged_out, _ = run_git(["diff", "--cached", "--quiet"])
    if code == 0:
        # Nothing staged
        return False

    # 3. Create commit
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    commit_msg = f"auto: sync platform updates [{now_str}]"
    code, out, err = run_git(["commit", "-m", commit_msg])
    if code != 0:
        print(f"[AUTOPUSH ERROR] Commit failed: {err}")
        return False
    print(f"➜ [AUTOPUSH] Created commit: {commit_msg}")

    # 4. Push to origin main
    print(f"➜ [AUTOPUSH] Pushing changes to https://github.com/surajmujumdar/vajraxsentinal (main)...")
    code, out, err = run_git(["push", "origin", "main"])
    if code == 0:
        print(f"✅ [AUTOPUSH SUCCESS] Pushed updates to GitHub successfully at {now_str}\n")
        return True
    else:
        print(f"⚠️  [AUTOPUSH NOTICE] Push requires authentication or remote is busy: {err or out}\n")
        return False

def main():
    print("\n" + "=" * 70)
    print("   🔄  VAJRA + SENTINEL | CONTINUOUS GIT AUTO-PUSHER ACTIVE")
    print("=" * 70)
    print(f"   ➜ Target Repo: https://github.com/surajmujumdar/vajraxsentinal")
    print(f"   ➜ Auto-sync interval: every {SYNC_INTERVAL_SECONDS}s")
    print("=" * 70 + "\n")

    # Initial push check
    if has_changes():
        push_changes()
    else:
        # Try pushing existing unpushed commits
        run_git(["push", "origin", "main"])

    while True:
        try:
            time.sleep(SYNC_INTERVAL_SECONDS)
            if has_changes():
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Detected local modifications, syncing...")
                push_changes()
        except KeyboardInterrupt:
            print("\n[AUTOPUSH] Auto-pusher terminated cleanly.")
            break
        except Exception as e:
            print(f"[AUTOPUSH ERROR] Unexpected error: {e}")
            time.sleep(SYNC_INTERVAL_SECONDS)

if __name__ == "__main__":
    main()
