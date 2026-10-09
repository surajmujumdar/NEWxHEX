#!/usr/bin/env python3
"""
========================================================================
   🛡️  VAJRA CYBERSECURITY & THREAT INTELLIGENCE PLATFORM LAUNCHER
========================================================================
Single entry point to boot VAJRA FastAPI backend & Next.js frontend
on localhost with real-time AI security & threat feeds.
"""

import os
import sys
import time
import subprocess
import signal
import urllib.request
import json
import threading
from pathlib import Path

# Ensure UTF-8 output on all platforms
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend" if (ROOT_DIR / "backend").exists() else ROOT_DIR / "V X S" / "backend"
FRONTEND_DIR = (ROOT_DIR / "frontend") if (ROOT_DIR / "frontend" / "node_modules" / "next").exists() else (ROOT_DIR / "V X S" / "frontend")

processes = []

def cleanup(signum=None, frame=None):
    print("\n[SHUTDOWN] Terminating VAJRA platform processes...")
    for p in processes:
        try:
            p.terminate()
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    print("[SHUTDOWN] All services stopped cleanly. Goodbye!\n")
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def check_backend_health(url="http://127.0.0.1:8000/api/health", timeout_secs=25):
    start = time.time()
    while time.time() - start < timeout_secs:
        try:
            req = urllib.request.urlopen(url, timeout=2)
            if req.status == 200:
                data = json.loads(req.read().decode("utf-8"))
                return data
        except Exception:
            pass
        time.sleep(0.5)
    return None

def stream_pipe(pipe, prefix):
    try:
        for line in iter(pipe.readline, ''):
            if line:
                print(f"{prefix} {line.rstrip()}", flush=True)
    except Exception:
        pass
    finally:
        pipe.close()

def main():
    print("\n" + "=" * 76)
    print("   🛡️  VAJRA CYBERSECURITY & THREAT INTELLIGENCE PLATFORM")
    print("=" * 76)
    print("   Initializing Vajra threat engine & cyber intelligence matrix...\n")

    # Verify directories
    if not BACKEND_DIR.exists() or not FRONTEND_DIR.exists():
        print(f"[ERROR] Missing backend or frontend directory under {ROOT_DIR}")
        sys.exit(1)

    # 1. Start Backend
    backend_cmd = [sys.executable, str(BACKEND_DIR / "run_backend.py")]
    print(f"➜ [BACKEND] Starting FastAPI server on port 8000...")
    backend_proc = subprocess.Popen(
        backend_cmd,
        cwd=str(BACKEND_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    processes.append(backend_proc)

    # Stream backend logs in background thread
    t_backend = threading.Thread(target=stream_pipe, args=(backend_proc.stdout, "[BACKEND]"), daemon=True)
    t_backend.start()

    # Wait for backend health check
    print("➜ [BACKEND] Waiting for database initialization and services...")
    health_data = check_backend_health()
    if not health_data:
        print("[ERROR] VAJRA backend failed to start within timeout.")
        cleanup()

    v_status = health_data.get("vajra_status", health_data.get("status", "ONLINE"))

    print(f"\n   [VAJRA]    Backend initialized & Database connected ({v_status})")
    print(f"   [API]      Swagger Documentation available at http://localhost:8000/docs\n")

    # 2. Start Frontend
    print("➜ [FRONTEND] Starting Next.js UI on port 3000...")
    npm_bin = "npm.cmd" if os.name == "nt" else "npm"
    frontend_cmd = [npm_bin, "run", "dev"]
    frontend_proc = subprocess.Popen(
        frontend_cmd,
        cwd=str(FRONTEND_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    processes.append(frontend_proc)

    # Stream frontend logs in background thread
    t_frontend = threading.Thread(target=stream_pipe, args=(frontend_proc.stdout, "[FRONTEND]"), daemon=True)
    t_frontend.start()

    time.sleep(3)

    print("\n" + "=" * 76)
    print("   🚀  VAJRA CYBERSECURITY PLATFORM IS LIVE & READY!")
    print("=" * 76)
    print(f"   ➜ Web Application UI:     http://localhost:3000")
    print(f"   ➜ REST API Docs:          http://localhost:8000/docs")
    print(f"   ➜ Health Status:          http://localhost:8000/api/health")
    print("=" * 76)
    print("   Press Ctrl+C at any time to shut down all servers.\n")

    # Keep alive and monitor child processes
    try:
        while True:
            if backend_proc.poll() is not None:
                print(f"\n[ERROR] Backend exited unexpectedly with code {backend_proc.returncode}")
                break
            if frontend_proc.poll() is not None:
                print(f"\n[ERROR] Frontend exited unexpectedly with code {frontend_proc.returncode}")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()

if __name__ == "__main__":
    main()
