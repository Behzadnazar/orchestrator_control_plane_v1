from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from scripts.worker_supervisor import (
    load_registry,
    matches_expected_identity,
    read_pid,
)


WORKER_ID = "frontend-worker-v1"


def registry_snapshot() -> dict:
    reg = load_registry()
    return reg.get("workers", {}).get(WORKER_ID, {})


def print_snapshot(label: str) -> None:
    entry = registry_snapshot()
    print(
        f"{label} | "
        f"pid={entry.get('pid')} | "
        f"process_state={entry.get('process_state')} | "
        f"desired_state={entry.get('desired_state')} | "
        f"last_stop_intent={entry.get('last_stop_intent')} | "
        f"restart_count={entry.get('restart_count')} | "
        f"restart_history={entry.get('restart_history')} | "
        f"process_identity={entry.get('process_identity')} | "
        f"crash_loop_protection={entry.get('crash_loop_protection')}",
        flush=True,
    )


def kill_worker_hard_and_verify() -> None:
    pid = read_pid(WORKER_ID)
    if not pid or not matches_expected_identity(WORKER_ID, pid):
        print(f"no-matching-alive-pid for {WORKER_ID}", flush=True)
        return

    os.killpg(pid, signal.SIGKILL)
    print(f"sent-sigkill {WORKER_ID} pid={pid}", flush=True)

    deadline = time.time() + 5
    while time.time() < deadline:
        if not matches_expected_identity(WORKER_ID, pid):
            print(f"verified-dead {WORKER_ID} old_pid={pid}", flush=True)
            return
        time.sleep(0.2)

    print(f"kill-not-verified {WORKER_ID} old_pid={pid}", flush=True)


def main() -> None:
    print_snapshot("before")
    for i in range(1, 5):
        kill_worker_hard_and_verify()
        time.sleep(7)
        print_snapshot(f"after_kill_{i}")
    print_snapshot("final")


if __name__ == "__main__":
    main()
