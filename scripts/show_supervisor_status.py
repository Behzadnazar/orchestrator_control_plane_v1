from __future__ import annotations

import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
REGISTRY_PATH = BASE_DIR / "run" / "worker_registry.json"
PID_DIR = BASE_DIR / "run" / "worker-pids"
LOG_DIR = BASE_DIR / "logs" / "workers"
POLICY_PATH = BASE_DIR / "config" / "policies" / "worker_supervisor.json"
SUPERVISOR_RUN_DIR = BASE_DIR / "run" / "supervisor"


def main() -> None:
    print("# SUPERVISOR FILES")
    print(f"policy_path         : {POLICY_PATH}")
    print(f"registry_path       : {REGISTRY_PATH}")
    print(f"pid_dir             : {PID_DIR}")
    print(f"log_dir             : {LOG_DIR}")
    print(f"supervisor_run_dir  : {SUPERVISOR_RUN_DIR}")
    print()

    if POLICY_PATH.exists():
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        print("# SUPERVISOR POLICY")
        print(f"version             : {policy.get('supervisor_version')}")
        print(f"monitor_loop        : {policy.get('monitor_loop')}")
        for worker_id, cfg in policy.get("workers", {}).items():
            print(
                f"- worker_id={worker_id} | "
                f"enabled={cfg.get('enabled')} | "
                f"autorestart={cfg.get('autorestart')} | "
                f"maintenance={cfg.get('maintenance')} | "
                f"once_idle_exit={cfg.get('once_idle_exit')}"
            )
        print()

    if REGISTRY_PATH.exists():
        registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        print("# SUPERVISOR REGISTRY")
        print(f"updated_at          : {registry.get('updated_at')}")
        print(f"supervisor          : {registry.get('supervisor')}")
        for worker_id, entry in registry.get("workers", {}).items():
            clp = entry.get("crash_loop_protection", {})
            print(
                f"- worker_id={worker_id} | "
                f"pid={entry.get('pid')} | "
                f"process_state={entry.get('process_state')} | "
                f"desired_state={entry.get('desired_state')} | "
                f"last_stop_intent={entry.get('last_stop_intent')} | "
                f"restart_count={entry.get('restart_count')} | "
                f"restart_history={entry.get('restart_history')} | "
                f"crash_loop_state={clp.get('state')} | "
                f"crash_loop_reason={clp.get('reason')} | "
                f"log={entry.get('log_path')} | "
                f"note={entry.get('note')}"
            )
    else:
        print("# SUPERVISOR REGISTRY")
        print("registry not found")


if __name__ == "__main__":
    main()
