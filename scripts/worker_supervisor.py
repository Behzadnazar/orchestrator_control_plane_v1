from __future__ import annotations

import argparse
import json
import os
import secrets
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from scripts.task_registry import AGENT_REGISTRY


RUN_DIR = BASE_DIR / "run"
PID_DIR = RUN_DIR / "worker-pids"
LOG_DIR = BASE_DIR / "logs" / "workers"
SUPERVISOR_RUN_DIR = RUN_DIR / "supervisor"
REGISTRY_PATH = RUN_DIR / "worker_registry.json"
SUPERVISOR_POLICY_PATH = BASE_DIR / "config" / "policies" / "worker_supervisor.json"
WORKER_ENTRYPOINT = BASE_DIR / "worker_loop_final.py"

PID_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)
RUN_DIR.mkdir(parents=True, exist_ok=True)
SUPERVISOR_RUN_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class WorkerPolicy:
    enabled: bool
    autorestart: bool
    maintenance: bool
    once_idle_exit: bool


def now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    return datetime.fromisoformat(ts)


def load_supervisor_policy() -> dict[str, Any]:
    return json.loads(SUPERVISOR_POLICY_PATH.read_text(encoding="utf-8"))


def get_monitor_loop_settings() -> dict[str, Any]:
    policy = load_supervisor_policy()
    return dict(policy.get("monitor_loop", {}))


def get_supervisor_lockfile() -> Path:
    name = str(get_monitor_loop_settings().get("lockfile_name", "supervisor.lock"))
    return SUPERVISOR_RUN_DIR / name


def get_supervisor_pidfile() -> Path:
    name = str(get_monitor_loop_settings().get("pidfile_name", "supervisor.pid"))
    return SUPERVISOR_RUN_DIR / name


def get_poll_interval_seconds() -> int:
    return int(get_monitor_loop_settings().get("poll_interval_seconds", 5))


def get_graceful_stop_timeout_seconds() -> int:
    return int(get_monitor_loop_settings().get("graceful_stop_timeout_seconds", 10))


def get_restart_backoff_seconds() -> int:
    return int(get_monitor_loop_settings().get("restart_backoff_seconds", 6))


def get_restart_window_seconds() -> int:
    return int(get_monitor_loop_settings().get("restart_window_seconds", 60))


def get_max_restarts_in_window() -> int:
    return int(get_monitor_loop_settings().get("max_restarts_in_window", 3))


def get_worker_policy(worker_id: str) -> WorkerPolicy:
    policy = load_supervisor_policy()
    workers = policy.get("workers", {})
    cfg = workers.get(worker_id, {})
    return WorkerPolicy(
        enabled=bool(cfg.get("enabled", False)),
        autorestart=bool(cfg.get("autorestart", False)),
        maintenance=bool(cfg.get("maintenance", False)),
        once_idle_exit=bool(cfg.get("once_idle_exit", False)),
    )


def default_registry() -> dict[str, Any]:
    return {
        "supervisor_version": "phase_g_v1",
        "updated_at": None,
        "supervisor": {},
        "workers": {},
    }


def load_registry() -> dict[str, Any]:
    if not REGISTRY_PATH.exists():
        return default_registry()
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def save_registry(registry: dict[str, Any]) -> None:
    registry["updated_at"] = now_ts()
    REGISTRY_PATH.write_text(json.dumps(registry, indent=2, ensure_ascii=False), encoding="utf-8")


def pid_file(worker_id: str) -> Path:
    return PID_DIR / f"{worker_id}.pid"


def log_file(worker_id: str) -> Path:
    return LOG_DIR / f"{worker_id}.log"


def read_pid(worker_id: str) -> int | None:
    path = pid_file(worker_id)
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def write_pid(worker_id: str, pid: int) -> None:
    pid_file(worker_id).write_text(str(pid), encoding="utf-8")


def clear_pid(worker_id: str) -> None:
    path = pid_file(worker_id)
    if path.exists():
        path.unlink()


def is_pid_alive(pid: int | None) -> bool:
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def python_executable() -> str:
    return sys.executable


def _proc_path(pid: int, name: str) -> Path:
    return Path("/proc") / str(pid) / name


def read_proc_starttime(pid: int) -> str | None:
    try:
        stat_text = _proc_path(pid, "stat").read_text(encoding="utf-8")
    except Exception:
        return None
    try:
        right = stat_text.rsplit(") ", 1)[1]
        parts = right.split()
        return parts[19]
    except Exception:
        return None


def read_proc_cmdline(pid: int) -> str | None:
    try:
        raw = _proc_path(pid, "cmdline").read_bytes()
    except Exception:
        return None
    if not raw:
        return ""
    return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()


def read_proc_environ_var(pid: int, var_name: str) -> str | None:
    try:
        raw = _proc_path(pid, "environ").read_bytes()
    except Exception:
        return None

    prefix = f"{var_name}=".encode("utf-8")
    for item in raw.split(b"\x00"):
        if item.startswith(prefix):
            return item[len(prefix):].decode("utf-8", errors="replace")
    return None


def current_process_identity(pid: int) -> dict[str, Any]:
    return {
        "pid": pid,
        "starttime": read_proc_starttime(pid),
        "cmdline": read_proc_cmdline(pid),
        "worker_id_env": read_proc_environ_var(pid, "OCP_WORKER_ID"),
        "supervisor_token_env": read_proc_environ_var(pid, "OCP_SUPERVISOR_TOKEN"),
    }


def matches_expected_identity(worker_id: str, pid: int) -> bool:
    if not is_pid_alive(pid):
        return False

    entry = ensure_worker_entry(worker_id)
    expected = entry.get("process_identity") or {}
    current = current_process_identity(pid)

    expected_token = expected.get("supervisor_token")
    expected_starttime = expected.get("starttime")
    current_cmdline = current.get("cmdline") or ""

    if expected_token and current.get("supervisor_token_env") != expected_token:
        return False

    if expected_starttime and current.get("starttime") != expected_starttime:
        return False

    if "worker_loop_final.py" not in current_cmdline:
        return False

    if current.get("worker_id_env") != worker_id:
        return False

    return True


def ensure_worker_entry(worker_id: str) -> dict[str, Any]:
    registry = load_registry()
    workers = registry.setdefault("workers", {})
    if worker_id not in workers:
        policy = get_worker_policy(worker_id)
        workers[worker_id] = {
            "worker_id": worker_id,
            "pid": None,
            "process_state": "stopped",
            "desired_state": "running" if policy.enabled else "stopped",
            "last_stop_intent": "none",
            "started_at": None,
            "last_seen_at": None,
            "maintenance": policy.maintenance,
            "once_idle_exit": policy.once_idle_exit,
            "autorestart": policy.autorestart,
            "log_path": str(log_file(worker_id)),
            "pid_path": str(pid_file(worker_id)),
            "restart_count": 0,
            "restart_history": [],
            "process_identity": {},
            "crash_loop_protection": {
                "state": "clear",
                "reason": ""
            },
            "note": "initialized"
        }
        save_registry(registry)
    return load_registry()["workers"][worker_id]


def get_desired_state(worker_id: str) -> str:
    entry = ensure_worker_entry(worker_id)
    return str(entry.get("desired_state", "stopped"))


def set_desired_state(worker_id: str, desired_state: str, note: str = "") -> None:
    registry = load_registry()
    workers = registry.setdefault("workers", {})
    entry = workers.get(worker_id) or ensure_worker_entry(worker_id)
    entry["desired_state"] = desired_state
    if note:
        entry["note"] = note
    entry["last_seen_at"] = now_ts()
    workers[worker_id] = entry
    save_registry(registry)


def get_restart_history(worker_id: str) -> list[str]:
    entry = ensure_worker_entry(worker_id)
    return list(entry.get("restart_history", []))


def prune_restart_history(history: list[str]) -> list[str]:
    window_seconds = get_restart_window_seconds()
    cutoff = datetime.now() - timedelta(seconds=window_seconds)
    kept: list[str] = []
    for item in history:
        dt = parse_ts(item)
        if dt and dt >= cutoff:
            kept.append(item)
    return kept


def mark_crash_loop_state(worker_id: str, state: str, reason: str) -> None:
    registry = load_registry()
    workers = registry.setdefault("workers", {})
    entry = workers.get(worker_id) or ensure_worker_entry(worker_id)
    entry["crash_loop_protection"] = {
        "state": state,
        "reason": reason,
    }
    entry["last_seen_at"] = now_ts()
    workers[worker_id] = entry
    save_registry(registry)


def append_restart_history(worker_id: str) -> None:
    registry = load_registry()
    workers = registry.setdefault("workers", {})
    entry = workers.get(worker_id) or ensure_worker_entry(worker_id)
    history = prune_restart_history(list(entry.get("restart_history", [])))
    history.append(now_ts())
    entry["restart_history"] = history
    entry["restart_count"] = int(entry.get("restart_count", 0)) + 1
    workers[worker_id] = entry
    save_registry(registry)


def can_autorestart(worker_id: str) -> tuple[bool, str]:
    entry = ensure_worker_entry(worker_id)
    history = prune_restart_history(list(entry.get("restart_history", [])))
    registry = load_registry()
    registry["workers"][worker_id]["restart_history"] = history
    save_registry(registry)

    count = len(history)
    max_restarts = get_max_restarts_in_window()

    if count >= max_restarts:
        reason = (
            f"restart limit exceeded: {count} restarts in "
            f"{get_restart_window_seconds()}s window"
        )
        mark_crash_loop_state(worker_id, "blocked", reason)
        return False, reason

    mark_crash_loop_state(worker_id, "clear", "")
    return True, "allowed"


def update_registry_entry(
    worker_id: str,
    process_state: str,
    pid: int | None,
    maintenance: bool,
    once_idle_exit: bool,
    autorestart: bool,
    note: str = "",
    increment_restart_count: bool = False,
    desired_state: str | None = None,
    last_stop_intent: str | None = None,
    process_identity: dict[str, Any] | None = None,
) -> None:
    registry = load_registry()
    workers = registry.setdefault("workers", {})
    current = workers.get(worker_id, {})
    restart_count = int(current.get("restart_count", 0))
    if increment_restart_count:
        restart_count += 1

    effective_desired_state = desired_state if desired_state is not None else current.get("desired_state", "stopped")
    effective_last_stop_intent = last_stop_intent if last_stop_intent is not None else current.get("last_stop_intent", "none")
    effective_process_identity = process_identity if process_identity is not None else current.get("process_identity", {})

    workers[worker_id] = {
        "worker_id": worker_id,
        "pid": pid,
        "process_state": process_state,
        "desired_state": effective_desired_state,
        "last_stop_intent": effective_last_stop_intent,
        "started_at": current.get("started_at"),
        "last_seen_at": now_ts(),
        "maintenance": maintenance,
        "once_idle_exit": once_idle_exit,
        "autorestart": autorestart,
        "log_path": str(log_file(worker_id)),
        "pid_path": str(pid_file(worker_id)),
        "restart_count": restart_count,
        "restart_history": current.get("restart_history", []),
        "process_identity": effective_process_identity,
        "crash_loop_protection": current.get("crash_loop_protection", {"state": "clear", "reason": ""}),
        "note": note,
    }

    if process_state == "running":
        workers[worker_id]["started_at"] = now_ts()

    save_registry(registry)


def update_supervisor_registry(state: str, note: str = "") -> None:
    registry = load_registry()
    registry["supervisor"] = {
        "pid": os.getpid(),
        "state": state,
        "lockfile": str(get_supervisor_lockfile()),
        "pidfile": str(get_supervisor_pidfile()),
        "poll_interval_seconds": get_poll_interval_seconds(),
        "graceful_stop_timeout_seconds": get_graceful_stop_timeout_seconds(),
        "restart_backoff_seconds": get_restart_backoff_seconds(),
        "restart_window_seconds": get_restart_window_seconds(),
        "max_restarts_in_window": get_max_restarts_in_window(),
        "last_seen_at": now_ts(),
        "note": note,
    }
    save_registry(registry)


def reset_supervisor_runtime_state() -> None:
    registry = load_registry()
    workers = registry.setdefault("workers", {})

    for worker_id in AGENT_REGISTRY.keys():
        entry = workers.get(worker_id) or ensure_worker_entry(worker_id)
        desired_state = entry.get("desired_state", "running")
        workers[worker_id] = {
            "worker_id": worker_id,
            "pid": None,
            "process_state": "stopped",
            "desired_state": desired_state,
            "last_stop_intent": "none",
            "started_at": None,
            "last_seen_at": now_ts(),
            "maintenance": entry.get("maintenance"),
            "once_idle_exit": entry.get("once_idle_exit"),
            "autorestart": entry.get("autorestart"),
            "log_path": str(log_file(worker_id)),
            "pid_path": str(pid_file(worker_id)),
            "restart_count": 0,
            "restart_history": [],
            "process_identity": {},
            "crash_loop_protection": {"state": "clear", "reason": ""},
            "note": "runtime state reset",
        }
        clear_pid(worker_id)

    save_registry(registry)


def build_worker_command(
    worker_id: str,
    maintenance: bool,
    once_idle_exit: bool,
    reset_demo: bool,
) -> list[str]:
    cmd = [python_executable(), str(WORKER_ENTRYPOINT), "--worker-id", worker_id]
    if maintenance:
        cmd.append("--maintenance")
    if once_idle_exit:
        cmd.append("--once-idle-exit")
    if reset_demo:
        cmd.append("--reset-demo")
    return cmd


def start_worker(
    worker_id: str,
    maintenance: bool | None = None,
    once_idle_exit: bool | None = None,
    reset_demo: bool = False,
    force: bool = False,
    desired_state: str = "running",
    note: str = "started by supervisor",
) -> None:
    policy = get_worker_policy(worker_id)
    if not policy.enabled:
        raise SystemExit(f"Worker '{worker_id}' is disabled in supervisor policy")

    current_pid = read_pid(worker_id)
    if current_pid and matches_expected_identity(worker_id, current_pid):
        if not force:
            raise SystemExit(f"Worker '{worker_id}' is already running with PID {current_pid}")
        stop_worker(worker_id, intent="manual", preserve_desired_state=True)

    maintenance_final = policy.maintenance if maintenance is None else maintenance
    once_idle_exit_final = policy.once_idle_exit if once_idle_exit is None else once_idle_exit

    lf = open(log_file(worker_id), "a", encoding="utf-8")
    worker_token = secrets.token_hex(16)
    env = os.environ.copy()
    env["OCP_WORKER_ID"] = worker_id
    env["OCP_SUPERVISOR_TOKEN"] = worker_token

    cmd = build_worker_command(
        worker_id=worker_id,
        maintenance=maintenance_final,
        once_idle_exit=once_idle_exit_final,
        reset_demo=reset_demo,
    )
    proc = subprocess.Popen(
        cmd,
        cwd=str(BASE_DIR),
        stdout=lf,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env=env,
    )

    write_pid(worker_id, proc.pid)
    time.sleep(0.2)
    identity = current_process_identity(proc.pid)
    identity["supervisor_token"] = worker_token

    update_registry_entry(
        worker_id=worker_id,
        process_state="running",
        pid=proc.pid,
        maintenance=maintenance_final,
        once_idle_exit=once_idle_exit_final,
        autorestart=policy.autorestart,
        note=note,
        desired_state=desired_state,
        last_stop_intent="none",
        process_identity=identity,
    )
    print(f"started {worker_id} pid={proc.pid}")


def stop_worker(
    worker_id: str,
    timeout_seconds: int | None = None,
    intent: str = "manual",
    preserve_desired_state: bool = False,
) -> None:
    pid = read_pid(worker_id)
    policy = get_worker_policy(worker_id)
    timeout = get_graceful_stop_timeout_seconds() if timeout_seconds is None else timeout_seconds
    desired_state = get_desired_state(worker_id) if preserve_desired_state else "stopped"

    if not pid or not matches_expected_identity(worker_id, pid):
        clear_pid(worker_id)
        update_registry_entry(
            worker_id=worker_id,
            process_state="stopped",
            pid=None,
            maintenance=policy.maintenance,
            once_idle_exit=policy.once_idle_exit,
            autorestart=policy.autorestart,
            note="worker already not running",
            desired_state=desired_state,
            last_stop_intent=intent,
            process_identity={},
        )
        print(f"stopped {worker_id} pid=None")
        return

    os.killpg(pid, signal.SIGTERM)

    deadline = time.time() + timeout
    while time.time() < deadline:
        if not matches_expected_identity(worker_id, pid):
            break
        time.sleep(0.2)

    if matches_expected_identity(worker_id, pid):
        os.killpg(pid, signal.SIGKILL)

    hard_deadline = time.time() + 5
    while time.time() < hard_deadline:
        if not matches_expected_identity(worker_id, pid):
            break
        time.sleep(0.2)

    clear_pid(worker_id)
    update_registry_entry(
        worker_id=worker_id,
        process_state="stopped",
        pid=None,
        maintenance=policy.maintenance,
        once_idle_exit=policy.once_idle_exit,
        autorestart=policy.autorestart,
        note="stopped by supervisor",
        desired_state=desired_state,
        last_stop_intent=intent,
        process_identity={},
    )
    print(f"stopped {worker_id} pid={pid}")


def restart_worker(
    worker_id: str,
    maintenance: bool | None = None,
    once_idle_exit: bool | None = None,
    reset_demo: bool = False,
    autorestart_triggered: bool = False,
) -> None:
    policy = get_worker_policy(worker_id)
    current_pid = read_pid(worker_id)
    was_alive = current_pid is not None and matches_expected_identity(worker_id, current_pid)
    if was_alive:
        stop_worker(worker_id, intent="manual", preserve_desired_state=True)

    if autorestart_triggered:
        time.sleep(get_restart_backoff_seconds())

    start_worker(
        worker_id=worker_id,
        maintenance=maintenance,
        once_idle_exit=once_idle_exit,
        reset_demo=reset_demo,
        force=True,
        desired_state="running",
        note="auto-restarted by supervisor loop" if autorestart_triggered else "restarted by supervisor command",
    )

    append_restart_history(worker_id)

    registry = load_registry()
    entry = registry["workers"].get(worker_id, {})
    entry["autorestart"] = policy.autorestart
    entry["desired_state"] = "running"
    entry["last_stop_intent"] = "crash" if autorestart_triggered else "manual"
    entry["note"] = "auto-restarted by supervisor loop" if autorestart_triggered else "restarted by supervisor command"
    registry["workers"][worker_id] = entry
    save_registry(registry)
    print(f"restarted {worker_id}")


def status_workers() -> None:
    policy = load_supervisor_policy()
    registry = load_registry()
    workers = sorted(policy.get("workers", {}).keys())

    print("# SUPERVISOR")
    print(f"policy_source   : {SUPERVISOR_POLICY_PATH}")
    print(f"policy_version  : {policy.get('supervisor_version')}")
    print(f"registry_path   : {REGISTRY_PATH}")
    print(f"lockfile        : {get_supervisor_lockfile()}")
    print(f"pidfile         : {get_supervisor_pidfile()}")
    print()

    print("# WORKERS")
    for worker_id in workers:
        pid = read_pid(worker_id)
        alive = matches_expected_identity(worker_id, pid) if pid else False
        entry = registry.get("workers", {}).get(worker_id, {})
        process_state = "running" if alive else entry.get("process_state", "stopped")
        clp = entry.get("crash_loop_protection", {})
        print(
            f"- worker_id={worker_id} | "
            f"pid={pid} | "
            f"alive={alive} | "
            f"process_state={process_state} | "
            f"desired_state={entry.get('desired_state', 'stopped')} | "
            f"last_stop_intent={entry.get('last_stop_intent', 'none')} | "
            f"restart_count={entry.get('restart_count', 0)} | "
            f"crash_loop_state={clp.get('state', 'clear')} | "
            f"log={log_file(worker_id)}"
        )


def reconcile_worker(worker_id: str, cfg: dict[str, Any]) -> None:
    pid = read_pid(worker_id)
    alive = matches_expected_identity(worker_id, pid) if pid else False
    policy = get_worker_policy(worker_id)
    entry = ensure_worker_entry(worker_id)
    desired_state = str(entry.get("desired_state", "running" if policy.enabled else "stopped"))
    last_stop_intent = str(entry.get("last_stop_intent", "none"))

    if alive:
        update_registry_entry(
            worker_id=worker_id,
            process_state="running",
            pid=pid,
            maintenance=bool(cfg.get("maintenance", False)),
            once_idle_exit=bool(cfg.get("once_idle_exit", False)),
            autorestart=bool(cfg.get("autorestart", False)),
            note="healthy",
            desired_state=desired_state,
            last_stop_intent=last_stop_intent,
        )
        print(f"healthy {worker_id} pid={pid}")
        return

    clear_pid(worker_id)

    if desired_state == "stopped":
        update_registry_entry(
            worker_id=worker_id,
            process_state="stopped",
            pid=None,
            maintenance=bool(cfg.get("maintenance", False)),
            once_idle_exit=bool(cfg.get("once_idle_exit", False)),
            autorestart=bool(cfg.get("autorestart", False)),
            note="intentionally stopped; restart suppressed",
            desired_state="stopped",
            last_stop_intent=last_stop_intent,
            process_identity={},
        )
        print(f"stopped-intent {worker_id}")
        return

    update_registry_entry(
        worker_id=worker_id,
        process_state="crashed",
        pid=None,
        maintenance=bool(cfg.get("maintenance", False)),
        once_idle_exit=bool(cfg.get("once_idle_exit", False)),
        autorestart=bool(cfg.get("autorestart", False)),
        note="process identity missing or process not alive",
        desired_state=desired_state,
        last_stop_intent="crash",
        process_identity={},
    )
    print(f"crashed {worker_id}")

    if bool(cfg.get("autorestart", False)) and bool(cfg.get("enabled", False)) and desired_state == "running":
        allowed, reason = can_autorestart(worker_id)
        if not allowed:
            update_registry_entry(
                worker_id=worker_id,
                process_state="crash_loop_blocked",
                pid=None,
                maintenance=bool(cfg.get("maintenance", False)),
                once_idle_exit=bool(cfg.get("once_idle_exit", False)),
                autorestart=bool(cfg.get("autorestart", False)),
                note=reason,
                desired_state="running",
                last_stop_intent="crash",
                process_identity={},
            )
            print(f"crash-loop-blocked {worker_id} reason={reason}")
            return

        restart_worker(
            worker_id=worker_id,
            maintenance=bool(cfg.get("maintenance", False)),
            once_idle_exit=bool(cfg.get("once_idle_exit", False)),
            reset_demo=False,
            autorestart_triggered=True,
        )


def monitor_once() -> None:
    policy = load_supervisor_policy()
    for worker_id, cfg in policy.get("workers", {}).items():
        reconcile_worker(worker_id, cfg)


def start_all(reset_demo: bool = False) -> None:
    if reset_demo:
        reset_supervisor_runtime_state()

    policy = load_supervisor_policy()
    first = True
    for worker_id, cfg in policy.get("workers", {}).items():
        if not bool(cfg.get("enabled", False)):
            continue
        start_worker(
            worker_id=worker_id,
            maintenance=bool(cfg.get("maintenance", False)),
            once_idle_exit=bool(cfg.get("once_idle_exit", False)),
            reset_demo=reset_demo and first,
            force=False,
            desired_state="running",
            note="started by supervisor",
        )
        first = False


def stop_all() -> None:
    policy = load_supervisor_policy()
    for worker_id, cfg in policy.get("workers", {}).items():
        if not bool(cfg.get("enabled", False)):
            continue
        stop_worker(worker_id, intent="manual", preserve_desired_state=False)


def read_supervisor_pid() -> int | None:
    path = get_supervisor_pidfile()
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def write_supervisor_pid(pid: int) -> None:
    get_supervisor_pidfile().write_text(str(pid), encoding="utf-8")


def clear_supervisor_pid() -> None:
    path = get_supervisor_pidfile()
    if path.exists():
        path.unlink()


def acquire_supervisor_lock() -> None:
    lockfile = get_supervisor_lockfile()
    existing_pid = read_supervisor_pid()
    if lockfile.exists() and is_pid_alive(existing_pid):
        raise SystemExit(f"Supervisor loop already running with PID {existing_pid}")
    lockfile.write_text(f"{os.getpid()}\n", encoding="utf-8")
    write_supervisor_pid(os.getpid())


def release_supervisor_lock() -> None:
    lockfile = get_supervisor_lockfile()
    if lockfile.exists():
        lockfile.unlink()
    clear_supervisor_pid()


def monitor_loop() -> None:
    acquire_supervisor_lock()
    update_supervisor_registry(state="running", note="monitor loop started")

    stop_requested = {"value": False}

    def _handle_signal(signum: int, frame: object) -> None:
        stop_requested["value"] = True
        update_supervisor_registry(state="stopping", note=f"received signal {signum}")

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    try:
        while not stop_requested["value"]:
            monitor_once()
            update_supervisor_registry(state="running", note="monitor loop heartbeat")
            time.sleep(get_poll_interval_seconds())
    finally:
        update_supervisor_registry(state="stopped", note="monitor loop exited")
        release_supervisor_lock()


def stop_supervisor_loop() -> None:
    pid = read_supervisor_pid()
    if not is_pid_alive(pid):
        release_supervisor_lock()
        print("supervisor loop not running")
        return

    assert pid is not None
    os.kill(pid, signal.SIGTERM)

    deadline = time.time() + get_graceful_stop_timeout_seconds()
    while time.time() < deadline:
        if not is_pid_alive(pid):
            break
        time.sleep(0.2)

    if is_pid_alive(pid):
        os.kill(pid, signal.SIGKILL)

    release_supervisor_lock()
    update_supervisor_registry(state="stopped", note="supervisor loop stopped by command")
    print(f"stopped supervisor loop pid={pid}")


def status_supervisor_loop() -> None:
    pid = read_supervisor_pid()
    alive = is_pid_alive(pid)
    print("# SUPERVISOR LOOP")
    print(f"pid                    : {pid}")
    print(f"alive                  : {alive}")
    print(f"lockfile               : {get_supervisor_lockfile()}")
    print(f"pidfile                : {get_supervisor_pidfile()}")
    print(f"poll_seconds           : {get_poll_interval_seconds()}")
    print(f"restart_backoff_seconds: {get_restart_backoff_seconds()}")
    print(f"restart_window_seconds : {get_restart_window_seconds()}")
    print(f"max_restarts_in_window : {get_max_restarts_in_window()}")


def parse_args() -> argparse.Namespace:
    worker_choices = sorted(AGENT_REGISTRY.keys())

    parser = argparse.ArgumentParser(description="Phase G worker supervisor")
    sub = parser.add_subparsers(dest="command", required=True)

    p_start = sub.add_parser("start-worker")
    p_start.add_argument("--worker-id", required=True, choices=worker_choices)
    p_start.add_argument("--maintenance", action="store_true")
    p_start.add_argument("--once-idle-exit", action="store_true")
    p_start.add_argument("--reset-demo", action="store_true")
    p_start.add_argument("--force", action="store_true")

    p_stop = sub.add_parser("stop-worker")
    p_stop.add_argument("--worker-id", required=True, choices=worker_choices)

    p_restart = sub.add_parser("restart-worker")
    p_restart.add_argument("--worker-id", required=True, choices=worker_choices)
    p_restart.add_argument("--maintenance", action="store_true")
    p_restart.add_argument("--once-idle-exit", action="store_true")
    p_restart.add_argument("--reset-demo", action="store_true")

    p_desired = sub.add_parser("set-desired-state")
    p_desired.add_argument("--worker-id", required=True, choices=worker_choices)
    p_desired.add_argument("--state", required=True, choices=["running", "stopped"])

    sub.add_parser("status-workers")
    sub.add_parser("monitor-once")

    p_start_all = sub.add_parser("start-all")
    p_start_all.add_argument("--reset-demo", action="store_true")

    sub.add_parser("stop-all")
    sub.add_parser("monitor-loop")
    sub.add_parser("stop-monitor-loop")
    sub.add_parser("status-monitor-loop")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.command == "start-worker":
        maintenance = True if args.maintenance else None
        once_idle_exit = True if args.once_idle_exit else None
        start_worker(
            worker_id=args.worker_id,
            maintenance=maintenance,
            once_idle_exit=once_idle_exit,
            reset_demo=args.reset_demo,
            force=args.force,
            desired_state="running",
            note="started by supervisor",
        )
        return

    if args.command == "stop-worker":
        stop_worker(worker_id=args.worker_id, intent="manual", preserve_desired_state=False)
        return

    if args.command == "restart-worker":
        maintenance = True if args.maintenance else None
        once_idle_exit = True if args.once_idle_exit else None
        restart_worker(
            worker_id=args.worker_id,
            maintenance=maintenance,
            once_idle_exit=once_idle_exit,
            reset_demo=args.reset_demo,
            autorestart_triggered=False,
        )
        return

    if args.command == "set-desired-state":
        set_desired_state(args.worker_id, args.state, note=f"desired_state set to {args.state}")
        print(f"desired_state updated {args.worker_id} -> {args.state}")
        return

    if args.command == "status-workers":
        status_workers()
        return

    if args.command == "monitor-once":
        monitor_once()
        return

    if args.command == "start-all":
        start_all(reset_demo=args.reset_demo)
        return

    if args.command == "stop-all":
        stop_all()
        return

    if args.command == "monitor-loop":
        monitor_loop()
        return

    if args.command == "stop-monitor-loop":
        stop_supervisor_loop()
        return

    if args.command == "status-monitor-loop":
        status_supervisor_loop()
        return


if __name__ == "__main__":
    main()
