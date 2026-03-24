from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


PIDS_DIR = Path("runtime")
PIDS_DIR.mkdir(parents=True, exist_ok=True)


def _pid_file(name: str) -> Path:
    return PIDS_DIR / f"{name}.pid"


def _is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _read_pid(name: str) -> int | None:
    p = _pid_file(name)
    if not p.exists():
        return None
    try:
        return int(p.read_text(encoding="utf-8").strip())
    except Exception:
        return None


def _write_pid(name: str, pid: int) -> None:
    _pid_file(name).write_text(str(pid), encoding="utf-8")


def _remove_pid(name: str) -> None:
    p = _pid_file(name)
    if p.exists():
        p.unlink()


def _start_process(name: str, module: str) -> None:
    existing = _read_pid(name)
    if existing and _is_running(existing):
        print(f"{name.upper()}_ALREADY_RUNNING pid={existing}")
        return

    proc = subprocess.Popen(
        [sys.executable, "-m", module],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    _write_pid(name, proc.pid)
    print(f"{name.upper()}_STARTED pid={proc.pid}")


def _stop_process(name: str) -> None:
    pid = _read_pid(name)
    if not pid:
        print(f"{name.upper()}_NOT_RUNNING")
        return

    if not _is_running(pid):
        _remove_pid(name)
        print(f"{name.upper()}_STALE_PID_REMOVED")
        return

    os.kill(pid, signal.SIGTERM)

    deadline = time.time() + 5
    while time.time() < deadline:
        if not _is_running(pid):
            _remove_pid(name)
            print(f"{name.upper()}_STOPPED")
            return
        time.sleep(0.2)

    os.kill(pid, signal.SIGKILL)
    _remove_pid(name)
    print(f"{name.upper()}_KILLED")


def cmd_start_all(_: argparse.Namespace) -> None:
    _start_process("grpc", "app.server")
    _start_process("daemon", "app.daemon")
    _start_process("http_health", "app.http_health")

def cmd_stop_all(_: argparse.Namespace) -> None:
    _stop_process("http_health")
    _stop_process("daemon")
    _stop_process("grpc")

def cmd_status(_: argparse.Namespace) -> None:
    report = {}
    for name in ("grpc", "daemon", "http_health"):
        pid = _read_pid(name)
        report[name] = {
            "pid": pid,
            "running": bool(pid and _is_running(pid)),
        }
    import json
    print(json.dumps(report, ensure_ascii=False, indent=2))

def cmd_start_profile(args: argparse.Namespace) -> None:
    profile = args.profile
    if profile == "core":
        _start_process("grpc", "app.server")
        _start_process("daemon", "app.daemon")
    elif profile == "ops":
        _start_process("http_health", "app.http_health")
    elif profile == "full":
        _start_process("grpc", "app.server")
        _start_process("daemon", "app.daemon")
        _start_process("http_health", "app.http_health")
    else:
        raise SystemExit(f"unknown profile: {profile}")

def cmd_stop_profile(args: argparse.Namespace) -> None:
    profile = args.profile
    if profile == "core":
        _stop_process("daemon")
        _stop_process("grpc")
    elif profile == "ops":
        _stop_process("http_health")
    elif profile == "full":
        _stop_process("http_health")
        _stop_process("daemon")
        _stop_process("grpc")
    else:
        raise SystemExit(f"unknown profile: {profile}")

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Unified runtime manager")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("start-all")
    s.set_defaults(func=cmd_start_all)

    s = sub.add_parser("stop-all")
    s.set_defaults(func=cmd_stop_all)

    s = sub.add_parser("status")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("start-profile")
    s.add_argument("--profile", required=True, choices=["core", "ops", "full"])
    s.set_defaults(func=cmd_start_profile)

    s = sub.add_parser("stop-profile")
    s.add_argument("--profile", required=True, choices=["core", "ops", "full"])
    s.set_defaults(func=cmd_stop_profile)

    return p

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
