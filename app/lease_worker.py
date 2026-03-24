from __future__ import annotations

import argparse
import signal
import threading

from . import db


STOP_EVENT = threading.Event()


def _handle_signal(signum, frame) -> None:
    STOP_EVENT.set()


def main() -> None:
    parser = argparse.ArgumentParser(description="Lease worker")
    parser.add_argument("--worker-id", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--ttl", type=int, default=10)
    parser.add_argument("--interval", type=int, default=2)
    args = parser.parse_args()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    db.init_db()
    lease_id = db.acquire_worker_lease(
        worker_id=args.worker_id,
        task_id=args.task_id,
        ttl_seconds=args.ttl,
        details={"interval": args.interval},
    )
    print(f"LEASE_ACQUIRED lease_id={lease_id} task_id={args.task_id}")

    while not STOP_EVENT.is_set():
        db.renew_worker_lease(
            task_id=args.task_id,
            ttl_seconds=args.ttl,
            details={"interval": args.interval, "renewed": True},
        )
        print(f"LEASE_RENEWED task_id={args.task_id}")
        STOP_EVENT.wait(args.interval)

    db.release_worker_lease(args.task_id, status="released")
    print(f"LEASE_RELEASED task_id={args.task_id}")


if __name__ == "__main__":
    main()
