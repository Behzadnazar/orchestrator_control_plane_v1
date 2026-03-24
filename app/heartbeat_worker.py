from __future__ import annotations

import argparse
import signal
import threading
import time

from . import db


STOP_EVENT = threading.Event()


def _handle_signal(signum, frame) -> None:
    STOP_EVENT.set()


def main() -> None:
    parser = argparse.ArgumentParser(description="Heartbeat worker")
    parser.add_argument("--worker-id", required=True)
    parser.add_argument("--worker-type", required=True)
    parser.add_argument("--status", default="running")
    parser.add_argument("--interval", type=int, default=2)
    args = parser.parse_args()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    db.init_db()

    while not STOP_EVENT.is_set():
        db.upsert_heartbeat(
            worker_id=args.worker_id,
            worker_type=args.worker_type,
            status=args.status,
            details={"interval": args.interval},
        )
        print(f"HEARTBEAT_SENT worker_id={args.worker_id}")
        STOP_EVENT.wait(args.interval)

    db.upsert_heartbeat(
        worker_id=args.worker_id,
        worker_type=args.worker_type,
        status="stopped",
        details={"interval": args.interval, "shutdown": "clean"},
    )
    print(f"HEARTBEAT_STOPPED worker_id={args.worker_id}")


if __name__ == "__main__":
    main()
