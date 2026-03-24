from __future__ import annotations

import signal
import threading
import time
from pathlib import Path

from . import db
from .config import BASE_DIR
from .logger import setup_logging
from .orchestrator import Orchestrator
from .validator import validate_config


STOP_EVENT = threading.Event()


def _handle_signal(signum, frame) -> None:
    STOP_EVENT.set()


def main() -> None:
    logger = setup_logging()
    ok, errors = validate_config(Path(BASE_DIR))
    if not ok:
        for err in errors:
            logger.error("config validation failed", extra={"module_name": "validator", "details": err})
        raise SystemExit(1)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    db.init_db()
    orch = Orchestrator()

    logger.info("daemon init ok", extra={"module_name": "daemon"})

    while not STOP_EVENT.is_set():
        task = db.next_runnable_task()
        if not task:
            logger.info("worker idle", extra={"module_name": "daemon"})
            STOP_EVENT.wait(2.0)
            continue

        logger.info(
            "worker picked task",
            extra={
                "module_name": "daemon",
                "task_id": task["task_id"],
                "details": {"title": task["title"], "priority": task["priority"], "task_type": task["task_type"]},
            },
        )

        try:
            result = orch.process_next_task()
            logger.info(
                "worker processed task",
                extra={"module_name": "daemon", "task_id": task["task_id"], "details": result},
            )
        except Exception as e:
            logger.exception(
                "worker loop crashed on task",
                extra={"module_name": "daemon", "task_id": task["task_id"], "details": str(e)},
            )
            STOP_EVENT.wait(1.0)

    logger.info("daemon shutdown clean", extra={"module_name": "daemon"})


if __name__ == "__main__":
    main()
