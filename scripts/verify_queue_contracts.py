#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_DIR = PROJECT_ROOT / "artifacts" / "test_reports"


def ensure_project_root_on_syspath() -> None:
    root = str(PROJECT_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


ensure_project_root_on_syspath()

from app.queue_contracts import QueueFailureCode, QueueStatus  # noqa: E402
from app.queue_runtime import (  # noqa: E402
    claim_queue_item,
    count_dead_letters,
    dead_letter_queue_item,
    ensure_queue_schema,
    get_queue_item,
    insert_queue_item,
    transition_queue_item,
)


def main() -> int:
    os.chdir(PROJECT_ROOT)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "queue_contracts.sqlite3"
        ensure_queue_schema(db_path)

        seed = {
            "queue_item_id": "q-100",
            "task_id": "t-100",
            "task_type": "backend.test",
            "status": QueueStatus.QUEUED.value,
        }

        inserted = insert_queue_item(db_path, seed).to_dict()
        claimed = claim_queue_item(db_path, "q-100", "worker-a").to_dict()
        duplicate_claim = claim_queue_item(db_path, "q-100", "worker-a").to_dict()
        invalid_transition = transition_queue_item(db_path, "q-100", QueueStatus.COMPLETED.value).to_dict()
        to_running = transition_queue_item(db_path, "q-100", QueueStatus.RUNNING.value).to_dict()
        to_failed = transition_queue_item(db_path, "q-100", QueueStatus.FAILED.value).to_dict()
        dead_lettered = dead_letter_queue_item(db_path, "q-100", "EXECUTION_REJECTED", "terminal failure").to_dict()
        final_item = get_queue_item(db_path, "q-100")
        dead_letter_count = count_dead_letters(db_path)

        malformed_insert = insert_queue_item(
            db_path,
            {"task_id": "broken", "task_type": "backend.test", "status": QueueStatus.QUEUED.value},
        ).to_dict()

        summary = {
            "phase": "J.5",
            "successful": (
                inserted["ok"] is True
                and claimed["ok"] is True
                and duplicate_claim["code"] == QueueFailureCode.DUPLICATE_CLAIM.value
                and invalid_transition["code"] == QueueFailureCode.INVALID_STATE_TRANSITION.value
                and to_running["ok"] is True
                and to_failed["ok"] is True
                and dead_lettered["ok"] is True
                and final_item is not None
                and final_item["status"] == QueueStatus.DEAD_LETTERED.value
                and dead_letter_count == 1
                and malformed_insert["code"] == QueueFailureCode.MISSING_QUEUE_ITEM_ID.value
            ),
            "checks": {
                "inserted": inserted,
                "claimed": claimed,
                "duplicate_claim": duplicate_claim,
                "invalid_transition": invalid_transition,
                "to_running": to_running,
                "to_failed": to_failed,
                "dead_lettered": dead_lettered,
                "final_item": final_item,
                "dead_letter_count": dead_letter_count,
                "malformed_insert": malformed_insert,
            },
        }

    json_path = REPORT_DIR / "latest_queue_contracts.json"
    txt_path = REPORT_DIR / "latest_queue_contracts.txt"

    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "phase=J.5",
        f"successful={summary['successful']}",
        f"duplicate_claim_code={summary['checks']['duplicate_claim']['code']}",
        f"invalid_transition_code={summary['checks']['invalid_transition']['code']}",
        f"dead_letter_count={summary['checks']['dead_letter_count']}",
        f"final_status={summary['checks']['final_item']['status']}",
        f"malformed_insert_code={summary['checks']['malformed_insert']['code']}",
    ]
    txt_path.write_text("\n".join(lines), encoding="utf-8")

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if summary["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
