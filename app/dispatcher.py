from __future__ import annotations

import json

from . import db


class Dispatcher:
    def dispatch_task(self, task: dict) -> str:
        queue_item_id = db.enqueue_task(
            task_id=task["task_id"],
            task_type=task["task_type"],
            priority=task["priority"],
        )
        db.append_event("task", task["task_id"], "TaskEnqueued", {
            "queue_item_id": queue_item_id,
            "priority": task["priority"],
        })
        return queue_item_id

    def claim_work(self, worker_id: str, agent_type: str) -> dict | None:
        task = db.claim_next_task_for_agent(worker_id, agent_type)
        if task:
            db.append_event("task", task["task_id"], "TaskClaimed", {
                "worker_id": worker_id,
                "agent_type": agent_type,
            })
        return task

    def finalize_claim(self, task_id: str, final_status: str) -> None:
        db.complete_queue_item(task_id, final_status)
        db.append_event("task", task_id, "QueueItemFinalized", {
            "final_status": final_status,
        })

    def send_to_dlq(self, task_id: str, reason: str) -> str:
        dlq_item_id = db.move_queue_item_to_dlq(task_id, reason)
        db.append_event("task", task_id, "TaskMovedToDLQ", {
            "reason": reason,
            "dlq_item_id": dlq_item_id,
        })
        return dlq_item_id


def main() -> None:
    print(json.dumps({"ok": True, "component": "dispatcher"}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
