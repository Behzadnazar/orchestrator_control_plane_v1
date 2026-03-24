from __future__ import annotations
import argparse
import json

from . import db
from .config import CONFIG_DIR
from .orchestrator import Orchestrator

orch = Orchestrator()

def cmd_init_db(_: argparse.Namespace) -> None:
    db.init_db()
    print("DB initialized.")

def cmd_seed_agents(_: argparse.Namespace) -> None:
    db.init_db()
    orch.seed_agents_from_config(str(CONFIG_DIR / "agents.json"))
    print("Agents seeded.")

def cmd_list_agents(_: argparse.Namespace) -> None:
    for agent in db.list_agents():
        print(json.dumps(agent, ensure_ascii=False, indent=2))

def cmd_submit_task(args: argparse.Namespace) -> None:
    db.init_db()
    payload = json.loads(args.payload_json)
    done_criteria = json.loads(args.done_criteria_json)
    task_id = orch.submit_task(
        task_type=args.task_type,
        title=args.title,
        priority=args.priority,
        payload=payload,
        done_criteria=done_criteria,
        max_retries=args.max_retries,
    )
    print(task_id)

def cmd_list_tasks(_: argparse.Namespace) -> None:
    for task in db.list_tasks():
        print(json.dumps(task, ensure_ascii=False, indent=2))

def cmd_process_next(_: argparse.Namespace) -> None:
    db.init_db()
    print(orch.process_next_task())

def cmd_approve(args: argparse.Namespace) -> None:
    db.init_db()
    orch.approve_task(args.task_id, args.approver, args.decision, args.reason)
    print("approval recorded.")

def cmd_resume(args: argparse.Namespace) -> None:
    db.init_db()
    print(orch.resume_reviewed_task(args.task_id))

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Orchestrator / Control Plane v1")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init-db")
    s.set_defaults(func=cmd_init_db)

    s = sub.add_parser("seed-agents")
    s.set_defaults(func=cmd_seed_agents)

    s = sub.add_parser("list-agents")
    s.set_defaults(func=cmd_list_agents)

    s = sub.add_parser("submit-task")
    s.add_argument("--task-type", required=True)
    s.add_argument("--title", required=True)
    s.add_argument("--priority", default="normal", choices=["critical", "high", "normal", "low"])
    s.add_argument("--payload-json", required=True)
    s.add_argument("--done-criteria-json", required=True)
    s.add_argument("--max-retries", type=int, default=2)
    s.set_defaults(func=cmd_submit_task)

    s = sub.add_parser("list-tasks")
    s.set_defaults(func=cmd_list_tasks)

    s = sub.add_parser("process-next")
    s.set_defaults(func=cmd_process_next)

    s = sub.add_parser("approve")
    s.add_argument("--task-id", required=True)
    s.add_argument("--approver", required=True)
    s.add_argument("--decision", required=True, choices=["approve", "reject"])
    s.add_argument("--reason", default=None)
    s.set_defaults(func=cmd_approve)

    s = sub.add_parser("resume")
    s.add_argument("--task-id", required=True)
    s.set_defaults(func=cmd_resume)

    return p

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
