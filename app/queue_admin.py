from __future__ import annotations

import argparse
import json

from . import db


def cmd_list(_: argparse.Namespace) -> None:
    db.init_db()
    print(json.dumps(db.list_queue(), ensure_ascii=False, indent=2))

def cmd_dlq(_: argparse.Namespace) -> None:
    db.init_db()
    print(json.dumps(db.list_dead_letter_queue(), ensure_ascii=False, indent=2))

def cmd_requeue(args: argparse.Namespace) -> None:
    db.init_db()
    changed = db.requeue_task(args.task_id)
    print(json.dumps({"task_id": args.task_id, "requeued": changed}, ensure_ascii=False, indent=2))

def cmd_recover_claims(args: argparse.Namespace) -> None:
    db.init_db()
    print(json.dumps(db.recover_stale_claims(args.timeout_seconds), ensure_ascii=False, indent=2))

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Queue admin tools")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("list")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("dlq")
    s.set_defaults(func=cmd_dlq)

    s = sub.add_parser("requeue")
    s.add_argument("--task-id", required=True)
    s.set_defaults(func=cmd_requeue)

    s = sub.add_parser("recover-claims")
    s.add_argument("--timeout-seconds", type=int, default=30)
    s.set_defaults(func=cmd_recover_claims)

    return p

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
