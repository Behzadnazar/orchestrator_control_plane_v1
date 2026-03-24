from __future__ import annotations

import argparse
import json

from . import db


def cmd_list(_: argparse.Namespace) -> None:
    db.init_db()
    print(json.dumps(db.list_queue(), ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Queue tools")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("list")
    s.set_defaults(func=cmd_list)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
