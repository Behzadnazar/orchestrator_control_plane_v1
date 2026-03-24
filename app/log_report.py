from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def read_lines(path: Path, limit: int | None = None) -> list[dict]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    if limit is not None:
        lines = lines[-limit:]
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            out.append({"raw": line, "level": "UNKNOWN", "message": "unparseable"})
    return out


def cmd_tail(args: argparse.Namespace) -> None:
    rows = read_lines(Path(args.file), limit=args.lines)
    for row in rows:
        print(json.dumps(row, ensure_ascii=False))

def cmd_summary(args: argparse.Namespace) -> None:
    rows = read_lines(Path(args.file), limit=args.lines)
    level_counts = Counter(r.get("level", "UNKNOWN") for r in rows)
    message_counts = Counter(r.get("message", "UNKNOWN") for r in rows)

    report = {
        "rows": len(rows),
        "level_counts": dict(level_counts),
        "top_messages": dict(message_counts.most_common(10)),
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Log tools")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("tail")
    s.add_argument("--file", default="logs/orchestrator.jsonl")
    s.add_argument("--lines", type=int, default=20)
    s.set_defaults(func=cmd_tail)

    s = sub.add_parser("summary")
    s.add_argument("--file", default="logs/orchestrator.jsonl")
    s.add_argument("--lines", type=int, default=200)
    s.set_defaults(func=cmd_summary)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
