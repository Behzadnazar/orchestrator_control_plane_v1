from pathlib import Path
import sys
import os

def main() -> None:
    if len(sys.argv) != 2:
        print("usage: python3 scripts/write_text_file.py <target_path>")
        raise SystemExit(1)

    target = Path(sys.argv[1])
    content = sys.stdin.read()

    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")

    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, target)

    print(f"[WRITTEN] {target}")

if __name__ == "__main__":
    main()
