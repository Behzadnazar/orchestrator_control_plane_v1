from pathlib import Path
import sys
import os
import py_compile

def main() -> None:
    if len(sys.argv) != 2:
        print("usage: python3 scripts/write_python_file.py <target_path.py>")
        raise SystemExit(1)

    target = Path(sys.argv[1])
    content = sys.stdin.read()

    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")

    py_compile.compile(str(tmp), doraise=True)
    os.replace(tmp, target)

    print(f"[WRITTEN_AND_COMPILED] {target}")

if __name__ == "__main__":
    main()
