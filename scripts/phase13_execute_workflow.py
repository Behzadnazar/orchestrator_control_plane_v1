from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List


def run_cmd(project_root: Path, cmd: List[str], stdin_text: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(project_root), input=stdin_text, capture_output=True, text=True, check=False)


def load_state(project_root: Path) -> Dict[str, Any]:
    path = project_root / "artifacts" / "state" / "phase13" / "current_workflow_run.json"
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent

    seed = run_cmd(project_root, ["python3", "scripts/seed_phase13_workflow.py"])
    if seed.returncode != 0:
        print(seed.stdout)
        print(seed.stderr)
        return seed.returncode

    state = load_state(project_root)
    rounds: List[Dict[str, Any]] = []

    for index, item in enumerate(state["tasks"], start=1):
        task_type = str(item["task_type"])
        payload = json.dumps(item["payload"], ensure_ascii=False)
        res = run_cmd(project_root, ["python3", "scripts/phase13_operational_runner.py", task_type], stdin_text=payload)
        rounds.append({
            "round": index,
            "task_type": task_type,
            "returncode": res.returncode,
            "stdout": res.stdout,
            "stderr": res.stderr
        })
        if res.returncode != 0:
            print(json.dumps({"ok": False, "failed_task_type": task_type, "rounds": rounds}, ensure_ascii=False, indent=2))
            return res.returncode

    print(json.dumps({"ok": True, "rounds": rounds}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
