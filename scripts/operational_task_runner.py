from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.governance import Governance, GovernanceError  # noqa: E402
from app.governance_audit import GovernanceAudit  # noqa: E402


UTC = timezone.utc


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def load_payload() -> Dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("stdin payload must be a JSON object")
    return data


def governance() -> Governance:
    return Governance(PROJECT_ROOT)


def audit() -> GovernanceAudit:
    return GovernanceAudit(PROJECT_ROOT)


def safe_project_path(raw: str) -> Path:
    if not raw or not isinstance(raw, str):
        raise ValueError("path is required and must be a string")
    candidate = Path(raw)
    resolved = candidate.resolve() if candidate.is_absolute() else (PROJECT_ROOT / candidate).resolve()
    try:
        resolved.relative_to(PROJECT_ROOT)
    except ValueError as exc:
        raise ValueError(f"path escapes project root: {raw}") from exc
    return resolved


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_text_file(path: Path, content: str) -> Dict[str, Any]:
    ensure_parent(path)
    path.write_text(content, encoding="utf-8")
    return {
        "ok": True,
        "action": "write_text_file",
        "path": str(path),
        "bytes_written": len(content.encode("utf-8")),
        "ts": utc_now_iso(),
    }


def write_json_file(path: Path, value: Any) -> Dict[str, Any]:
    ensure_parent(path)
    with path.open("w", encoding="utf-8") as f:
        json.dump(value, f, ensure_ascii=False, indent=2, sort_keys=True)
    return {
        "ok": True,
        "action": "write_json_file",
        "path": str(path),
        "ts": utc_now_iso(),
    }


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_text(read_text(path))


def _read_paths(raw: Any) -> List[Path]:
    if not isinstance(raw, list):
        raise ValueError("input_paths must be a list")
    out: List[Path] = []
    for item in raw:
        if not isinstance(item, str):
            raise ValueError("every input path must be a string")
        out.append(safe_project_path(item))
    return out


def handle_research_collect_notes(payload: Dict[str, Any]) -> Dict[str, Any]:
    topic = str(payload.get("topic", "")).strip()
    notes = payload.get("notes", "")
    output_path = safe_project_path(str(payload.get("notes_output_path", "")))
    if not topic:
        raise ValueError("topic is required")
    if not isinstance(notes, str):
        raise ValueError("notes must be a string")

    md = [
        "# Research Notes",
        "",
        f"- topic: {topic}",
        f"- generated_at: {utc_now_iso()}",
        "",
        "## Findings",
        "",
        notes.strip() or "No findings provided.",
        "",
    ]
    return write_text_file(output_path, "\n".join(md))


def handle_frontend_write_component(payload: Dict[str, Any]) -> Dict[str, Any]:
    component_name = str(payload.get("component_name", "")).strip()
    source_notes_path = safe_project_path(str(payload.get("source_notes_path", "")))
    component_path = safe_project_path(str(payload.get("component_path", "")))
    if not component_name:
        raise ValueError("component_name is required")
    if not source_notes_path.exists():
        raise ValueError(f"source_notes_path does not exist: {source_notes_path}")

    notes_text = read_text(source_notes_path)
    content = payload.get("content")
    if not isinstance(content, str) or not content.strip():
        preview = notes_text[:500].replace("`", "")
        content = (
            f"export default function {component_name}() {{\n"
            f"  return (\n"
            f"    <section>\n"
            f"      <h1>{component_name}</h1>\n"
            f"      <pre>{preview}</pre>\n"
            f"    </section>\n"
            f"  );\n"
            f"}}\n"
        )
    return write_text_file(component_path, content)


def handle_backend_write_file(payload: Dict[str, Any]) -> Dict[str, Any]:
    target = safe_project_path(str(payload.get("path", "")))
    content = payload.get("content", "")
    if not isinstance(content, str):
        raise ValueError("content must be a string")
    return write_text_file(target, content)


def handle_memory_write_json(payload: Dict[str, Any]) -> Dict[str, Any]:
    target = safe_project_path(str(payload.get("path", "")))
    value = payload.get("json_value")
    return write_json_file(target, value)


def handle_memory_read_json(payload: Dict[str, Any]) -> Dict[str, Any]:
    target = safe_project_path(str(payload.get("path", "")))
    if not target.exists():
        raise ValueError(f"json file does not exist: {target}")
    return {
        "ok": True,
        "action": "read_json_file",
        "path": str(target),
        "value": read_json(target),
        "ts": utc_now_iso(),
    }


def handle_debugger_analyze_failure(payload: Dict[str, Any]) -> Dict[str, Any]:
    incident_title = str(payload.get("incident_title", "")).strip()
    error_source_path = safe_project_path(str(payload.get("error_source_path", "")))
    rca_output_path = safe_project_path(str(payload.get("rca_output_path", "")))
    if not incident_title:
        raise ValueError("incident_title is required")
    if not error_source_path.exists():
        raise ValueError(f"error_source_path does not exist: {error_source_path}")

    error_text = read_text(error_source_path)
    md = [
        "# Debugger RCA",
        "",
        f"- incident_title: {incident_title}",
        f"- generated_at: {utc_now_iso()}",
        f"- source: {error_source_path.relative_to(PROJECT_ROOT).as_posix()}",
        "",
        "## Observed Error",
        "",
        "```",
        error_text.strip(),
        "```",
        "",
        "## Root Cause",
        "",
        "Synthetic failure indicates missing dependency or handler contract mismatch in upstream backend stage.",
        "",
        "## Next Action",
        "",
        "Normalize payload contract and verify generated bundle path before release packaging.",
        "",
    ]
    return write_text_file(rca_output_path, "\n".join(md))


def handle_devops_build_release_bundle(payload: Dict[str, Any]) -> Dict[str, Any]:
    release_name = str(payload.get("release_name", "")).strip()
    notes_path = safe_project_path(str(payload.get("notes_path", "")))
    component_path = safe_project_path(str(payload.get("component_path", "")))
    backend_bundle_path = safe_project_path(str(payload.get("backend_bundle_path", "")))
    rca_path = safe_project_path(str(payload.get("rca_path", "")))
    manifest_output_path = safe_project_path(str(payload.get("manifest_output_path", "")))
    bundle_output_path = safe_project_path(str(payload.get("bundle_output_path", "")))

    if not release_name:
        raise ValueError("release_name is required")

    inputs = [notes_path, component_path, backend_bundle_path, rca_path]
    for path in inputs:
        if not path.exists():
            raise ValueError(f"required input does not exist: {path}")

    manifest = {
        "release_name": release_name,
        "generated_at": utc_now_iso(),
        "inputs": [
            {"path": str(p), "sha256": sha256_file(p)}
            for p in inputs
        ],
        "status": "ready-for-architecture-review"
    }
    write_json_file(manifest_output_path, manifest)

    bundle_text = [
        f"release_name={release_name}",
        f"generated_at={manifest['generated_at']}",
        f"notes={notes_path.relative_to(PROJECT_ROOT).as_posix()}",
        f"component={component_path.relative_to(PROJECT_ROOT).as_posix()}",
        f"backend_bundle={backend_bundle_path.relative_to(PROJECT_ROOT).as_posix()}",
        f"rca={rca_path.relative_to(PROJECT_ROOT).as_posix()}",
    ]
    write_text_file(bundle_output_path, "\n".join(bundle_text) + "\n")

    return {
        "ok": True,
        "action": "build_release_bundle",
        "manifest_output_path": str(manifest_output_path),
        "bundle_output_path": str(bundle_output_path),
        "ts": utc_now_iso(),
    }


def handle_architect_review_constraints(payload: Dict[str, Any]) -> Dict[str, Any]:
    review_title = str(payload.get("review_title", "")).strip()
    notes_path = safe_project_path(str(payload.get("notes_path", "")))
    component_path = safe_project_path(str(payload.get("component_path", "")))
    backend_bundle_path = safe_project_path(str(payload.get("backend_bundle_path", "")))
    release_manifest_path = safe_project_path(str(payload.get("release_manifest_path", "")))
    rca_path_raw = str(payload.get("rca_path", "")).strip()
    review_output_path = safe_project_path(str(payload.get("review_output_path", "")))

    if not review_title:
        raise ValueError("review_title is required")

    required = [notes_path, component_path, backend_bundle_path, release_manifest_path]
    for path in required:
        if not path.exists():
            raise ValueError(f"required input does not exist: {path}")

    summary = {
        "review_title": review_title,
        "generated_at": utc_now_iso(),
        "decision": "approved-with-constraints",
        "constraints": [
            "Keep research artifact immutable after frontend generation.",
            "Freeze release manifest before deployment execution.",
            "Route future deployment only through governed DevOps task."
        ],
        "evidence": {
            "notes_path": str(notes_path),
            "component_path": str(component_path),
            "backend_bundle_path": str(backend_bundle_path),
            "release_manifest_path": str(release_manifest_path),
            "rca_path": str(safe_project_path(rca_path_raw)) if rca_path_raw else None
        }
    }
    return write_json_file(review_output_path, summary)


def handle_backend_fail_test(payload: Dict[str, Any]) -> Dict[str, Any]:
    reason = str(payload.get("reason", "Intentional backend.fail_test execution")).strip()
    raise RuntimeError(reason)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python3 scripts/operational_task_runner.py <task_type>", file=sys.stderr)
        return 2

    task_type = sys.argv[1]
    payload = load_payload()
    gov = governance()
    gov_audit = audit()

    decision = gov.decide(task_type=task_type, payload=payload, service_path=task_type, mode="execution")
    if not decision.ok:
        gov_audit.log(
            "execution_denied_by_policy_runner",
            {
                "task_type": task_type,
                "owner_agent": decision.owner_agent,
                "reasons": decision.reasons,
                "payload_preview_keys": sorted(payload.keys()),
            },
        )
        print(json.dumps({
            "ok": False,
            "task_type": task_type,
            "error": "governance denied execution",
            "reasons": decision.reasons,
            "ts": utc_now_iso(),
        }, ensure_ascii=False))
        return 3

    gov_audit.log(
        "execution_allowed_by_policy_runner",
        {
            "task_type": task_type,
            "owner_agent": decision.owner_agent,
            "matched_paths": decision.matched_paths,
            "payload_preview_keys": sorted(payload.keys()),
        },
    )

    handlers = {
        "research.collect_notes": handle_research_collect_notes,
        "frontend.write_component": handle_frontend_write_component,
        "backend.write_file": handle_backend_write_file,
        "memory.write_json": handle_memory_write_json,
        "memory.read_json": handle_memory_read_json,
        "debugger.analyze_failure": handle_debugger_analyze_failure,
        "devops.build_release_bundle": handle_devops_build_release_bundle,
        "architect.review_constraints": handle_architect_review_constraints,
        "backend.fail_test": handle_backend_fail_test,
    }

    if task_type not in handlers:
        gov_audit.log(
            "execution_denied_unknown_task_type",
            {"task_type": task_type},
        )
        print(json.dumps({
            "ok": False,
            "task_type": task_type,
            "error": f"unknown task_type: {task_type}",
            "ts": utc_now_iso(),
        }, ensure_ascii=False))
        return 2

    try:
        result = handlers[task_type](payload)
        gov_audit.log(
            "execution_handler_succeeded",
            {
                "task_type": task_type,
                "result_action": result.get("action"),
                "result_path": result.get("path") or result.get("manifest_output_path") or result.get("bundle_output_path"),
            },
        )
        print(json.dumps({
            "ok": True,
            "task_type": task_type,
            "result": result,
            "ts": utc_now_iso(),
        }, ensure_ascii=False))
        return 0
    except (GovernanceError, ValueError, RuntimeError) as exc:
        gov_audit.log(
            "execution_handler_failed",
            {
                "task_type": task_type,
                "error": f"{type(exc).__name__}: {exc}",
            },
        )
        print(json.dumps({
            "ok": False,
            "task_type": task_type,
            "error": f"{type(exc).__name__}: {exc}",
            "ts": utc_now_iso(),
        }, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
