from __future__ import annotations

import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import db


def build_report() -> dict:
    db.init_db()

    db_path = Path("data/orchestrator.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    total_agents = cur.execute("SELECT COUNT(*) AS c FROM agents").fetchone()["c"]
    idle_agents = cur.execute("SELECT COUNT(*) AS c FROM agents WHERE status='Idle'").fetchone()["c"]

    total_tasks = cur.execute("SELECT COUNT(*) AS c FROM tasks").fetchone()["c"]
    completed_tasks = cur.execute("SELECT COUNT(*) AS c FROM tasks WHERE status='Completed'").fetchone()["c"]
    failed_tasks = cur.execute("SELECT COUNT(*) AS c FROM tasks WHERE status='Failed'").fetchone()["c"]
    idle_tasks = cur.execute("SELECT COUNT(*) AS c FROM tasks WHERE status='Idle'").fetchone()["c"]
    review_tasks = cur.execute("SELECT COUNT(*) AS c FROM tasks WHERE status='Review'").fetchone()["c"]

    total_events = cur.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]

    last_task = cur.execute("""
        SELECT task_id, title, status, priority, created_at, updated_at
        FROM tasks
        ORDER BY updated_at DESC
        LIMIT 1
    """).fetchone()

    report = {
        "service": "orchestrator_control_plane_v1",
        "db_exists": db_path.exists(),
        "db_path": str(db_path),
        "agents": {
            "total": total_agents,
            "idle": idle_agents,
        },
        "tasks": {
            "total": total_tasks,
            "completed": completed_tasks,
            "failed": failed_tasks,
            "idle": idle_tasks,
            "review": review_tasks,
        },
        "events": {
            "total": total_events,
        },
        "last_task": dict(last_task) if last_task else None,
        "status": "healthy" if db_path.exists() and total_agents > 0 else "unhealthy",
    }

    conn.close()
    return report


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/health", "/healthz", "/status"):
            self.send_response(404)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": False, "error": "not found"}).encode("utf-8"))
            return

        report = build_report()
        code = 200 if report["status"] == "healthy" else 503
        body = json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")

        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def main(host: str = "127.0.0.1", port: int = 8080) -> None:
    server = ThreadingHTTPServer((host, port), HealthHandler)
    print(f"HTTP_HEALTH_STARTED {host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("HTTP_HEALTH_STOPPED")


if __name__ == "__main__":
    main()
