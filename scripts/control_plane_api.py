from __future__ import annotations

import argparse
import hmac
import json
import os
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.services.control_plane_service import ControlPlaneService


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Control Plane HTTP API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    return parser.parse_args()


def error_payload(code: str, message: str, details: dict | None = None) -> dict:
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
        }
    }


def require_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def optional_string(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string when provided")
    stripped = value.strip()
    return stripped or None


def require_int_range(value: object, field_name: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{field_name} must be between {minimum} and {maximum}")
    return value


def require_dict(value: object, field_name: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be an object")
    return value


class ControlPlaneHandler(BaseHTTPRequestHandler):
    service = ControlPlaneService()

    def _send_json(self, payload: dict, status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_error(self, status: int, code: str, message: str, details: dict | None = None) -> None:
        self._send_json(error_payload(code, message, details), status=status)

    def _read_json_body(self) -> dict:
        content_type = self.headers.get("Content-Type", "")
        if "application/json" not in content_type:
            raise ValueError("Content-Type must be application/json")

        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            raise ValueError("Request body is required")

        body = self.rfile.read(length).decode("utf-8")
        if not body.strip():
            raise ValueError("Request body is empty")

        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON body: {exc.msg}") from exc

        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")

        return data

    def _require_auth(self) -> None:
        expected = os.environ.get("CONTROL_PLANE_API_TOKEN", "").strip()
        if not expected:
            raise PermissionError("Server is missing CONTROL_PLANE_API_TOKEN")

        supplied = self.headers.get("X-API-Token", "").strip()
        if not supplied:
            raise PermissionError("Missing X-API-Token header")

        if not hmac.compare_digest(supplied, expected):
            raise PermissionError("Invalid API token")

    def _parse_limit(self, query: dict[str, list[str]]) -> int:
        raw = query.get("limit", ["50"])[0]
        try:
            value = int(raw)
        except ValueError as exc:
            raise ValueError("limit must be an integer") from exc
        if value < 1 or value > 500:
            raise ValueError("limit must be between 1 and 500")
        return value

    def _validate_enqueue_payload(self, body: dict) -> dict:
        task_type = require_string(body.get("task_type"), "task_type")
        payload = require_dict(body.get("payload"), "payload")
        priority = require_int_range(body.get("priority", 100), "priority", 1, 1000)
        max_attempts = require_int_range(body.get("max_attempts", 3), "max_attempts", 1, 20)

        return {
            "task_type": task_type,
            "payload": payload,
            "priority": priority,
            "max_attempts": max_attempts,
            "correlation_id": optional_string(body.get("correlation_id"), "correlation_id"),
            "workflow_id": optional_string(body.get("workflow_id"), "workflow_id"),
            "workflow_run_key": optional_string(body.get("workflow_run_key"), "workflow_run_key"),
            "parent_task_id": optional_string(body.get("parent_task_id"), "parent_task_id"),
            "depends_on_task_id": optional_string(body.get("depends_on_task_id"), "depends_on_task_id"),
            "handoff_from_task_id": optional_string(body.get("handoff_from_task_id"), "handoff_from_task_id"),
        }

    def log_message(self, format: str, *args) -> None:
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query, keep_blank_values=False)

        try:
            self._require_auth()

            if path == "/health":
                self._send_json(self.service.health())
                return

            if path == "/workers":
                self._send_json(self.service.list_workers())
                return

            if path == "/tasks":
                limit = self._parse_limit(query)
                self._send_json(self.service.list_tasks(limit=limit))
                return

            if path.startswith("/tasks/"):
                task_id = path.split("/tasks/", 1)[1]
                self._send_json(self.service.get_task_details(require_string(task_id, "task_id")))
                return

            if path.startswith("/workflows/"):
                workflow_id = path.split("/workflows/", 1)[1]
                self._send_json(self.service.get_workflow_details(require_string(workflow_id, "workflow_id")))
                return

            self._send_error(HTTPStatus.NOT_FOUND, "not_found", "Route not found")
        except PermissionError as exc:
            self._send_error(HTTPStatus.UNAUTHORIZED, "unauthorized", str(exc))
        except ValueError as exc:
            self._send_error(HTTPStatus.BAD_REQUEST, "validation_error", str(exc))
        except Exception as exc:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error", str(exc))

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            self._require_auth()

            if path == "/reset-demo":
                self._send_json(self.service.reset_demo())
                return

            if path == "/seed-demo":
                self._send_json(self.service.seed_demo())
                return

            if path == "/tasks":
                body = self._read_json_body()
                validated = self._validate_enqueue_payload(body)
                result = self.service.enqueue_task(
                    task_type=validated["task_type"],
                    payload=validated["payload"],
                    priority=validated["priority"],
                    max_attempts=validated["max_attempts"],
                    correlation_id=validated["correlation_id"],
                    workflow_id=validated["workflow_id"],
                    workflow_run_key=validated["workflow_run_key"],
                    parent_task_id=validated["parent_task_id"],
                    depends_on_task_id=validated["depends_on_task_id"],
                    handoff_from_task_id=validated["handoff_from_task_id"],
                )
                self._send_json(result, status=HTTPStatus.CREATED)
                return

            if path.startswith("/workers/") and path.endswith("/register"):
                worker_id = path.split("/workers/", 1)[1].rsplit("/register", 1)[0]
                result = self.service.register_worker(require_string(worker_id, "worker_id"))
                self._send_json(result)
                return

            self._send_error(HTTPStatus.NOT_FOUND, "not_found", "Route not found")
        except PermissionError as exc:
            self._send_error(HTTPStatus.UNAUTHORIZED, "unauthorized", str(exc))
        except ValueError as exc:
            self._send_error(HTTPStatus.BAD_REQUEST, "validation_error", str(exc))
        except Exception as exc:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error", str(exc))


def main() -> None:
    args = parse_args()
    server = ThreadingHTTPServer((args.host, args.port), ControlPlaneHandler)
    print(f"control-plane-api listening on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
