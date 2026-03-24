from __future__ import annotations
import json
from typing import Any

from . import db, policy, router, executor
from .models import LifecycleState
from .state_machine import validate_transition

class Orchestrator:
    def seed_agents_from_config(self, config_path: str) -> None:
        agents = json.loads(open(config_path, "r", encoding="utf-8").read())
        for agent in agents:
            db.upsert_agent(agent)
            db.append_event("agent", agent["agent_id"], "AgentRegistered", {"agent_type": agent["agent_type"]})

    def submit_task(
        self,
        task_type: str,
        title: str,
        priority: str,
        payload: dict[str, Any],
        done_criteria: list[dict[str, Any]],
        max_retries: int = 2,
    ) -> str:
        temp_task = {
            "task_type": task_type,
            "payload": payload,
        }
        requires_human, reason = policy.requires_human(temp_task)
        task_id = db.create_task(
            task_type=task_type,
            title=title,
            priority=priority,
            payload=payload,
            done_criteria=done_criteria,
            max_retries=max_retries,
            requires_human=requires_human,
        )
        db.append_event("task", task_id, "TaskCreated", {
            "task_type": task_type,
            "priority": priority,
            "requires_human": requires_human,
            "reason": reason,
        })
        return task_id

    def approve_task(self, task_id: str, approver: str, decision: str, reason: str | None = None) -> None:
        db.create_approval(task_id, "review", approver, decision, reason)
        db.append_event("task", task_id, "TaskReviewDecision", {
            "approver": approver,
            "decision": decision,
            "reason": reason,
        })


    def process_specific_task(self, task_id: str) -> str:
        task = db.get_task(task_id)
        if not task:
            return f"task not found: {task_id}"

        current_status = task["status"]
        if current_status != LifecycleState.IDLE.value:
            return f"task is not runnable: {task_id} | status={current_status}"

        try:
            agent = router.route_task(task)
        except Exception as e:
            db.update_task(task["task_id"], last_error=str(e))
            db.append_event("task", task["task_id"], "RoutingFailed", {"error": str(e)})
            return f"routing failed: {e}"

        target_files = task["payload"].get("target_files", [])
        ok, msg = policy.check_file_write_permission(agent["agent_type"], target_files)
        if not ok:
            return self._fail_task(task, agent, f"file ownership denied: {msg}")

        locked, conflicts = db.acquire_file_locks(task["task_id"], agent["agent_id"], target_files)
        if not locked:
            db.append_event("task", task["task_id"], "FileConflictDetected", {"conflicts": conflicts})
            db.update_task(task["task_id"], status=LifecycleState.FAILED.value, last_error=f"file conflict: {conflicts}")
            return f"file conflict: {conflicts}"

        try:
            self._transition_task(task["task_id"], task["status"], LifecycleState.ASSIGNED.value)
            db.update_task(task["task_id"], assigned_agent_id=agent["agent_id"])
            db.update_agent_status(agent["agent_id"], LifecycleState.ASSIGNED.value, task["task_id"])
            db.append_event("task", task["task_id"], "TaskAssigned", {"agent_id": agent["agent_id"]})

            if task["requires_human"]:
                self._transition_task(task["task_id"], LifecycleState.ASSIGNED.value, LifecycleState.EXECUTING.value)
                self._transition_task(task["task_id"], LifecycleState.EXECUTING.value, LifecycleState.REVIEW.value)
                db.update_task(task["task_id"], review_status="awaiting_human")
                db.update_agent_status(agent["agent_id"], LifecycleState.IDLE.value, None)
                db.append_event("task", task["task_id"], "PauseForHuman", {"reason": "human approval required"})
                return f"task paused for human review: {task['task_id']}"

            tool_name = task["payload"].get("tool", "bash")
            ok, msg = policy.check_tool_permission(agent, tool_name)
            if not ok:
                return self._fail_task(task, agent, f"tool denied: {msg}")

            self._transition_task(task["task_id"], LifecycleState.ASSIGNED.value, LifecycleState.EXECUTING.value)
            db.update_agent_status(agent["agent_id"], LifecycleState.EXECUTING.value, task["task_id"])
            db.append_event("task", task["task_id"], "ExecutionStarted", {"tool": tool_name})

            exec_payload = dict(task["payload"])
            exec_payload["task_id"] = task["task_id"]
            result = executor.run_command(exec_payload)

            self._transition_task(task["task_id"], LifecycleState.EXECUTING.value, LifecycleState.REVIEW.value)
            db.update_agent_status(agent["agent_id"], LifecycleState.REVIEW.value, task["task_id"])
            db.append_event("task", task["task_id"], "ExecutionFinished", result)

            passed, reason = self._evaluate_done_criteria(task, result)

            if passed:
                approval = db.latest_approval(task["task_id"], "review")
                if task["requires_human"]:
                    if not approval or approval["decision"].lower() != "approve":
                        db.update_task(task["task_id"], review_status="awaiting_human")
                        db.update_agent_status(agent["agent_id"], LifecycleState.IDLE.value, None)
                        db.append_event("task", task["task_id"], "ReviewWaitingForApproval", {})
                        return f"task waiting for approval: {task['task_id']}"

                self._transition_task(task["task_id"], LifecycleState.REVIEW.value, LifecycleState.COMPLETED.value)
                if task["requires_human"]:
                    db.update_task(task["task_id"], review_status="approved")
                db.update_agent_status(agent["agent_id"], LifecycleState.IDLE.value, None)
                db.append_event("task", task["task_id"], "TaskCompleted", {"reason": reason})
                return f"task completed: {task['task_id']}"
            else:
                return self._fail_or_retry(task, agent, reason)

        finally:
            db.release_file_locks(task["task_id"])

    def process_next_task(self) -> str:
        task = db.next_runnable_task()
        if not task:
            return "هیچ task قابل اجرا وجود ندارد."

        try:
            agent = router.route_task(task)
        except Exception as e:
            db.update_task(task["task_id"], last_error=str(e))
            db.append_event("task", task["task_id"], "RoutingFailed", {"error": str(e)})
            return f"routing failed: {e}"

        target_files = task["payload"].get("target_files", [])
        ok, msg = policy.check_file_write_permission(agent["agent_type"], target_files)
        if not ok:
            return self._fail_task(task, agent, f"file ownership denied: {msg}")

        locked, conflicts = db.acquire_file_locks(task["task_id"], agent["agent_id"], target_files)
        if not locked:
            db.append_event("task", task["task_id"], "FileConflictDetected", {"conflicts": conflicts})
            db.update_task(task["task_id"], status=LifecycleState.FAILED.value, last_error=f"file conflict: {conflicts}")
            return f"file conflict: {conflicts}"

        try:
            self._transition_task(task["task_id"], task["status"], LifecycleState.ASSIGNED.value)
            db.update_task(task["task_id"], assigned_agent_id=agent["agent_id"])
            db.update_agent_status(agent["agent_id"], LifecycleState.ASSIGNED.value, task["task_id"])
            db.append_event("task", task["task_id"], "TaskAssigned", {"agent_id": agent["agent_id"]})

            if task["requires_human"]:
                self._transition_task(task["task_id"], LifecycleState.ASSIGNED.value, LifecycleState.EXECUTING.value)
                self._transition_task(task["task_id"], LifecycleState.EXECUTING.value, LifecycleState.REVIEW.value)
                db.update_task(task["task_id"], review_status="awaiting_human")
                db.update_agent_status(agent["agent_id"], LifecycleState.IDLE.value, None)
                db.append_event("task", task["task_id"], "PauseForHuman", {"reason": "human approval required"})
                return f"task paused for human review: {task['task_id']}"

            tool_name = task["payload"].get("tool", "bash")
            ok, msg = policy.check_tool_permission(agent, tool_name)
            if not ok:
                return self._fail_task(task, agent, f"tool denied: {msg}")

            self._transition_task(task["task_id"], LifecycleState.ASSIGNED.value, LifecycleState.EXECUTING.value)
            db.update_agent_status(agent["agent_id"], LifecycleState.EXECUTING.value, task["task_id"])
            db.append_event("task", task["task_id"], "ExecutionStarted", {"tool": tool_name})

            exec_payload = dict(task["payload"])
            exec_payload["task_id"] = task["task_id"]
            result = executor.run_command(exec_payload)

            self._transition_task(task["task_id"], LifecycleState.EXECUTING.value, LifecycleState.REVIEW.value)
            db.update_agent_status(agent["agent_id"], LifecycleState.REVIEW.value, task["task_id"])
            db.append_event("task", task["task_id"], "ExecutionFinished", result)

            passed, reason = self._evaluate_done_criteria(task, result)

            if passed:
                approval = db.latest_approval(task["task_id"], "review")
                if task["requires_human"]:
                    if not approval or approval["decision"].lower() != "approve":
                        db.update_task(task["task_id"], review_status="awaiting_human")
                        db.update_agent_status(agent["agent_id"], LifecycleState.IDLE.value, None)
                        db.append_event("task", task["task_id"], "ReviewWaitingForApproval", {})
                        return f"task waiting for approval: {task['task_id']}"

                self._transition_task(task["task_id"], LifecycleState.REVIEW.value, LifecycleState.COMPLETED.value)
                if task["requires_human"]:
                    db.update_task(task["task_id"], review_status="approved")
                db.update_agent_status(agent["agent_id"], LifecycleState.IDLE.value, None)
                db.append_event("task", task["task_id"], "TaskCompleted", {"reason": reason})
                return f"task completed: {task['task_id']}"
            else:
                return self._fail_or_retry(task, agent, reason)

        finally:
            db.release_file_locks(task["task_id"])

    def resume_reviewed_task(self, task_id: str) -> str:
        task = db.get_task(task_id)
        if not task:
            raise ValueError("task not found")
        if task["status"] != LifecycleState.REVIEW.value:
            raise ValueError("task is not in Review state")
        approval = db.latest_approval(task_id, "review")
        if not approval or approval["decision"].lower() != "approve":
            return "هنوز approval ثبت نشده است."
        self._transition_task(task_id, LifecycleState.REVIEW.value, LifecycleState.COMPLETED.value)
        db.update_task(task_id, review_status="approved")
        db.append_event("task", task_id, "TaskCompleted", {
            "reason": "completed after human approval",
            "approver": approval["approver"]
        })
        db.append_event("task", task_id, "TaskCompletedAfterHumanApproval", {"approver": approval["approver"]})
        if task["assigned_agent_id"]:
            db.update_agent_status(task["assigned_agent_id"], LifecycleState.IDLE.value, None)
        return f"task completed after approval: {task_id}"

    def _evaluate_done_criteria(self, task: dict[str, Any], result: dict[str, Any]) -> tuple[bool, str]:
        for criterion in task["done_criteria"]:
            ctype = criterion.get("type")
            if ctype == "exit_code":
                expected = criterion.get("equals", 0)
                if result["exit_code"] != expected:
                    return False, f"exit_code mismatch: expected={expected}, got={result['exit_code']}"
            elif ctype == "stdout_contains":
                value = criterion.get("value", "")
                if value not in result["stdout"]:
                    return False, f"stdout missing expected text: {value}"
            elif ctype == "stderr_empty":
                if result["stderr"].strip():
                    return False, "stderr is not empty"
            else:
                return False, f"unsupported done criterion: {ctype}"
        return True, "all criteria satisfied"

    def _transition_task(self, task_id: str, current: str, new: str) -> None:
        validate_transition(current, new)
        db.update_task(task_id, status=new)
        db.append_event("task", task_id, "TaskStateChanged", {"from": current, "to": new})

    def _fail_task(self, task: dict, agent: dict, reason: str) -> str:
        try:
            if task["status"] == LifecycleState.REVIEW.value:
                self._transition_task(task["task_id"], LifecycleState.REVIEW.value, LifecycleState.FAILED.value)
            elif task["status"] == LifecycleState.EXECUTING.value:
                self._transition_task(task["task_id"], LifecycleState.EXECUTING.value, LifecycleState.REVIEW.value)
                self._transition_task(task["task_id"], LifecycleState.REVIEW.value, LifecycleState.FAILED.value)
            elif task["status"] == LifecycleState.ASSIGNED.value:
                self._transition_task(task["task_id"], LifecycleState.ASSIGNED.value, LifecycleState.EXECUTING.value)
                self._transition_task(task["task_id"], LifecycleState.EXECUTING.value, LifecycleState.REVIEW.value)
                self._transition_task(task["task_id"], LifecycleState.REVIEW.value, LifecycleState.FAILED.value)
            elif task["status"] == LifecycleState.IDLE.value:
                self._transition_task(task["task_id"], LifecycleState.IDLE.value, LifecycleState.ASSIGNED.value)
                self._transition_task(task["task_id"], LifecycleState.ASSIGNED.value, LifecycleState.EXECUTING.value)
                self._transition_task(task["task_id"], LifecycleState.EXECUTING.value, LifecycleState.REVIEW.value)
                self._transition_task(task["task_id"], LifecycleState.REVIEW.value, LifecycleState.FAILED.value)
        except Exception:
            db.update_task(task["task_id"], status=LifecycleState.FAILED.value)

        db.update_task(task["task_id"], last_error=reason)
        if agent:
            db.update_agent_status(agent["agent_id"], LifecycleState.IDLE.value, None)
        db.append_event("task", task["task_id"], "TaskFailed", {"reason": reason})
        return f"task failed: {task['task_id']} | reason={reason}"

    def _fail_or_retry(self, task: dict, agent: dict, reason: str) -> str:
        self._transition_task(task["task_id"], LifecycleState.REVIEW.value, LifecycleState.FAILED.value)
        db.update_task(task["task_id"], last_error=reason)
        db.update_agent_status(agent["agent_id"], LifecycleState.IDLE.value, None)
        db.append_event("task", task["task_id"], "TaskFailed", {"reason": reason})

        if task["attempt_no"] < task["max_retries"]:
            new_task_id = db.create_task(
                task_type=task["task_type"],
                title=f"{task['title']} [retry {task['attempt_no'] + 1}]",
                priority=task["priority"],
                payload=task["payload"],
                done_criteria=task["done_criteria"],
                max_retries=task["max_retries"],
                parent_task_id=task["task_id"],
                attempt_no=task["attempt_no"] + 1,
                requires_human=task["requires_human"],
            )
            db.append_event("task", new_task_id, "RetryTaskCreated", {
                "parent_task_id": task["task_id"],
                "reason": reason,
                "attempt_no": task["attempt_no"] + 1,
            })
            return f"task failed and retry created: old={task['task_id']} new={new_task_id}"
        return f"task failed permanently: {task['task_id']} | reason={reason}"
