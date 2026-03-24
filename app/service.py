from __future__ import annotations

import json
import grpc

import control_plane_pb2 as pb2
import control_plane_pb2_grpc as pb2_grpc

from .orchestrator import Orchestrator
from . import db


class ControlPlaneService(pb2_grpc.ControlPlaneServiceServicer):
    def __init__(self) -> None:
        db.init_db()
        self.orch = Orchestrator()

    def RegisterAgent(self, request, context):
        try:
            agent = {
                "agent_id": request.agent_id,
                "agent_type": request.agent_type,
                "capabilities": list(request.capabilities),
                "allowed_tools": list(request.allowed_tools),
                "status": request.status or "Idle",
            }
            db.upsert_agent(agent)
            db.append_event("agent", agent["agent_id"], "AgentRegistered", {"agent_type": agent["agent_type"]})
            return pb2.SimpleReply(ok=True, message=f"agent registered: {agent['agent_id']}")
        except Exception as e:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details(str(e))
            return pb2.SimpleReply(ok=False, message=str(e))

    def SubmitTask(self, request, context):
        try:
            payload = json.loads(request.payload_json) if request.payload_json else {}
            done_criteria = json.loads(request.done_criteria_json) if request.done_criteria_json else []
            task_id = self.orch.submit_task(
                task_type=request.task_type,
                title=request.title,
                priority=request.priority or "normal",
                payload=payload,
                done_criteria=done_criteria,
            )
            task = db.get_task(task_id)
            return pb2.TaskReply(
                task_id=task_id,
                status=task["status"],
                assigned_agent_id=task["assigned_agent_id"] or "",
                message="task submitted",
            )
        except Exception as e:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details(str(e))
            return pb2.TaskReply()

    def ApproveTask(self, request, context):
        try:
            self.orch.approve_task(
                task_id=request.task_id,
                approver=request.approver,
                decision=request.decision,
                reason=request.reason or None,
            )
            return pb2.SimpleReply(ok=True, message=f"approval recorded for {request.task_id}")
        except Exception as e:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details(str(e))
            return pb2.SimpleReply(ok=False, message=str(e))

    def GetTaskStatus(self, request, context):
        task = db.get_task(request.task_id)
        if not task:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("task not found")
            return pb2.TaskStatusReply()
        return pb2.TaskStatusReply(
            task_id=task["task_id"],
            status=task["status"],
            assigned_agent_id=task["assigned_agent_id"] or "",
            last_error=task["last_error"] or "",
        )
