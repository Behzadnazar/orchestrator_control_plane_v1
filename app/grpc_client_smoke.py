from __future__ import annotations

import json
import grpc

import control_plane_pb2 as pb2
import control_plane_pb2_grpc as pb2_grpc


def main() -> None:
    channel = grpc.insecure_channel("127.0.0.1:50051")
    stub = pb2_grpc.ControlPlaneServiceStub(channel)

    reply = stub.SubmitTask(
        pb2.TaskRequest(
            task_type="backend_feature",
            title="grpc smoke task",
            priority="high",
            payload_json=json.dumps({
                "tool": "bash",
                "command": "printf 'GRPC OK\n'",
                "target_files": ["apps/api/main.py"],
                "timeout_seconds": 60,
                "sandbox_mode": "local"
            }),
            done_criteria_json=json.dumps([
                {"type": "exit_code", "equals": 0},
                {"type": "stdout_contains", "value": "GRPC OK"}
            ]),
        )
    )

    print("SUBMIT_REPLY")
    print(f"task_id={reply.task_id}")
    print(f"status={reply.status}")
    print(f"assigned_agent_id={reply.assigned_agent_id}")
    print(f"message={reply.message}")

    status = stub.GetTaskStatus(pb2.TaskQuery(task_id=reply.task_id))
    print("\nINITIAL_STATUS")
    print(f"task_id={status.task_id}")
    print(f"status={status.status}")
    print(f"assigned_agent_id={status.assigned_agent_id}")
    print(f"last_error={status.last_error}")


if __name__ == "__main__":
    main()
