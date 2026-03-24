# Orchestrator / Control Plane v1

Local-first autonomous AI developer control layer.

## Components
- Agent Registry
- Task Queue / Scheduler
- Policy Engine
- State Machine
- Audit/Event Log
- File Locks
- Human Approval
- Sandbox Executor Adapter
- gRPC Protobuf schema (proto only in v1)

## Run
python3 -m app.cli init-db
python3 -m app.cli seed-agents
python3 -m app.cli list-agents
