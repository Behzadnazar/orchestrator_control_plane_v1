#!/usr/bin/env bash
set -e

cd ~/Schreibtisch/ai-dev-system/orchestrator_control_plane_v1 2>/dev/null || cd ~/Desktop/ai-dev-system/orchestrator_control_plane_v1 || exit 1
source .venv/bin/activate

echo "[CONTROL-PLANE] running stale recovery..."
python3 scripts/recover_stale_tasks_final.py

echo "[CONTROL-PLANE] running consistency check..."
python3 scripts/check_queue_consistency.py

echo "[CONTROL-PLANE] starting worker..."
python3 scripts/worker_loop_final.py
