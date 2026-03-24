#!/usr/bin/env bash
set -euo pipefail

cd ~/Schreibtisch/ai-dev-system/orchestrator_control_plane_v1 2>/dev/null || cd ~/Desktop/ai-dev-system/orchestrator_control_plane_v1 || exit 1
source .venv/bin/activate

rm -f /tmp/phase-e-backend.log /tmp/phase-e-frontend.log /tmp/phase-e-research.log

python3 worker_loop_final.py --worker-id backend-worker-v2 --reset-demo --maintenance --once-idle-exit > /tmp/phase-e-backend.log 2>&1 &
BACKEND_PID=$!

sleep 1

python3 worker_loop_final.py --worker-id frontend-worker-v1 --once-idle-exit > /tmp/phase-e-frontend.log 2>&1 &
FRONTEND_PID=$!

python3 worker_loop_final.py --worker-id research-worker-v1 --once-idle-exit > /tmp/phase-e-research.log 2>&1 &
RESEARCH_PID=$!

wait "$BACKEND_PID"
wait "$FRONTEND_PID"
wait "$RESEARCH_PID"

echo "=== BACKEND LOG ==="
cat /tmp/phase-e-backend.log
echo
echo "=== FRONTEND LOG ==="
cat /tmp/phase-e-frontend.log
echo
echo "=== RESEARCH LOG ==="
cat /tmp/phase-e-research.log
