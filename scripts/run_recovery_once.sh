#!/usr/bin/env bash
set -e

cd ~/Schreibtisch/ai-dev-system/orchestrator_control_plane_v1 2>/dev/null || cd ~/Desktop/ai-dev-system/orchestrator_control_plane_v1 || exit 1
source .venv/bin/activate

python3 scripts/recover_stale_tasks_final.py
