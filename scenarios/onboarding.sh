#!/usr/bin/env bash
# Live onboarding evidence: start Guardian (heuristic-only) and send twin-alt N+20.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
GUARDIAN="$REPO/guardian"
PYTHON="$REPO/.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON="$REPO/.venv/Scripts/python.exe"
fi
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
CAPTURE="$GUARDIAN/logs/onboarding-uvicorn-$STAMP.log"
PORT="${GUARDIAN_PORT:-8000}"
mkdir -p "$GUARDIAN/logs"
rm -rf "$GUARDIAN/data/onboarding-run"

export PYTHONPATH=src
export GUARDIAN_ONBOARDING_MIN_PROPOSERS=1
export GUARDIAN_FORWARD_TO_BRAIN=false
export GUARDIAN_TIMELINE_MODE=local
export GUARDIAN_PROFILE_DIR=data/onboarding-run
export GUARDIAN_ONBOARDING_CAPTURE="$CAPTURE"

cd "$GUARDIAN"
"$PYTHON" -m uvicorn guardian.main:app --host 127.0.0.1 --port "$PORT" --log-level info >"$CAPTURE" 2>&1 &
UVICORN_PID=$!
trap 'kill "$UVICORN_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:${PORT}/ready" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

"$PYTHON" -m mocks.onboarding_run --base-url "http://127.0.0.1:${PORT}" --count 21 --interval 0.5 --capture "$CAPTURE"
