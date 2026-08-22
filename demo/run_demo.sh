#!/usr/bin/env bash
#
# Record the narrated end-to-end demo video, from nothing to an MP4.
#
# Owner: Member 7 (UI + QA + Docs).
#
#   ./demo/run_demo.sh              # capture real output, then record
#   ./demo/run_demo.sh --recapture  # re-run the real commands first (slow)
#   ./demo/run_demo.sh --no-audio   # silent video
#
# It starts the API and the dashboard if they are not already up, leaves them
# running if they were, and refuses to record if DefectDojo is not reachable
# -- a video of an error page looks finished and is worse than no video.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="$ROOT/.venv/bin/python"
[ -x "$PYTHON" ] || PYTHON="python3"
export JAVA_HOME="${JAVA_HOME:-$HOME/.local/opt/jdk21}"

RECAPTURE=0
RECORD_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --recapture) RECAPTURE=1 ;;
    *) RECORD_ARGS+=("$arg") ;;
  esac
done

# .env.local carries DEFECTDOJO_URL / DEFECTDOJO_TOKEN and any LLM key. It is
# gitignored; nothing in it belongs in the repository.
if [ -f "$ROOT/.env.local" ]; then
  set -a; . "$ROOT/.env.local"; set +a
fi
DEFECTDOJO_URL="${DEFECTDOJO_URL:-http://localhost:8080}"

up() { curl -fsS -o /dev/null -m 4 "$1" 2>/dev/null; }

started_api=0
started_ui=0

echo "== services =="

if up http://localhost:8000/api/health; then
  echo "  api        already running on :8000"
else
  echo "  api        starting on :8000"
  setsid nohup "$PYTHON" server.py > /tmp/sast-demo-api.log 2>&1 < /dev/null &
  started_api=1
  for _ in $(seq 1 30); do up http://localhost:8000/api/health && break; sleep 1; done
fi

if up http://localhost:5173; then
  echo "  dashboard  already running on :5173"
else
  echo "  dashboard  starting on :5173"
  ( cd ui && setsid nohup npm run dev > /tmp/sast-demo-ui.log 2>&1 < /dev/null & )
  started_ui=1
  for _ in $(seq 1 40); do up http://localhost:5173 && break; sleep 1; done
fi

if up "$DEFECTDOJO_URL/login"; then
  echo "  defectdojo already running on $DEFECTDOJO_URL"
else
  echo "  defectdojo NOT reachable at $DEFECTDOJO_URL"
  echo
  echo "  Start it, then run this again:"
  echo "    cd ~/defectdojo && docker compose up -d"
  echo "  If something else has taken its port, set DD_PORT in its .env and"
  echo "  DEFECTDOJO_URL in .env.local to match."
  exit 1
fi

# The video shows real command output. Capture it if it is missing, or if
# --recapture was asked for. This is the slow part (the test suite alone is
# about four minutes) which is why it is not repeated on every recording.
if [ "$RECAPTURE" = "1" ] || [ ! -f demo/captures/02_scan.txt ]; then
  echo
  echo "== capturing real command output =="
  "$PYTHON" demo/capture.py
else
  echo
  echo "== captures =="
  echo "  reusing demo/captures ( --recapture to re-run the commands )"
fi

echo
echo "== recording =="
"$PYTHON" demo/record_demo.py "${RECORD_ARGS[@]+"${RECORD_ARGS[@]}"}"

echo
if [ "$started_api" = "1" ] || [ "$started_ui" = "1" ]; then
  echo "Note: this script started services that are still running."
  [ "$started_api" = "1" ] && echo "  api       pkill -f 'python server.py'"
  [ "$started_ui" = "1" ]  && echo "  dashboard pkill -f 'vite'"
fi
echo "Video: demo/output/sast-engine-demo.mp4"
