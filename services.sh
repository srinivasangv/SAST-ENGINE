#!/usr/bin/env bash
#
# Start, stop and check the three services the engine runs on.
#
#   ./services.sh start     # start whatever is not already up
#   ./services.sh stop      # stop the ones this script started
#   ./services.sh restart   # stop then start
#   ./services.sh status    # what is up, and what it reports about itself
#
# The three services:
#
#   :8000   API          server.py            ours
#   :5173   dashboard    vite (ui/)           ours
#   :8080   DefectDojo   docker compose       third party, in ~/defectdojo
#
# Ports are read from .env.local so they stay in step with whatever
# DefectDojo is actually published on -- it moves whenever something else
# claims 8080, which is exactly how it broke last time.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PYTHON="$ROOT/.venv/bin/python"
[ -x "$PYTHON" ] || PYTHON="python3"
export JAVA_HOME="${JAVA_HOME:-$HOME/.local/opt/jdk21}"

LOG_DIR="$ROOT/.run"
mkdir -p "$LOG_DIR"

if [ -f "$ROOT/.env.local" ]; then
  set -a; . "$ROOT/.env.local"; set +a
fi
DEFECTDOJO_URL="${DEFECTDOJO_URL:-http://localhost:8080}"
DEFECTDOJO_DIR="${DEFECTDOJO_DIR:-$HOME/defectdojo}"

API_URL="http://localhost:8000"
UI_URL="http://localhost:5173"

green() { printf '\033[32m%s\033[0m' "$1"; }
red()   { printf '\033[31m%s\033[0m' "$1"; }
dim()   { printf '\033[2m%s\033[0m'  "$1"; }

# Answering at all counts as up. DefectDojo redirects to a login page and the
# API has no route for /, so "is it a 200" is the wrong question -- a 302 or a
# 404 both mean something is listening and serving.
alive() { curl -s -o /dev/null -m 4 "$1" 2>/dev/null; }

# Whatever is listening on a port, whether or not this script started it.
pid_on_port() {
  ss -lptnH "sport = :$1" 2>/dev/null | grep -oP 'pid=\K[0-9]+' | sort -u | head -1
}

wait_for() {
  local url="$1" limit="${2:-40}" n=0
  while [ "$n" -lt "$limit" ]; do
    alive "$url" && return 0
    sleep 1; n=$((n + 1))
  done
  return 1
}

start_api() {
  if alive "$API_URL/api/health"; then
    echo "  api        $(green up)        already running on :8000"
    return
  fi
  setsid nohup "$PYTHON" server.py > "$LOG_DIR/api.log" 2>&1 < /dev/null &
  echo "$!" > "$LOG_DIR/api.pid"
  if wait_for "$API_URL/api/health" 30; then
    echo "  api        $(green started)   :8000  $(dim "log: .run/api.log")"
  else
    echo "  api        $(red FAILED)     see .run/api.log"
    tail -5 "$LOG_DIR/api.log" | sed 's/^/             /'
  fi
}

start_ui() {
  if alive "$UI_URL"; then
    echo "  dashboard  $(green up)        already running on :5173"
    return
  fi
  if [ ! -d "$ROOT/ui/node_modules" ]; then
    echo "  dashboard  $(red "no node_modules") -- run: cd ui && npm install"
    return
  fi
  ( cd "$ROOT/ui" && setsid nohup npm run dev > "$LOG_DIR/ui.log" 2>&1 < /dev/null & echo "$!" > "$LOG_DIR/ui.pid" )
  if wait_for "$UI_URL" 45; then
    echo "  dashboard  $(green started)   :5173  $(dim "log: .run/ui.log")"
  else
    echo "  dashboard  $(red FAILED)     see .run/ui.log"
    tail -5 "$LOG_DIR/ui.log" | sed 's/^/             /'
  fi
}

start_dojo() {
  if alive "$DEFECTDOJO_URL/login"; then
    echo "  defectdojo $(green up)        already running on $DEFECTDOJO_URL"
    return
  fi
  if [ ! -d "$DEFECTDOJO_DIR" ]; then
    echo "  defectdojo $(red "not installed") -- expected at $DEFECTDOJO_DIR"
    return
  fi
  echo "  defectdojo starting      (docker compose, this takes a moment)"
  ( cd "$DEFECTDOJO_DIR" && docker compose up -d > "$LOG_DIR/dojo.log" 2>&1 )
  if wait_for "$DEFECTDOJO_URL/login" 90; then
    echo "  defectdojo $(green started)   $DEFECTDOJO_URL"
  else
    echo "  defectdojo $(red FAILED)     see .run/dojo.log"
    echo "             If its port is taken, set DD_PORT in $DEFECTDOJO_DIR/.env"
    echo "             and DEFECTDOJO_URL in .env.local to match."
  fi
}

stop_one() {
  local name="$1" port="$2"
  local pid; pid="$(pid_on_port "$port")"
  if [ -z "$pid" ]; then
    echo "  $name $(dim "not running")"
    return
  fi
  kill "$pid" 2>/dev/null
  sleep 2
  # Vite spawns a child that keeps the port; if it is still held, be firmer.
  pid="$(pid_on_port "$port")"
  [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
  echo "  $name $(green stopped)   was pid $pid on :$port"
}

status() {
  echo "== services =="
  local api_state ui_state dojo_state
  alive "$API_URL/api/health" && api_state="$(green up)" || api_state="$(red down)"
  alive "$UI_URL"             && ui_state="$(green up)"  || ui_state="$(red down)"
  alive "$DEFECTDOJO_URL/login" && dojo_state="$(green up)" || dojo_state="$(red down)"
  echo "  api        $api_state   $API_URL"
  echo "  dashboard  $ui_state   $UI_URL"
  echo "  defectdojo $dojo_state   $DEFECTDOJO_URL"

  if alive "$API_URL/api/health"; then
    echo
    echo "== what the engine reports about itself =="
    # Single quotes throughout the Python, because the whole program is
    # already inside a single-quoted shell string -- escaping quotes in there
    # reaches Python as a literal backslash and is a syntax error.
    curl -s -m 6 "$API_URL/api/health" | "$PYTHON" -c '
import json, sys
h = json.load(sys.stdin)
used = h.get("llm_last_used")
provider = h.get("llm_provider")
if used and used != "offline":
    llm = "{} ({})".format(used, h.get("llm_model"))
elif used == "offline":
    llm = "offline - {} is configured but did not answer".format(provider)
else:
    llm = "{} configured, nothing scanned yet".format(provider)
dojo = h.get("defectdojo") or {}
eng = h.get("engines") or {}
print("  validator   " + llm)
print("  engines     builtin"
      + (" + joern" if eng.get("joern") else " (joern missing)")
      + (" + semgrep" if h.get("semgrep_available") else ""))
print("  defectdojo  " + ("authenticated" if dojo.get("authenticated")
                          else (dojo.get("error") or "not connected")))
print("  scans       {} stored".format(h.get("scans_stored")))
'
  fi
}

clean_scans() {
  # Test runs and demo captures each leave a scan behind, so the history
  # panel fills up with dozens of identical runs and the dashboard becomes
  # hard to read. Keep the newest scan per repository and MOVE the rest into
  # an archive folder -- never delete them. Nothing here is expensive to
  # regenerate, but silently destroying a user's data to tidy a UI is not a
  # trade this script gets to make on its own.
  "$PYTHON" - <<'PYEOF'
import shutil
from pathlib import Path
from engine import config, store

config.ensure_dirs()
archive = config.SCANS_DIR / "archive"
archive.mkdir(exist_ok=True)

newest: dict[str, str] = {}
for scan in sorted(store.list_scans(), key=lambda s: s.get("started_at", "")):
    newest[scan.get("repo", "?")] = scan["id"]

keep = set(newest.values())
moved = 0
for path in config.SCANS_DIR.glob("*.json"):
    if path.stem not in keep:
        shutil.move(str(path), str(archive / path.name))
        moved += 1

print(f"  archived {moved} scan(s) to data/scans/archive/")
print(f"  kept {len(keep)}: " + ", ".join(f"{r} ({i})" for r, i in newest.items()))
PYEOF
}

case "${1:-status}" in
  start)
    echo "== starting =="
    start_api; start_ui; start_dojo
    echo
    status
    ;;
  stop)
    echo "== stopping =="
    stop_one "api       " 8000
    stop_one "dashboard " 5173
    echo "  defectdojo left running (docker) -- stop it with:"
    echo "             cd $DEFECTDOJO_DIR && docker compose stop"
    ;;
  restart)
    "$0" stop; echo; "$0" start
    ;;
  status) status ;;
  clean)
    echo "== tidying the scan history =="
    clean_scans
    ;;
  *)
    echo "usage: ./services.sh {start|stop|restart|status|clean}"
    echo
    echo "  start    start whatever is not already up"
    echo "  stop     stop the API and the dashboard (leaves DefectDojo running)"
    echo "  restart  stop then start"
    echo "  status   what is up, and what the engine reports about itself"
    echo "  clean    archive all but the newest scan per repo (does not delete)"
    exit 2
    ;;
esac
