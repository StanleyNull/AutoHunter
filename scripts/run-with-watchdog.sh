#!/bin/sh
set -eu

# ============================================================================
#  AutoHunter  ·  Powered By StanleyNull  ·  CC BY-NC 4.0
# ============================================================================

HOST="${AUTOHUNTER_HOST:-0.0.0.0}"
PORT="${AUTOHUNTER_PORT:-18800}"
INTERVAL="${AUTOHUNTER_WATCHDOG_INTERVAL:-20}"
TIMEOUT="${AUTOHUNTER_WATCHDOG_TIMEOUT:-5}"
MAX_FAILURES="${AUTOHUNTER_WATCHDOG_MAX_FAILURES:-3}"
START_GRACE="${AUTOHUNTER_WATCHDOG_START_GRACE:-20}"
DIAG_SIGNAL="${AUTOHUNTER_WATCHDOG_DIAG_SIGNAL:-USR1}"
DIAG_GRACE="${AUTOHUNTER_WATCHDOG_DIAG_GRACE:-3}"

dump_proc_file() {
  file="$1"
  if [ -r "$file" ]; then
    echo "----- $file -----" >&2
    cat "$file" >&2 || true
  else
    echo "----- $file (unavailable) -----" >&2
  fi
}

dump_native_diagnostics() {
  if ! kill -0 "$UVICORN_PID" 2>/dev/null; then
    return 0
  fi

  echo "[watchdog] native diagnostics begin pid=$UVICORN_PID" >&2
  dump_proc_file "/proc/$UVICORN_PID/status"
  dump_proc_file "/proc/$UVICORN_PID/wchan"
  dump_proc_file "/proc/$UVICORN_PID/sched"

  if [ -d "/proc/$UVICORN_PID/fd" ]; then
    echo "----- /proc/$UVICORN_PID/fd -----" >&2
    ls -l "/proc/$UVICORN_PID/fd" >&2 || true
  fi

  if [ -d "/proc/$UVICORN_PID/task" ]; then
    echo "----- /proc/$UVICORN_PID/task -----" >&2
    for task_dir in /proc/"$UVICORN_PID"/task/*; do
      tid="${task_dir##*/}"
      echo "[watchdog] thread tid=$tid" >&2
      dump_proc_file "$task_dir/comm"
      dump_proc_file "$task_dir/status"
      dump_proc_file "$task_dir/wchan"
      dump_proc_file "$task_dir/sched"
      dump_proc_file "$task_dir/stack"
    done
  fi
  echo "[watchdog] native diagnostics end pid=$UVICORN_PID" >&2
}

# ============================================================================
#  启动前安全检查：websockets 主版本必须 >=13。
#  pyppeteer/selenium/undetected-chromedriver 等包会把 websockets 降级到 <13，
#  导致 uvicorn 报 ImportError: cannot import name 'ServerProtocol'。
#  只在被降级到 <13 时才自动修复；高版本（>=15）uvicorn 通常向后兼容，
#  不强制降级（避免在受限网络里 pip 反复失败拖慢启动）。
# ============================================================================
WS_MAJOR=$(python3 -c "import websockets; print(websockets.__version__.split('.')[0])" 2>/dev/null || echo "0")
if [ "$WS_MAJOR" -lt 13 ] 2>/dev/null; then
  echo "[watchdog] websockets major=$WS_MAJOR < 13, auto-repairing..." >&2
  pip3 install --quiet 'websockets>=13.0' 2>&1 || pip install --quiet 'websockets>=13.0' 2>&1 || true
  WS_MAJOR=$(python3 -c "import websockets; print(websockets.__version__.split('.')[0])" 2>/dev/null || echo "0")
  echo "[watchdog] websockets repaired, new major=$WS_MAJOR" >&2
fi

uvicorn app.main:app --host "$HOST" --port "$PORT" &
UVICORN_PID="$!"

terminate() {
  if kill -0 "$UVICORN_PID" 2>/dev/null; then
    kill -TERM "$UVICORN_PID" 2>/dev/null || true
    sleep 5
    kill -KILL "$UVICORN_PID" 2>/dev/null || true
  fi
}

trap 'terminate; exit 143' INT TERM

sleep "$START_GRACE" || true
failures=0

while kill -0 "$UVICORN_PID" 2>/dev/null; do
  if curl -fsS --max-time "$TIMEOUT" "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
    failures=0
  else
    failures=$((failures + 1))
    echo "[watchdog] health check failed ${failures}/${MAX_FAILURES}" >&2
    if [ "$failures" -ge "$MAX_FAILURES" ]; then
      echo "[watchdog] dumping runtime diagnostics via SIG${DIAG_SIGNAL}" >&2
      kill "-${DIAG_SIGNAL}" "$UVICORN_PID" 2>/dev/null || true
      sleep "$DIAG_GRACE" || true
      dump_native_diagnostics
      echo "[watchdog] uvicorn appears hung; terminating container for Docker restart" >&2
      terminate
      exit 70
    fi
  fi
  sleep "$INTERVAL" || true
done

wait "$UVICORN_PID"
