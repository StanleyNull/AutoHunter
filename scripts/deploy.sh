#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
SERVICE="${SERVICE:-autohunter}"
MODE="${1:-build}"

cd "$ROOT_DIR"

case "$MODE" in
  build)
    docker compose -f "$COMPOSE_FILE" build "$SERVICE"
    docker compose -f "$COMPOSE_FILE" up -d "$SERVICE"
    ;;
  hot)
    # Emergency path for hosts where Docker registry/proxy is temporarily broken.
    # It keeps volumes/env intact, copies the already-synced source into the running container, then restarts.
    docker cp app/. "$SERVICE":/app/app/
    docker cp scripts/. "$SERVICE":/app/scripts/
    if [ -f requirements.txt ]; then
      docker cp requirements.txt "$SERVICE":/app/requirements.txt
      if [ "${AUTOHUNTER_HOT_INSTALL_REQUIREMENTS:-0}" = "1" ]; then
        docker exec "$SERVICE" python -m pip install -r /app/requirements.txt
      fi
    fi
    if [ -d web/dist ]; then
      docker cp web/dist/. "$SERVICE":/app/web/dist/
    fi
   # 依赖冲突检测：pyppeteer/selenium 等包可能将 websockets 降级到 <13，
   # 导致 uvicorn[standard] 启动失败。热更新前自动检测并修复。
    # 容器内 import/pip 偶发挂死，用容器内 timeout 兜底，避免永久阻塞热更新。
    # 三态：ok=版本达标；bad=明确版本<13，需修复；fail=超时/异常，只告警不盲动。
    WS_VER=$(docker exec "$SERVICE" timeout 15 python3 -c "import websockets,sys; sys.stdout.write(websockets.__version__)" 2>/dev/null || true)
    WS_MAJOR="${WS_VER%%.*}"
    if [ -n "$WS_MAJOR" ] && [ "$WS_MAJOR" -ge 13 ] 2>/dev/null; then
      WS_OK="ok"
    elif [ -n "$WS_MAJOR" ] && [ "$WS_MAJOR" -lt 13 ] 2>/dev/null; then
      WS_OK="bad"
    else
      WS_OK="fail"
    fi
    if [ "$WS_OK" = "bad" ]; then
      echo "[hot] websockets ${WS_VER:-?} < 13.0 detected, repairing dependency conflict..."
      docker exec "$SERVICE" timeout 60 python3 -m pip install --quiet 'websockets>=13.0' 2>/dev/null || true
    elif [ "$WS_OK" = "fail" ]; then
      echo "[hot] websockets version probe failed/timed out (got '${WS_VER:-empty}'); skip auto-repair, continue."
    fi
    # Graceful stop (-t 30) gives the lifespan shutdown hook time to cancel running
    # workers and let them flush already-found findings before the process is killed.
    # Combined with realtime finding persistence, an update no longer drops in-flight findings.
    GRACE="${AUTOHUNTER_HOT_STOP_GRACE:-30}"
    docker stop -t "$GRACE" "$SERVICE"
    docker compose -f "$COMPOSE_FILE" start "$SERVICE" \
      || docker compose -f "$COMPOSE_FILE" up -d "$SERVICE" \
      || docker start "$SERVICE"
    ;;
  *)
    echo "Usage: $0 [build|hot]" >&2
    exit 2
    ;;
esac

docker compose -f "$COMPOSE_FILE" ps "$SERVICE"
