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
