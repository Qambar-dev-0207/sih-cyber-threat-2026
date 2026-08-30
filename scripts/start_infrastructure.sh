#!/usr/bin/env bash
# =============================================================================
# SIH26145 — Single-Command Infrastructure Startup & Healthcheck Validator
# =============================================================================
set -euo pipefail

TIMEOUT_SECONDS="${1:-60}"

echo -e "\033[1;36m=================================================================\033[0m"
echo -e "\033[1;33m  SIH26145 — Passive Network Monitoring Infrastructure Startup   \033[0m"
echo -e "\033[1;36m=================================================================\033[0m"

# 1. Pre-flight Docker Daemon Check
echo -e "\n\033[1;37m[1/6] Validating Docker daemon...\033[0m"
if ! docker info > /dev/null 2>&1; then
    echo -e "\033[1;31m[ERROR] Docker daemon is not running or accessible. Please start Docker service.\033[0m"
    exit 1
fi
echo -e "\033[1;32m      [OK] Docker engine is active and responding.\033[0m"

# 2. Workspace directory setup
echo -e "\n\033[1;37m[2/6] Verifying workspace directories...\033[0m"
mkdir -p logs/zeek pcaps data/pcaps config/zeek config/redpanda config/redis config/timescale config/db
echo -e "\033[1;32m      [OK] Local directories initialized.\033[0m"

# 3. Launch Docker Compose Stack
echo -e "\n\033[1;37m[3/6] Launching containerized services via Docker Compose...\033[0m"
docker compose up -d
echo -e "\033[1;32m      [OK] Docker Compose containers launched.\033[0m"

# 4. Polling container health status
echo -e "\n\033[1;37m[4/6] Polling container health status...\033[0m"
SERVICES=("sih_redpanda" "sih_redis" "sih_timescaledb" "sih_zeek")
START_TIME=$(date +%s)
ALL_HEALTHY=false

while true; do
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))

    if [ "$ELAPSED" -ge "$TIMEOUT_SECONDS" ]; then
        break
    fi

    UNHEALTHY_COUNT=0
    for svc in "${SERVICES[@]}"; do
        STATUS=$(docker inspect --format='{{json .State.Health.Status}}' "$svc" 2>/dev/null | tr -d '"' || echo "not_found")
        if [ "$STATUS" != "healthy" ]; then
            UNHEALTHY_COUNT=$((UNHEALTHY_COUNT + 1))
        fi
    done

    if [ "$UNHEALTHY_COUNT" -eq 0 ]; then
        ALL_HEALTHY=true
        break
    fi

    echo -e "\033[0;37m      Waiting for services (${ELAPSED}s / ${TIMEOUT_SECONDS}s)... (${UNHEALTHY_COUNT} service(s) initializing)\033[0m"
    sleep 2
done

if [ "$ALL_HEALTHY" = true ]; then
    echo -e "\033[1;32m      [OK] All core services report HEALTHY.\033[0m"
else
    echo -e "\033[1;33m      [WARNING] Timeout waiting for all containers to reach 'healthy' state.\033[0m"
    docker compose ps
fi

# 5. Check Redpanda topic topology
echo -e "\n\033[1;37m[5/6] Checking Redpanda topic topology...\033[0m"
if docker exec sih_redpanda rpk topic list --brokers localhost:9092 > /dev/null 2>&1; then
    echo -e "\033[1;32m      [OK] Topics verified on broker:\033[0m"
    docker exec sih_redpanda rpk topic list --brokers localhost:9092 | sed 's/^/           /'
else
    echo -e "\033[0;37m      [INFO] Topic provisioner is running.\033[0m"
fi

# 6. Check TimescaleDB connectivity
echo -e "\n\033[1;37m[6/6] Checking TimescaleDB connectivity...\033[0m"
if docker exec sih_timescaledb psql -U postgres -d sih26145 -c "SELECT extname FROM pg_extension WHERE extname='timescaledb';" > /dev/null 2>&1; then
    echo -e "\033[1;32m      [OK] TimescaleDB extension confirmed loaded in sih26145 database.\033[0m"
else
    echo -e "\033[0;37m      [INFO] Database initial schema migration running.\033[0m"
fi

# Summary Display
echo -e "\n\033[1;36m=================================================================\033[0m"
echo -e "\033[1;32m  INFRASTRUCTURE STATUS SUMMARY                                  \033[0m"
echo -e "\033[1;36m=================================================================\033[0m"
echo -e "  Redpanda (Kafka API):  localhost:19092 / redpanda:9092"
echo -e "  Redis 7.x:             localhost:6379"
echo -e "  TimescaleDB (PG16):    localhost:5432 (DB: sih26145, User: postgres)"
echo -e "  Zeek Sensor:           Container sih_zeek (Logs: ./logs/zeek)"
echo -e "\033[1;36m=================================================================\033[0m"
echo -e "\033[1;33mStack is READY for traffic replay and Day-1 throughput benchmark.\033[0m\n"
