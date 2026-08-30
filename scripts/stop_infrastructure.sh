#!/usr/bin/env bash
# =============================================================================
# SIH26145 — Single-Command Infrastructure Teardown Script
# =============================================================================
set -euo pipefail

REMOVE_VOLUMES="${1:-}"

echo -e "\033[1;36m=================================================================\033[0m"
echo -e "\033[1;33m  SIH26145 — Stopping Containerized Infrastructure Stack         \033[0m"
echo -e "\033[1;36m=================================================================\033[0m"

if [ "$REMOVE_VOLUMES" != "-v" ] && [ "$REMOVE_VOLUMES" != "--volumes" ]; then
    echo -e "\033[1;37m[+] Stopping containers and preserving persistent data volumes...\033[0m"
    docker compose down --remove-orphans
else
    echo -e "\033[1;33m[+] Stopping containers and wiping persistent data volumes...\033[0m"
    docker compose down -v --remove-orphans
fi

echo -e "\033[1;32m[OK] SIH26145 Infrastructure stack stopped cleanly.\033[0m"
