#!/bin/bash
# Send a Telegram crash alert. Usage: tg_crash_alert.sh "message text"
# Loads TELEGRAM_TOKEN and TELEGRAM_CHAT_ID from /home/rosse/.env
set -euo pipefail

ENV_FILE="/home/rosse/.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "ERROR: $ENV_FILE not found" >&2
    exit 1
fi

# shellcheck source=/dev/null
source "$ENV_FILE"

if [ -z "${TELEGRAM_TOKEN:-}" ] || [ -z "${TELEGRAM_CHAT_ID:-}" ]; then
    echo "ERROR: TELEGRAM_TOKEN or TELEGRAM_CHAT_ID not set in $ENV_FILE" >&2
    exit 1
fi

MESSAGE="${1:-CRASH ALERT - no message provided}"

curl -s "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_CHAT_ID}&text=${MESSAGE}" > /dev/null
