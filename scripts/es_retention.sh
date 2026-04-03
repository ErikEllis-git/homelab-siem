#!/bin/bash
# es_retention.sh — Delete Filebeat docs older than 30 days
# Runs via cron, logs to siem/scripts/cron.log

ES="http://localhost:9200"
DAYS=30
LOG="/home/rosse/siem/scripts/cron.log"

echo "" >> "$LOG"
echo "── ES Retention $(date '+%Y-%m-%d %H:%M:%S') ──" >> "$LOG"

RESULT=$(curl -s -X POST "$ES/filebeat-*/_delete_by_query?conflicts=proceed" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"range\":{\"@timestamp\":{\"lt\":\"now-${DAYS}d\"}}}}")

DELETED=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('deleted', 0))" 2>/dev/null)
echo "Deleted $DELETED docs older than ${DAYS} days" >> "$LOG"
