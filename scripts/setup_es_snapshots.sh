#!/bin/bash
# One-time ES snapshot repo + SLM policy setup (P2-2). ES runtime state, not a
# file, so this script documents/reproduces it. Requires path.repo mounted
# (see docker-compose.yml es_snapshots volume). Idempotent.
set -e
ES=http://localhost:9200
curl -s -X PUT "$ES/_snapshot/homelab_backup" -H "Content-Type: application/json" \
  -d "{\"type\":\"fs\",\"settings\":{\"location\":\"/usr/share/elasticsearch/snapshots\",\"compress\":true}}"
curl -s -X PUT "$ES/_slm/policy/daily-homelab" -H "Content-Type: application/json" \
  -d "{\"schedule\":\"0 30 2 * * ?\",\"name\":\"<homelab-{now/d}>\",\"repository\":\"homelab_backup\",\"config\":{\"indices\":[\"*\"],\"include_global_state\":true},\"retention\":{\"expire_after\":\"14d\",\"min_count\":3,\"max_count\":30}}"
echo "done. manual snapshot: curl -X POST $ES/_slm/policy/daily-homelab/_execute"
echo "restore: curl -X POST $ES/_snapshot/homelab_backup/<snap>/_restore"
