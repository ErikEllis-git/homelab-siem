#!/bin/bash
# honeypot_deploy.sh — reproduce the honeypot VPS container stack.
#
# Runs ON the honeypot VM (Oracle Cloud Always Free, Ubuntu 24.04, user `ubuntu`).
# Assumes Docker + Tailscale already installed and the repo's honeypot/ dir present
# at ~/webhoneypot (app.py + Dockerfile) and ~/cowrie/etc/cowrie.cfg in place.
#
# There is NO docker-compose for the honeypot (kept as plain `docker run` for
# simplicity on a single throwaway box). This script IS the source of truth for
# how the three containers are launched. See vault Cluster/Honeypot.md for the
# full architecture + current IPs.
set -euo pipefail

ES_HOST="http://100.107.153.112:9200"   # rosee over Tailscale

# --- Cowrie: SSH honeypot, host :22 -> container :2222 ---
docker rm -f cowrie 2>/dev/null || true
mkdir -p ~/cowrie/var/lib/cowrie ~/cowrie/var/log/cowrie ~/cowrie/var/run
sudo chown -R 999:999 ~/cowrie/var         # cowrie container runs as uid 999
docker run -d --name cowrie --restart unless-stopped --memory 512m \
  -p 22:2222 \
  -v ~/cowrie/etc:/cowrie/cowrie-git/etc \
  -v ~/cowrie/var:/cowrie/cowrie-git/var \
  cowrie/cowrie:latest

# --- Web honeypot: Flask/gunicorn behind fake Apache headers, host :80 -> :8080 ---
cd ~/webhoneypot && docker build -t webhoneypot .
docker rm -f webhoneypot 2>/dev/null || true
docker run -d --name webhoneypot --restart unless-stopped --memory 512m \
  -p 80:8080 \
  -v ~/webhoneypot/logs:/app/logs \
  webhoneypot

# --- Filebeat: ships cowrie + web honeypot logs to rosee's ES over Tailscale ---
docker rm -f filebeat-honeypot 2>/dev/null || true
docker run -d --name filebeat-honeypot --restart unless-stopped --memory 512m \
  --user root \
  -v ~/filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro \
  -v ~/cowrie/var/log/cowrie:/var/log/cowrie:ro \
  -v ~/webhoneypot/logs:/var/log/webhoneypot:ro \
  docker.elastic.co/beats/filebeat:8.15.0 filebeat -e --strict.perms=false

echo "Deployed. Verify: docker ps ; curl -sI http://localhost/wp-login.php"
