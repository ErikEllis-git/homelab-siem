# Honeypot deployment (separate host, not part of the Docker Swarm)

Runs on a standalone VPS (Oracle Cloud Always Free as of 2026-09-14, previously
Vultr) — see vault Cluster/Honeypot.md for current IP/access details, which
change whenever the VPS is rebuilt.

- `webhoneypot/` — Flask app faking Apache/2.4.57 + PHP/8.1.2, port 80 -> 8080.
  Reconstructed 2026-09-14 after the original source was lost with the old
  VPS (it was never committed here the first time around — this directory
  exists specifically so that does not happen again).
- Cowrie itself is NOT custom code — deployed straight from the official
  `cowrie/cowrie:latest` Docker image, config extracted from the image and
  tuned (download_limit_size=0). No source to commit here, just the deploy
  notes in the vault.
- Filebeat on the honeypot VPS is a standalone container (this VPS is not a
  Swarm member), config also documented in the vault, not committed here
  since it is host-specific (hardcoded ES_HOST IP).
