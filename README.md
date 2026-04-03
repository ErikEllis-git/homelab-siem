# Homelab SIEM

A distributed security monitoring stack I built on three old machines: a Dell Optiplex, an old Dell Inspiron, and a Chromebook running Lubuntu. I connected them into a Docker Swarm cluster and built a SIEM on top of it, mostly to learn, but it's turned into something I actually use and keep improving.

---

## What's in here

### ELK Stack
Elasticsearch and Kibana run on the main node (the Optiplex), with Filebeat deployed as a global Docker Swarm service so every node ships its logs centrally. Auth logs, Docker container logs, and Suricata alerts all land in Elasticsearch. I have some Kibana dashboards but honestly I mostly query ES directly.

### Suricata
Running on the main node to monitor all network traffic. It feeds alerts straight into Elasticsearch via the EVE JSON log. Mostly I see port scans and probes that wouldn't show up in auth logs alone, which is exactly the point.

### SSH Hardening + Firewalls
Because I have Claude Code roaming across all nodes via SSH, I needed to lock things down properly. Key-based auth only, passwords disabled everywhere. iptables and fail2ban handle automated IP blocking, and I use Tailscale as a secure mesh VPN so I can SSH in from anywhere.

### Honeypot
My favourite part. I deployed Cowrie on a cheap VPS. Port 22 goes to the honeypot, port 2222 is real SSH. It has a fake shell and a fake filesystem. It's been live a few weeks and has caught real attacks, mostly SSH bots. I keep seeing a cryptominer called Redtail that uploads binaries, injects SSH keys, and tries to establish persistence. Everything gets logged to Elasticsearch.

### Multi-node Correlation
The correlator runs every 15 minutes and pulls three independent signal sources from Elasticsearch: Suricata scan alerts, SSH brute force attempts, and successful logins. It correlates them by attacker IP over a 2-hour window. An IP showing up in two or more categories indicates kill-chain progression that individual detectors would miss. SCAN + BRUTE is HIGH, anything involving a successful login is CRITICAL.

### Outbound Monitoring
Every 5 minutes the outbound monitor SSHes into all three nodes, pulls active connections via `ss`, and flags anything unexpected going outbound. Connections to known threat intel IPs on any port go straight to the SOC dispatcher. It deduplicates against the previous poll so persistent connections don't spam alerts.

### Machine Learning
I added an IsolationForest + Local Outlier Factor ensemble that runs against the SIEM data to flag anomalous behaviour. I'm still experimenting with it and tuning the thresholds, but it's caught a few things the rule-based detectors missed. There is also a separate ML pipeline on the web honeypot that uses DBSCAN clustering to group IPs by behaviour (what rules they hit, credential attempts, scanner vs targeted) and surfaces anything unusual.

### Purple Team Testing
Once a week `purple_team.py` runs a set of automated attack simulations against the cluster to verify the detection pipeline actually fires. It tests log ingestion latency across all three nodes, injects synthetic SSH brute force events into Elasticsearch to check brute_watch thresholds, and runs a real nmap scan against one of the worker nodes to confirm Suricata picks it up. If something goes undetected the weekly report flags it.

### Alerting: Claude as a SOC Analyst
When a high-severity event fires, I get a Telegram alert and Claude investigates it. It queries Elasticsearch for attacker history across all nodes, checks for live connections, cross-references IPs against abuse.ch and ThreatFox, then sends a plain-text report back to my phone. There are still occasional false positives but they're usually obvious.

---

## Stack

| Component     | Tech                                      |
|---------------|-------------------------------------------|
| Log shipping  | Filebeat 8.15 (global Docker Swarm)       |
| Storage       | Elasticsearch 8.15                        |
| Visualisation | Kibana 8.15                               |
| IDS           | Suricata 7                                |
| Honeypot      | Cowrie                                    |
| ML            | scikit-learn (IsolationForest, LOF, DBSCAN) |
| Alerting      | Telegram + Claude (via LiteLLM)           |
| VPN           | Tailscale                                 |
| Firewall      | iptables + fail2ban                       |

---

## Layout

```
siem/
├── docker-compose.yml          # Elasticsearch + Kibana (main node)
├── docker-compose-filebeat.yml # Filebeat global Swarm service
├── filebeat/
│   └── filebeat.yml            # Filebeat input/output config
├── scripts/
│   ├── brute_watch.py          # SSH brute force detector
│   ├── correlator.py           # Multi-node attack correlator
│   ├── anomaly_detector.py     # ML-based anomaly detection
│   ├── ml_detector.py          # IsolationForest + LOF pipeline
│   ├── feature_extractor.py    # Feature engineering from ES logs
│   ├── feature_store.py        # SQLite feature cache
│   ├── threat_intel.py         # AbuseIPDB / ThreatFox lookups
│   ├── geo_intel.py            # IP geolocation
│   ├── incident_responder.py   # Webhook receiver for IR actions
│   ├── soc_dispatch.py         # Routes alerts to Claude or Telegram
│   ├── suricata_alerter.py     # Suricata EVE → Telegram alerts
│   ├── honeypot_analyzer.py    # Cowrie session analysis
│   ├── web_honeypot_analyzer.py# Web honeypot ML clustering + alerting
│   ├── outbound_monitor.py     # Unexpected outbound connection detection
│   ├── network_scan.py         # LAN device inventory
│   ├── purple_team.py          # Weekly automated detection coverage tests
│   ├── es_retention.sh         # Index cleanup
│   └── requirements.txt
└── systemd/
    ├── suricata-alerter.service
    └── incident-responder.service
```

---

## Setup

**Requirements:** Docker, Docker Swarm initialised, Python 3.12+, Suricata, Tailscale

```bash
# 1. Start Elasticsearch + Kibana
docker compose -f docker-compose.yml up -d

# 2. Deploy Filebeat to all Swarm nodes
docker stack deploy -c docker-compose-filebeat.yml filebeat

# 3. Python env
cd scripts
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 4. Environment variables
cp ../.env.example ../.env
# fill in TELEGRAM_TOKEN, TELEGRAM_CHAT_ID, IR_WEBHOOK_SECRET

# 5. Systemd services (main node)
sudo cp ../systemd/suricata-alerter.service /etc/systemd/system/
sudo cp ../systemd/incident-responder.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now suricata-alerter incident-responder
```

---

## How alerts work

```
auth.log / suricata / cowrie logs
        ↓
    Filebeat (all nodes)
        ↓
  Elasticsearch
        ↓
  brute_watch / anomaly_detector / correlator (cron)
        ↓
  soc_dispatch.py
     ├── low severity  → plain Telegram message
     └── high severity → Claude investigates → Telegram report
```

---

Built on a Dell Optiplex 7010, a Dell Inspiron, and a Chromebook. Total hardware cost: $0.
