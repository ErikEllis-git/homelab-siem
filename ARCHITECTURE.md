# Homelab SIEM — Architecture

## Cluster Overview

```mermaid
graph TD
    subgraph LAN ["Home LAN"]
        rosse["🖥️ rosse — Orchestrator\nDell Optiplex 7010\nLAN + Tailscale"]
        rikdell["💻 rikdell — Worker 1\nDell Inspiron\nTailscale"]
        lubunt["💻 lubunt — Worker 2\nChromebook/Lubuntu\nLAN + Tailscale"]
        olddell["💻 olddell — Worker 3\nLAN"]
    end

    subgraph VPS ["Public VPS (Vultr)"]
        honey["🍯 honey — Honeypot\n[redacted]\nCowrie SSH on :22\nReal SSH on :2222"]
    end

    subgraph Tailscale ["Tailscale Mesh (100.x.x.x)"]
        ts_note["All nodes connected\nEncrypted overlay network"]
    end

    subgraph SIEM ["SIEM Stack (on rosse)"]
        suricata["Suricata 7.0.3\nNetwork IDS\nwlx060c000a5f6e"]
        es["Elasticsearch\nlocalhost:9200\nindices: filebeat-*, cowrie-*, webhoneypot-*"]
        kibana["Kibana\nlocalhost:5601"]
        scripts["SIEM Scripts\n/home/rosse/siem/scripts/\nbrute_watch, anomaly_detector\ncorrelator, ml_detector"]
    end

    subgraph Alerting ["Alerting Pipeline"]
        ir["incident-responder\nlocalhost:8766\nwebhook receiver"]
        bot["claude-telegram bot\nlocalhost:8765\n@roseebot_bot"]
        claude["Claude AI\nSOC Analyst\nauto-investigates anomalies"]
        tg["📱 Telegram\nReal-time alerts"]
    end

    %% Filebeat ships logs to ES
    rikdell -- "filebeat → ES" --> es
    lubunt -- "filebeat → ES" --> es
    olddell -- "filebeat → ES" --> es
    rosse -- "filebeat + suricata → ES" --> es
    honey -- "cowrie logs → ES" --> es

    %% Kibana reads ES
    es --> kibana

    %% SIEM scripts query ES and fire webhooks
    es --> scripts
    scripts -- "webhook POST" --> ir
    ir -- "dispatch" --> bot
    bot -- "anomalies" --> claude
    claude -- "verdict + action" --> tg
    bot -- "brute force / honeypot" --> tg

    %% Tailscale connects everything
    rosse -. "Tailscale" .- rikdell
    rosse -. "Tailscale" .- lubunt
    rosse -. "Tailscale" .- honey
```

## Data Flow

```
Internet → [attack]
              │
    ┌─────────┴──────────────────────┐
    │                                │
🍯 Honeypot (honey)          🖥️ Cluster nodes
Cowrie catches sessions       Fail2ban + iptables
    │                                │
    └──────────┬─────────────────────┘
               │
          Filebeat ships logs
               │
               ▼
      Elasticsearch (rosse:9200)
               │
        ┌──────┴───────┐
        │              │
     Kibana         SIEM Scripts
   (dashboards)   (cron every 5–60m)
                       │
                 Webhook → incident-responder
                       │
               claude-telegram bot
                  /         \
           SSH brute       SIEM anomaly
           (direct TG)    (→ Claude AI)
                                │
                         Investigation +
                         auto-block if warranted
                                │
                         📱 Telegram report
```

## Node Roles

| Node    | Role            | Key Services                                                            |
|---------|-----------------|-------------------------------------------------------------------------|
| rosse   | Orchestrator    | ES, Kibana, Suricata, SIEM scripts, claude-telegram, incident-responder |
| rikdell | Swarm Worker 1  | Docker Swarm, Filebeat, Fail2ban                                        |
| lubunt  | Swarm Worker 2  | Docker Swarm, Filebeat, Fail2ban                                        |
| olddell | Swarm Worker 3  | Docker Swarm, Filebeat                                                  |
| honey   | Honeypot VPS    | Cowrie SSH, web honeypot                                                |

## Detection Layers

| Layer | Tool | What it catches |
|-------|------|-----------------|
| Network | Suricata | Malicious traffic, C2 beacons, port scans |
| Auth | Fail2ban | SSH brute force on worker nodes |
| Log correlation | brute_watch.py | Multi-node SSH attacks |
| Behavioral | anomaly_detector.py | Unusual login patterns, new services |
| ML | ml_detector.py | IsolationForest + LOF ensemble anomalies |
| Honeypot | Cowrie + cowrie_alerter.py | Attacker TTPs, credential spray lists |
| Threat intel | ThreatFox / Feodo | Known malware C2 IPs |
