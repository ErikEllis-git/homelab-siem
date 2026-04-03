#!/usr/bin/env python3
"""
anomaly_detector.py — Phase 3: AI-Powered SIEM Anomaly Detection

Pipeline:
  1. Query Elasticsearch for suspicious events in the last 60 minutes
  2. Send formatted logs to LiteLLM proxy for AI analysis
  3. Ship the AI's verdict to Telegram
"""

import os
import sys
import json
import re
import ipaddress
import requests
from datetime import datetime, timezone
from dotenv import dotenv_values
from pathlib import Path

from threat_intel import lookup_ips, format_enrichment_block
from geo_intel import geolocate, format_geo
from soc_dispatch import dispatch_anomaly, is_tg_suppressed, record_tg_alert

TELEGRAM_DEDUP_TTL = 7200  # 2 hr — anomaly_detector runs hourly; only alert every other run at most

# ── Configuration ─────────────────────────────────────────────────────────────

# Load both env files; ai-gateway holds the LiteLLM master key
env        = dotenv_values(Path.home() / ".env")
env_gw     = dotenv_values(Path.home() / "ai-gateway/.env")

ES_HOST           = "http://localhost:9200"
LITELLM_URL       = "http://localhost:4000/v1/chat/completions"
LITELLM_MODEL     = "openrouter/llama-3.3-70b"
LITELLM_KEY       = env_gw.get("LITELLM_MASTER_KEY", "")

TELEGRAM_TOKEN    = env.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID  = env.get("TELEGRAM_CHAT_ID", "")

LOOKBACK_MINUTES  = 60
MAX_EVENTS        = 100   # cap to keep the AI prompt manageable

# Phrases matched only against host auth logs (log_type: auth)
AUTH_PHRASES = [
    "Failed password",
    "Invalid user",
    "authentication failure",
    "BREAK-IN ATTEMPT",
    "Connection closed by invalid user",
    "error: maximum authentication attempts exceeded",
    "Accepted password",
    "permission denied",
    "segfault",
]

# Phrases matched only against Docker container logs (not host auth)
CONTAINER_PHRASES = [
    "OOMKill",
    "exited with code",
    "container died",
    "health_status: unhealthy",
]

# ── System prompt ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a Senior SOC (Security Operations Center) Analyst reviewing \
security and operational logs from a private homelab. The environment consists of 3 nodes:
  - orchestrator: runs Elasticsearch, LiteLLM, Suricata IDS, Docker Swarm manager
  - worker-1: Docker Swarm worker, Filebeat, Fail2ban
  - worker-2: Docker Swarm worker, Filebeat, Fail2ban
All nodes are connected via Tailscale VPN. Auth and syslog from all 3 nodes ship to Elasticsearch.

Analyze the provided log events and determine:
  1. Whether any events represent genuine security threats or operational anomalies
  2. A severity rating: CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
  3. Which node(s) are involved
  4. A specific recommendation

Trusted internal IPs (never flag these as attackers or sources of malicious activity):
  - All IPs in 100.64.0.0/10 (entire Tailscale CGNAT range — all Tailscale SSH sessions are legitimate)
  - All IPs in 192.168.0.0/16 (RFC-1918 LAN range)
  - All IPs in 10.0.0.0/8 (RFC-1918 range)
  - Any IP in 203.0.113.0/24 or 198.51.100.0/24 (RFC 5737 purple team synthetic ranges — internal security testing only, never real attackers)

Expected scheduled activity (do NOT flag as threats):
  - Port scan traffic sourced from orchestrator LAN/Tailscale IP: orchestrator runs a \
    scheduled nmap scan of the LAN every 30 minutes as part of its network_scan.py \
    monitoring script. Port scan signatures triggered by these source IPs are \
    INFORMATIONAL, not attacks.
  - Outbound connections from rosse to ip-api.com: GeoIP enrichment by SIEM scripts.
  - Outbound connections from rosse to api.telegram.org: SIEM alert delivery.

Rules:
- Routine CRON PAM session open/close events are INFORMATIONAL noise — note their \
  volume but do not flag them as threats unless the frequency is abnormal.
- SSH events originating from the trusted internal IPs above are expected cluster \
  activity — do NOT recommend blocking them.
- CROSS-NODE ATTACKS are HIGH priority: if the same external IP appears in logs from \
  multiple nodes, treat this as coordinated reconnaissance or a distributed attack. \
  Escalate severity by one level.
- Focus on: repeated SSH failures, successful logins from unexpected sources, \
  privilege escalation, container crashes, OOM kills, lateral-movement patterns, \
  and Suricata IDS alerts (especially severity 1 critical signatures).
- Be concise. Your entire response must fit in ~300 words.

Respond in exactly this format:
SEVERITY: <level>
THREAT: <Yes | No | Uncertain>
NODES AFFECTED: <list>
CROSS-NODE: <Yes | No>  (Yes if same external IP seen on 2+ nodes)
SUMMARY: <2-3 sentences>
RECOMMENDATION: <specific action, or "Monitor only">"""

# ── Step 1: Fetch suspicious logs from Elasticsearch ──────────────────────────

def fetch_logs() -> list[dict]:
    # Auth log events: any host-level auth event matching known suspicious phrases
    auth_clause = {
        "bool": {
            "filter": [{"term": {"log_type": "auth"}}],
            "should": [{"match_phrase": {"message": p}} for p in AUTH_PHRASES],
            "minimum_should_match": 1,
        }
    }
    # Container crash/OOM events: Docker logs only
    container_clause = {
        "bool": {
            "filter": [{"exists": {"field": "container.name"}}],
            "should": [{"match_phrase": {"message": p}} for p in CONTAINER_PHRASES],
            "minimum_should_match": 1,
        }
    }
    # Suricata IDS alerts (severity 1+2 only — skip noisy sev3)
    suricata_clause = {
        "bool": {
            "filter": [
                {"term": {"log_type": "suricata"}},
                {"term": {"event_type": "alert"}},
                {"terms": {"alert.severity": [1, 2]}},
            ]
        }
    }
    query = {
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{LOOKBACK_MINUTES}m"}}}
                ],
                "should": [auth_clause, container_clause, suricata_clause],
                "minimum_should_match": 1,
            }
        },
        "size": MAX_EVENTS,
        "sort": [{"@timestamp": {"order": "desc"}}],  # newest first so cap keeps recent events
        "_source": [
            "@timestamp",
            "message",
            "host.name",
            "log_type",
            "event_type",
            "container.name",
            "input.type",
            "alert.signature",
            "alert.severity",
            "alert.category",
            "src_ip",
            "dest_ip",
            "proto",
        ],
    }

    resp = requests.post(
        f"{ES_HOST}/filebeat-*/_search",
        json=query,
        headers={"Content-Type": "application/json"},
        timeout=15,
    )
    resp.raise_for_status()
    hits = resp.json()["hits"]["hits"]
    print(f"[ES]  {len(hits)} events matched (lookback: {LOOKBACK_MINUTES}m, cap: {MAX_EVENTS})")
    return hits


def format_logs(hits: list[dict]) -> str:
    if not hits:
        return "No suspicious events found in the specified time window."

    header = (
        f"=== SIEM Log Report  |  "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  |  "
        f"{len(hits)} events ===\n"
    )
    rows = []
    for hit in hits:
        src       = hit["_source"]
        ts        = src.get("@timestamp", "")[:19].replace("T", " ")
        host      = (src.get("host") or {}).get("name", "unknown")

        if src.get("log_type") == "suricata":
            sig      = src.get("alert.signature") or (src.get("alert") or {}).get("signature", "unknown")
            sev      = src.get("alert.severity") or (src.get("alert") or {}).get("severity", "?")
            cat      = src.get("alert.category") or (src.get("alert") or {}).get("category", "")
            src_ip   = src.get("src_ip", "?")
            dest_ip  = src.get("dest_ip", "?")
            proto    = src.get("proto", "?")
            rows.append(f"{ts}  {host:<10} [suricata-sev{sev}]         {src_ip} -> {dest_ip} [{proto}] {sig}" + (f" ({cat})" if cat else ""))
        else:
            container = (src.get("container") or {}).get("name", "")
            origin    = f"[{container}]" if container else "[host]"
            message   = src.get("message", "").strip()
            if len(message) > 250:
                message = message[:247] + "..."
            rows.append(f"{ts}  {host:<10} {origin:<28} {message}")

    return header + "\n".join(rows)


# ── Cross-node IP correlation ──────────────────────────────────────────────────

# Configure: set TRUSTED_NODE_IPS in .env as a comma-separated list of your cluster node IPs
TRUSTED_IPS = set(filter(None, env.get("TRUSTED_NODE_IPS", "").split(",")))
TRUSTED_PREFIXES = ("127.", "::1", "10.", "192.168.", "203.0.113.", "198.51.100.")  # last two: RFC 5737 purple team test nets
# Tailscale assigns addresses from the CGNAT range 100.64.0.0/10 — never flag these
TAILSCALE_NET = ipaddress.ip_network("100.64.0.0/10")

def is_internal(ip: str) -> bool:
    if ip in TRUSTED_IPS:
        return True
    if any(ip.startswith(p) for p in TRUSTED_PREFIXES):
        return True
    try:
        return ipaddress.ip_address(ip) in TAILSCALE_NET
    except ValueError:
        return False


def filter_trusted_hits(hits: list[dict]) -> list[dict]:
    """Drop events where every extracted IP is trusted/internal.

    - Auth events: drop if all IPs in the message are internal.
    - Suricata events: drop if src_ip is internal (catches network_scan.py noise
      from the orchestrator and other cluster nodes generating false scan alerts).
    - Container events: passed through unchanged.
    """
    ip_pattern = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
    filtered = []
    for hit in hits:
        src = hit["_source"]
        log_type = src.get("log_type")

        if log_type == "suricata":
            src_ip = src.get("src_ip", "")
            if src_ip and is_internal(src_ip):
                continue  # drop — internal source (e.g. network_scan.py on rosse)
            filtered.append(hit)
            continue

        if log_type != "auth":
            filtered.append(hit)
            continue

        ips = {m.group(1) for m in ip_pattern.finditer(src.get("message", ""))}
        if src.get("src_ip"):
            ips.add(src["src_ip"])
        external = [ip for ip in ips if not is_internal(ip)]
        if external or not ips:
            filtered.append(hit)
    return filtered


def cross_node_summary(hits: list[dict]) -> str:
    """Return a summary of external IPs seen on more than one node."""
    import re
    from collections import defaultdict

    ip_to_nodes: dict[str, set] = defaultdict(set)
    ip_pattern = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')

    for hit in hits:
        src = hit["_source"]
        # Get the node this event came from
        node = (src.get("host") or {}).get("name") or src.get("host_name", "unknown")
        # Collect IPs from message and explicit src_ip field
        candidate_ips = set()
        if src.get("src_ip"):
            candidate_ips.add(src["src_ip"])
        for m in ip_pattern.finditer(src.get("message", "")):
            candidate_ips.add(m.group(1))
        for ip in candidate_ips:
            if not is_internal(ip):
                ip_to_nodes[ip].add(node)

    multi_node = {ip: nodes for ip, nodes in ip_to_nodes.items() if len(nodes) > 1}
    if not multi_node:
        return ""

    lines = ["=== CROSS-NODE ACTIVITY DETECTED ==="]
    for ip, nodes in sorted(multi_node.items(), key=lambda x: -len(x[1])):
        lines.append(f"  {ip} seen on: {', '.join(sorted(nodes))}")
    return "\n".join(lines)


# ── Step 2: AI analysis via LiteLLM proxy ─────────────────────────────────────

def analyze(log_text: str) -> str:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {LITELLM_KEY}",
    }
    payload = {
        "model": LITELLM_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": f"Analyse these logs:\n\n{log_text}"},
        ],
        "temperature": 0.1,
        "max_tokens": 2000,   # reasoning models need headroom before producing content
    }

    print(f"[AI]  Sending {len(log_text):,} chars to LiteLLM ({LITELLM_MODEL})...")
    resp = requests.post(LITELLM_URL, json=payload, headers=headers, timeout=120)
    resp.raise_for_status()

    msg = resp.json()["choices"][0]["message"]
    # Reasoning models (DeepSeek-R1, etc.) put the answer in content;
    # if the model ran out of tokens during reasoning, fall back to reasoning_content.
    analysis = msg.get("content") or msg.get("reasoning_content") or ""
    analysis = analysis.strip()
    if not analysis:
        raise ValueError(f"Empty response from model. Full message: {json.dumps(msg)}")
    print(f"[AI]  Response received ({len(analysis)} chars)")
    return analysis


# ── Step 3: Telegram alert ─────────────────────────────────────────────────────

def should_alert(analysis: str, has_cross_node: bool = False) -> bool:
    """Suppress alert only when AI is certain there is nothing of interest."""
    if has_cross_node:
        return True  # always alert on cross-node activity
    lower = analysis.lower()
    return not ("severity: informational" in lower and "threat: no" in lower)


def _format_analysis(analysis: str) -> str:
    """Reformat the AI key:value response into clean Telegram Markdown."""
    label_map = {
        "SEVERITY":       "Severity",
        "THREAT":         "Threat",
        "NODES AFFECTED": "Nodes",
        "CROSS-NODE":     "Cross-node",
        "SUMMARY":        "Summary",
        "RECOMMENDATION": "Action",
    }
    lines = [l.rstrip() for l in analysis.splitlines()]
    out = []
    for line in lines:
        matched = False
        for key, label in label_map.items():
            if line.upper().startswith(key + ":"):
                value = line[len(key) + 1:].strip()
                out.append(f"*{label}:* {value}")
                matched = True
                break
        if not matched and line:
            out.append(line)
    return "\n".join(out)


def send_telegram(analysis: str, event_count: int) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[TG]  Token or Chat ID missing — skipping Telegram alert.")
        return

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    formatted = _format_analysis(analysis)
    text = (
        f"🔍 *SIEM Anomaly*\n"
        f"_{now} · {event_count} events · {LOOKBACK_MINUTES}m window_\n\n"
        f"{formatted}"
    )

    url  = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    resp = requests.post(
        url,
        json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"},
        timeout=15,
    )
    if resp.ok:
        mid = resp.json().get("result", {}).get("message_id", "?")
        print(f"[TG]  Alert sent  (message_id: {mid})")
    else:
        print(f"[TG]  Send failed: {resp.status_code} — {resp.text[:200]}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n[anomaly_detector] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # 1 — Fetch
    hits     = fetch_logs()
    before   = len(hits)
    hits     = filter_trusted_hits(hits)
    dropped  = before - len(hits)
    if dropped:
        print(f"[filter] Dropped {dropped} trusted-IP auth event(s)")
    log_text = format_logs(hits)

    cross = cross_node_summary(hits)
    if cross:
        print(f"\n[CORRELATION]\n{cross}\n")
        log_text = cross + "\n\n" + log_text

    # Threat intel enrichment — check all external IPs against abuse.ch feeds
    all_ips = set()
    ip_pattern = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
    for hit in hits:
        src = hit["_source"]
        if src.get("src_ip"):
            all_ips.add(src["src_ip"])
        for m in ip_pattern.finditer(src.get("message", "")):
            all_ips.add(m.group(1))
    external_ips = [ip for ip in all_ips if not is_internal(ip)]
    ti_hits = lookup_ips(external_ips)
    if ti_hits:
        ti_block = format_enrichment_block(ti_hits)
        print(f"\n[THREAT INTEL]\n{ti_block}\n")
        log_text = ti_block + "\n\n" + log_text
    else:
        print("[THREAT INTEL] no abuse.ch matches")

    geo_hits = geolocate(external_ips)
    if geo_hits:
        geo_lines = ["=== GEO ENRICHMENT ==="]
        for ip, g in geo_hits.items():
            geo_lines.append(f"  {ip} — {format_geo(g)}")
        geo_block = "\n".join(geo_lines)
        print(f"[GEO] {len(geo_hits)} IP(s) enriched")
        log_text = geo_block + "\n\n" + log_text

    if hits:
        print(f"[preview] {log_text.splitlines()[0]}")

    # 2 — Analyse
    if not hits:
        print("✓ No suspicious events — skipping AI call.\n")
        return
    try:
        analysis = analyze(log_text)
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            print("[AI]  Rate limited (429) — skipping this cycle.\n")
            return
        raise
    print(f"\n[AI ANALYSIS]\n{analysis}\n")

    # 3 — Alert / Escalate
    severity_line = next(
        (l for l in analysis.splitlines() if l.startswith("SEVERITY:")), ""
    )
    severity = severity_line.replace("SEVERITY:", "").strip().upper()
    threat_line = next(
        (l for l in analysis.splitlines() if l.startswith("THREAT:")), ""
    )
    threat = threat_line.replace("THREAT:", "").strip()
    nodes_line = next(
        (l for l in analysis.splitlines() if l.startswith("NODES AFFECTED:")), ""
    )
    nodes = nodes_line.replace("NODES AFFECTED:", "").strip()
    summary_line = next(
        (l for l in analysis.splitlines() if l.startswith("SUMMARY:")), ""
    )
    summary = summary_line.replace("SUMMARY:", "").strip()
    rec_line = next(
        (l for l in analysis.splitlines() if l.startswith("RECOMMENDATION:")), ""
    )
    recommendation = rec_line.replace("RECOMMENDATION:", "").strip()

    if severity == "CRITICAL":
        # Hand off to Claude for full live investigation
        print(f"[SOC] CRITICAL event — escalating to Claude for investigation...")
        ti_summary = format_enrichment_block(ti_hits) if ti_hits else None
        dispatched = dispatch_anomaly(
            severity=severity,
            threat=threat,
            nodes_affected=nodes,
            summary=summary,
            recommendation=recommendation,
            cross_node=bool(cross),
            threat_intel=ti_summary,
            raw_log_sample=log_text[:800],
        )
        if not dispatched:
            print("[SOC] dispatch failed — falling back to simple Telegram alert")
            send_telegram(analysis, len(hits))
    elif severity == "HIGH":
        # HIGH: short Telegram only — no full Claude investigation
        tg_key = f"anomaly_tg:HIGH"
        if not is_tg_suppressed(tg_key, ttl=TELEGRAM_DEDUP_TTL):
            print("[TG]  HIGH severity — sending short Telegram alert...")
            send_telegram(analysis, len(hits))
            record_tg_alert(tg_key, ttl=TELEGRAM_DEDUP_TTL)
        else:
            print(f"[TG]  Suppressed — HIGH already alerted within {TELEGRAM_DEDUP_TTL//60}m")
    elif should_alert(analysis, has_cross_node=bool(cross)):
        tg_key = f"anomaly_tg:{severity}"
        if not is_tg_suppressed(tg_key, ttl=TELEGRAM_DEDUP_TTL):
            print("[TG]  Severity warrants an alert — sending...")
            send_telegram(analysis, len(hits))
            record_tg_alert(tg_key, ttl=TELEGRAM_DEDUP_TTL)
        else:
            print(f"[TG]  Suppressed — {severity} already alerted within {TELEGRAM_DEDUP_TTL//60}m")
    else:
        print("[TG]  INFORMATIONAL / no threat — alert suppressed.")

    print("\n✓ Pipeline complete.\n")


if __name__ == "__main__":
    main()
