#!/usr/bin/env python3
"""
brute_watch.py — Fast SSH brute force detector.

Runs every 5 minutes via cron. Queries ES for failed SSH logins across
all nodes in the last 5 minutes. Fires an immediate Telegram alert if
any external IP exceeds the failure threshold.
"""

import re
import subprocess
import sys
import os
from collections import defaultdict
from datetime import datetime

import requests
from dotenv import dotenv_values

sys.path.insert(0, os.path.dirname(__file__))
from threat_intel import lookup_ips
from geo_intel import geolocate, format_geo
from soc_dispatch import dispatch_brute_force, is_tg_suppressed, record_tg_alert

TELEGRAM_DEDUP_TTL = 1800  # 30 min — at most one Telegram alert per IP per 30 min

env = dotenv_values("/home/rosse/.env")
TELEGRAM_TOKEN   = env.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = env.get("TELEGRAM_CHAT_ID", "")
ES_HOST          = "http://localhost:9200"
THRESHOLD        = 10   # failures within LOOKBACK to trigger alert
LOOKBACK         = "5m"

# Configure: set TRUSTED_NODE_IPS in .env as a comma-separated list of your cluster node IPs
TRUSTED_IPS = set(filter(None, env.get("TRUSTED_NODE_IPS", "").split(",")))
TRUSTED_PREFIXES = ("127.", "::1", "10.", "192.168.", "203.0.113.", "198.51.100.")  # last two: RFC 5737 purple team test nets

# Matches: "from 1.2.3.4 port" in auth log lines
IP_RE = re.compile(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port')


def is_internal(ip: str) -> bool:
    return ip in TRUSTED_IPS or any(ip.startswith(p) for p in TRUSTED_PREFIXES)


def is_blocked(ip: str) -> bool:
    """Return True if ip already has a DROP rule in iptables INPUT chain."""
    try:
        result = subprocess.run(
            ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def fetch_failures() -> list[dict]:
    query = {
        "size": 500,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"log_type": "auth"}},
                    {"range": {"@timestamp": {"gte": f"now-{LOOKBACK}"}}},
                ],
                "should": [
                    {"match_phrase": {"message": "Failed password"}},
                    {"match_phrase": {"message": "Invalid user"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "_source": ["message", "host.name", "host_name"],
    }
    resp = requests.post(
        f"{ES_HOST}/filebeat-*/_search",
        json=query,
        headers={"Content-Type": "application/json"},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["hits"]["hits"]


def send_telegram(text: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[TG] not configured")
        return
    requests.post(
        f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
        json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"},
        timeout=15,
    )


def main() -> None:
    hits = fetch_failures()
    if not hits:
        return

    # Aggregate failure counts: ip -> node -> count
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for hit in hits:
        src  = hit["_source"]
        node = (src.get("host") or {}).get("name") or src.get("host_name", "unknown")
        m    = IP_RE.search(src.get("message", ""))
        if m:
            ip = m.group(1)
            if not is_internal(ip):
                counts[ip][node] += 1

    alerts = []
    for ip, nodes in counts.items():
        total = sum(nodes.values())
        if total >= THRESHOLD:
            node_str = ", ".join(f"{n}:{c}" for n, c in sorted(nodes.items()))
            alerts.append((total, ip, node_str))

    if not alerts:
        return

    alerts.sort(reverse=True)

    # Skip IPs already blocked in iptables — Suricata still fires on them but there's nothing to do
    alerts = [(t, ip, n) for t, ip, n in alerts if not is_blocked(ip)]
    if not alerts:
        print("[brute_watch] all triggering IPs already blocked — nothing to do")
        return

    ti  = lookup_ips([a[1] for a in alerts])
    geo = geolocate([a[1] for a in alerts])

    # Filter to IPs not recently alerted (dedup suppresses repeat floods)
    tg_alerts = [
        (total, ip, nodes) for total, ip, nodes in alerts
        if not is_tg_suppressed(f"brute_tg:{ip}", ttl=TELEGRAM_DEDUP_TTL)
    ]
    suppressed = len(alerts) - len(tg_alerts)
    if suppressed:
        print(f"[brute_watch] suppressed {suppressed} IP(s) — already alerted within {TELEGRAM_DEDUP_TTL//60}m")

    if tg_alerts:
        now   = datetime.now().strftime("%H:%M:%S")
        lines = [
            "🚨 *SSH Brute Force Detected*",
            f"_{now} — last {LOOKBACK}_",
            "",
        ]
        for total, ip, nodes in tg_alerts:
            cross     = " ⚡ MULTI-NODE" if "," in nodes else ""
            intel     = ti.get(ip)
            intel_str = f" — _{intel['malware']} ({intel['source']})_" if intel else ""
            geo_str   = f" [{format_geo(geo[ip])}]" if geo.get(ip) else ""
            lines.append(f"`{ip}`{geo_str} — {total} failures ({nodes}){cross}{intel_str}")
        send_telegram("\n".join(lines))
        for _, ip, _ in tg_alerts:
            record_tg_alert(f"brute_tg:{ip}", ttl=TELEGRAM_DEDUP_TTL)
        print(f"[brute_watch] alerted on {len(tg_alerts)} IP(s): {[a[1] for a in tg_alerts]}")

    # Escalate to Claude for full investigation if multi-node or known malware
    should_escalate = any(
        ("," in nodes) or ti.get(ip)
        for _, ip, nodes in alerts
    )
    if should_escalate:
        dispatch_brute_force([
            {
                "ip":             ip,
                "total_failures": total,
                "nodes":          nodes,
                "intel":          f"{ti[ip]['malware']} ({ti[ip]['source']})" if ti.get(ip) else None,
            }
            for total, ip, nodes in alerts
        ], lookback=LOOKBACK)


if __name__ == "__main__":
    main()
