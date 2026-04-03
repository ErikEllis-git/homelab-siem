#!/usr/bin/env python3
"""
correlator.py — Cross-signal IP correlation engine.

Runs every 15 minutes via cron. Pulls three independent signal sources from ES
over a 2-hour lookback window and correlates them by attacker IP:

  SCAN    — Suricata IDS alert (port scan, exploit, recon signature)
  BRUTE   — SSH authentication failures
  ACCESS  — Successful SSH login from external IP

An IP appearing in 2+ categories within the window indicates kill-chain
progression that individual detectors would miss.

Scoring:
  SCAN + BRUTE           → HIGH    (recon → access attempt)
  BRUTE + ACCESS         → CRITICAL (brute force success)
  SCAN  + ACCESS         → CRITICAL (recon → successful entry)
  SCAN  + BRUTE + ACCESS → CRITICAL (full kill chain observed)

Run via cron every 15 minutes:
  */15 * * * * /opt/siem/scripts/.venv/bin/python3 /opt/siem/scripts/correlator.py >> /opt/siem/scripts/cron.log 2>&1
"""

import ipaddress
import json
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import dotenv_values

sys.path.insert(0, os.path.dirname(__file__))
from geo_intel import format_geo, geolocate
from soc_dispatch import dispatch_anomaly, is_tg_suppressed, record_tg_alert
from threat_intel import lookup_ips

# ── Config ───────────────────────────────────────────────────────────────────

LOOKBACK  = "2h"
DEDUP_TTL = 14400  # 4 hours — suppress re-escalation of the same IP
DEDUP_FILE = Path(__file__).parent / "correlator_dedup.json"

ES_HOST = "http://localhost:9200"

env = dotenv_values(Path.home() / ".env")
TELEGRAM_TOKEN   = env.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = env.get("TELEGRAM_CHAT_ID", "")

# IPs that are always trusted — never correlate, never alert
# Configure: set TRUSTED_NODE_IPS in .env as a comma-separated list of your cluster node IPs
TRUSTED_IPS = set(filter(None, env.get("TRUSTED_NODE_IPS", "").split(",")))
# Prefix-based trust (string match for speed)
TRUSTED_PREFIXES = ("127.", "::1", "203.0.113.", "198.51.100.")
# Network-based trust (covers RFC-1918, Tailscale CGNAT, loopback)
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),   # Tailscale CGNAT
    ipaddress.ip_network("127.0.0.0/8"),
]

IP_RE      = re.compile(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port')
SUCCESS_RE = re.compile(r'Accepted \S+ for \S+ from (\d{1,3}(?:\.\d{1,3}){3})\s+port')


def _is_trusted(ip: str) -> bool:
    if ip in TRUSTED_IPS:
        return True
    if any(ip.startswith(p) for p in TRUSTED_PREFIXES):
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return True  # unparseable → treat as trusted to avoid false positives


def _es_search(query: dict) -> list[dict]:
    resp = requests.post(
        f"{ES_HOST}/filebeat-*/_search",
        json=query,
        headers={"Content-Type": "application/json"},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["hits"]["hits"]


# ── Signal fetchers ──────────────────────────────────────────────────────────

def fetch_suricata_alerts() -> dict[str, dict]:
    """Return {src_ip: {nodes, sigs}} for external IPs seen in Suricata alerts."""
    hits = _es_search({
        "size": 500,
        "query": {
            "bool": {
                "filter": [
                    {"term":  {"log_type": "suricata"}},
                    {"term":  {"event_type": "alert"}},
                    {"range": {"@timestamp": {"gte": f"now-{LOOKBACK}"}}},
                ]
            }
        },
        "_source": ["src_ip", "alert.signature", "host.hostname", "agent.name"],
    })
    result: dict[str, dict] = defaultdict(lambda: {"nodes": set(), "sigs": []})
    for h in hits:
        src = h["_source"].get("src_ip", "")
        if not src or _is_trusted(src):
            continue
        node = (h["_source"].get("host", {}).get("hostname")
                or h["_source"].get("agent", {}).get("name", "unknown"))
        sig = (h["_source"].get("alert") or {}).get("signature", "unknown")
        result[src]["nodes"].add(node)
        if sig not in result[src]["sigs"]:
            result[src]["sigs"].append(sig)
    return dict(result)


def fetch_ssh_failures() -> dict[str, dict]:
    """Return {src_ip: {nodes, count}} for SSH failures across all nodes."""
    hits = _es_search({
        "size": 1000,
        "query": {
            "bool": {
                "filter": [
                    {"term":  {"log_type": "auth"}},
                    {"range": {"@timestamp": {"gte": f"now-{LOOKBACK}"}}},
                ],
                "should": [
                    {"match_phrase": {"message": "Failed password"}},
                    {"match_phrase": {"message": "Invalid user"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "_source": ["message", "host.hostname", "host_name"],
    })
    result: dict[str, dict] = defaultdict(lambda: {"nodes": set(), "count": 0})
    for h in hits:
        m = IP_RE.search(h["_source"].get("message", ""))
        if not m:
            continue
        ip = m.group(1)
        if _is_trusted(ip):
            continue
        node = (h["_source"].get("host", {}).get("hostname")
                or h["_source"].get("host_name", "unknown"))
        result[ip]["nodes"].add(node)
        result[ip]["count"] += 1
    return dict(result)


def fetch_ssh_successes() -> dict[str, dict]:
    """Return {src_ip: {nodes, users}} for successful SSH logins from external IPs."""
    hits = _es_search({
        "size": 200,
        "query": {
            "bool": {
                "filter": [
                    {"term":  {"log_type": "auth"}},
                    {"range": {"@timestamp": {"gte": f"now-{LOOKBACK}"}}},
                    {"match_phrase": {"message": "Accepted"}},
                ],
            }
        },
        "_source": ["message", "host.hostname", "host_name"],
    })
    result: dict[str, dict] = defaultdict(lambda: {"nodes": set(), "users": []})
    for h in hits:
        m = SUCCESS_RE.search(h["_source"].get("message", ""))
        if not m:
            continue
        ip = m.group(1)
        if _is_trusted(ip):
            continue
        node = (h["_source"].get("host", {}).get("hostname")
                or h["_source"].get("host_name", "unknown"))
        user_m = re.search(r'Accepted \S+ for (\S+) from', h["_source"].get("message", ""))
        user = user_m.group(1) if user_m else "unknown"
        result[ip]["nodes"].add(node)
        if user not in result[ip]["users"]:
            result[ip]["users"].append(user)
    return dict(result)


# ── Correlation ──────────────────────────────────────────────────────────────

def correlate(scans: dict, failures: dict, successes: dict) -> list[dict]:
    """
    Return scored events for every IP present in 2+ signal categories.
    Sorted CRITICAL-first, then by signal count descending.
    """
    all_ips = set(scans) | set(failures) | set(successes)
    events = []
    for ip in all_ips:
        has_scan   = ip in scans
        has_brute  = ip in failures
        has_access = ip in successes
        if sum([has_scan, has_brute, has_access]) < 2:
            continue

        nodes: set[str] = set()
        if has_scan:   nodes |= scans[ip]["nodes"]
        if has_brute:  nodes |= failures[ip]["nodes"]
        if has_access: nodes |= successes[ip]["nodes"]

        severity = "CRITICAL" if has_access else "HIGH"

        stages = []
        if has_scan:
            sigs = scans[ip]["sigs"]
            stages.append(f"SCAN ({', '.join(sigs[:2])}{'…' if len(sigs) > 2 else ''})")
        if has_brute:
            stages.append(f"BRUTE ({failures[ip]['count']} failures)")
        if has_access:
            stages.append(f"ACCESS (user: {', '.join(successes[ip]['users'])})")

        events.append({
            "ip":         ip,
            "severity":   severity,
            "stages":     stages,
            "nodes":      sorted(nodes),
            "has_scan":   has_scan,
            "has_brute":  has_brute,
            "has_access": has_access,
        })

    events.sort(key=lambda e: (
        0 if e["severity"] == "CRITICAL" else 1,
        -sum([e["has_scan"], e["has_brute"], e["has_access"]]),
    ))
    return events


# ── Dedup ────────────────────────────────────────────────────────────────────

def _load_dedup() -> dict:
    try:
        return json.loads(DEDUP_FILE.read_text())
    except Exception:
        return {}


def _is_suppressed(ip: str) -> bool:
    return (time.time() - _load_dedup().get(ip, 0)) < DEDUP_TTL


def _record(ip: str) -> None:
    state = _load_dedup()
    now = time.time()
    state = {k: v for k, v in state.items() if (now - v) < DEDUP_TTL}
    state[ip] = now
    DEDUP_FILE.write_text(json.dumps(state))


# ── Alerting ─────────────────────────────────────────────────────────────────

def send_telegram(text: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"},
            timeout=15,
        )
    except Exception as e:
        print(f"[TG] failed: {e}")


def _alert(ev: dict, intel: str | None) -> None:
    ip         = ev["ip"]
    severity   = ev["severity"]
    nodes_str  = ", ".join(ev["nodes"])
    stages_str = " → ".join(ev["stages"])
    geo        = format_geo(geolocate(ip))
    intel_tag  = f" | TI: {intel}" if intel else ""

    if severity == "CRITICAL" or intel:
        summary = (
            f"Multi-stage correlation from {ip} ({geo}): {stages_str}. "
            f"Nodes: {nodes_str}.{intel_tag}"
        )
        rec = (
            "Block this IP on all nodes immediately if ACCESS is confirmed. "
            "Investigate for lateral movement and persistence."
            if ev["has_access"] else
            "Monitor closely. Block if brute force volume is high or TI matched."
        )
        dispatched = dispatch_anomaly(
            severity=severity,
            threat=f"correlation:{ip}",
            nodes_affected=nodes_str,
            summary=summary,
            recommendation=rec,
            cross_node=len(ev["nodes"]) > 1,
            threat_intel=intel,
        )
        if dispatched:
            return
        # Fall through to Telegram if dispatch failed

    tg_key = f"correlator:{ip}"
    if not is_tg_suppressed(tg_key):
        intel_line = f"\n⚠️ *TI:* {intel}" if intel else ""
        send_telegram(
            f"🔗 *Correlation [{severity}]* `{ip}`\n"
            f"_{geo}_\n"
            f"`{stages_str}`\n"
            f"Nodes: {nodes_str}"
            f"{intel_line}"
        )
        record_tg_alert(tg_key)


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"\n[correlator] {ts}")

    scans     = fetch_suricata_alerts()
    failures  = fetch_ssh_failures()
    successes = fetch_ssh_successes()
    print(f"  signals: {len(scans)} scan IPs | {len(failures)} brute IPs | {len(successes)} access IPs")

    events = correlate(scans, failures, successes)
    print(f"  correlations: {len(events)} multi-signal IP(s)")

    if not events:
        print("  [ok] no correlated threats")
        return

    intel_map = lookup_ips([e["ip"] for e in events])
    new_events = 0

    for ev in events:
        ip        = ev["ip"]
        intel     = intel_map.get(ip)
        nodes_str = ", ".join(ev["nodes"])
        stages_str = " → ".join(ev["stages"])
        print(f"  [{ev['severity']}] {ip} | {stages_str} | nodes: {nodes_str}"
              + (f" | TI: {intel}" if intel else ""))

        if _is_suppressed(ip):
            print(f"  [dedup] {ip} suppressed (within {DEDUP_TTL // 3600}h window)")
            continue

        new_events += 1
        _record(ip)
        _alert(ev, intel)

    print(f"  [done] {new_events} new event(s) escalated")


if __name__ == "__main__":
    main()
