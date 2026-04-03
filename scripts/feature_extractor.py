#!/usr/bin/env python3
"""
feature_extractor.py — Phase 1: Extract hourly ML feature vectors from ES.

Runs every hour via cron. Queries filebeat-* for the previous completed hour,
parses raw auth log messages, and writes structured feature rows to SQLite.

Two feature sets:
  node_features — aggregate stats per node per hour (ssh failures, successes, etc.)
  ip_features   — per attacker-IP stats per hour (fail count, nodes hit, etc.)

Usage:
  # Extract the last completed hour (normal cron mode)
  python3 feature_extractor.py

  # Backfill all historical data from ES
  python3 feature_extractor.py --backfill

  # Extract a specific hour (ISO8601, e.g. 2026-03-08T14:00:00)
  python3 feature_extractor.py --hour 2026-03-08T14:00:00
"""

import re
import sys
import json
import argparse
import ipaddress
from collections import defaultdict
from datetime import datetime, timezone, timedelta

import requests
from dotenv import dotenv_values

from feature_store import (
    init_db, upsert_node_features, upsert_ip_features, get_stats,
    get_node_history, get_last_node_success,
)
from threat_intel import lookup_ips

# ── Config ─────────────────────────────────────────────────────────────────────

env = dotenv_values("/home/rosse/.env")

ES_HOST = "http://localhost:9200"
ES_INDEX = "filebeat-*"

# Configure: set TRUSTED_NODE_IPS in .env as a comma-separated list of your cluster node IPs
TRUSTED_IPS = set(filter(None, env.get("TRUSTED_NODE_IPS", "").split(",")))
TRUSTED_PREFIXES = ("127.", "::1", "10.", "192.168.", "203.0.113.", "198.51.100.")  # last two: RFC 5737 purple team test nets
# Tailscale assigns addresses from the CGNAT range 100.64.0.0/10 — never flag these
TAILSCALE_NET = ipaddress.ip_network("100.64.0.0/10")

# Normalize OS hostnames to logical node names
HOSTNAME_MAP = {
    "olddell":  "rikdell",
    "OLDDELL":  "rikdell",
    "lubunt":   "lubunt",
    "LUBUNT":   "lubunt",
    "rosse":    "rosse",
}

# ── Regex patterns ──────────────────────────────────────────────────────────────

# "from 1.2.3.4 port 12345" — covers both Failed password and Accepted lines
RE_FROM_IP   = re.compile(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port')
# "Failed password for [invalid user] USERNAME from"
RE_FAIL_USER = re.compile(r'(?:Failed password|Invalid user)\s+(?:invalid user\s+)?(\S+)\s+from')
# "Accepted password/publickey for USERNAME from"
RE_SUCC_USER = re.compile(r'Accepted\s+\S+\s+for\s+(\S+)\s+from')
# CRON events
RE_CRON      = re.compile(r'\bCRON\b')
# Real syslog event timestamp embedded in the message field
# Matches: 2026-03-08T23:59:01.126097-04:00  or  2026-03-08T23:59:01Z
RE_SYSLOG_TS = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)'
)

# ── Helpers ─────────────────────────────────────────────────────────────────────

def is_internal(ip: str) -> bool:
    if ip in TRUSTED_IPS or any(ip.startswith(p) for p in TRUSTED_PREFIXES):
        return True
    try:
        return ipaddress.ip_address(ip) in TAILSCALE_NET
    except ValueError:
        return False


def normalize_node(raw: str) -> str:
    return HOSTNAME_MAP.get(raw, raw.lower())


def hour_bucket(dt: datetime) -> str:
    """Truncate a datetime to the start of its hour, return ISO string."""
    return dt.replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:00:00")


def parse_event_time(message: str) -> datetime | None:
    """Extract the real syslog event timestamp from the message field.

    Filebeat's @timestamp reflects ingestion time, which can lag significantly
    when filebeat flushes a backlog. The syslog message itself always contains
    the real event time as its first field. We parse that here so features are
    bucketed by when events *actually happened*, not when filebeat shipped them.
    """
    m = RE_SYSLOG_TS.match(message.strip())
    if not m:
        return None
    try:
        return datetime.fromisoformat(m.group(1))
    except ValueError:
        return None


def to_utc_naive(dt: datetime) -> datetime:
    """Convert any datetime to UTC and strip tzinfo for comparison."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


# ── ES fetch ────────────────────────────────────────────────────────────────────

def fetch_auth_logs(start: datetime, end: datetime) -> list[dict]:
    """Fetch all auth log events in [start, end) from ES."""
    query = {
        "size": 5000,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"log_type": "auth"}},
                    {"range": {
                        "@timestamp": {
                            "gte": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "lt":  end.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        }
                    }},
                ]
            }
        },
        "_source": ["@timestamp", "message", "host.name", "host_name"],
        "sort": [{"@timestamp": {"order": "asc"}}],
    }
    resp = requests.post(
        f"{ES_HOST}/{ES_INDEX}/_search",
        json=query,
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    hits = resp.json()["hits"]["hits"]

    # Handle ES pagination if more than 5000 events in window
    total = resp.json()["hits"]["total"]["value"]
    if total > 5000:
        print(f"  [warn] {total} events in window — only first 5000 fetched")

    return hits


# ── Feature extraction ──────────────────────────────────────────────────────────

def extract_features(
    hits: list[dict],
    bucket: str,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
) -> tuple[list[dict], list[dict]]:
    """
    Parse auth log hits and return (node_rows, ip_rows) for the given bucket.

    node_rows: one dict per node with aggregate stats
    ip_rows:   one dict per external src_ip with per-attacker stats

    When window_start/window_end are provided, each event's real timestamp is
    parsed from the syslog message field and events outside the window are
    discarded. This prevents filebeat ingestion bursts (where old log lines are
    flushed all at once) from inflating a single hour bucket and triggering
    false-positive ML anomalies.
    """
    # Pre-compute UTC-naive window bounds for fast comparison
    ws = to_utc_naive(window_start) if window_start else None
    we = to_utc_naive(window_end)   if window_end   else None

    # Per-node accumulators
    node_failures:     dict[str, int]       = defaultdict(int)
    node_successes:    dict[str, int]       = defaultdict(int)
    node_src_ips:      dict[str, set]       = defaultdict(set)
    node_failed_users: dict[str, set]       = defaultdict(set)
    node_cron:         dict[str, int]       = defaultdict(int)

    # Per-IP accumulators
    ip_failures:    dict[str, int]          = defaultdict(int)
    ip_successes:   dict[str, int]          = defaultdict(int)
    ip_users:       dict[str, set]          = defaultdict(set)
    ip_nodes:       dict[str, set]          = defaultdict(set)

    skipped_ingestion_lag = 0

    for hit in hits:
        src     = hit["_source"]
        message = src.get("message", "")
        # Authoritative node name: use host_name field (set by filebeat config),
        # fall back to host.name and normalize
        raw_node = src.get("host_name") or (src.get("host") or {}).get("name", "unknown")
        node = normalize_node(raw_node)

        # ── Real-timestamp gating ──────────────────────────────────────────────
        # Filebeat's @timestamp is ingestion time, not event time. When filebeat
        # flushes a backlog, dozens or thousands of old log lines arrive with the
        # same @timestamp, skewing the feature bucket. We parse the real event
        # time from the syslog message and drop anything outside our window.
        if ws is not None and we is not None:
            event_time = parse_event_time(message)
            if event_time is not None:
                ev_utc = to_utc_naive(event_time)
                if not (ws <= ev_utc < we):
                    skipped_ingestion_lag += 1
                    continue

        # CRON events — count them but skip further parsing
        if RE_CRON.search(message):
            node_cron[node] += 1
            continue

        ip_match = RE_FROM_IP.search(message)
        if not ip_match:
            continue
        ip = ip_match.group(1)
        if is_internal(ip):
            continue

        # Failure
        if "Failed password" in message or "Invalid user" in message:
            node_failures[node] += 1
            node_src_ips[node].add(ip)
            ip_failures[ip] += 1
            ip_nodes[ip].add(node)
            user_m = RE_FAIL_USER.search(message)
            if user_m:
                user = user_m.group(1)
                node_failed_users[node].add(user)
                ip_users[ip].add(user)

        # Success
        elif "Accepted" in message:
            node_successes[node] += 1
            node_src_ips[node].add(ip)
            ip_successes[ip] += 1
            ip_nodes[ip].add(node)

    if skipped_ingestion_lag:
        print(f"  [timestamp-gate] dropped {skipped_ingestion_lag} events outside window "
              f"(filebeat ingestion lag)")

    # Parse bucket time for time-of-day features
    bucket_dt = datetime.fromisoformat(bucket)
    hour_of_day = bucket_dt.hour
    day_of_week = bucket_dt.weekday()  # 0=Monday

    # Build all nodes we saw (union of all accumulators)
    all_nodes = (
        set(node_failures) | set(node_successes) |
        set(node_cron) | set(node_src_ips)
    )

    # Always emit a row for every known node even if quiet (zero activity = normal baseline)
    node_rows = []
    for node in (all_nodes or {"rosse", "rikdell", "lubunt"}):
        failures  = node_failures.get(node, 0)
        successes = node_successes.get(node, 0)
        total     = failures + successes
        node_rows.append({
            "bucket_time":        bucket,
            "node":               node,
            "ssh_failures":       failures,
            "ssh_successes":      successes,
            "unique_src_ips":     len(node_src_ips.get(node, set())),
            "unique_users_failed":len(node_failed_users.get(node, set())),
            "failure_rate":       failures / total if total > 0 else 0.0,
            "cron_events":        node_cron.get(node, 0),
            "hour_of_day":        hour_of_day,
            "day_of_week":        day_of_week,
        })

    # Threat intel enrichment for attacker IPs
    external_ips = list(ip_failures.keys() | ip_successes.keys())
    ti = lookup_ips(external_ips) if external_ips else {}

    ip_rows = []
    for ip in external_ips:
        ip_rows.append({
            "bucket_time":       bucket,
            "src_ip":            ip,
            "fail_count":        ip_failures.get(ip, 0),
            "success_count":     ip_successes.get(ip, 0),
            "unique_users_tried":len(ip_users.get(ip, set())),
            "node_count":        len(ip_nodes.get(ip, set())),
            "has_threat_intel":  1 if ip in ti else 0,
        })

    return node_rows, ip_rows


# ── Derived feature enrichment ──────────────────────────────────────────────────

ORCHESTRATOR_NODE = "rosse"
MAX_HOURS_SINCE_SUCCESS = 168.0  # cap at 1 week — beyond this it's all equally "never"


def enrich_node_rows(node_rows: list[dict], bucket: str) -> list[dict]:
    """
    Compute and attach derived features to each node row after base extraction.

    is_orchestrator    — 1.0 for rosse, 0.0 for workers. Lets the model learn
                         that high cron_events on rosse is normal, not anomalous.

    failure_velocity   — ssh_failures this hour minus the rolling 3-hour average
                         for this node. Positive = accelerating attack; negative =
                         quieting down. Catches slow-ramp brute force that looks
                         normal in any single hour.

    hours_since_success — hours since the last external SSH success on this node,
                          capped at 168 (1 week). A sudden drop from 168 → 0 is a
                          high-signal indicator of a brute force success.
    """
    bucket_dt = datetime.fromisoformat(bucket).replace(tzinfo=None)

    for row in node_rows:
        node = row["node"]

        # is_orchestrator
        row["is_orchestrator"] = 1.0 if node == ORCHESTRATOR_NODE else 0.0

        # failure_velocity: current failures - mean(last 3h for this node)
        history = get_node_history(node, hours=3)
        if history:
            avg = sum(r["ssh_failures"] for r in history) / len(history)
            row["failure_velocity"] = float(row["ssh_failures"]) - avg
        else:
            row["failure_velocity"] = 0.0

        # hours_since_success: hours since last external SSH success on this node
        last = get_last_node_success(node)
        if last:
            last_dt = datetime.fromisoformat(last["bucket_time"]).replace(tzinfo=None)
            delta_h = (bucket_dt - last_dt).total_seconds() / 3600
            row["hours_since_success"] = min(delta_h, MAX_HOURS_SINCE_SUCCESS)
        else:
            row["hours_since_success"] = MAX_HOURS_SINCE_SUCCESS

    return node_rows


# ── Backfill ────────────────────────────────────────────────────────────────────

def fetch_honeypot_ips(days: int = 7) -> set:
    """Return src_ip values seen in cowrie honeypot logs in the last N days.
    Used to cross-reference cluster attackers against known honeypot visitors.
    """
    try:
        resp = requests.post(
            f"{ES_HOST}/cowrie-*/_search",
            json={
                "size": 0,
                "query": {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
                "aggs": {"ips": {"terms": {"field": "src_ip", "size": 5000}}},
            },
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()
        buckets = resp.json()["aggregations"]["ips"]["buckets"]
        return {b["key"] for b in buckets}
    except Exception as e:
        print(f"  [honeypot-xref] ES query failed: {e}")
        return set()


def enrich_ip_rows(ip_rows: list[dict], honeypot_ips: set) -> list[dict]:
    """Mark cluster-attacking IPs that were also seen on the honeypot.
    Treats prior honeypot activity as threat intel — these are known attackers.
    """
    for row in ip_rows:
        if row["src_ip"] in honeypot_ips:
            row["has_threat_intel"] = 1
    return ip_rows


def get_earliest_es_timestamp() -> datetime:
    """Find the oldest auth log event in ES."""
    resp = requests.post(
        f"{ES_HOST}/{ES_INDEX}/_search",
        json={
            "size": 1,
            "query": {"term": {"log_type": "auth"}},
            "sort": [{"@timestamp": {"order": "asc"}}],
            "_source": ["@timestamp"],
        },
        headers={"Content-Type": "application/json"},
        timeout=15,
    )
    resp.raise_for_status()
    hits = resp.json()["hits"]["hits"]
    if not hits:
        return datetime.now(timezone.utc) - timedelta(days=7)
    ts = hits[0]["_source"]["@timestamp"]
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def backfill() -> None:
    """Extract features for every hour from earliest ES data to now."""
    earliest = get_earliest_es_timestamp()
    # Truncate to start of that hour
    start = earliest.replace(minute=0, second=0, microsecond=0, tzinfo=None)
    now   = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0, tzinfo=None)

    hours = []
    cursor = start
    while cursor < now:
        hours.append(cursor)
        cursor += timedelta(hours=1)

    print(f"Backfilling {len(hours)} hours from {start} to {now}")
    total_node_rows = 0
    total_ip_rows   = 0

    for hour_start in hours:
        hour_end = hour_start + timedelta(hours=1)
        bucket   = hour_bucket(hour_start)
        hits     = fetch_auth_logs(hour_start, hour_end)
        if not hits:
            # Still write zero rows so the baseline captures quiet hours
            node_rows, ip_rows = extract_features([], bucket, hour_start, hour_end)
        else:
            node_rows, ip_rows = extract_features(hits, bucket, hour_start, hour_end)

        node_rows = enrich_node_rows(node_rows, bucket)
        n = upsert_node_features(node_rows)
        i = upsert_ip_features(ip_rows)
        total_node_rows += n
        total_ip_rows   += i
        print(f"  {bucket}  auth={len(hits):4d}  node_rows={n}  ip_rows={i}")

    print(f"\nBackfill complete: {total_node_rows} node rows, {total_ip_rows} IP rows")


# ── Single-hour extract ─────────────────────────────────────────────────────────

def extract_hour(hour_start: datetime) -> None:
    hour_end = hour_start + timedelta(hours=1)
    bucket   = hour_bucket(hour_start)

    print(f"Extracting features for {bucket}")
    hits = fetch_auth_logs(hour_start, hour_end)
    print(f"  Auth events fetched (by ingestion time): {len(hits)}")

    node_rows, ip_rows = extract_features(hits, bucket, hour_start, hour_end)
    node_rows = enrich_node_rows(node_rows, bucket)
    if ip_rows:
        honeypot_ips = fetch_honeypot_ips()
        ip_rows = enrich_ip_rows(ip_rows, honeypot_ips)
        hp_hits = sum(1 for r in ip_rows if r["has_threat_intel"])
        if hp_hits:
            print(f"  [honeypot-xref] {hp_hits} IP(s) also seen on honeypot")
    n = upsert_node_features(node_rows)
    i = upsert_ip_features(ip_rows)
    print(f"  Wrote {n} node rows, {i} IP rows")

    if node_rows:
        print("\n  Node summary:")
        for r in node_rows:
            print(f"    {r['node']:<10} failures={r['ssh_failures']:3d}  "
                  f"successes={r['ssh_successes']:3d}  "
                  f"unique_ips={r['unique_src_ips']:3d}  "
                  f"cron={r['cron_events']:4d}  "
                  f"failure_rate={r['failure_rate']:.2f}")

    if ip_rows:
        print(f"\n  Top attacker IPs ({min(5, len(ip_rows))} of {len(ip_rows)}):")
        for r in sorted(ip_rows, key=lambda x: -x['fail_count'])[:5]:
            ti_flag = " [TI MATCH]" if r['has_threat_intel'] else ""
            print(f"    {r['src_ip']:<18} fails={r['fail_count']:3d}  "
                  f"nodes={r['node_count']}  "
                  f"users={r['unique_users_tried']}{ti_flag}")


# ── Main ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Extract ML features from ES auth logs")
    group  = parser.add_mutually_exclusive_group()
    group.add_argument("--backfill", action="store_true",
                       help="Backfill all historical data from ES")
    group.add_argument("--hour", metavar="YYYY-MM-DDTHH:00:00",
                       help="Extract a specific hour (UTC)")
    args = parser.parse_args()

    init_db()

    if args.backfill:
        backfill()
    elif args.hour:
        hour_start = datetime.fromisoformat(args.hour)
        extract_hour(hour_start)
    else:
        # Default: extract the last completed hour
        now        = datetime.now(timezone.utc).replace(tzinfo=None)
        hour_start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
        extract_hour(hour_start)

    stats = get_stats()
    print(f"\nStore totals: {stats['node_rows']} node rows, "
          f"{stats['ip_rows']} IP rows, "
          f"{stats['anomalies']} anomalies flagged")


if __name__ == "__main__":
    main()
