#!/usr/bin/env python3
"""
purple_team.py — Automated purple team: run attack simulations, measure detection coverage.

Scenarios:
  1. log_ingestion    — write unique marker via logger on all 3 nodes, measure
                        filebeat → ES ingestion latency per node
  2. ssh_brute        — inject 15 synthetic SSH failure docs to ES, verify
                        brute_watch threshold logic would fire
  3. port_scan        — nmap TCP connect scan against lubunt LAN IP, check
                        Suricata detects and ships alert to ES
  4. cross_node       — inject same fake external IP on 2 nodes' auth logs,
                        verify anomaly_detector cross-node correlation fires

Each scenario records: detected (bool), MTTD in seconds, and notes to SQLite.
A Telegram report is sent at the end of a full run.

Usage:
  python3 purple_team.py                       # run all scenarios
  python3 purple_team.py --scenario port_scan  # single scenario
  python3 purple_team.py --report-only         # show last 7 days of results
  python3 purple_team.py --dry-run             # describe actions, no execution
  python3 purple_team.py --no-telegram         # suppress Telegram report

Cron (weekly, Sunday 3:30am):
  30 3 * * 0  /opt/siem/scripts/.venv/bin/python3 /opt/siem/scripts/purple_team.py >> /opt/siem/scripts/cron.log 2>&1
"""

import argparse
import json
import os
import random
import re
import sqlite3
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
from dotenv import dotenv_values

# ── Config ────────────────────────────────────────────────────────────────────

ES_HOST  = "http://localhost:9200"
SCRIPTS  = Path(__file__).parent
DB_PATH  = SCRIPTS / "purple_team.db"

env = dotenv_values(Path.home() / ".env")
TELEGRAM_TOKEN   = env.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = env.get("TELEGRAM_CHAT_ID", "")

# SSH prefixes for each node (None = local)
NODES_SSH = {
    "rosse":   None,
    "worker1": ["ssh", "-i", str(Path.home() / ".ssh/id_rsa_swarm"),
                "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no",
                env.get("WORKER1_SSH_TARGET", "user@worker1")],
    "worker2": ["ssh", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no",
                env.get("WORKER2_SSH_TARGET", "user@worker2")],
}

# Worker 2 LAN IP — used for port scan so Suricata on eno1 sees the traffic
LUBUNT_LAN_IP = env.get("WORKER2_LAN_IP", "")

# RFC 5737 TEST-NET ranges — safe fake attacker IPs, never routed on the internet
TEST_NET_2 = "198.51.100"   # 198.51.100.0/24
TEST_NET_3 = "203.0.113"    # 203.0.113.0/24


# ── Database ──────────────────────────────────────────────────────────────────

def init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id         TEXT NOT NULL,
            scenario       TEXT NOT NULL,
            target_node    TEXT,
            attack_time    REAL NOT NULL,
            detection_time REAL,
            mttd_seconds   REAL,
            detected       INTEGER NOT NULL DEFAULT 0,
            es_hit_count   INTEGER DEFAULT 0,
            notes          TEXT,
            created_at     TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    return conn


def save_result(conn: sqlite3.Connection, run_id: str, scenario: str,
                target_node: str | None, attack_time: float,
                detection_time: float | None, detected: bool,
                es_hit_count: int = 0, notes: str = "") -> None:
    mttd = round(detection_time - attack_time, 1) if (detection_time and detected) else None
    conn.execute(
        """INSERT INTO runs
               (run_id, scenario, target_node, attack_time, detection_time,
                mttd_seconds, detected, es_hit_count, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (run_id, scenario, target_node, attack_time, detection_time,
         mttd, int(detected), es_hit_count, notes),
    )
    conn.commit()


# ── Elasticsearch helpers ─────────────────────────────────────────────────────

def es_search(query: dict, index: str = "filebeat-*") -> list[dict]:
    resp = requests.post(
        f"{ES_HOST}/{index}/_search",
        json=query,
        headers={"Content-Type": "application/json"},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["hits"]["hits"]


def es_bulk_index(docs: list[dict], index: str) -> bool:
    body = ""
    for doc in docs:
        body += json.dumps({"index": {"_index": index}}) + "\n"
        body += json.dumps(doc) + "\n"
    resp = requests.post(
        f"{ES_HOST}/_bulk",
        data=body,
        headers={"Content-Type": "application/x-ndjson"},
        timeout=15,
    )
    return resp.ok


def es_delete_by_query(field: str, value: str, index: str = "filebeat-purple-*") -> int:
    resp = requests.post(
        f"{ES_HOST}/{index}/_delete_by_query",
        json={"query": {"term": {field: value}}},
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    if resp.ok:
        return resp.json().get("deleted", 0)
    return 0


def poll_es(query: dict, index: str = "filebeat-*",
            max_wait: int = 90, poll_interval: int = 5) -> tuple[bool, float | None, int]:
    """Poll ES until query returns hits. Returns (found, detection_time, hit_count)."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            hits = es_search(query, index=index)
            if hits:
                return True, time.time(), len(hits)
        except Exception as e:
            print(f"  [ES] poll error: {e}")
        time.sleep(poll_interval)
    return False, None, 0


# ── SSH helpers ───────────────────────────────────────────────────────────────

def run_on_node(node: str, cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    ssh = NODES_SSH.get(node)
    if ssh is None:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return subprocess.run(ssh + [cmd], capture_output=True, text=True, timeout=timeout)


# ── Telegram ──────────────────────────────────────────────────────────────────

def send_telegram(text: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[TG] not configured")
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"},
            timeout=15,
        )
    except Exception as e:
        print(f"[TG] failed: {e}")


# ── Scenario 1: Log Ingestion Latency ────────────────────────────────────────

def scenario_log_ingestion(run_id: str, conn: sqlite3.Connection,
                           dry_run: bool = False) -> list[dict]:
    """
    Write a unique marker to syslog (auth facility) on all 3 nodes via `logger`.
    Measure how long filebeat takes to ship each entry to Elasticsearch.

    Tests: filebeat pipeline health, per-node ingestion latency, log_type tagging.
    MITRE: T1070.002 (log deletion — inverse: if logs DON'T appear, something cleared them)
    """
    print("\n[purple] scenario: log_ingestion_latency")
    results = []

    for node in ["rosse", "rikdell", "lubunt"]:
        marker    = f"purple-team-ingest-{run_id[:12]}-{node}"
        ts_before = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        if dry_run:
            print(f"  [dry] would logger -p auth.info on {node}: {marker}")
            results.append({"scenario": f"log_ingestion[{node}]", "detected": None,
                            "mttd": None, "notes": "dry-run"})
            continue

        attack_time = time.time()
        cmd = f"logger -p auth.info -t sshd 'Invalid user {marker} from 203.0.113.99 port 54321'"
        result = run_on_node(node, cmd, timeout=15)

        if result.returncode != 0:
            err = result.stderr.strip()[:100]
            print(f"  [{node}] logger failed: {err}")
            save_result(conn, run_id, f"log_ingestion[{node}]", node,
                        attack_time, None, False, 0, f"logger failed: {err}")
            results.append({"scenario": f"log_ingestion[{node}]", "detected": False,
                            "mttd": None, "notes": f"logger failed: {err}"})
            continue

        print(f"  [{node}] marker written, polling ES (up to 90s)...")

        query = {
            "size": 5,
            "query": {"bool": {"filter": [
                {"match_phrase": {"message": marker}},
                {"range":        {"@timestamp": {"gte": ts_before}}},
            ]}},
        }
        found, det_time, count = poll_es(query, max_wait=90, poll_interval=5)
        mttd = round(det_time - attack_time, 1) if found else None
        note = f"hit_count={count}" if found else "not found in ES within 90s"

        print(f"  [{node}] {'✓ detected' if found else '✗ MISSED'}"
              + (f"  MTTD={mttd}s" if mttd else ""))

        save_result(conn, run_id, f"log_ingestion[{node}]", node,
                    attack_time, det_time, found, count, note)
        results.append({"scenario": f"log_ingestion[{node}]", "detected": found,
                        "mttd": mttd, "notes": note})

    return results


# ── Scenario 2: SSH Brute Force (Synthetic) ───────────────────────────────────

def scenario_ssh_brute_synthetic(run_id: str, conn: sqlite3.Connection,
                                 dry_run: bool = False) -> list[dict]:
    """
    Inject 15 synthetic failed SSH auth log docs into a dedicated ES index using
    a TEST-NET-3 source IP (203.0.113.x — RFC 5737, never routed). Then replay
    brute_watch's detection query and threshold check against those docs.

    Tests: ES query structure, IP extraction regex, threshold logic (>=10 failures/5m).
    MITRE: T1110.001 (Brute Force: Password Guessing)
    """
    print("\n[purple] scenario: ssh_brute_synthetic")

    fake_ip     = f"{TEST_NET_3}.{random.randint(2, 254)}"
    marker_user = f"pt_{run_id[:8]}"
    index       = f"filebeat-purple-{datetime.now().strftime('%Y.%m.%d')}"

    if dry_run:
        print(f"  [dry] would inject 15 fake SSH failures from {fake_ip} → {index}")
        return [{"scenario": "ssh_brute_synthetic", "detected": None,
                 "mttd": None, "notes": "dry-run"}]

    attack_time = time.time()
    ts_now      = datetime.now(timezone.utc)

    # Build 15 auth log entries spread over the last 4 minutes (brute_watch window = 5m)
    docs = []
    for i in range(15):
        ts   = (ts_now - timedelta(seconds=240 - i * 15)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        port = 40000 + i
        docs.append({
            "@timestamp":        ts,
            "message":           f"Invalid user {marker_user} from {fake_ip} port {port}",
            "log_type":          "auth",
            "host_name":         "rikdell",
            "host":              {"name": "rikdell"},
            "purple_team_run_id": run_id,
        })

    print(f"  [ES] indexing 15 synthetic docs — fake IP: {fake_ip}, user: {marker_user} → {index}")
    if not es_bulk_index(docs, index):
        print("  [ES] bulk index failed")
        save_result(conn, run_id, "ssh_brute_synthetic", "rikdell",
                    attack_time, None, False, 0, "ES bulk index failed")
        return [{"scenario": "ssh_brute_synthetic", "detected": False,
                 "mttd": None, "notes": "ES bulk index failed"}]

    time.sleep(2)  # allow ES to flush

    # Replay brute_watch detection query against the synthetic index
    query = {
        "size": 50,
        "query": {
            "bool": {
                "filter": [
                    {"term":  {"log_type": "auth"}},
                    {"range": {"@timestamp": {"gte": "now-5m"}}},
                    {"match_phrase": {"message": fake_ip}},
                ],
                "should": [
                    {"match_phrase": {"message": "Failed password"}},
                    {"match_phrase": {"message": "Invalid user"}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    try:
        hits     = es_search(query, index=index)
        detected = len(hits) >= 10   # brute_watch threshold
    except Exception as e:
        print(f"  [ES] detection query failed: {e}")
        hits, detected = [], False

    det_time = time.time() if detected else None
    mttd     = round(det_time - attack_time, 1) if detected else None
    note     = (f"injected=15 retrieved={len(hits)} threshold=10 "
                f"would_fire={'yes' if detected else 'no'}")

    print(f"  {'✓ detected' if detected else '✗ MISSED'} — "
          f"retrieved {len(hits)}/15 docs  threshold=10")

    deleted = es_delete_by_query("purple_team_run_id", run_id, index=index)
    print(f"  [ES] cleaned up {deleted} synthetic doc(s)")

    save_result(conn, run_id, "ssh_brute_synthetic", "rikdell",
                attack_time, det_time, detected, len(hits), note)
    return [{"scenario": "ssh_brute_synthetic", "detected": detected,
             "mttd": mttd, "notes": note}]


# ── Scenario 3: Port Scan Detection ──────────────────────────────────────────

def scenario_port_scan(run_id: str, conn: sqlite3.Connection,
                       dry_run: bool = False) -> list[dict]:
    """
    Run an nmap TCP connect scan from rosse against worker-2's LAN IP (WORKER2_LAN_IP).
    Suricata listens on eno1 and will see this LAN-to-LAN traffic. Poll ES for
    any resulting Suricata alert with dest_ip matching the target.

    Tests: Suricata ET SCAN rule coverage, suricata-alerter → ES ingestion pipeline.
    MITRE: T1046 (Network Service Discovery)
    """
    print("\n[purple] scenario: port_scan")

    target_ip   = LUBUNT_LAN_IP
    target_node = "lubunt"
    ports       = "22,25,80,443,3306,5432,5900,8080,8443"

    if dry_run:
        print(f"  [dry] would nmap -Pn -sT -p {ports} {target_ip}")
        return [{"scenario": "port_scan", "detected": None,
                 "mttd": None, "notes": "dry-run"}]

    print(f"  [nmap] scanning {target_ip} ports {ports}...")
    ts_before   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    attack_time = time.time()

    subprocess.run(
        ["nmap", "-Pn", "-sT", "-p", ports,
         "--max-rtt-timeout", "500ms", "--min-rate", "100", target_ip],
        capture_output=True, text=True, timeout=60,
    )
    print(f"  [nmap] scan complete, polling ES for Suricata alert (up to 90s)...")

    sig   = ""
    query = {
        "size": 5,
        "query": {
            "bool": {
                "filter": [
                    {"term":  {"log_type": "suricata"}},
                    {"term":  {"event_type": "alert"}},
                    {"range": {"@timestamp": {"gte": ts_before}}},
                    {"term":  {"dest_ip": target_ip}},
                ],
            }
        },
        "_source": ["@timestamp", "alert.signature", "alert.category",
                    "alert.severity", "src_ip", "dest_ip"],
    }

    found, det_time, count = False, None, 0
    deadline = time.time() + 90
    while time.time() < deadline:
        try:
            hits = es_search(query, index="filebeat-*")
            if hits:
                found    = True
                det_time = time.time()
                count    = len(hits)
                src      = hits[0]["_source"]
                sig      = (src.get("alert.signature")
                            or (src.get("alert") or {}).get("signature", "unknown"))
                break
        except Exception as e:
            print(f"  [ES] poll error: {e}")
        time.sleep(5)

    mttd = round(det_time - attack_time, 1) if found else None
    note = f"sig: {sig}" if found else "no Suricata alert in ES within 90s"

    print(f"  {'✓ detected' if found else '✗ MISSED'}"
          + (f"  MTTD={mttd}s  sig={sig}" if found else ""))

    save_result(conn, run_id, "port_scan", target_node,
                attack_time, det_time, found, count, note)
    return [{"scenario": "port_scan", "detected": found, "mttd": mttd, "notes": note}]


# ── Scenario 4: Cross-Node Correlation ───────────────────────────────────────

def scenario_cross_node(run_id: str, conn: sqlite3.Connection,
                        dry_run: bool = False) -> list[dict]:
    """
    Inject the same fake external IP (TEST-NET-2) in auth log entries on two
    different nodes (rosse + rikdell). Then replay anomaly_detector's
    cross_node_summary() logic to confirm it would flag the IP as multi-node.

    Tests: IP extraction regex, cross-node aggregation, coordination detection.
    MITRE: T1021.004 (Remote Services: SSH) + T1078 (Valid Accounts — lateral move)
    """
    print("\n[purple] scenario: cross_node_correlation")

    fake_ip  = f"{TEST_NET_2}.{random.randint(2, 254)}"
    marker   = f"pt-xnode-{run_id[:8]}"
    index    = f"filebeat-purple-{datetime.now().strftime('%Y.%m.%d')}"

    if dry_run:
        print(f"  [dry] would inject fake IP {fake_ip} on rosse + rikdell → {index}")
        return [{"scenario": "cross_node_correlation", "detected": None,
                 "mttd": None, "notes": "dry-run"}]

    attack_time = time.time()
    ts_now      = datetime.now(timezone.utc)

    docs = []
    for node in ["rosse", "rikdell"]:
        for i in range(3):
            ts   = (ts_now - timedelta(seconds=30 - i * 5)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            port = 50000 + i
            docs.append({
                "@timestamp":        ts,
                "message":           f"Failed password for {marker} from {fake_ip} port {port}",
                "log_type":          "auth",
                "host_name":         node,
                "host":              {"name": node},
                "purple_team_run_id": run_id,
            })

    print(f"  [ES] injecting fake IP {fake_ip} on rosse + rikdell (3 docs each) → {index}")
    if not es_bulk_index(docs, index):
        print("  [ES] bulk index failed")
        save_result(conn, run_id, "cross_node_correlation", "rosse,rikdell",
                    attack_time, None, False, 0, "ES bulk index failed")
        return [{"scenario": "cross_node_correlation", "detected": False,
                 "mttd": None, "notes": "ES bulk index failed"}]

    time.sleep(2)

    # Replay anomaly_detector cross_node_summary() logic
    query = {
        "size": 50,
        "query": {"bool": {"filter": [
            {"match_phrase": {"message": fake_ip}},
            {"term":         {"log_type": "auth"}},
        ]}},
        "_source": ["message", "host.name", "host_name"],
    }
    try:
        hits = es_search(query, index=index)
    except Exception as e:
        print(f"  [ES] query failed: {e}")
        hits = []

    ip_pattern  = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
    ip_to_nodes: dict[str, set] = {}

    for hit in hits:
        src  = hit["_source"]
        node = (src.get("host") or {}).get("name") or src.get("host_name", "unknown")
        for m in ip_pattern.finditer(src.get("message", "")):
            ip = m.group(1)
            if ip == fake_ip:
                ip_to_nodes.setdefault(ip, set()).add(node)

    nodes_seen = ip_to_nodes.get(fake_ip, set())
    detected   = len(nodes_seen) >= 2
    det_time   = time.time() if detected else None
    mttd       = round(det_time - attack_time, 1) if detected else None
    note       = f"fake_ip={fake_ip} nodes_seen={sorted(nodes_seen)} docs={len(hits)}"

    print(f"  {'✓ detected' if detected else '✗ MISSED'} — "
          f"IP seen on {sorted(nodes_seen)}")

    deleted = es_delete_by_query("purple_team_run_id", run_id, index=index)
    print(f"  [ES] cleaned up {deleted} synthetic doc(s)")

    save_result(conn, run_id, "cross_node_correlation", "rosse,rikdell",
                attack_time, det_time, detected, len(hits), note)
    return [{"scenario": "cross_node_correlation", "detected": detected,
             "mttd": mttd, "notes": note}]


# ── Report ────────────────────────────────────────────────────────────────────

def build_report(run_id: str, all_results: list[dict], elapsed: float) -> str:
    now      = datetime.now().strftime("%Y-%m-%d %H:%M")
    detected = [r for r in all_results if r.get("detected") is True]
    missed   = [r for r in all_results if r.get("detected") is False]
    coverage = f"{len(detected)}/{len(all_results)}"

    mttd_vals = [r["mttd"] for r in detected if r.get("mttd") is not None]
    avg_mttd  = round(sum(mttd_vals) / len(mttd_vals), 1) if mttd_vals else None

    lines = [
        "🟣 *Purple Team Report*",
        f"_{now}_",
        f"*Run ID:* `{run_id[:12]}`",
        "",
    ]

    for r in all_results:
        det = r.get("detected")
        if det is None:
            icon, status = "⚪", "DRY RUN"
        elif det:
            mttd   = r.get("mttd")
            icon   = "✅"
            status = f"DETECTED  (MTTD: {mttd}s)" if mttd is not None else "DETECTED"
        else:
            icon, status = "❌", "MISSED"
        lines.append(f"{icon} *{r['scenario']}* — {status}")

    lines.append("")
    lines.append(f"*Coverage:* {coverage} scenarios detected")
    if avg_mttd is not None:
        lines.append(f"*Avg MTTD:* {avg_mttd}s")
    if missed:
        lines.append(f"*Gaps:* {', '.join(r['scenario'] for r in missed)}")
    else:
        lines.append("*Gaps:* none")
    lines.append(f"_Completed in {round(elapsed)}s_")

    return "\n".join(lines)


def report_only(conn: sqlite3.Connection, days: int = 7) -> None:
    rows = conn.execute(
        """SELECT run_id, scenario, target_node, detected, mttd_seconds, notes, created_at
           FROM runs
           WHERE created_at >= datetime('now', ?)
           ORDER BY created_at DESC""",
        (f"-{days} days",),
    ).fetchall()

    if not rows:
        print(f"No purple team runs in the last {days} days.")
        return

    print(f"\n{'─'*90}")
    print(f"{'RUN_ID':<14} {'SCENARIO':<34} {'NODE':<14} {'OK':<4} {'MTTD':>6}  NOTES")
    print(f"{'─'*90}")
    for run_id, scenario, node, detected, mttd, notes, created_at in rows:
        ok       = "✓" if detected else "✗"
        mttd_str = f"{mttd:.1f}s" if mttd is not None else "—"
        print(f"{run_id[:12]:<14} {scenario:<34} {(node or ''):<14} {ok:<4} "
              f"{mttd_str:>6}  {notes or ''}")
    print(f"{'─'*90}\n")


# ── Entry point ───────────────────────────────────────────────────────────────

SCENARIOS = {
    "log_ingestion":       scenario_log_ingestion,
    "ssh_brute_synthetic": scenario_ssh_brute_synthetic,
    "port_scan":           scenario_port_scan,
    "cross_node":          scenario_cross_node,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Purple team — detection coverage testing")
    parser.add_argument("--scenario",    choices=list(SCENARIOS),
                        help="Run a single scenario only")
    parser.add_argument("--dry-run",     action="store_true",
                        help="Describe actions without executing attacks")
    parser.add_argument("--report-only", action="store_true",
                        help="Print last 7 days of results from DB, then exit")
    parser.add_argument("--no-telegram", action="store_true",
                        help="Suppress Telegram report")
    args = parser.parse_args()

    conn   = init_db()
    run_id = uuid.uuid4().hex

    print(f"\n[purple_team] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  "
          f"run_id={run_id[:12]}")

    if args.report_only:
        report_only(conn)
        conn.close()
        return

    to_run = {args.scenario: SCENARIOS[args.scenario]} if args.scenario else SCENARIOS

    start       = time.time()
    all_results: list[dict] = []

    for name, fn in to_run.items():
        results = fn(run_id, conn, dry_run=args.dry_run)
        all_results.extend(results)

    elapsed = time.time() - start
    report  = build_report(run_id, all_results, elapsed)

    print(f"\n{'='*60}")
    # Strip Markdown formatting for terminal output (leave underscores in names intact)
    plain = re.sub(r'\*|`|(?<!\w)_(?!\w)', '', report)
    print(plain)
    print(f"{'='*60}\n")

    if not args.no_telegram and not args.dry_run:
        send_telegram(report)
        print("[TG] report sent")

    conn.close()


if __name__ == "__main__":
    main()
