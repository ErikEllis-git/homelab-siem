#!/usr/bin/env python3
"""
morning_report.py — Daily Telegram SOC summary.

Runs at 06:45 via cron. Pulls the last 24h from Elasticsearch: Suricata
alerts by severity (excluding the disabled STUN SIDs), top attacker IPs,
SSH auth success/fail per node, cowrie honeypot activity, web honeypot
request volume, disk usage, and ES cluster health. Sends one Telegram
message. Rebuilt 2026-09-14 (P1-3) — the original was lost with the SSD.
"""

import shutil
import sys
import time
from pathlib import Path

import requests
from dotenv import dotenv_values

sys.path.insert(0, str(Path(__file__).parent))
from es_fields import LOG_TYPE, HOST_NAME  # noqa: E402

ES_HOST = "http://localhost:9200"
LOOKBACK = "now-24h"
DISABLED_SIDS = [2016149, 2016150]  # noisy Tailscale STUN, disabled cluster-wide

env = dotenv_values(Path.home() / ".env")
TELEGRAM_TOKEN = env.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = env.get("TELEGRAM_CHAT_ID", "")


def es_search(index: str, body: dict) -> dict:
    r = requests.post(f"{ES_HOST}/{index}/_search", json=body,
                       headers={"Content-Type": "application/json"}, timeout=20)
    r.raise_for_status()
    return r.json()


def count(index: str, query: dict) -> int:
    return es_search(index, {"size": 0, "query": query})["hits"]["total"]["value"]


def suricata_summary():
    q = {"bool": {
        "filter": [{"range": {"@timestamp": {"gte": LOOKBACK}}},
                   {"term": {LOG_TYPE: "suricata"}}, {"term": {"event_type": "alert"}}],
        "must_not": [{"terms": {"alert.signature_id": DISABLED_SIDS}}],
    }}
    body = {"size": 0, "query": q, "aggs": {
        "by_sev": {"terms": {"field": "alert.severity", "size": 5}},
        "top_ips": {"terms": {"field": "src_ip", "size": 5}},
    }}
    r = es_search("filebeat-*", body)["aggregations"]
    by_sev = {str(b["key"]): b["doc_count"] for b in r["by_sev"]["buckets"]}
    top_ips = [(b["key"], b["doc_count"]) for b in r["top_ips"]["buckets"]]
    return by_sev, top_ips


def ssh_auth_per_node() -> dict:
    body = {"size": 0, "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": LOOKBACK}}}, {"term": {LOG_TYPE: "auth"}}]}},
            "aggs": {"by_node": {"terms": {"field": HOST_NAME, "size": 10}, "aggs": {
                "outcome": {"filters": {"filters": {
                    "success": {"match_phrase": {"message": "Accepted"}},
                    "fail": {"match_phrase": {"message": "Failed password"}}}}}}}}}
    r = es_search("filebeat-*", body)
    out = {}
    for b in r["aggregations"]["by_node"]["buckets"]:
        f = b["outcome"]["buckets"]
        out[b["key"]] = (f["success"]["doc_count"], f["fail"]["doc_count"])
    return out


def cowrie_stats():
    rng = {"range": {"@timestamp": {"gte": LOOKBACK}}}
    sessions = count("cowrie-*", {"bool": {"filter": [rng, {"term": {"eventid": "cowrie.session.connect"}}]}})
    logins = count("cowrie-*", {"bool": {"filter": [rng, {"term": {"eventid": "cowrie.login.success"}}]}})
    return sessions, logins


def disk_pct() -> float:
    du = shutil.disk_usage("/")
    return round(du.used / du.total * 100, 1)


def es_health() -> str:
    return requests.get(f"{ES_HOST}/_cluster/health", timeout=10).json().get("status", "unknown")


def send_telegram(text: str) -> bool:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[morning_report] TELEGRAM_TOKEN/TELEGRAM_CHAT_ID not set")
        return False
    for attempt in range(3):
        try:
            resp = requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                                  json={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=10)
            if resp.status_code == 200:
                return True
            print(f"[morning_report] Telegram {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            print(f"[morning_report] Telegram send failed (attempt {attempt+1}/3): {e}")
        time.sleep(2)
    return False


def main() -> int:
    by_sev, top_ips = suricata_summary()
    sev_line = "  ".join(f"sev{k}:{v}" for k, v in sorted(by_sev.items())) or "none"
    ip_lines = "\n".join(f"  {ip} ({n})" for ip, n in top_ips) or "  none"

    ssh_nodes = ssh_auth_per_node()
    ssh_lines = "\n".join(f"  {n}: {ok} ok / {fail} fail"
                           for n, (ok, fail) in sorted(ssh_nodes.items())) or "  none"

    sessions, logins = cowrie_stats()
    web_reqs = count("webhoneypot-*", {"range": {"@timestamp": {"gte": LOOKBACK}}})
    disk, health = disk_pct(), es_health()

    text = "\n".join([
        "☀️ Morning SOC Report — last 24h", "",
        f"Suricata alerts: {sev_line}",
        f"Top attacker IPs:\n{ip_lines}", "",
        f"SSH auth by node:\n{ssh_lines}", "",
        f"Cowrie: {sessions} sessions, {logins} successful logins",
        f"Web honeypot: {web_reqs} requests", "",
        f"Disk usage: {disk}%  |  ES cluster: {health}",
    ])
    print(text)

    if not send_telegram(text):
        print("[morning_report] FAILED to send Telegram message")
        return 1
    print("[morning_report] sent OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
