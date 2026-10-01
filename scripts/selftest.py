#!/usr/bin/env python3
"""
selftest.py — end-to-end health check for the SIEM pipeline (P2-6).

Catches the class of silent breakage the external review found (dead analyzers,
missing scripts, broken correlation). Runs every check, prints a PASS/FAIL line
each, and on ANY failure sends one Telegram alert and exits non-zero. Wire into
a daily cron. Exits 0 when everything passes.
"""
import json
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import dotenv_values

sys.path.insert(0, str(Path(__file__).parent))

ES = "http://localhost:9200"
LITELLM = "http://localhost:4000"
IR_HOST, IR_PORT = "127.0.0.1", 8766

env = dotenv_values(Path.home() / ".env")
TELEGRAM_TOKEN = env.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = env.get("TELEGRAM_CHAT_ID", "")
LITELLM_KEY = env.get("LITELLM_KEY", "")

results = []  # (name, ok, detail)


def check(name):
    def deco(fn):
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, f"exception: {e}"
        results.append((name, ok, detail))
    return deco


def _recent_count(index, ts_field):
    q = {"query": {"range": {ts_field: {"gte": "now-1h"}}}}
    r = requests.post(f"{ES}/{index}/_count", json=q, timeout=10)
    return r.json().get("count", 0)


@check("es-cluster")
def _():
    h = requests.get(f"{ES}/_cluster/health", timeout=10).json()
    st = h.get("status")
    return st in ("green", "yellow"), f"status={st}"


@check("filebeat-fresh")
def _():
    n = _recent_count("filebeat-*", "@timestamp")
    return n > 0, f"{n} docs in last 1h"


@check("cowrie-fresh")
def _():
    n = _recent_count("cowrie-*", "timestamp")
    return n > 0, f"{n} events in last 1h"


@check("webhoneypot-index")
def _():
    # web traffic is burstier; just require the index exists + is queryable
    r = requests.get(f"{ES}/webhoneypot-*/_count", timeout=10).json()
    return "count" in r, f"{r.get('count','?')} total docs"


@check("analyzers-import")
def _():
    import honeypot_analyzer, web_honeypot_analyzer, anomaly_detector, morning_report  # noqa
    return True, "all analyzer modules import"


@check("cross-node-correlation")
def _():
    from web_honeypot_analyzer import cross_reference_ips
    # must run without error and return a dict (empty is fine)
    out = cross_reference_ips(["100.81.207.17"])
    return isinstance(out, dict), f"returned {type(out).__name__}"


@check("block-parser-strict")
def _():
    from incident_responder import _is_block as b
    bad = [{"block": "false", "confidence": "high", "threat": True},
           {"block": "true", "confidence": "low"}, {}]
    good = {"block": True, "confidence": "high", "threat": True}
    return all(b(x) is False for x in bad) and b(good) is True, "rejects bad, accepts good"


@check("litellm-gateway")
def _():
    r = requests.post(f"{LITELLM}/chat/completions",
                      headers={"Authorization": f"Bearer {LITELLM_KEY}"},
                      json={"model": "openrouter/llama-3.3-70b",
                            "messages": [{"role": "user", "content": "reply OK"}],
                            "max_tokens": 5}, timeout=45)
    ok = r.status_code == 200 and "choices" in r.json()
    return ok, f"http {r.status_code}"


@check("incident-responder-listening")
def _():
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((IR_HOST, IR_PORT))
        return True, f"{IR_HOST}:{IR_PORT} open"
    finally:
        s.close()


def _telegram(text):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                      json={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=10)
    except Exception:
        pass


def main():
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    failures = [(n, d) for n, ok, d in results if not ok]
    for n, ok, d in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {n}: {d}")
    if failures:
        lines = "\n".join(f"- {n}: {d}" for n, d in failures)
        _telegram(f"SIEM SELFTEST FAILED ({ts})\n{len(failures)}/{len(results)} checks failed:\n{lines}")
        print(f"\n{len(failures)} FAILURE(S)")
        sys.exit(1)
    print(f"\nAll {len(results)} checks passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
