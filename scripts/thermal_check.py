#!/usr/bin/env python3
"""
thermal_check.py — thermal watch for worker nodes, run FROM rosee every 5 minutes.

The worker runs hphdd-thermal-sample.py every 30 s (a JSON line per sample). This script:
  1. pulls the samples it has not seen yet over SSH (so nothing between runs is lost),
  2. stores them in Elasticsearch (thermal-YYYY.MM, idempotent doc ids) for history/trends,
  3. alerts on Telegram (deduped; only when the problem set changes, + hourly re-alert if critical).

Why built this way: hpHDD has a history of running hot and exposes NO fan speed, so a failing
fan or clogged airflow can only be inferred. Hence, besides plain thresholds, it watches for:
  - ANY thermal-throttle counter increase (the CPU actually hit its limit),
  - "hot while idle" (median package temp high with near-zero load),
  - slow DRIFT: idle temperature creeping above its own 10-day baseline,
  - the sampler going quiet, and the node vanishing (an overheat shutdown looks like that), with
    the last known reading attached so you can tell "died hot" from "lost power".

Thresholds (env-overridable, used for testing): CPU Tjmax on this i5-1035G1 is 100 C.
"""
import json
import os
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import dotenv_values

HERE = Path(__file__).parent
STATE_FILE = HERE / "thermal_state.json"
ES = "http://localhost:9200"
SWARM_KEY = str(Path.home() / ".ssh/id_rsa_swarm")

env = dotenv_values(Path.home() / ".env")
TELEGRAM_TOKEN = env.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = env.get("TELEGRAM_CHAT_ID", "")


def _f(name, default):
    return float(os.environ.get(name, default))


PKG_WARN = _f("THERMAL_PKG_WARN", 80)
PKG_CRIT = _f("THERMAL_PKG_CRIT", 90)
HDD_WARN = _f("THERMAL_HDD_WARN", 50)
HDD_CRIT = _f("THERMAL_HDD_CRIT", 55)
IDLE_HOT = _f("THERMAL_IDLE_HOT", 65)
DRIFT_C = _f("THERMAL_DRIFT_C", 8)
WINDOW = 10            # samples (~5 min)
SUSTAIN_WARN = 6       # of WINDOW samples >= PKG_WARN  (~3 min sustained)
SUSTAIN_CRIT = 2       # of WINDOW samples >= PKG_CRIT  (~1 min)
STALE_S = 360          # no new sample for this long while the node answers SSH
UNREACH_FAILS = 2      # consecutive failed runs (~10 min) before "unreachable"
REALERT_S = 3600

NODES = {
    "hpHDD": {"target": env.get("WORKER2_SSH_TARGET", ""), "log": "/var/log/hphdd-thermal.jsonl"},
}

REMOTE_PY = r'''
import json, sys
since, path = int(sys.argv[1]), sys.argv[2]
try:
    lines = open(path).read().splitlines()[-6000:]
except Exception as e:
    print("ERR", e); sys.exit(0)
for l in lines:
    try:
        if json.loads(l)["ts"] > since: print(l)
    except Exception:
        pass
'''


def fetch(target, log, since):
    """New samples (list), [] if the log is missing/empty, None if the node is unreachable."""
    cmd = ["ssh", "-i", SWARM_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
           "-o", "StrictHostKeyChecking=no", target, "python3", "-", str(int(since)), log]
    try:
        r = subprocess.run(cmd, input=REMOTE_PY, capture_output=True, text=True, timeout=45)
    except Exception:
        return None
    if r.returncode != 0 and not r.stdout:
        return None
    out = []
    for line in r.stdout.splitlines():
        if line.startswith("ERR"):
            return []
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def ingest(node, samples):
    if not samples:
        return
    lines = []
    for s in samples:
        ts = datetime.fromtimestamp(s["ts"], timezone.utc)
        doc = {k: v for k, v in s.items() if k != "ts"}
        doc["@timestamp"] = ts.isoformat()
        doc["node"] = node
        lines.append(json.dumps({"index": {"_index": "thermal-" + ts.strftime("%Y.%m"), "_id": f"{node}-{s['ts']}"}}))
        lines.append(json.dumps(doc))
    try:
        r = requests.post(ES + "/_bulk?refresh=wait_for", data="\n".join(lines) + "\n",
                          headers={"Content-Type": "application/x-ndjson"}, timeout=30)
        if r.status_code != 200 or r.json().get("errors"):
            print(f"[thermal] ES bulk problem: HTTP {r.status_code} errors={r.json().get('errors')}")
    except Exception as e:
        print(f"[thermal] ES ingest failed: {e}")


def evaluate(win, prev_throttle):
    """Pure function. win = last <=WINDOW samples, oldest first. Returns {code: (level, msg)}."""
    probs = {}
    if not win:
        return probs
    last = win[-1]
    pkg = [s["cpu_pkg_c"] for s in win if s.get("cpu_pkg_c") is not None]
    hdd = [s["hdd_c"] for s in win if s.get("hdd_c") is not None]

    if sum(v >= PKG_CRIT for v in pkg) >= SUSTAIN_CRIT:
        probs["cpu_crit"] = ("crit", f"CPU package >= {PKG_CRIT:.0f}C (peak {max(pkg):.0f}C in the last ~5 min)")
    elif pkg and sum(v >= PKG_WARN for v in pkg) >= min(SUSTAIN_WARN, len(win)):
        probs["cpu_warn"] = ("warn", f"CPU package >= {PKG_WARN:.0f}C sustained (~3 min, peak {max(pkg):.0f}C)")

    if hdd and max(hdd) >= HDD_CRIT:
        probs["hdd_crit"] = ("crit", f"HDD at {max(hdd):.0f}C (>= {HDD_CRIT:.0f}C)")
    elif hdd and max(hdd) >= HDD_WARN:
        probs["hdd_warn"] = ("warn", f"HDD at {max(hdd):.0f}C (>= {HDD_WARN:.0f}C)")

    if prev_throttle is not None:
        dp = last.get("throttle_pkg_count", 0) - prev_throttle.get("pkg", 0)
        dc = last.get("throttle_core_count", 0) - prev_throttle.get("core", 0)
        if dp > 0 or dc > 0:
            ms = last.get("throttle_pkg_ms", 0) - prev_throttle.get("ms", 0)
            probs["throttle"] = ("crit", f"CPU thermal throttling occurred (+{dp} package / +{dc} core events, +{ms} ms throttled) — the CPU hit its limit")

    idle = [s["cpu_pkg_c"] for s in win if s.get("cpu_pkg_c") is not None and (s.get("load1") or 0) < 0.5]
    if len(idle) >= 6 and statistics.median(idle) >= IDLE_HOT:
        probs["idle_hot"] = ("warn", f"hot while idle: median CPU {statistics.median(idle):.0f}C at load < 0.5 (fan/airflow/dust?)")
    return probs


def es_percentile50(node, gte, lt):
    q = {"size": 0, "query": {"bool": {"filter": [
            {"term": {"node.keyword": node}},
            {"range": {"@timestamp": {"gte": gte, "lt": lt}}},
            {"range": {"load1": {"lt": 0.5}}}]}},
         "aggs": {"p": {"percentiles": {"field": "cpu_pkg_c", "percents": [50]}},
                  "n": {"value_count": {"field": "cpu_pkg_c"}}}}
    try:
        d = requests.post(ES + "/thermal-*/_search", json=q, timeout=20).json()
        return d["aggregations"]["p"]["values"]["50.0"], d["aggregations"]["n"]["value"]
    except Exception:
        return None, 0


def drift(node):
    """Idle CPU temp, last 24h vs the prior 2..10 days. Returns (problem|None, note)."""
    recent, n1 = es_percentile50(node, "now-1d", "now")
    base, n2 = es_percentile50(node, "now-10d", "now-2d")
    if recent is None or base is None or n1 < 300 or n2 < 1000:
        return None, f"drift: collecting baseline (idle samples recent={n1}, baseline={n2})"
    delta = recent - base
    if delta >= DRIFT_C:
        return ("warn", f"idle CPU temp drifting up: median {recent:.0f}C (24h) vs {base:.0f}C baseline (+{delta:.0f}C) — dust, fan or thermal paste"), f"drift +{delta:.1f}C"
    return None, f"drift ok ({delta:+.1f}C)"


def load_state():
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {}


def telegram(text):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[thermal] telegram not configured")
        return
    try:
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                      json={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=10)
    except Exception as e:
        print(f"[thermal] telegram failed: {e}")


def last_known(node):
    try:
        d = requests.post(ES + "/thermal-*/_search", json={"size": 1, "sort": [{"@timestamp": "desc"}],
                          "query": {"term": {"node.keyword": node}}}, timeout=15).json()
        h = d["hits"]["hits"][0]["_source"]
        age = int((datetime.now(timezone.utc) - datetime.fromisoformat(h["@timestamp"])).total_seconds() / 60)
        return f"last reading {age} min ago: CPU {h.get('cpu_pkg_c')}C, HDD {h.get('hdd_c')}C, load {h.get('load1')}, AC={h.get('ac_online')}"
    except Exception:
        return "no earlier reading found"


def summary(s):
    ac = "AC" if s.get("ac_online") == 1 else f"BATTERY {s.get('bat_pct')}%"
    return (f"CPU {s.get('cpu_pkg_c')}C (core max {s.get('cpu_core_max_c')}C) | HDD {s.get('hdd_c')}C | "
            f"load {s.get('load1')} | {ac} | throttle events {s.get('throttle_pkg_count', 0) + s.get('throttle_core_count', 0)}")


def main():
    state = load_state()
    now = time.time()
    for node, cfg in NODES.items():
        if not cfg["target"]:
            print(f"[thermal] {node}: no SSH target configured")
            continue
        st = state.setdefault(node, {"last_ts": 0, "fails": 0, "active": {}, "thr": None,
                                     "last_alert": 0, "last_drift_check": 0, "drift_note": ""})
        samples = fetch(cfg["target"], cfg["log"], st["last_ts"])
        probs, latest = {}, None

        if samples is None:
            st["fails"] += 1
            if st["fails"] >= UNREACH_FAILS:
                probs["unreachable"] = ("crit", f"node unreachable for {st['fails'] * 5}+ min — possible overheat shutdown, power loss or network; {last_known(node)}")
            print(f"[thermal] {node}: UNREACHABLE (consecutive fails={st['fails']})")
        else:
            st["fails"] = 0
            ingest(node, samples)
            if samples:
                st["last_ts"] = max(s["ts"] for s in samples)
            # The evaluation window lives in our own state, NOT in Elasticsearch: alerting must keep
            # working if ES is down, and a just-indexed doc is not searchable until the next refresh
            # (that read-your-own-write gap produced a false "no samples" alert on the first run).
            merged = {s["ts"]: s for s in st.get("buf", []) + samples}
            win = [merged[k] for k in sorted(merged)][-WINDOW:]
            st["buf"] = win
            if win:
                latest = win[-1]
                if now - latest["ts"] > STALE_S:
                    probs["stale"] = ("warn", f"no thermal sample for {int((now - latest['ts']) / 60)} min but the node answers SSH — sampler/timer stopped?")
                prev = st["thr"]
                probs.update(evaluate(win, prev))
                st["thr"] = {"pkg": latest.get("throttle_pkg_count", 0), "core": latest.get("throttle_core_count", 0),
                             "ms": latest.get("throttle_pkg_ms", 0)}
            else:
                probs["stale"] = ("warn", "no thermal samples at all for this node (sampler never ran?)")

            if now - st["last_drift_check"] > 6 * 3600:
                st["last_drift_check"] = now
                p, note = drift(node)
                st["drift_note"] = note
                if p:
                    probs["drift"] = p
            elif "drift" in st["active"]:
                probs["drift"] = tuple(st["active"]["drift"])   # keep until the next 6-hourly check clears it
            print(f"[thermal] {node}: {'OK' if not probs else 'PROBLEMS: ' + ', '.join(probs)} | "
                  f"{summary(latest) if latest else 'no samples yet'} | +{len(samples)} samples | {st['drift_note']}")

        prev_codes = set(st["active"])
        codes = set(probs)
        crit = any(v[0] == "crit" for v in probs.values())
        if codes and (codes != prev_codes or (crit and now - st["last_alert"] > REALERT_S)):
            head = "THERMAL CRITICAL" if crit else "THERMAL WARNING"
            body = "\n".join(f"- {m}" for _, m in probs.values())
            tail = f"\n{summary(latest)}" if latest else ""
            telegram(f"{head} on {node}:\n{body}{tail}")
            st["last_alert"] = now
        elif not codes and prev_codes:
            telegram(f"THERMAL RECOVERED on {node}." + (f"\n{summary(latest)}" if latest else ""))
        st["active"] = {k: list(v) for k, v in probs.items()}

    STATE_FILE.write_text(json.dumps(state))


if __name__ == "__main__":
    main()
