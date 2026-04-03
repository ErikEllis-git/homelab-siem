#!/usr/bin/env python3
"""
honeypot_analyzer.py — ML-based Cowrie honeypot session analysis.

Runs every 30 min via cron. Queries ES cowrie-* for new sessions,
extracts per-session features, scores with IsolationForest + DBSCAN,
cross-references attacker IPs against cluster node traffic, and dispatches
high-interest sessions to Claude via soc_dispatch.

IsolationForest flags sessions that deviate from the bot-noise baseline
(the vast majority of traffic). DBSCAN clusters similar sessions so outliers
stand out. Rule-based triage overrides ML for clear-cut cases (login +
commands run, cross-node IP hit).

Usage:
  python3 honeypot_analyzer.py            # normal cron mode
  python3 honeypot_analyzer.py --dry-run  # analyze without alerting
  python3 honeypot_analyzer.py --lookback 2h  # look back further
"""

import argparse
import json
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import requests
from dotenv import dotenv_values
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).parent))

from geo_intel import format_geo, geolocate
from soc_dispatch import dispatch_honeypot, dispatch_honeypot_digest, is_tg_suppressed, record_tg_alert
from threat_intel import lookup_ips

# ── Config ────────────────────────────────────────────────────────────────────

ENV_FILE   = Path("/home/rosse/.env")
ES_HOST    = "http://localhost:9200"
DEDUP_FILE   = Path(__file__).parent / "honeypot_dedup.json"
DIGEST_FILE  = Path(__file__).parent / "honeypot_digest_state.json"

LOOKBACK_DEFAULT = "35m"   # 30min cron + 5min overlap to avoid edge gaps
DIGEST_INTERVAL  = 21600   # 6 hours — how often to send the Telegram digest

# IsolationForest: decision_function negated so higher = more anomalous
IF_ANOMALY_THRESHOLD = 0.05
MIN_SESSIONS_FOR_ML  = 5    # skip ML below this (cold start / quiet windows)

# DBSCAN: label -1 = outlier (no close neighbors = behaviorally unique)
DBSCAN_EPS     = 0.8
DBSCAN_SAMPLES = 2

DEDUP_TTL = 86400   # 24h — don't re-alert the same session

SESSION_FEATURE_COLS = [
    "session_duration",    # how long they stayed
    "login_attempts",      # total auth attempts
    "login_success",       # got a shell
    "commands_run",        # commands executed in fake shell
    "unique_commands",     # distinct commands (script diversity)
    "used_pubkey",         # tried public key auth
    "locale_vars_count",   # LC_* env vars forwarded (real interactive client signal)
    "client_is_openssh",   # OpenSSH vs known scanner library
    "multi_session_ip",    # this IP has multiple sessions in the window
    "hour_of_day",         # timing pattern
]


# ── Env / Telegram ────────────────────────────────────────────────────────────

def _load_env() -> dict:
    env = {}
    try:
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        pass
    return env


def _send_telegram(token: str, chat_id: str, text: str) -> None:
    try:
        requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
            timeout=10,
        )
    except Exception as e:
        print(f"  [warn] Telegram send failed: {e}", file=sys.stderr)


# ── Dedup ─────────────────────────────────────────────────────────────────────

def _load_dedup() -> dict:
    try:
        return json.loads(DEDUP_FILE.read_text())
    except Exception:
        return {}


def _is_session_seen(session_id: str) -> bool:
    return (time.time() - _load_dedup().get(session_id, 0)) < DEDUP_TTL


def _looks_like_human(sess: dict) -> bool:
    """Return True if session shows signs of a real user rather than an automated bot.
    Bots use scanner libraries (libssh, paramiko), no locale vars, no pubkey.
    Humans use OpenSSH with locale forwarding or pubkey auth.
    """
    cv = sess.get("client_version", "")
    return cv.startswith("SSH-2.0-OpenSSH") and (
        sess.get("locale_vars", 0) > 0 or sess.get("used_pubkey", False)
    )


def _load_digest_state() -> dict:
    try:
        return json.loads(DIGEST_FILE.read_text())
    except Exception:
        return {
            "last_sent":    0.0,
            "period_start": datetime.now(timezone.utc).isoformat(),
            "sessions":     0,
            "shells":       0,
            "unique_ips":   [],
            "commands":     {},
            "countries":    {},
            "severity":     {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0},
            "ti_hits":      [],
        }


def _save_digest_state(state: dict) -> None:
    try:
        DIGEST_FILE.write_text(json.dumps(state))
    except Exception as e:
        print(f"[honeypot] could not write digest state: {e}")


def _record_sessions(session_ids: list[str]) -> None:
    state = _load_dedup()
    now   = time.time()
    state = {k: v for k, v in state.items() if (now - v) < DEDUP_TTL}
    for sid in session_ids:
        state[sid] = now
    try:
        DEDUP_FILE.write_text(json.dumps(state))
    except Exception as e:
        print(f"[honeypot] could not write dedup: {e}")


# ── ES queries ────────────────────────────────────────────────────────────────

def fetch_sessions(lookback: str) -> dict[str, dict]:
    """
    Pull all cowrie events in the lookback window and aggregate per session_id.
    Returns session_id -> session dict.
    """
    query = {
        "size": 2000,
        "query": {"range": {"@timestamp": {"gte": f"now-{lookback}"}}},
        "sort": [{"@timestamp": {"order": "asc"}}],
        "_source": [
            "@timestamp", "eventid", "src_ip", "session",
            "username", "password", "message", "duration",
            "version", "name", "value", "key", "fingerprint",
        ],
    }
    try:
        resp = requests.post(
            f"{ES_HOST}/cowrie-*/_search",
            json=query,
            headers={"Content-Type": "application/json"},
            timeout=20,
        )
        resp.raise_for_status()
        hits = resp.json()["hits"]["hits"]
    except Exception as e:
        print(f"[honeypot] ES query failed: {e}", file=sys.stderr)
        return {}

    sessions: dict[str, dict] = {}
    for hit in hits:
        s   = hit["_source"]
        sid = s.get("session", "unknown")
        if sid not in sessions:
            sessions[sid] = {
                "session_id":     sid,
                "src_ip":         s.get("src_ip", ""),
                "first_seen":     s.get("@timestamp", ""),
                "login_attempts": 0,
                "login_success":  False,
                "commands":       [],
                "duration":       0.0,
                "client_version": "",
                "used_pubkey":    False,
                "locale_vars":    0,
            }
        sess = sessions[sid]
        eid  = s.get("eventid", "")

        if eid == "cowrie.login.failed":
            sess["login_attempts"] += 1
        elif eid == "cowrie.login.success":
            sess["login_attempts"] += 1
            sess["login_success"]   = True
        elif eid == "cowrie.command.input":
            # filebeat's own 'input' field collides with Cowrie's — read from message instead
            msg = s.get("message", "")
            cmd = msg[5:].strip() if msg.startswith("CMD: ") else ""
            if cmd:
                sess["commands"].append(cmd)
        elif eid == "cowrie.session.closed":
            try:
                sess["duration"] = float(s.get("duration") or 0)
            except (TypeError, ValueError):
                pass
        elif eid == "cowrie.client.version":
            sess["client_version"] = s.get("version", "")
        elif eid == "cowrie.client.fingerprint":
            sess["used_pubkey"] = True
        elif eid == "cowrie.client.var":
            name = s.get("name", "")
            if name.startswith("LC_") or name == "LANG":
                sess["locale_vars"] += 1

    return sessions


def cross_reference_ips(ips: list[str]) -> dict[str, list[str]]:
    """
    Check whether honeypot attacker IPs appear in cluster node logs (filebeat-*)
    in the last 24h. Returns {ip: [node, ...]} for any matches found.
    """
    result = {}
    for ip in ips:
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-24h"}}},
                        {"match_phrase": {"message": ip}},
                        # auth logs only — excludes tailscaled, syslog noise, etc.
                        {"term": {"fields.log_type": "auth"}},
                    ],
                }
            },
            "aggs": {"by_node": {"terms": {"field": "host_name", "size": 5}}},
        }
        try:
            resp = requests.post(
                f"{ES_HOST}/filebeat-*/_search",
                json=query,
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            resp.raise_for_status()
            nodes = [b["key"] for b in resp.json()["aggregations"]["by_node"]["buckets"]]
            if nodes:
                result[ip] = nodes
        except Exception as e:
            print(f"[honeypot] cross-ref failed for {ip}: {e}", file=sys.stderr)
    return result


# ── Feature extraction ────────────────────────────────────────────────────────

def extract_features(sessions: dict[str, dict]) -> dict[str, list[float]]:
    """Build a numeric feature vector for each session (see SESSION_FEATURE_COLS)."""
    ip_count = defaultdict(int)
    for sess in sessions.values():
        ip_count[sess["src_ip"]] += 1

    features = {}
    for sid, sess in sessions.items():
        cv         = sess.get("client_version", "")
        is_openssh = 1.0 if cv.startswith("SSH-2.0-OpenSSH") else 0.0
        try:
            hour = datetime.fromisoformat(
                sess.get("first_seen", "").replace("Z", "+00:00")
            ).hour
        except Exception:
            hour = 0.0

        features[sid] = [
            min(sess["duration"], 3600.0),            # cap at 1h to avoid distortion
            float(sess["login_attempts"]),
            1.0 if sess["login_success"] else 0.0,
            float(len(sess["commands"])),
            float(len(set(sess["commands"]))),
            1.0 if sess["used_pubkey"] else 0.0,
            float(sess["locale_vars"]),
            is_openssh,
            float(min(ip_count[sess["src_ip"]], 10)),  # cap at 10
            float(hour),
        ]
    return features


# ── ML ────────────────────────────────────────────────────────────────────────

def score_sessions(feature_map: dict[str, list[float]]) -> dict[str, float]:
    """
    IsolationForest anomaly scoring.
    Trained fresh on the current window — we want outliers within this batch,
    not relative to a stale historical model.
    Returns session_id -> score where higher = more anomalous.
    """
    if len(feature_map) < MIN_SESSIONS_FOR_ML:
        print(f"[honeypot] {len(feature_map)} sessions — skipping IF (need {MIN_SESSIONS_FOR_ML})")
        return {}

    sids     = list(feature_map.keys())
    X        = np.array([feature_map[s] for s in sids], dtype=float)
    X_scaled = StandardScaler().fit_transform(X)

    model  = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
    model.fit(X_scaled)
    scores = -model.decision_function(X_scaled)   # negate: higher = more anomalous
    return {sid: float(score) for sid, score in zip(sids, scores)}


def cluster_sessions(feature_map: dict[str, list[float]]) -> dict[str, int]:
    """
    DBSCAN clustering.
    Label -1 = outlier (behaviorally unique, no close neighbors).
    Label >= 0 = bot cluster (same script, same credential spray pattern).
    """
    if len(feature_map) < DBSCAN_SAMPLES:
        return {sid: -1 for sid in feature_map}

    sids     = list(feature_map.keys())
    X        = np.array([feature_map[s] for s in sids], dtype=float)
    X_scaled = StandardScaler().fit_transform(X)
    labels   = DBSCAN(eps=DBSCAN_EPS, min_samples=DBSCAN_SAMPLES).fit_predict(X_scaled)
    return {sid: int(label) for sid, label in zip(sids, labels)}


# ── Triage ────────────────────────────────────────────────────────────────────

def triage_session(
    sess: dict,
    if_score: float | None,
    dbscan_label: int | None,
    ti: dict,
    cross_ref: dict,
) -> str:
    """
    Return CRITICAL / HIGH / MEDIUM / LOW / INFO.
    Rule-based checks take priority; ML is a secondary signal for anomalous probes.
    """
    ip         = sess["src_ip"]
    has_intel  = bool(ti.get(ip))
    on_cluster = ip in cross_ref

    # Rule-based (highest priority — always override ML)
    if on_cluster and sess["login_success"]:
        return "CRITICAL"
    if on_cluster:
        return "HIGH"
    if sess["login_success"] and sess["commands"]:
        return "CRITICAL"
    if sess["login_success"] and (has_intel or sess["used_pubkey"]):
        return "HIGH"
    if sess["login_success"]:
        return "MEDIUM"

    # ML layer — for probes that never got a shell
    if if_score is not None and if_score > IF_ANOMALY_THRESHOLD:
        if has_intel or on_cluster:
            return "HIGH"
        if dbscan_label == -1:
            return "MEDIUM"

    return "INFO"


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run",  action="store_true", help="analyze without alerting")
    parser.add_argument("--lookback", default=LOOKBACK_DEFAULT)
    args = parser.parse_args()

    env        = _load_env()
    tg_token   = env.get("TELEGRAM_TOKEN", "")
    tg_chat_id = env.get("TELEGRAM_CHAT_ID", "")

    print(f"[honeypot] analyzing cowrie sessions (lookback={args.lookback})")

    sessions = fetch_sessions(args.lookback)
    if not sessions:
        print("[honeypot] no sessions found")
        return

    new_sessions = {sid: s for sid, s in sessions.items() if not _is_session_seen(sid)}
    print(f"[honeypot] {len(sessions)} sessions total, {len(new_sessions)} new")
    if not new_sessions:
        print("[honeypot] all sessions already seen — done")
        return

    all_ips = list({s["src_ip"] for s in new_sessions.values() if s["src_ip"]})

    # Enrichment
    ti    = lookup_ips(all_ips)
    geo   = geolocate(all_ips)
    x_ref = cross_reference_ips(all_ips)
    if x_ref:
        print(f"[honeypot] CROSS-NODE HIT: {list(x_ref.keys())}")

    # ML
    feat_map    = extract_features(new_sessions)
    if_scores   = score_sessions(feat_map)
    dbscan_lbls = cluster_sessions(feat_map)

    # Triage
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    triaged = sorted(
        [
            (
                triage_session(sess, if_scores.get(sid), dbscan_lbls.get(sid), ti, x_ref),
                sid,
                sess,
            )
            for sid, sess in new_sessions.items()
        ],
        key=lambda x: SEV_ORDER.get(x[0], 99),
    )

    crit_high  = [(s, sid, sess) for s, sid, sess in triaged if s in ("CRITICAL", "HIGH")]
    medium     = [(s, sid, sess) for s, sid, sess in triaged if s == "MEDIUM"]
    info_count = sum(1 for s, _, _ in triaged if s in ("LOW", "INFO"))

    print(
        f"[honeypot] triage: {len(crit_high)} CRITICAL/HIGH  "
        f"{len(medium)} MEDIUM  {info_count} INFO/LOW"
    )

    # ── Digest accumulation ───────────────────────────────────────────────────
    digest = _load_digest_state()
    now    = time.time()

    digest["sessions"] += len(new_sessions)
    digest["shells"]   += sum(1 for s in new_sessions.values() if s["login_success"])
    seen_ips = set(digest["unique_ips"])
    for sess in new_sessions.values():
        seen_ips.add(sess["src_ip"])
        for cmd in sess["commands"]:
            key = cmd[:80]
            digest["commands"][key] = digest["commands"].get(key, 0) + 1
        country = (geo.get(sess["src_ip"]) or {}).get("country", "")
        if country:
            digest["countries"][country] = digest["countries"].get(country, 0) + 1
        if ti.get(sess["src_ip"]):
            entry = f"{sess['src_ip']}: {ti[sess['src_ip']]['malware']}"
            if entry not in digest["ti_hits"]:
                digest["ti_hits"].append(entry)
    digest["unique_ips"] = list(seen_ips)
    for sev, _, _ in triaged:
        key = sev if sev in ("CRITICAL", "HIGH", "MEDIUM") else "INFO"
        digest["severity"][key] = digest["severity"].get(key, 0) + 1

    # ── Immediate alerts: cross-node or human-looking sessions only ───────────
    immediate = [
        (sev, sid, sess)
        for sev, sid, sess in crit_high
        if sess["src_ip"] in x_ref or _looks_like_human(sess)
    ]

    if immediate and not args.dry_run:
        payloads  = [
            {
                "session_id":     sid,
                "src_ip":         sess["src_ip"],
                "severity":       sev,
                "login_success":  sess["login_success"],
                "commands":       "; ".join(sess["commands"][:10]),
                "duration":       sess["duration"],
                "client_version": sess.get("client_version", ""),
                "used_pubkey":    sess["used_pubkey"],
                "geo":            format_geo(geo[sess["src_ip"]]) if geo.get(sess["src_ip"]) else "",
                "intel":          (
                    f"{ti[sess['src_ip']]['malware']} ({ti[sess['src_ip']]['source']})"
                    if ti.get(sess["src_ip"]) else ""
                ),
                "if_score":     if_scores.get(sid),
                "dbscan_label": dbscan_lbls.get(sid),
            }
            for sev, sid, sess in immediate
        ]
        cross_ips = [p["src_ip"] for p in payloads if p["src_ip"] in x_ref]
        summary   = "; ".join(
            f"{p['src_ip']} — {'cross-node' if p['src_ip'] in x_ref else 'human-looking'}"
            for p in payloads
        )
        dispatch_honeypot(
            sessions=payloads,
            severity=payloads[0]["severity"],
            summary=summary,
            cross_node_ips=cross_ips or None,
        )
        print(f"[honeypot] {len(payloads)} immediate alert(s) dispatched (cross-node/human)")
    else:
        print(f"[honeypot] no immediate alerts — {len(crit_high)} CRIT/HIGH queued for digest")

    # ── 6-hour digest ─────────────────────────────────────────────────────────
    if (now - digest["last_sent"]) >= DIGEST_INTERVAL and not args.dry_run:
        dispatch_honeypot_digest(digest)
        digest["last_sent"]    = now
        digest["period_start"] = datetime.now(timezone.utc).isoformat()
        digest["sessions"]     = 0
        digest["shells"]       = 0
        digest["unique_ips"]   = []
        digest["commands"]     = {}
        digest["countries"]    = {}
        digest["severity"]     = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
        digest["ti_hits"]      = []

    # Mark all new sessions seen (including INFO — no repeat checks tomorrow)
    if not args.dry_run:
        _save_digest_state(digest)
        _record_sessions(list(new_sessions.keys()))

    print(f"[honeypot] done — {len(immediate)} immediate, digest accumulating")


if __name__ == "__main__":
    main()
