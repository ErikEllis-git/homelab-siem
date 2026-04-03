#!/usr/bin/env python3
"""
web_honeypot_analyzer.py — ML-based web honeypot request analysis.

Runs every 30 min via cron. Queries ES webhoneypot-* for new requests,
clusters IPs by behavior (what rules they hit, credential attempts, scanner
vs targeted), and surfaces anything interesting via Telegram + SOC dispatch.

Usage:
  python3 web_honeypot_analyzer.py            # normal cron mode
  python3 web_honeypot_analyzer.py --dry-run
  python3 web_honeypot_analyzer.py --lookback 6h
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
from soc_dispatch import dispatch_honeypot, is_tg_suppressed, record_tg_alert
from threat_intel import lookup_ips

ENV_FILE   = Path("/home/rosse/.env")
ES_HOST    = "http://localhost:9200"
DEDUP_FILE = Path(__file__).parent / "web_honeypot_dedup.json"

LOOKBACK_DEFAULT = "35m"
DEDUP_TTL        = 3600   # 1h per IP (web scanners are noisy — shorter than SSH)
MIN_IPS_FOR_ML   = 5

# Rules that indicate a targeted/interesting probe (not generic internet noise)
HIGH_VALUE_RULES = {
    "env_file_exposure",
    "git_config_exposure",
    "spring_actuator",
    "webshell_attempt",
    "phpmyadmin_login",
    "wordpress_login",
    "wordpress_xmlrpc",
    "admin_panel",
}

# Rules that are pure background noise
NOISE_RULES = {"unknown_probe"}


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


def _is_ip_seen(ip: str) -> bool:
    return (time.time() - _load_dedup().get(ip, 0)) < DEDUP_TTL


def _record_ips(ips: list[str]) -> None:
    state = _load_dedup()
    now   = time.time()
    state = {k: v for k, v in state.items() if (now - v) < DEDUP_TTL}
    for ip in ips:
        state[ip] = now
    try:
        DEDUP_FILE.write_text(json.dumps(state))
    except Exception as e:
        print(f"[web_honeypot] could not write dedup: {e}")


# ── ES query ──────────────────────────────────────────────────────────────────

def fetch_requests(lookback: str) -> dict[str, dict]:
    """
    Pull web honeypot events and aggregate per src_ip.
    Returns ip -> profile dict.
    """
    query = {
        "size": 2000,
        "query": {"range": {"@timestamp": {"gte": f"now-{lookback}"}}},
        "sort": [{"@timestamp": {"order": "asc"}}],
        "_source": [
            "@timestamp", "src_ip", "method", "path",
            "matched_rule", "user_agent", "post_data", "query", "body",
        ],
    }
    try:
        resp = requests.post(
            f"{ES_HOST}/webhoneypot-*/_search",
            json=query,
            headers={"Content-Type": "application/json"},
            timeout=20,
        )
        resp.raise_for_status()
        hits = resp.json()["hits"]["hits"]
    except Exception as e:
        print(f"[web_honeypot] ES query failed: {e}", file=sys.stderr)
        return {}

    profiles: dict[str, dict] = {}
    for hit in hits:
        s   = hit["_source"]
        ip  = s.get("src_ip", "")
        if not ip:
            continue
        if ip not in profiles:
            profiles[ip] = {
                "src_ip":        ip,
                "first_seen":    s.get("@timestamp", ""),
                "request_count": 0,
                "rules_hit":     set(),
                "paths":         set(),
                "credentials":   [],
                "user_agents":   set(),
                "has_post":      False,
                "webshell_cmds": [],
            }
        p   = profiles[ip]
        rule = s.get("matched_rule", "unknown_probe")
        p["request_count"] += 1
        p["rules_hit"].add(rule)
        p["paths"].add(s.get("path", ""))
        ua = s.get("user_agent", "")
        if ua:
            p["user_agents"].add(ua[:80])
        post = s.get("post_data")
        if post and isinstance(post, dict) and post:
            p["has_post"] = True
            # Harvest credentials from any login attempt
            for field in ("log", "pwd", "username", "password", "user", "pass",
                          "pma_username", "pma_password", "email"):
                if post.get(field):
                    p["credentials"].append({field: post[field][:100]})
        cmd = s.get("cmd", "")
        if cmd:
            p["webshell_cmds"].append(cmd[:200])

    # Convert sets to lists for JSON serialisation
    for p in profiles.values():
        p["rules_hit"]   = list(p["rules_hit"])
        p["paths"]       = list(p["paths"])
        p["user_agents"] = list(p["user_agents"])

    return profiles


def cross_reference_ips(ips: list[str]) -> dict[str, list[str]]:
    """Check if web attacker IPs also appear in cluster auth logs."""
    result = {}
    for ip in ips:
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-24h"}}},
                        {"match_phrase": {"message": ip}},
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
            print(f"[web_honeypot] cross-ref failed for {ip}: {e}", file=sys.stderr)
    return result


# ── Feature extraction ────────────────────────────────────────────────────────

def extract_features(profiles: dict[str, dict]) -> dict[str, list[float]]:
    """Build feature vector per IP for IsolationForest."""
    features = {}
    for ip, p in profiles.items():
        rules      = set(p["rules_hit"])
        n_hv_rules = len(rules & HIGH_VALUE_RULES)
        n_noise    = len(rules & NOISE_RULES)
        try:
            hour = datetime.fromisoformat(
                p["first_seen"].replace("Z", "+00:00")
            ).hour
        except Exception:
            hour = 0.0

        features[ip] = [
            float(p["request_count"]),
            float(len(rules)),            # rule diversity
            float(n_hv_rules),            # high-value rules hit
            float(len(p["paths"])),       # path diversity
            1.0 if p["credentials"] else 0.0,
            1.0 if p["webshell_cmds"] else 0.0,
            1.0 if p["has_post"] else 0.0,
            float(len(p["user_agents"])),  # UA rotation = bot
            float(n_noise),
            float(hour),
        ]
    return features


# ── ML ────────────────────────────────────────────────────────────────────────

def score_ips(feature_map: dict[str, list[float]]) -> dict[str, float]:
    if len(feature_map) < MIN_IPS_FOR_ML:
        print(f"[web_honeypot] {len(feature_map)} IPs — skipping ML (need {MIN_IPS_FOR_ML})")
        return {}
    ips      = list(feature_map.keys())
    X        = np.array([feature_map[i] for i in ips], dtype=float)
    X_scaled = StandardScaler().fit_transform(X)
    model    = IsolationForest(n_estimators=100, contamination=0.2, random_state=42)
    model.fit(X_scaled)
    scores   = -model.decision_function(X_scaled)
    return {ip: float(s) for ip, s in zip(ips, scores)}


def cluster_ips(feature_map: dict[str, list[float]]) -> dict[str, int]:
    if len(feature_map) < 2:
        return {ip: -1 for ip in feature_map}
    ips      = list(feature_map.keys())
    X        = np.array([feature_map[i] for i in ips], dtype=float)
    X_scaled = StandardScaler().fit_transform(X)
    labels   = DBSCAN(eps=0.8, min_samples=2).fit_predict(X_scaled)
    return {ip: int(l) for ip, l in zip(ips, labels)}


# ── Triage ────────────────────────────────────────────────────────────────────

def triage_ip(
    profile: dict,
    if_score: float | None,
    dbscan_label: int | None,
    ti: dict,
    cross_ref: dict,
) -> str:
    ip         = profile["src_ip"]
    rules      = set(profile["rules_hit"])
    has_intel  = bool(ti.get(ip))
    on_cluster = ip in cross_ref

    if on_cluster and profile["credentials"]:
        return "CRITICAL"
    if on_cluster:
        return "HIGH"
    if profile["webshell_cmds"]:
        return "CRITICAL"
    if profile["credentials"] and has_intel:
        return "HIGH"
    if profile["credentials"]:
        return "MEDIUM"
    if rules & HIGH_VALUE_RULES and has_intel:
        return "HIGH"
    if if_score is not None and if_score > 0.05:
        if has_intel or on_cluster:
            return "HIGH"
        if dbscan_label == -1 and rules & HIGH_VALUE_RULES:
            return "MEDIUM"
    return "INFO"


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run",  action="store_true")
    parser.add_argument("--lookback", default=LOOKBACK_DEFAULT)
    args = parser.parse_args()

    env        = _load_env()
    tg_token   = env.get("TELEGRAM_TOKEN", "")
    tg_chat_id = env.get("TELEGRAM_CHAT_ID", "")

    print(f"[web_honeypot] analyzing requests (lookback={args.lookback})")

    profiles = fetch_requests(args.lookback)
    if not profiles:
        print("[web_honeypot] no requests found")
        return

    new_profiles = {ip: p for ip, p in profiles.items() if not _is_ip_seen(ip)}
    print(f"[web_honeypot] {len(profiles)} IPs total, {len(new_profiles)} new")
    if not new_profiles:
        print("[web_honeypot] all IPs already seen — done")
        return

    all_ips = list(new_profiles.keys())
    ti      = lookup_ips(all_ips)
    geo     = geolocate(all_ips)
    x_ref   = cross_reference_ips(all_ips)
    if x_ref:
        print(f"[web_honeypot] CROSS-NODE HIT: {list(x_ref.keys())}")

    feat_map    = extract_features(new_profiles)
    if_scores   = score_ips(feat_map)
    dbscan_lbls = cluster_ips(feat_map)

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    triaged = sorted(
        [
            (
                triage_ip(p, if_scores.get(ip), dbscan_lbls.get(ip), ti, x_ref),
                ip,
                p,
            )
            for ip, p in new_profiles.items()
        ],
        key=lambda x: SEV_ORDER.get(x[0], 99),
    )

    crit_high  = [(s, ip, p) for s, ip, p in triaged if s in ("CRITICAL", "HIGH")]
    medium     = [(s, ip, p) for s, ip, p in triaged if s == "MEDIUM"]
    info_count = sum(1 for s, _, _ in triaged if s in ("LOW", "INFO"))

    print(f"[web_honeypot] triage: {len(crit_high)} CRITICAL/HIGH  {len(medium)} MEDIUM  {info_count} INFO")

    # ── Telegram ──────────────────────────────────────────────────────────────
    if not args.dry_run:
        notable = [
            (sev, ip, p) for sev, ip, p in crit_high + medium
            if p["credentials"] or p["webshell_cmds"] or ip in x_ref or ti.get(ip)
        ]
        lines = []
        for sev, ip, p in notable:
            country = (geo.get(ip) or {}).get("country", "??")
            if p["webshell_cmds"]:
                detail = f"shell: {p['webshell_cmds'][0][:50]}"
            elif p["credentials"]:
                cred = p["credentials"][0]
                detail = f"creds: {list(cred.items())[0]}"
            elif ip in x_ref:
                detail = f"also on cluster ({', '.join(x_ref[ip])})"
            elif ti.get(ip):
                detail = ti[ip]["malware"]
            else:
                rules_str = ", ".join(list(set(p["rules_hit"]) & HIGH_VALUE_RULES)[:3])
                detail = rules_str or "anomalous"
            lines.append(f"🌐 {ip} [{country}] — {detail}")

        if notable:
            print("[web_honeypot] Notable sessions: " + " | ".join(lines))
        else:
            print("[web_honeypot] No notable sessions")

    # ── SOC dispatch (CRITICAL only) ──────────────────────────────────────────
    dispatch_sessions = [
        {
            "session_id":     ip,
            "src_ip":         ip,
            "severity":       sev,
            "login_success":  bool(p["credentials"]),
            "commands":       "; ".join(p["webshell_cmds"][:5]),
            "duration":       0,
            "client_version": next(iter(p["user_agents"]), ""),
            "used_pubkey":    False,
            "geo":            format_geo(geo[ip]) if geo.get(ip) else "",
            "intel":          (
                f"{ti[ip]['malware']} ({ti[ip]['source']})" if ti.get(ip) else ""
            ),
            "if_score":       if_scores.get(ip),
            "dbscan_label":   dbscan_lbls.get(ip),
        }
        for sev, ip, p in crit_high
        if sev == "CRITICAL"
    ]

    if dispatch_sessions and not args.dry_run:
        top_sev   = dispatch_sessions[0]["severity"]
        cross_ips = [s["src_ip"] for s in dispatch_sessions if s["src_ip"] in x_ref]
        summary   = "; ".join(
            f"{s['src_ip']} — {'web shell' if s['commands'] else 'credential harvest'}"
            for s in dispatch_sessions
        )
        dispatch_honeypot(
            sessions=dispatch_sessions,
            severity=top_sev,
            summary=summary,
            cross_node_ips=cross_ips or None,
        )

    if not args.dry_run:
        _record_ips(all_ips)

    print(f"[web_honeypot] done — {len(dispatch_sessions)} dispatched to SOC")


if __name__ == "__main__":
    main()
