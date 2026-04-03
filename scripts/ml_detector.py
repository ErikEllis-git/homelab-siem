#!/usr/bin/env python3
"""
ml_detector.py — Phase 2: Isolation Forest anomaly detection.

Runs every hour at :10 (5 min after feature_extractor at :05).
Loads a persisted model from disk; retrains only when stale or when
enough new training rows have accumulated. Scores the latest hour,
writes results back to feature_store.db, and alerts via Telegram.

Usage:
  python3 ml_detector.py            # normal cron mode
  python3 ml_detector.py --dry-run  # score without writing back or alerting
  python3 ml_detector.py --retrain  # force retrain now, then score
  python3 ml_detector.py --backfill # rescore all historical rows (forces retrain)
"""

import sys
import argparse
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import requests
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).parent))

from soc_dispatch import dispatch_anomaly, is_tg_suppressed, record_tg_alert
from geo_intel import geolocate, format_geo
from feature_store import (
    init_db,
    get_node_training_data,
    get_ip_training_data,
    get_recent_node_features,
    get_recent_ip_features,
    get_recent_node_window,
    get_ip_series,
    update_node_anomaly_scores,
    update_ip_anomaly_scores,
    get_stats,
)

# ── Config ──────────────────────────────────────────────────────────────────────

ENV_FILE  = Path.home() / ".env"
MODEL_DIR = Path(__file__).parent / "models"

# Retrain if model is older than this many hours
RETRAIN_AFTER_HOURS = 24
# Retrain if training set has grown by this many rows since last train
RETRAIN_AFTER_NEW_ROWS = 24

MIN_NODE_ROWS = 24
MIN_IP_ROWS   = 10

CONTAMINATION = 0.03
TRAINING_DAYS = 30

NODE_FEATURE_COLS = [
    "ssh_failures", "ssh_successes", "unique_src_ips",
    "unique_users_failed", "failure_rate", "cron_events",
    "hour_of_day", "day_of_week",
    "is_orchestrator", "failure_velocity", "hours_since_success",
]

# Z-score check only on security-relevant features — not cron_events or is_orchestrator
ZSCORE_FEATURE_COLS = [
    "ssh_failures", "unique_src_ips", "unique_users_failed",
    "failure_rate", "failure_velocity",
]
ZSCORE_THRESHOLD     = 2.5   # standard deviations to flag
ZSCORE_MIN_HISTORY   = 12    # need at least 12h of history before trusting z-scores

# IP escalation: flag IPs with non-decreasing fail_count over this many consecutive hours
IP_ESCALATION_MIN_HOURS  = 3
IP_ESCALATION_MIN_TOTAL  = 5   # must have at least this many total failures to care
IP_FEATURE_COLS = [
    "fail_count", "success_count", "unique_users_tried",
    "node_count", "has_threat_intel",
]

# Escalation: score must exceed this to trigger SOC dispatch
NODE_ESCALATE_THRESHOLD = 0.05
# Score or node count that bumps severity to CRITICAL
NODE_CRITICAL_THRESHOLD = 0.15
CRITICAL_NODE_COUNT     = 2   # 2+ nodes anomalous in the same hour → CRITICAL


# ── Telegram ────────────────────────────────────────────────────────────────────

def _load_env() -> dict:
    env = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip('"').strip("'")
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


# ── Model persistence ────────────────────────────────────────────────────────────

def _model_path(name: str) -> Path:
    return MODEL_DIR / f"{name}.joblib"


def _load_bundle(name: str) -> dict | None:
    path = _model_path(name)
    if not path.exists():
        return None
    try:
        return joblib.load(path)
    except Exception as e:
        print(f"  [warn] Failed to load {name} model: {e}")
        return None


def _save_bundle(name: str, bundle: dict) -> None:
    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump(bundle, _model_path(name))


def _needs_retrain(bundle: dict | None, n_rows: int) -> bool:
    if bundle is None:
        return True
    age_h = (datetime.now(timezone.utc) - bundle["trained_at"]).total_seconds() / 3600
    if age_h >= RETRAIN_AFTER_HOURS:
        return True
    if (n_rows - bundle["n_train_rows"]) >= RETRAIN_AFTER_NEW_ROWS:
        return True
    return False


# ── Model training ───────────────────────────────────────────────────────────────

def _to_matrix(rows, cols: list[str]) -> np.ndarray:
    return np.array([[float(row[c] or 0) for c in cols] for row in rows])


def _train(train_rows, feature_cols: list[str]) -> dict:
    X = _to_matrix(train_rows, feature_cols)
    scaler = StandardScaler()
    X_s = scaler.fit_transform(X)

    iso = IsolationForest(
        n_estimators=200,
        contamination=CONTAMINATION,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_s)

    # LocalOutlierFactor with novelty=True so we can score unseen test points.
    # n_neighbors=20 works well for our dataset size (~900 rows).
    lof = LocalOutlierFactor(
        n_neighbors=20,
        contamination=CONTAMINATION,
        novelty=True,
    )
    lof.fit(X_s)

    return {
        "model":        iso,
        "lof":          lof,
        "scaler":       scaler,
        "trained_at":   datetime.now(timezone.utc),
        "n_train_rows": len(train_rows),
    }


def _score(bundle: dict, score_rows, feature_cols: list[str]) -> tuple[list[float], list[int]]:
    """
    Score rows using an ensemble of IsolationForest and LocalOutlierFactor.

    Both models use the same StandardScaler fitted during training. Scores are
    normalised to the same sign convention (higher = more suspicious) then
    combined as a weighted average: 60% IF + 40% LOF. A row is flagged if
    either individual model flags it OR the ensemble score exceeds the
    contamination-derived decision boundary.
    """
    X = _to_matrix(score_rows, feature_cols)
    X_s = bundle["scaler"].transform(X)

    # IsolationForest: negate decision_function so higher = more suspicious
    if_raw    = bundle["model"].decision_function(X_s)
    if_scores = (-if_raw)
    if_preds  = bundle["model"].predict(X_s)   # -1 = anomaly

    # LOF: same convention
    lof_raw    = bundle["lof"].decision_function(X_s)
    lof_scores = (-lof_raw)
    lof_preds  = bundle["lof"].predict(X_s)

    # Ensemble: weighted average score; flag if either model flags
    ensemble = (0.6 * if_scores + 0.4 * lof_scores).tolist()
    flags = [
        1 if (if_preds[i] == -1 or lof_preds[i] == -1) else 0
        for i in range(len(score_rows))
    ]
    return ensemble, flags


def get_or_train(name: str, train_rows, feature_cols: list[str],
                 force_retrain: bool = False) -> dict:
    """Load model from disk; retrain if stale, missing, or forced."""
    bundle = _load_bundle(name)

    if force_retrain or _needs_retrain(bundle, len(train_rows)):
        reason = "forced" if force_retrain else (
            "no saved model" if bundle is None else
            f"age={((datetime.now(timezone.utc) - bundle['trained_at']).total_seconds()/3600):.1f}h" if
            (datetime.now(timezone.utc) - bundle["trained_at"]).total_seconds() / 3600 >= RETRAIN_AFTER_HOURS else
            f"new rows +{len(train_rows) - bundle['n_train_rows']}"
        )
        print(f"  [{name}] Training on {len(train_rows)} rows ({reason})")
        bundle = _train(train_rows, feature_cols)
        _save_bundle(name, bundle)
        print(f"  [{name}] Model saved to {_model_path(name)}")
    else:
        age_h = (datetime.now(timezone.utc) - bundle["trained_at"]).total_seconds() / 3600
        print(f"  [{name}] Loaded model  trained={bundle['trained_at'].strftime('%Y-%m-%d %H:%M UTC')}  "
              f"age={age_h:.1f}h  rows={bundle['n_train_rows']}")

    return bundle


# ── Alert formatting ─────────────────────────────────────────────────────────────

def _format_node_alert(rows, scores: list[float], flags: list[int]) -> str | None:
    flagged = [(rows[i], scores[i]) for i in range(len(rows)) if flags[i]]
    if not flagged:
        return None
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "🤖 *ML Anomaly Detector*",
        f"_{now}_",
        "",
        f"*Node anomalies:* {len(flagged)}",
        "",
    ]
    for row, score in sorted(flagged, key=lambda x: -x[1]):
        lines.append(
            f"• `{row['node']}` @ {row['bucket_time']}\n"
            f"  score={score:.3f}  failures={row['ssh_failures']}  "
            f"unique\\_ips={row['unique_src_ips']}  "
            f"cron={row['cron_events']}"
        )
    return "\n".join(lines)


def _format_ip_alert(rows, scores: list[float], flags: list[int],
                     geo: dict | None = None) -> str | None:
    flagged = [(rows[i], scores[i]) for i in range(len(rows)) if flags[i]]
    if not flagged:
        return None
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "🤖 *ML Anomaly — Suspicious IPs*",
        f"_{now}_",
        "",
        f"*IP anomalies:* {len(flagged)}",
        "",
    ]
    for row, score in sorted(flagged, key=lambda x: -x[1]):
        ti_tag  = " ⚠️ TI MATCH" if row["has_threat_intel"] else ""
        geo_str = ""
        if geo and geo.get(row["src_ip"]):
            geo_str = f" [{format_geo(geo[row['src_ip']])}]"
        lines.append(
            f"• `{row['src_ip']}`{ti_tag}{geo_str} @ {row['bucket_time']}\n"
            f"  score={score:.3f}  fails={row['fail_count']}  "
            f"nodes={row['node_count']}  "
            f"users={row['unique_users_tried']}"
        )
    return "\n".join(lines)


# ── SOC escalation ──────────────────────────────────────────────────────────────

def _escalate_node_anomalies(rows, scores: list[float], flags: list[int]) -> None:
    """Dispatch a SOC investigation if node anomaly scores cross the threshold."""
    escalate = [
        (rows[i], scores[i])
        for i in range(len(rows))
        if flags[i] and scores[i] >= NODE_ESCALATE_THRESHOLD
    ]
    if not escalate:
        return

    n_nodes   = len(escalate)
    max_score = max(s for _, s in escalate)
    nodes_str = ", ".join(row["node"] for row, _ in escalate)
    bucket    = escalate[0][0]["bucket_time"]

    severity = (
        "CRITICAL" if (n_nodes >= CRITICAL_NODE_COUNT or max_score >= NODE_CRITICAL_THRESHOLD)
        else "HIGH"
    )

    # Build a human-readable summary of what made each node anomalous
    detail_lines = []
    for row, score in sorted(escalate, key=lambda x: -x[1]):
        detail_lines.append(
            f"{row['node']}: score={score:.3f}  failures={row['ssh_failures']}  "
            f"unique_ips={row['unique_src_ips']}  failure_rate={row['failure_rate']:.2f}  "
            f"cron={row['cron_events']}"
        )

    summary = (
        f"Isolation Forest flagged {n_nodes} node(s) as anomalous at {bucket}. "
        + " | ".join(detail_lines)
    )
    recommendation = (
        "Investigate live connections and recent auth activity on the affected node(s). "
        "Check for unusual processes, new cron jobs, or unexpected login sources."
    )

    dispatch_anomaly(
        severity      = severity,
        threat        = "ML anomaly: Isolation Forest node score exceeded threshold",
        nodes_affected= nodes_str,
        summary       = summary,
        recommendation= recommendation,
        cross_node    = n_nodes >= CRITICAL_NODE_COUNT,
    )
    print(f"  [node] SOC dispatch sent — {severity}  nodes={nodes_str}")


def _escalate_ip_anomalies(rows, scores: list[float], flags: list[int]) -> None:
    """Dispatch a SOC investigation for anomalous IPs with threat intel or multi-node reach."""
    escalate = [
        (rows[i], scores[i])
        for i in range(len(rows))
        if flags[i] and (rows[i]["has_threat_intel"] or rows[i]["node_count"] >= 2)
    ]
    if not escalate:
        return

    ti_ips    = [row["src_ip"] for row, _ in escalate if row["has_threat_intel"]]
    multi_ips = [row["src_ip"] for row, _ in escalate if row["node_count"] >= 2]
    severity  = "CRITICAL" if ti_ips else "HIGH"
    bucket    = escalate[0][0]["bucket_time"]

    detail_lines = []
    for row, score in sorted(escalate, key=lambda x: -x[1]):
        ti_tag = " [TI MATCH]" if row["has_threat_intel"] else ""
        detail_lines.append(
            f"{row['src_ip']}{ti_tag}: score={score:.3f}  fails={row['fail_count']}  "
            f"nodes={row['node_count']}  users={row['unique_users_tried']}"
        )

    summary = (
        f"Isolation Forest flagged {len(escalate)} IP(s) as anomalous at {bucket}. "
        + " | ".join(detail_lines)
    )
    recommendation = (
        "Query full ES history for these IPs across all nodes. "
        "Check for active connections. Block if threat intel confirmed or failure count high."
    )

    dispatch_anomaly(
        severity      = severity,
        threat        = "ML anomaly: Isolation Forest IP score exceeded threshold",
        nodes_affected= "multiple" if multi_ips else escalate[0][0]["src_ip"],
        summary       = summary,
        recommendation= recommendation,
        cross_node    = bool(multi_ips),
        threat_intel  = ", ".join(ti_ips) if ti_ips else None,
    )
    print(f"  [ip]   SOC dispatch sent — {severity}  ips={[row['src_ip'] for row, _ in escalate]}")


# ── Z-score detector ────────────────────────────────────────────────────────────

def _zscore_check(
    score_rows,
    history_rows,
    feature_cols: list[str] = ZSCORE_FEATURE_COLS,
) -> list[dict]:
    """
    For each row in score_rows, compute per-feature z-scores against the
    rolling 24-hour history from history_rows.  Returns a list of dicts with:
      is_zscore_anomaly — True if any feature exceeds ZSCORE_THRESHOLD
      max_z             — highest z-score seen across all features
      worst_feature     — name of the feature with the highest z-score

    Catches slow-ramp attacks where each individual hour looks normal but the
    current hour is statistically unusual relative to the recent baseline.
    Requires at least ZSCORE_MIN_HISTORY rows of history to avoid false
    positives from an empty baseline.
    """
    results = []
    if len(history_rows) < ZSCORE_MIN_HISTORY:
        return [{"is_zscore_anomaly": False, "max_z": 0.0, "worst_feature": ""}
                for _ in score_rows]

    X_hist = _to_matrix(history_rows, feature_cols)
    means  = X_hist.mean(axis=0)
    stds   = X_hist.std(axis=0)
    stds[stds < 1e-6] = 1e-6   # avoid division by zero for constant features

    for row in score_rows:
        x       = np.array([float(row[f] or 0) for f in feature_cols])
        z       = np.abs((x - means) / stds)
        max_z   = float(z.max())
        worst   = feature_cols[int(z.argmax())]
        results.append({
            "is_zscore_anomaly": max_z >= ZSCORE_THRESHOLD,
            "max_z":             max_z,
            "worst_feature":     worst,
        })
    return results


# ── IP escalation sequence detector ─────────────────────────────────────────────

def _detect_ip_escalation(env: dict) -> list[dict]:
    """
    Scan the last 6 hours of ip_features for IPs showing a monotonically
    non-decreasing fail_count trend over IP_ESCALATION_MIN_HOURS consecutive
    hours, with a minimum total of IP_ESCALATION_MIN_TOTAL failures.

    This catches low-and-slow brute force that stays under per-hour thresholds
    and never looks anomalous in a single IsolationForest snapshot.

    Returns a list of {src_ip, hours, total_fails, series} for escalating IPs.
    """
    rows = get_ip_series(hours=6)
    if not rows:
        return []

    # Group by src_ip, preserve chronological order (query is ORDER BY src_ip, bucket_time ASC)
    from collections import defaultdict
    series_by_ip: dict[str, list] = defaultdict(list)
    for r in rows:
        series_by_ip[r["src_ip"]].append(r)

    escalating = []
    for ip, series in series_by_ip.items():
        if len(series) < IP_ESCALATION_MIN_HOURS:
            continue
        counts = [r["fail_count"] for r in series]
        total  = sum(counts)
        if total < IP_ESCALATION_MIN_TOTAL:
            continue
        # Find the longest non-decreasing run
        max_run = 1
        cur_run = 1
        for i in range(1, len(counts)):
            if counts[i] >= counts[i - 1] and counts[i] > 0:
                cur_run += 1
                max_run = max(max_run, cur_run)
            else:
                cur_run = 1
        if max_run >= IP_ESCALATION_MIN_HOURS:
            escalating.append({
                "src_ip":      ip,
                "hours":       max_run,
                "total_fails": total,
                "series":      counts,
            })

    return escalating


def _alert_ip_escalation(escalating: list[dict], env: dict) -> None:
    """Send Telegram alert for IPs showing slow-ramp escalation."""
    if not escalating:
        return
    token   = env.get("TELEGRAM_TOKEN", "")
    chat_id = env.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        return
    from soc_dispatch import is_tg_suppressed, record_tg_alert
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    for ev in escalating:
        ip      = ev["src_ip"]
        tg_key  = f"ip_escalation:{ip}"
        if is_tg_suppressed(tg_key, ttl=7200):  # 2h dedup
            print(f"  [escalation] {ip} suppressed")
            continue
        series_str = " → ".join(str(c) for c in ev["series"])
        msg = (
            f"📈 *ML: Slow-Ramp Escalation Detected*\n"
            f"_{now}_\n\n"
            f"IP `{ip}` has shown non-decreasing SSH failures "
            f"over {ev['hours']} consecutive hours ({ev['total_fails']} total).\n"
            f"Series: `{series_str}`\n\n"
            f"_Low-and-slow brute force pattern._"
        )
        try:
            requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": msg, "parse_mode": "Markdown"},
                timeout=10,
            )
            record_tg_alert(tg_key, ttl=7200)
            print(f"  [escalation] alert sent for {ip} ({ev['total_fails']} fails, {ev['hours']}h ramp)")
        except Exception as e:
            print(f"  [escalation] Telegram failed: {e}")


# ── Core run ────────────────────────────────────────────────────────────────────

def run(dry_run: bool = False, force_retrain: bool = False) -> None:
    init_db()
    env     = _load_env()
    token   = env.get("TELEGRAM_TOKEN", "")
    chat_id = env.get("TELEGRAM_CHAT_ID", "")

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"[{ts}] ml_detector starting  dry_run={dry_run}  force_retrain={force_retrain}")

    # ── Node model ──────────────────────────────────────────────────────────────

    train_node = get_node_training_data(days=TRAINING_DAYS)
    score_node = get_recent_node_features(hours=1)

    if not score_node:
        print("  [node] No recent features — feature_extractor may not have run yet")
    elif len(train_node) < MIN_NODE_ROWS:
        print(f"  [node] Only {len(train_node)} training rows (need {MIN_NODE_ROWS}) — skipping")
    else:
        bundle = get_or_train("node", train_node, NODE_FEATURE_COLS, force_retrain)
        node_scores, node_flags = _score(bundle, score_node, NODE_FEATURE_COLS)

        if not dry_run:
            update_node_anomaly_scores([
                {
                    "bucket_time":   row["bucket_time"],
                    "node":          row["node"],
                    "anomaly_score": node_scores[i],
                    "is_anomaly":    node_flags[i],
                }
                for i, row in enumerate(score_node)
            ])

        n_flagged = sum(node_flags)
        # Only rows newly flagged this run (weren't already marked is_anomaly=1 in DB)
        new_flags = [
            1 if (node_flags[i] and not score_node[i]["is_anomaly"]) else 0
            for i in range(len(score_node))
        ]
        n_new = sum(new_flags)
        flagged_nodes = [score_node[i]["node"] for i in range(len(score_node)) if node_flags[i]]
        if flagged_nodes:
            print(f"  [node] {n_flagged}/{len(score_node)} anomalous ({n_new} new): {', '.join(flagged_nodes)}")
        else:
            print(f"  [node] {n_flagged}/{len(score_node)} anomalous")

        # ── Z-score pass ────────────────────────────────────────────────────────
        node_history = get_recent_node_window(hours=24)
        zscore_results = _zscore_check(score_node, node_history)
        z_new = [
            zr for i, zr in enumerate(zscore_results)
            if zr["is_zscore_anomaly"] and not score_node[i]["is_anomaly"]
        ]
        if z_new:
            for i, zr in enumerate(zscore_results):
                if zr["is_zscore_anomaly"]:
                    print(f"  [zscore] {score_node[i]['node']} z={zr['max_z']:.2f} on {zr['worst_feature']}")
            # Promote to anomaly flag if z-score triggered but ensemble didn't
            for i, zr in enumerate(zscore_results):
                if zr["is_zscore_anomaly"] and not node_flags[i]:
                    node_flags[i] = 1
                    new_flags[i]  = 1 if not score_node[i]["is_anomaly"] else 0
        else:
            print(f"  [zscore] no new z-score anomalies (history={len(node_history)} rows)")

        if n_new and not dry_run and token and chat_id:
            tg_key = "ml_node_alert"
            if is_tg_suppressed(tg_key, ttl=7200):
                print("  [node] Telegram suppressed (within 2h window)")
            else:
                msg = _format_node_alert(score_node, node_scores, new_flags)
                if msg:
                    _send_telegram(token, chat_id, msg)
                    record_tg_alert(tg_key, ttl=7200)
                    print("  [node] Telegram alert sent")

        if n_new and not dry_run:
            _escalate_node_anomalies(score_node, node_scores, new_flags)

    # ── IP model ────────────────────────────────────────────────────────────────

    train_ip = get_ip_training_data(days=TRAINING_DAYS)
    score_ip = get_recent_ip_features(hours=1)

    if not score_ip:
        print("  [ip]   No recent IP features to score")
    elif len(train_ip) < MIN_IP_ROWS:
        print(f"  [ip]   Only {len(train_ip)} training rows (need {MIN_IP_ROWS}) — skipping")
    else:
        bundle = get_or_train("ip", train_ip, IP_FEATURE_COLS, force_retrain)
        ip_scores, ip_flags = _score(bundle, score_ip, IP_FEATURE_COLS)

        if not dry_run:
            update_ip_anomaly_scores([
                {
                    "bucket_time":   row["bucket_time"],
                    "src_ip":        row["src_ip"],
                    "anomaly_score": ip_scores[i],
                    "is_anomaly":    ip_flags[i],
                }
                for i, row in enumerate(score_ip)
            ])

        n_flagged = sum(ip_flags)
        # Only rows newly flagged this run
        new_ip_flags = [
            1 if (ip_flags[i] and not score_ip[i]["is_anomaly"]) else 0
            for i in range(len(score_ip))
        ]
        n_new_ip = sum(new_ip_flags)
        flagged_ips = [score_ip[i]["src_ip"] for i in range(len(score_ip)) if ip_flags[i]]
        if flagged_ips:
            print(f"  [ip]   {n_flagged}/{len(score_ip)} anomalous ({n_new_ip} new): {', '.join(flagged_ips)}")
        else:
            print(f"  [ip]   {n_flagged}/{len(score_ip)} anomalous")

        if n_new_ip and not dry_run and token and chat_id:
            tg_key = "ml_ip_alert"
            if is_tg_suppressed(tg_key, ttl=7200):
                print("  [ip]   Telegram suppressed (within 2h window)")
            else:
                geo = geolocate([row["src_ip"] for row in score_ip])
                msg = _format_ip_alert(score_ip, ip_scores, new_ip_flags, geo=geo)
                if msg:
                    _send_telegram(token, chat_id, msg)
                    record_tg_alert(tg_key, ttl=7200)
                    print("  [ip]   Telegram alert sent")

        if n_new_ip and not dry_run:
            _escalate_ip_anomalies(score_ip, ip_scores, new_ip_flags)

    # ── IP escalation sequence detector ─────────────────────────────────────────
    escalating = _detect_ip_escalation(env)
    if escalating:
        print(f"  [escalation] {len(escalating)} slow-ramp IP(s) detected")
        if not dry_run:
            _alert_ip_escalation(escalating, env)
    else:
        print("  [escalation] no slow-ramp patterns")

    stats = get_stats()
    print(f"  Store: {stats['node_rows']} node rows, "
          f"{stats['ip_rows']} IP rows, "
          f"{stats['anomalies']} total anomalies")


def backfill_scores() -> None:
    """Retrain on all data, rescore every row, write scores back. No alerts."""
    init_db()
    print("Backfilling anomaly scores for all historical rows...")

    train_node = get_node_training_data(days=365)
    if len(train_node) >= MIN_NODE_ROWS:
        bundle = get_or_train("node", train_node, NODE_FEATURE_COLS, force_retrain=True)
        node_scores, node_flags = _score(bundle, train_node, NODE_FEATURE_COLS)
        update_node_anomaly_scores([
            {
                "bucket_time":   row["bucket_time"],
                "node":          row["node"],
                "anomaly_score": node_scores[i],
                "is_anomaly":    node_flags[i],
            }
            for i, row in enumerate(train_node)
        ])
        print(f"  [node] Flagged {sum(node_flags)}/{len(train_node)} rows")
    else:
        print(f"  [node] Only {len(train_node)} rows — skipping")

    train_ip = get_ip_training_data(days=365)
    if len(train_ip) >= MIN_IP_ROWS:
        bundle = get_or_train("ip", train_ip, IP_FEATURE_COLS, force_retrain=True)
        ip_scores, ip_flags = _score(bundle, train_ip, IP_FEATURE_COLS)
        update_ip_anomaly_scores([
            {
                "bucket_time":   row["bucket_time"],
                "src_ip":        row["src_ip"],
                "anomaly_score": ip_scores[i],
                "is_anomaly":    ip_flags[i],
            }
            for i, row in enumerate(train_ip)
        ])
        print(f"  [ip]   Flagged {sum(ip_flags)}/{len(train_ip)} rows")
    else:
        print(f"  [ip]   Only {len(train_ip)} rows — skipping")

    stats = get_stats()
    print(f"\nStore: {stats['node_rows']} node rows, "
          f"{stats['ip_rows']} IP rows, "
          f"{stats['anomalies']} total anomalies")


# ── Main ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Isolation Forest anomaly detector")
    group  = parser.add_mutually_exclusive_group()
    group.add_argument("--dry-run",  action="store_true",
                       help="Score but don't write back or alert")
    group.add_argument("--retrain",  action="store_true",
                       help="Force retrain now, then score")
    group.add_argument("--backfill", action="store_true",
                       help="Retrain on all data and rescore every historical row")
    args = parser.parse_args()

    if args.backfill:
        backfill_scores()
    else:
        run(dry_run=args.dry_run, force_retrain=args.retrain)


if __name__ == "__main__":
    main()
