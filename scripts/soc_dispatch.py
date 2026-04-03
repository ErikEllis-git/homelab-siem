#!/usr/bin/env python3
"""
soc_dispatch.py — Escalate high-severity SIEM events to Claude for investigation.

Posts structured payloads to the claude-telegram webhook. Claude Code spawns
with full tool access (Bash, SSH, ES queries) and CLAUDE.md cluster context,
investigates the event, and sends a report back to Telegram automatically.

Usage:
    from soc_dispatch import dispatch_brute_force, dispatch_anomaly
"""

import json
import os
import time
import uuid
from pathlib import Path
from typing import Optional

import requests

# claude-telegram webhook
WEBHOOK_URL = "http://localhost:8765/webhooks/siem"

# Direct Telegram API — loaded once at import time
def _load_env() -> dict:
    env = {}
    try:
        for line in Path("/home/rosse/.env").read_text().splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
    except Exception:
        pass
    env.update({k: v for k, v in os.environ.items() if k in ("TELEGRAM_TOKEN", "TELEGRAM_CHAT_ID")})
    return env

_ENV = _load_env()
_TG_TOKEN      = _ENV.get("TELEGRAM_TOKEN", "")
_TG_CHAT_ID    = _ENV.get("TELEGRAM_CHAT_ID", "")
WEBHOOK_SECRET = _ENV.get("SOC_WEBHOOK_SECRET", "")


def _send_telegram(text: str) -> bool:
    """Send a message directly to Telegram, bypassing Claude."""
    if not _TG_TOKEN or not _TG_CHAT_ID:
        print("[dispatch] TELEGRAM_TOKEN or TELEGRAM_CHAT_ID not set")
        return False
    for attempt in range(3):
        try:
            resp = requests.post(
                f"https://api.telegram.org/bot{_TG_TOKEN}/sendMessage",
                json={"chat_id": _TG_CHAT_ID, "text": text},
                timeout=10,
            )
            if resp.status_code == 200:
                return True
            print(f"[dispatch] Telegram returned {resp.status_code}: {resp.text[:200]}")
            return False
        except Exception as e:
            print(f"[dispatch] failed to reach Telegram (attempt {attempt+1}/3): {e}")
            if attempt < 2:
                time.sleep(3)
    return False

# Suppress repeat Claude dispatches for the same event within this window
DEDUP_TTL_SECONDS        = 3600   # 60 minutes — brute force
ANOMALY_DEDUP_TTL        = 14400  # 4 hours — anomaly_detector runs hourly; max 1 dispatch per 4 runs
_DEDUP_FILE = Path(__file__).parent / "dispatch_dedup.json"

# Suppress repeat Telegram alerts (shared across scripts)
TELEGRAM_DEDUP_TTL = 1800  # 30 minutes
_TELEGRAM_DEDUP_FILE = Path(__file__).parent / "telegram_dedup.json"


def _load_dedup() -> dict:
    try:
        return json.loads(_DEDUP_FILE.read_text())
    except Exception:
        return {}


def _is_suppressed(key: str, ttl: int = DEDUP_TTL_SECONDS) -> bool:
    state = _load_dedup()
    last = state.get(key, 0)
    return (time.time() - last) < ttl


def _record_dispatch(key: str, ttl: int = DEDUP_TTL_SECONDS) -> None:
    state = _load_dedup()
    now = time.time()
    # Prune with the provided TTL so short-TTL entries don't linger
    state = {k: v for k, v in state.items() if (now - v) < max(ttl, ANOMALY_DEDUP_TTL)}
    state[key] = now
    try:
        _DEDUP_FILE.write_text(json.dumps(state))
    except Exception as e:
        print(f"[dispatch] could not write dedup state: {e}")


def _load_tg_dedup() -> dict:
    try:
        return json.loads(_TELEGRAM_DEDUP_FILE.read_text())
    except Exception:
        return {}


def is_tg_suppressed(key: str, ttl: int = TELEGRAM_DEDUP_TTL) -> bool:
    """Return True if a Telegram alert with this key was sent within ttl seconds."""
    state = _load_tg_dedup()
    return (time.time() - state.get(key, 0)) < ttl


def record_tg_alert(key: str, ttl: int = TELEGRAM_DEDUP_TTL) -> None:
    """Record that a Telegram alert was sent, pruning expired entries."""
    state = _load_tg_dedup()
    now = time.time()
    state = {k: v for k, v in state.items() if (now - v) < ttl}
    state[key] = now
    try:
        _TELEGRAM_DEDUP_FILE.write_text(json.dumps(state))
    except Exception as e:
        print(f"[dispatch] could not write telegram dedup state: {e}")


def _post(event_type: str, payload: dict) -> bool:
    """POST a structured investigation request to the claude-telegram webhook."""
    try:
        resp = requests.post(
            WEBHOOK_URL,
            json=payload,
            headers={
                "Authorization": f"Bearer {WEBHOOK_SECRET}",
                "X-Event-Type": event_type,
                "X-Delivery-ID": str(uuid.uuid4()),
                "Content-Type": "application/json",
            },
            timeout=10,
        )
        ok = resp.status_code in (200, 202)
        if not ok:
            print(f"[dispatch] webhook returned {resp.status_code}: {resp.text[:200]}")
        return ok
    except Exception as e:
        print(f"[dispatch] failed to reach claude-telegram: {e}")
        return False


def dispatch_brute_force(
    attackers: list[dict],
    lookback: str = "5m",
) -> bool:
    """
    Send SSH brute force alert directly to Telegram.

    attackers: list of dicts with keys: ip, total_failures, nodes, intel (optional)
    """
    multi_node = any("," in a.get("nodes", "") for a in attackers)
    known_malware = any(a.get("intel") for a in attackers)

    severity = (
        "CRITICAL" if (multi_node and known_malware)
        else "HIGH"   if (multi_node or known_malware)
        else "MEDIUM"
    )

    ip_key = ",".join(sorted(a["ip"] for a in attackers))
    dedup_key = f"brute_force:{ip_key}"
    if _is_suppressed(dedup_key):
        print(f"[dispatch] suppressed duplicate brute force dispatch for {ip_key} (within {DEDUP_TTL_SECONDS//60}m window)")
        return False

    lines = [f"🔒 Brute Force — {severity}"]
    for a in attackers:
        line = f"{a['ip']} — {a['total_failures']} fails — {a['nodes']}"
        if a.get("intel"):
            line += f"\n  {a['intel']}"
        lines.append(line)

    text = "\n".join(lines)

    print(f"[dispatch] sending {severity} brute force alert ({len(attackers)} attacker(s)) to Telegram")
    result = _send_telegram(text)
    if result:
        _record_dispatch(dedup_key)
    return result


def dispatch_honeypot(
    sessions: list[dict],
    severity: str,
    summary: str,
    cross_node_ips: Optional[list[str]] = None,
) -> bool:
    """
    Send honeypot session alert directly to Telegram.

    sessions: list of dicts with keys: session_id, src_ip, login_success,
              commands, duration, client_version, used_pubkey, geo, intel,
              if_score, dbscan_label
    """
    ip_key    = ",".join(sorted({s.get("src_ip", "") for s in sessions}))
    dedup_key = f"honeypot_ip:{ip_key}"
    if _is_suppressed(dedup_key, ttl=ANOMALY_DEDUP_TTL):
        print("[dispatch] suppressed duplicate honeypot dispatch")
        return False

    messages = []
    for s in sessions:
        geo     = f" [{s['geo']}]" if s.get("geo") else ""
        intel   = f" — {s['intel']}" if s.get("intel") else ""
        action  = "MONITORING"

        if s.get("login_success"):
            if s.get("commands"):
                did = f"got shell, ran: {s['commands'][:120]}"
            else:
                did = "got shell, no commands"
        elif s.get("used_pubkey"):
            did = "probed with pubkey"
        else:
            did = "password spray, no shell"

        if cross_node_ips and s.get("src_ip") in cross_node_ips:
            action = "BLOCKED"

        messages.append(f"🍯 {s['src_ip']}{geo}{intel}\nDid: {did}\nAction: {action}")

    text = "\n\n".join(messages)

    print(f"[dispatch] sending {severity} honeypot alert ({len(sessions)} session(s)) to Telegram")
    result = _send_telegram(text)
    if result:
        _record_dispatch(dedup_key, ttl=ANOMALY_DEDUP_TTL)
    return result


def dispatch_honeypot_digest(state: dict) -> bool:
    """Send the 6-hour honeypot activity digest directly to Telegram."""
    sessions  = state.get("sessions", 0)
    shells    = state.get("shells", 0)
    n_ips     = len(state.get("unique_ips", []))
    severity  = state.get("severity", {})
    countries = state.get("countries", {})
    commands  = state.get("commands", {})
    ti_hits   = state.get("ti_hits", [])

    if sessions == 0:
        print("[dispatch] digest: no sessions in period, skipping")
        return False

    top_countries = sorted(countries.items(), key=lambda x: -x[1])[:3]
    country_str   = ", ".join(f"{c} ({n})" for c, n in top_countries) or "—"

    top_cmds = sorted(commands.items(), key=lambda x: -x[1])[:3]
    cmd_lines = "\n  ".join(f"{cmd[:60]} ({n}x)" for cmd, n in top_cmds) or "—"

    crit_high = severity.get("CRITICAL", 0) + severity.get("HIGH", 0)
    med       = severity.get("MEDIUM", 0)
    info      = severity.get("INFO", 0)

    period_start = state.get("period_start", "")[:16].replace("T", " ")

    lines = [
        f"Honeypot Digest (since {period_start} UTC)",
        f"Sessions: {sessions}  |  Shells: {shells}  |  IPs: {n_ips}",
        f"Countries: {country_str}",
        f"Top commands:\n  {cmd_lines}",
        f"Severity: {crit_high} CRIT/HIGH  {med} MED  {info} INFO",
    ]
    if ti_hits:
        lines.append("TI matches: " + ", ".join(ti_hits[:5]))

    text = "\n".join(lines)
    print(f"[dispatch] sending 6h honeypot digest ({sessions} sessions, {n_ips} IPs)")
    return _send_telegram(text)


def dispatch_anomaly(
    severity: str,
    threat: str,
    nodes_affected: str,
    summary: str,
    recommendation: str,
    cross_node: bool = False,
    threat_intel: Optional[str] = None,
    raw_log_sample: Optional[str] = None,
) -> bool:
    """
    Escalate a SIEM anomaly for full investigation.

    Only call this for HIGH or CRITICAL severity — LOW/MEDIUM go through
    the standard Telegram alert path.
    """
    payload = {
        "investigation_type": "siem_anomaly",
        "severity":           severity,
        "threat":             threat,
        "nodes_affected":     nodes_affected,
        "cross_node_attack":  str(cross_node),
        "ai_summary":         summary,
        "ai_recommendation":  recommendation,
        "task": (
            "A SIEM anomaly has been flagged HIGH or CRITICAL. "
            "Follow the CLAUDE.md investigation procedure: gather live system state "
            "on affected nodes, query ES for full attacker history, check for lateral "
            "movement indicators. Act on the AI recommendation if it says to block. "
            "Report findings in the CLAUDE.md response format."
        ),
    }

    if threat_intel:
        payload["threat_intel_matches"] = threat_intel
    if raw_log_sample:
        payload["log_sample"] = raw_log_sample[:800]  # keep payload reasonable

    # Dedup: suppress if we already escalated the same threat/nodes recently
    dedup_key = f"anomaly:{threat}:{nodes_affected}"
    if _is_suppressed(dedup_key, ttl=ANOMALY_DEDUP_TTL):
        print(f"[dispatch] suppressed duplicate anomaly dispatch for '{threat}' on {nodes_affected} (within {ANOMALY_DEDUP_TTL//60}m window)")
        return False

    print(f"[dispatch] escalating {severity} anomaly to Claude — nodes: {nodes_affected}")
    result = _post("siem_anomaly", payload)
    if result:
        _record_dispatch(dedup_key, ttl=ANOMALY_DEDUP_TTL)
    return result
