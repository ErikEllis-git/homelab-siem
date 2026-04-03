#!/usr/bin/env python3
"""
suricata_alerter.py — Tail Suricata EVE JSON and send Telegram alerts on IDS hits.

Deduplicates: same signature won't fire again within COOLDOWN_SECONDS.
Run as a systemd service.
"""

import json
import os
import time
from pathlib import Path
from dotenv import dotenv_values
import requests

EVE_LOG          = "/var/log/suricata/eve.json"
COOLDOWN_SECONDS = 3600  # same signature silenced for 1 hour
POLL_INTERVAL    = 2     # seconds between file checks
COOLDOWN_FILE    = Path(__file__).parent / "suricata_cooldowns.json"

env = dotenv_values("/home/rosse/.env")
TELEGRAM_TOKEN   = env.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = env.get("TELEGRAM_CHAT_ID", "")

INTERNAL_PREFIXES = ("127.", "10.", "192.168.", "::1", "100.64.")  # 100.64.0.0/10 = Tailscale CGNAT


def _is_internal(ip: str) -> bool:
    return any(ip.startswith(p) for p in INTERNAL_PREFIXES)


CLAUDE_WEBHOOK_URL    = "http://localhost:8765/webhooks/suricata"
CLAUDE_WEBHOOK_SECRET = env.get("SOC_WEBHOOK_SECRET", "")

IR_WEBHOOK_URL    = "http://localhost:8766/webhooks/suricata"
IR_WEBHOOK_SECRET = env.get("IR_WEBHOOK_SECRET", "")


def send_telegram(text: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[TG] not configured")
        return
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text},
            timeout=10,
        )
        resp.raise_for_status()
    except Exception as exc:
        print(f"[TG] send failed: {exc}")


def _load_cooldowns() -> dict:
    try:
        data = json.loads(COOLDOWN_FILE.read_text())
        now = time.time()
        return {k: v for k, v in data.items() if now - v < COOLDOWN_SECONDS}
    except Exception:
        return {}


def _save_cooldowns(cooldowns: dict) -> None:
    try:
        COOLDOWN_FILE.write_text(json.dumps(cooldowns))
    except Exception as exc:
        print(f"[cooldown] could not persist: {exc}")


def notify_claude(event: dict, signature: str) -> None:
    # Time-bucketed delivery ID: same signature within the same hour = duplicate
    bucket = int(time.time() // COOLDOWN_SECONDS)
    delivery_id = f"suricata:{signature}:{bucket}"
    try:
        requests.post(
            CLAUDE_WEBHOOK_URL,
            json={"event": event},
            headers={
                "Authorization": f"Bearer {CLAUDE_WEBHOOK_SECRET}",
                "X-Delivery-ID": delivery_id,
            },
            timeout=5,
        )
    except Exception as exc:
        print(f"[claude-webhook] failed: {exc}")


def notify_incident_responder(event: dict) -> None:
    try:
        requests.post(
            IR_WEBHOOK_URL,
            json={"event": event},
            headers={"Authorization": f"Bearer {IR_WEBHOOK_SECRET}"},
            timeout=5,
        )
    except Exception as exc:
        print(f"[ir-webhook] failed: {exc}")


def format_alert(e: dict) -> str:
    alert     = e.get("alert", {})
    signature = alert.get("signature", "unknown")
    severity  = alert.get("severity", "?")
    category  = alert.get("category", "")
    src       = f"{e.get('src_ip', '?')}:{e.get('src_port', '?')}"
    dst       = f"{e.get('dest_ip', '?')}:{e.get('dest_port', '?')}"
    proto     = e.get("proto", "?")
    ts        = e.get("timestamp", "")[:19].replace("T", " ")

    sev_icon = {1: "🔴", 2: "🟠", 3: "🟡"}.get(severity, "⚪")

    lines = [
        f"{sev_icon} Suricata Alert (sev {severity})",
        f"Sig: {signature}",
    ]
    if category:
        lines.append(f"Cat: {category}")
    lines += [
        f"Src: {src}  ->  Dst: {dst}  [{proto}]",
        f"Time: {ts}",
    ]
    return "\n".join(lines)


def tail(path: str):
    """Yield new lines appended to path, surviving log rotations."""
    while not os.path.exists(path):
        print(f"Waiting for {path}...")
        time.sleep(5)

    f = open(path)
    f.seek(0, 2)  # start at end
    inode = os.fstat(f.fileno()).st_ino

    while True:
        line = f.readline()
        if line:
            yield line
        else:
            time.sleep(POLL_INTERVAL)
            try:
                if os.stat(path).st_ino != inode:
                    f.close()
                    f = open(path)
                    inode = os.fstat(f.fileno()).st_ino
            except FileNotFoundError:
                pass


def main():
    print(f"suricata_alerter starting — watching {EVE_LOG}")
    cooldowns = _load_cooldowns()
    print(f"[cooldown] loaded {len(cooldowns)} persisted entries")

    for raw in tail(EVE_LOG):
        try:
            e = json.loads(raw)
        except json.JSONDecodeError:
            continue

        if e.get("event_type") != "alert":
            continue

        signature = e.get("alert", {}).get("signature", "unknown")
        now = time.time()

        if now - cooldowns.get(signature, 0) < COOLDOWN_SECONDS:
            print(f"[cooldown] {signature}")
            continue

        cooldowns[signature] = now
        _save_cooldowns(cooldowns)
        msg = format_alert(e)
        print(msg)

        src_ip = e.get("src_ip", "")
        if _is_internal(src_ip):
            print(f"[internal] skipping Telegram/IR for internal src {src_ip}: {signature}")
            continue

        send_telegram(msg)
        notify_incident_responder(e)
        # Only escalate to Claude for sev1 (critical) — sev2/3 are handled by
        # anomaly_detector's hourly intelligent analysis, no need for a full SOC report
        severity = e.get("alert", {}).get("severity", 99)
        if severity == 1:
            notify_claude(e, signature)


if __name__ == "__main__":
    main()
