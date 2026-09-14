#!/usr/bin/env python3
"""
watchdog.py — checks the health of the SIEM's own infrastructure (the pieces
that don't alert on their own failure) and pings Telegram if something's down.

Checks:
  - incident-responder.service  (systemd)
  - swarm-monitor.service       (systemd)
  - litellm-gateway             (docker container)

Runs via cron every 10 min. Dedups: only alerts once per outage (won't spam
every 10 min while something stays down), and sends a recovery message when
it comes back.
"""

import json
import subprocess
from pathlib import Path

import requests
from dotenv import dotenv_values

ENV_FILE = Path.home() / ".env"
STATE_FILE = Path(__file__).parent / "watchdog_state.json"

env = dotenv_values(ENV_FILE)
TELEGRAM_TOKEN = env.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = env.get("TELEGRAM_CHAT_ID", "")

CHECKS = {
    "incident-responder": lambda: _systemd_active("incident-responder"),
    "swarm-monitor": lambda: _systemd_active("swarm-monitor"),
    "litellm-gateway": lambda: _docker_running("litellm-gateway"),
}


def _systemd_active(unit: str) -> bool:
    try:
        out = subprocess.check_output(
            ["systemctl", "is-active", unit], stderr=subprocess.DEVNULL, timeout=5
        ).decode().strip()
        return out == "active"
    except Exception:
        return False


def _docker_running(name: str) -> bool:
    try:
        out = subprocess.check_output(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            stderr=subprocess.DEVNULL, timeout=5,
        ).decode().strip()
        return out == "true"
    except Exception:
        return False


def _load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    try:
        STATE_FILE.write_text(json.dumps(state))
    except Exception as e:
        print(f"[watchdog] could not write state: {e}")


def _send_telegram(text: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[watchdog] telegram not configured")
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text},
            timeout=10,
        )
    except Exception as e:
        print(f"[watchdog] telegram send failed: {e}")


def main():
    state = _load_state()
    changed = False

    for name, check in CHECKS.items():
        up = check()
        was_up = state.get(name, True)  # assume up on first run, don't alert immediately

        if not up and was_up:
            _send_telegram(f"DOWN: {name} is not running/responding.")
            print(f"[watchdog] {name} went DOWN")
            changed = True
        elif up and not was_up:
            _send_telegram(f"RECOVERED: {name} is back up.")
            print(f"[watchdog] {name} RECOVERED")
            changed = True

        state[name] = up

    if changed:
        _save_state(state)
    else:
        _save_state(state)  # keep first-run state persisted either way


if __name__ == "__main__":
    main()
