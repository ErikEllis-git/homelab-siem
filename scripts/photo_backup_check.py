#!/usr/bin/env python3
"""
photo_backup_check.py — alerts to Telegram if the Immich photo backup is unhealthy.

Immich runs on hpHDD (~/immich). A nightly cron there (backup_photos.sh, 04:00)
rsyncs the library to rikdell:~/photo-backup and appends a line to
~/immich/backup.log.

Checks:
  - the last line of backup.log is OK and newer than MAX_AGE_H hours
  - the immich_server container is healthy

Runs via cron hourly. Dedups like watchdog.py: alerts once per problem, sends a
recovery message when it clears.
"""

import json
import subprocess
import time
from datetime import datetime
from pathlib import Path

import requests
from dotenv import dotenv_values

HERE = Path(__file__).parent
STATE_FILE = HERE / "photo_backup_state.json"
SWARM_KEY = str(Path.home() / ".ssh/id_rsa_swarm")
MAX_AGE_H = 26  # nightly job + slack

env = dotenv_values(Path.home() / ".env")
TELEGRAM_TOKEN = env.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = env.get("TELEGRAM_CHAT_ID", "")
TARGET = env.get("WORKER2_SSH_TARGET", "")  # hpHDD, same setting as thermal_check/hdd_health

REMOTE_CMD = (
    "tail -n1 ~/immich/backup.log 2>/dev/null; echo ---; "
    "docker inspect -f '{{.State.Health.Status}}' immich_server 2>/dev/null"
)


def _remote():
    """(last backup.log line, immich health) from hpHDD, or None if unreachable."""
    cmd = ["ssh", "-i", SWARM_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
           "-o", "StrictHostKeyChecking=no", TARGET, REMOTE_CMD]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
    except Exception:
        return None
    if r.returncode != 0 and not r.stdout:
        return None
    log, _, health = r.stdout.partition("---")
    return log.strip(), health.strip()


def _backup_problem(log_line: str):
    """None if the last backup is fine, else a short reason."""
    if not log_line:
        return "no backup has run yet (backup.log empty)"
    stamp, _, status = log_line.partition(" ")
    if not status.startswith("OK"):
        return f"last backup failed: {log_line}"
    try:
        age_h = (time.time() - datetime.fromisoformat(stamp).timestamp()) / 3600
    except ValueError:
        return f"unreadable backup.log line: {log_line}"
    if age_h > MAX_AGE_H:
        return f"last good backup was {age_h:.0f}h ago"
    return None


def _load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {}


def _send_telegram(text: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[photo_backup_check] telegram not configured")
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text},
            timeout=10,
        )
    except Exception as e:
        print(f"[photo_backup_check] telegram send failed: {e}")


def main():
    state = _load_state()
    remote = _remote()

    if remote is None:
        problems = {"hpHDD": "unreachable over SSH"}
    else:
        log_line, health = remote
        problems = {}
        reason = _backup_problem(log_line)
        if reason:
            problems["backup"] = reason
        if health != "healthy":
            problems["immich"] = f"immich_server is '{health or 'not running'}'"

    for name in ("hpHDD", "backup", "immich"):
        reason = problems.get(name)
        was_ok = state.get(name, True)  # first run: don't alert on a clean slate

        if reason and was_ok:
            _send_telegram(f"PHOTO BACKUP: {name} — {reason}.")
            print(f"[photo_backup_check] {name} PROBLEM: {reason}")
        elif not reason and not was_ok:
            _send_telegram(f"PHOTO BACKUP RECOVERED: {name} is fine again.")
            print(f"[photo_backup_check] {name} RECOVERED")

        # an unreachable hpHDD says nothing about backup/immich: keep their last state
        if name == "hpHDD" or "hpHDD" not in problems:
            state[name] = reason is None

    STATE_FILE.write_text(json.dumps(state))


if __name__ == "__main__":
    main()
