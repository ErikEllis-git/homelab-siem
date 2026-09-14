#!/usr/bin/env python3
"""
disk_health.py — SMART health monitoring for rosee's boot SSD.

Runs daily via cron. Checks the drive's actual SMART attributes (not just
"is it mounted") and Telegram-alerts on early warning signs BEFORE the drive
dies catastrophically — this is the thing that was missing before the old
SSD died with zero warning.

Added 2026-09-14 after the original rosse SSD failed with no prior warning
(no SMART monitoring existed). Dedups like watchdog.py: alerts on state
change (healthy -> warning, warning -> healthy), not every single run.
"""

import json
import re
import subprocess
from pathlib import Path

import requests
from dotenv import dotenv_values

DEVICE = "/dev/sda"
ENV_FILE = Path.home() / ".env"
STATE_FILE = Path(__file__).parent / "disk_health_state.json"

env = dotenv_values(ENV_FILE)
TELEGRAM_TOKEN = env.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = env.get("TELEGRAM_CHAT_ID", "")

# Known TBW rating for the current drive (WD Blue SA510 250GB) - update if
# the drive is ever swapped again.
RATED_TBW = 100
WARN_TBW_PCT = 70   # warn once 70% of rated endurance is used
CRIT_TBW_PCT = 90


def run_smartctl() -> str:
    try:
        return subprocess.check_output(
            ["sudo", "-n", "smartctl", "-a", DEVICE],
            stderr=subprocess.DEVNULL, timeout=15,
        ).decode()
    except Exception as e:
        return ""


def parse_attr(output: str, attr_id: int) -> int | None:
    for line in output.splitlines():
        m = re.match(rf"\s*{attr_id}\s+\S+.*\s(\d+)\s*$", line)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                return None
    return None


def check() -> dict:
    out = run_smartctl()
    if not out:
        return {"ok": False, "reason": "smartctl failed to run or device unreachable"}

    passed = "PASSED" in out
    reallocated = parse_attr(out, 5) or 0
    reported_uncorrect = parse_attr(out, 187) or 0
    grown_bad_blocks = parse_attr(out, 170) or 0
    host_writes_gib = parse_attr(out, 241) or 0

    problems = []
    if not passed:
        problems.append("SMART overall self-assessment did NOT pass")
    if reallocated > 0:
        problems.append(f"{reallocated} reallocated sectors (should be 0)")
    if reported_uncorrect > 0:
        problems.append(f"{reported_uncorrect} uncorrectable errors reported")
    if grown_bad_blocks > 0:
        problems.append(f"{grown_bad_blocks} new bad blocks grown since manufacture")

    tbw_used_pct = round(host_writes_gib / 1024 / RATED_TBW * 100, 1) if host_writes_gib else 0
    if tbw_used_pct >= CRIT_TBW_PCT:
        problems.append(f"{tbw_used_pct}% of rated endurance (TBW) used — CRITICAL")
    elif tbw_used_pct >= WARN_TBW_PCT:
        problems.append(f"{tbw_used_pct}% of rated endurance (TBW) used — approaching limit")

    return {
        "ok": len(problems) == 0,
        "problems": problems,
        "tbw_used_pct": tbw_used_pct,
    }


def _load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {"ok": True}


def _save_state(state: dict) -> None:
    try:
        STATE_FILE.write_text(json.dumps(state))
    except Exception as e:
        print(f"[disk_health] could not write state: {e}")


def _send_telegram(text: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[disk_health] telegram not configured")
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text},
            timeout=10,
        )
    except Exception as e:
        print(f"[disk_health] telegram send failed: {e}")


def main():
    result = check()
    state = _load_state()
    was_ok = state.get("ok", True)

    if not result["ok"] and was_ok:
        problems = "\n".join(f"- {p}" for p in result.get("problems", [result.get("reason", "unknown")]))
        _send_telegram(f"DISK HEALTH WARNING on rosee ({DEVICE}):\n{problems}")
        print(f"[disk_health] WARNING: {result}")
    elif result["ok"] and not was_ok:
        _send_telegram(f"DISK HEALTH RECOVERED on rosee ({DEVICE}).")
        print("[disk_health] recovered")
    else:
        print(f"[disk_health] ok={result['ok']} tbw_used_pct={result.get('tbw_used_pct')}")

    _save_state({"ok": result["ok"]})


if __name__ == "__main__":
    main()
