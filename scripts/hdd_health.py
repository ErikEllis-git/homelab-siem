#!/usr/bin/env python3
"""
hdd_health.py — SMART monitoring for spinning-disk worker nodes, run FROM rosee over SSH
(so the Telegram token never has to live on the worker).

Why baselines: a used laptop HDD can legitimately carry a couple of reallocated sectors or a
past cable error. Alerting on "any non-zero" would fire on day one and then be ignored. This
records the first-seen values per node and alerts on CHANGE (plus hard failures).

Alerts (Telegram, deduped: only when the problem set changes, plus a recovery message):
  - SMART overall health not PASSED
  - Current_Pending_Sector / Offline_Uncorrectable / Reported_Uncorrect > 0
  - Reallocated_Sector_Ct above baseline
  - ATA error count above baseline
  - UDMA_CRC_Error_Count up by >= 5 over baseline (cable/connector trouble)
  - Load_Cycle_Count normalized value < 60 (head-park wear)
  - temperature >= 55 C
  - last self-test finished with an error
  - SMART unreadable (node unreachable / smartctl failing)

Added 2026-10-14 when hpHDD (HP Pavilion 14, Toshiba MQ04ABF100) joined the swarm.
"""
import json
import os
import re
import subprocess
from pathlib import Path

import requests
from dotenv import dotenv_values

HERE = Path(__file__).parent
BASELINE_FILE = HERE / "hdd_baselines.json"
STATE_FILE = HERE / "hdd_health_state.json"

env = dotenv_values(Path.home() / ".env")
TELEGRAM_TOKEN = env.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = env.get("TELEGRAM_CHAT_ID", "")
SWARM_KEY = str(Path.home() / ".ssh/id_rsa_swarm")

# name -> (ssh target, device). Target comes from .env so a re-IP only touches one place.
NODES = {
    "hpHDD": (env.get("WORKER2_SSH_TARGET", ""), "/dev/sda"),
}

TEMP_MAX_C = 55
CRC_JUMP = 5
LOAD_CYCLE_MIN_NORMALIZED = 60


def read_smart(target: str, dev: str) -> str:
    cmd = ["ssh", "-i", SWARM_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
           "-o", "StrictHostKeyChecking=no", target,
           f"sudo -n smartctl -H -A -l error -l selftest {dev}; true"]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout
    except Exception:
        return ""


def parse(out: str) -> dict | None:
    if "SMART Attributes Data Structure" not in out:
        return None
    attrs = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 10 and parts[0].isdigit():
            try:
                attrs[int(parts[0])] = {"value": int(parts[3]), "raw": int(parts[9])}
            except ValueError:
                pass
    m = re.search(r"ATA Error Count:\s*(\d+)", out)
    last_test = next((l for l in out.splitlines() if re.match(r"#\s*1\s", l)), "")
    return {
        "passed": "PASSED" in out,
        "realloc": attrs.get(5, {}).get("raw", 0),
        "pending": attrs.get(197, {}).get("raw", 0),
        "uncorrectable": attrs.get(198, {}).get("raw", 0),
        "reported_uncorrect": attrs.get(187, {}).get("raw", 0),
        "crc": attrs.get(199, {}).get("raw", 0),
        "load_cycle_norm": attrs.get(193, {}).get("value", 100),
        "load_cycle_raw": attrs.get(193, {}).get("raw", 0),
        "temp": attrs.get(194, {}).get("raw", 0),
        "power_on_hours": attrs.get(9, {}).get("raw", 0),
        "ata_errors": int(m.group(1)) if m else 0,
        "last_test": last_test.strip(),
    }


def load(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def problems_for(cur: dict | None, base: dict) -> list[str]:
    if cur is None:
        return ["SMART unreadable (node unreachable, sudo denied, or smartctl failing)"]
    p = []
    if not cur["passed"]:
        p.append("SMART overall health is NOT 'PASSED'")
    if cur["pending"] > 0:
        p.append(f"{cur['pending']} pending sector(s)")
    if cur["uncorrectable"] > 0:
        p.append(f"{cur['uncorrectable']} offline-uncorrectable sector(s)")
    if cur["reported_uncorrect"] > 0:
        p.append(f"{cur['reported_uncorrect']} reported-uncorrectable error(s)")
    if cur["realloc"] > base.get("realloc", 0):
        p.append(f"reallocated sectors grew {base.get('realloc', 0)} -> {cur['realloc']}")
    if cur["ata_errors"] > base.get("ata_errors", 0):
        p.append(f"new ATA errors logged ({base.get('ata_errors', 0)} -> {cur['ata_errors']})")
    if cur["crc"] >= base.get("crc", 0) + CRC_JUMP:
        p.append(f"UDMA CRC errors up {base.get('crc', 0)} -> {cur['crc']} (cable/connector)")
    if cur["load_cycle_norm"] < LOAD_CYCLE_MIN_NORMALIZED:
        p.append(f"Load_Cycle_Count wear low (normalized {cur['load_cycle_norm']})")
    if cur["temp"] >= TEMP_MAX_C:
        p.append(f"temperature {cur['temp']} C")
    lt = cur["last_test"]
    if lt and "Completed" in lt and "without error" not in lt:
        p.append(f"last self-test failed: {lt[:90]}")
    return p


def telegram(text: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[hdd_health] telegram not configured")
        return
    try:
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                      json={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=10)
    except Exception as e:
        print(f"[hdd_health] telegram failed: {e}")


def main() -> None:
    baselines, state = load(BASELINE_FILE), load(STATE_FILE)
    for name, (target, dev) in NODES.items():
        if not target:
            print(f"[hdd_health] {name}: no SSH target configured, skipping")
            continue
        cur = parse(read_smart(target, dev))
        if cur and name not in baselines:
            baselines[name] = {k: cur[k] for k in ("realloc", "ata_errors", "crc", "load_cycle_raw", "power_on_hours")}
            print(f"[hdd_health] {name}: first run, baseline recorded: {baselines[name]}")
        probs = problems_for(cur, baselines.get(name, {}))
        prev = state.get(name, [])
        if probs and probs != prev:
            telegram(f"HDD HEALTH WARNING on {name} ({dev}):\n" + "\n".join(f"- {x}" for x in probs))
        elif not probs and prev:
            telegram(f"HDD HEALTH RECOVERED on {name} ({dev}).")
        state[name] = probs
        if cur:
            print(f"[hdd_health] {name}: {'OK' if not probs else 'PROBLEMS: ' + '; '.join(probs)} | "
                  f"realloc={cur['realloc']} pending={cur['pending']} unc={cur['uncorrectable']} "
                  f"ata_err={cur['ata_errors']} crc={cur['crc']} loadcyc={cur['load_cycle_raw']} "
                  f"temp={cur['temp']}C poh={cur['power_on_hours']}")
        else:
            print(f"[hdd_health] {name}: PROBLEMS: {'; '.join(probs)}")
    BASELINE_FILE.write_text(json.dumps(baselines, indent=1))
    STATE_FILE.write_text(json.dumps(state))


if __name__ == "__main__":
    main()
