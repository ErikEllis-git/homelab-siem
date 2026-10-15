#!/usr/bin/env python3
"""
hphdd-thermal-sample.py — write one thermal sample (JSON line) for this laptop.

Runs as root from a systemd timer every 30 s (see hphdd-thermal.timer) so a heat spike
between rosee's 5-minute checks is still on record. rosee's thermal_check.py pulls the new
lines over SSH, stores them in Elasticsearch (thermal-*) and does the alerting; this script
only measures. Output: /var/log/hphdd-thermal.jsonl (rotated at 4 MB, one .1 kept).

This laptop (HP Pavilion 14-ce3xxx) exposes: coretemp (package + per-core), platform thermal
zones, Intel throttle counters, battery/AC. It exposes NO fan tachometer, so a failing fan can
only be inferred from "hot while idle" — hence load1 and the throttle counters in every sample.
HDD temperature comes from the kernel drivetemp module (loaded here if missing).
"""
import glob
import json
import os
import subprocess
import time

OUT = "/var/log/hphdd-thermal.jsonl"
MAX_BYTES = 4 * 1024 * 1024


def rd(path, default=None):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return default


def num(path):
    v = rd(path)
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def hwmon(name):
    for h in glob.glob("/sys/class/hwmon/hwmon*"):
        if rd(h + "/name") == name:
            return h
    return None


def main():
    if not hwmon("drivetemp"):
        subprocess.run(["modprobe", "drivetemp"], capture_output=True)

    s = {"ts": int(time.time())}

    ct = hwmon("coretemp")
    cores = []
    s["cpu_pkg_c"] = None
    if ct:
        for f in glob.glob(ct + "/temp*_input"):
            label = rd(f.replace("_input", "_label"), "")
            v = num(f)
            if v is None:
                continue
            if label.startswith("Package"):
                s["cpu_pkg_c"] = v / 1000.0
            elif label.startswith("Core"):
                cores.append(v / 1000.0)
    s["cpu_core_max_c"] = max(cores) if cores else None

    zones = {}
    for z in glob.glob("/sys/class/thermal/thermal_zone*"):
        t, v = rd(z + "/type"), num(z + "/temp")
        if t and v is not None and t != "INT3400 Thermal":
            zones[t] = v / 1000.0
    s["zones"] = zones

    dt = hwmon("drivetemp")
    v = num(dt + "/temp1_input") if dt else None
    s["hdd_c"] = v / 1000.0 if v is not None else None

    thr = "/sys/devices/system/cpu/cpu*/thermal_throttle/"
    pk = [num(p) or 0 for p in glob.glob(thr + "package_throttle_count")]
    s["throttle_pkg_count"] = max(pk) if pk else 0
    s["throttle_core_count"] = sum(num(p) or 0 for p in glob.glob(thr + "core_throttle_count"))
    pm = [num(p) or 0 for p in glob.glob(thr + "package_throttle_total_time_ms")]
    s["throttle_pkg_ms"] = max(pm) if pm else 0

    freqs = [num(p) for p in glob.glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq")]
    freqs = [f for f in freqs if f]
    s["freq_avg_mhz"] = round(sum(freqs) / len(freqs) / 1000) if freqs else None
    try:
        s["load1"] = float(rd("/proc/loadavg", "0").split()[0])
    except ValueError:
        s["load1"] = None

    s["ac_online"] = num("/sys/class/power_supply/ADP1/online")
    s["bat_pct"] = num("/sys/class/power_supply/BAT0/capacity")
    s["bat_status"] = rd("/sys/class/power_supply/BAT0/status")

    try:
        if os.path.getsize(OUT) > MAX_BYTES:
            os.replace(OUT, OUT + ".1")
    except FileNotFoundError:
        pass
    with open(OUT, "a") as f:
        f.write(json.dumps(s) + "\n")
    os.chmod(OUT, 0o644)


if __name__ == "__main__":
    main()
