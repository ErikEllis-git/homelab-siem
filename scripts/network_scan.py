#!/usr/bin/env python3
"""
network_scan.py — Periodic nmap subnet scan + trusted device presence detection.

- Scans the home subnet for open ports on cluster nodes
- Detects new open ports and alerts via Telegram
- Checks if a trusted device is on the network and sends presence update
- Stores results in Elasticsearch

Run via cron every 30 minutes:
  */30 * * * * /opt/siem/scripts/.venv/bin/python3 /opt/siem/scripts/network_scan.py
"""

import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from dotenv import dotenv_values
from pathlib import Path
import requests

env = dotenv_values(Path.home() / ".env")
TELEGRAM_TOKEN   = env.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = env.get("TELEGRAM_CHAT_ID", "")

SUBNET             = env.get("SCAN_SUBNET", "192.168.0.0/24")
TRUSTED_DEVICE_IP  = env.get("TRUSTED_DEVICE_IP", "")  # Configure: LAN IP of a trusted device to track presence
ES_HOST            = "http://localhost:9200"
ES_INDEX           = "nmap-scans"
BASELINE_FILE      = Path(__file__).parent / "nmap_baseline.json"

# Configure: set CLUSTER_NODE_IPS in .env as a comma-separated list of node LAN IPs to port-scan
CLUSTER_IPS = set(filter(None, env.get("CLUSTER_NODE_IPS", "").split(",")))


def send_telegram(text: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text},
            timeout=10,
        ).raise_for_status()
    except Exception as exc:
        print(f"[TG] failed: {exc}")


def run_nmap() -> dict:
    """Run nmap ping+port scan, return {ip: {hostname, ports: [...]}}"""
    print(f"[nmap] Scanning {SUBNET}...")
    result = subprocess.run(
        ["nmap", "-sn", "--open", "-oX", "-", SUBNET],
        capture_output=True, text=True, timeout=120,
    )
    hosts = {}
    try:
        root = ET.fromstring(result.stdout)
        for host in root.findall("host"):
            if host.find("status").get("state") != "up":
                continue
            addr_el = host.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr")
            hostname_el = host.find(".//hostname[@type='PTR']")
            hostname = hostname_el.get("name", "") if hostname_el is not None else ""
            hosts[ip] = {"hostname": hostname, "ports": []}
    except ET.ParseError as e:
        print(f"[nmap] XML parse error: {e}")
    return hosts


def run_port_scan(ips: list) -> dict:
    """Port scan specific IPs, return {ip: [port, ...]}"""
    if not ips:
        return {}
    print(f"[nmap] Port scanning {ips}...")
    result = subprocess.run(
        ["nmap", "-oX", "-", "--top-ports", "20", "--max-rate", "1"] + ips,
        capture_output=True, text=True, timeout=180,
    )
    port_map = {}
    try:
        root = ET.fromstring(result.stdout)
        for host in root.findall("host"):
            addr_el = host.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr")
            ports = []
            for port in host.findall(".//port"):
                if port.find("state").get("state") == "open":
                    ports.append(int(port.get("portid")))
            port_map[ip] = ports
    except ET.ParseError as e:
        print(f"[nmap] port scan XML parse error: {e}")
    return port_map


def load_baseline() -> dict:
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_baseline(baseline: dict) -> None:
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)


def ship_to_es(doc: dict) -> None:
    try:
        requests.post(
            f"{ES_HOST}/{ES_INDEX}/_doc",
            json=doc,
            headers={"Content-Type": "application/json"},
            timeout=10,
        ).raise_for_status()
    except Exception as exc:
        print(f"[ES] failed: {exc}")


def main():
    now = datetime.now(timezone.utc)
    ts  = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"\n[network_scan] {ts}")

    # 1 — ping sweep
    hosts = run_nmap()
    live_ips = set(hosts.keys())
    print(f"[nmap] {len(live_ips)} hosts up")

    # 2 — trusted device presence (requires 2 consecutive scans to confirm a state change)
    device_home = bool(TRUSTED_DEVICE_IP) and (TRUSTED_DEVICE_IP in live_ips)
    baseline = load_baseline()
    prev_device = baseline.get("device_home")

    if prev_device is None:
        # first run, just record
        print(f"[presence] First run — trusted device is {'home' if device_home else 'not home'}")
        baseline["device_home"] = device_home
        baseline["device_pending"] = None
        baseline["device_pending_count"] = 0
    elif device_home == prev_device:
        # state matches confirmed state — reset any pending change
        baseline["device_pending"] = None
        baseline["device_pending_count"] = 0
        print(f"[presence] Trusted device is {'home' if device_home else 'away'} (unchanged)")
    else:
        # state differs from confirmed — track consecutive count
        if baseline.get("device_pending") == device_home:
            baseline["device_pending_count"] = baseline.get("device_pending_count", 0) + 1
        else:
            baseline["device_pending"] = device_home
            baseline["device_pending_count"] = 1

        count = baseline["device_pending_count"]
        print(f"[presence] Possible state change ({count}/2): trusted device appears {'home' if device_home else 'away'}")

        if count >= 2:
            status = "arrived home" if device_home else "left home"
            msg = f"📍 Trusted device has {status}"
            print(f"[presence] Confirmed — {msg}")
            # send_telegram(msg)  # paused — re-enable to restore presence alerts
            baseline["device_home"] = device_home
            baseline["device_pending"] = None
            baseline["device_pending_count"] = 0

    # 3 — port scan cluster nodes that are up
    cluster_up = [ip for ip in CLUSTER_IPS if ip in live_ips]
    port_results = run_port_scan(cluster_up)

    # 4 — check for new ports vs baseline
    prev_ports = baseline.get("ports", {})
    alerts = []
    for ip, ports in port_results.items():
        prev = set(prev_ports.get(ip, []))
        curr = set(ports)
        new_ports = curr - prev
        closed_ports = prev - curr
        if new_ports:
            hostname = hosts.get(ip, {}).get("hostname", ip)
            alerts.append(f"🔓 New open port(s) on {hostname} ({ip}): {sorted(new_ports)}")
        if closed_ports:
            hostname = hosts.get(ip, {}).get("hostname", ip)
            print(f"[scan] Ports closed on {hostname} ({ip}): {sorted(closed_ports)}")

    for alert in alerts:
        print(alert)
        send_telegram(alert)

    # 5 — save baseline (device_home already managed in presence block above)
    baseline["ports"] = {ip: list(ports) for ip, ports in port_results.items()}
    save_baseline(baseline)

    # 6 — ship to ES
    doc = {
        "@timestamp": ts,
        "hosts_up": len(live_ips),
        "device_home": device_home,
        "cluster_ports": port_results,
        "new_port_alerts": alerts,
    }
    ship_to_es(doc)
    print(f"[ES] Scan result stored")
    print(f"[done] Device home: {device_home}, cluster nodes scanned: {len(cluster_up)}")


if __name__ == "__main__":
    main()
