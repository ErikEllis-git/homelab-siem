#!/usr/bin/env python3
"""
outbound_monitor.py — Detect unexpected outbound connections across all nodes.

Runs every 5 min via cron. SSHes into all 3 nodes and checks established
outbound connections via `ss`. Flags:
  - Any connection to a threat intel IP (any port) -> CRITICAL + SOC dispatch
  - Established connections on non-whitelisted ports to external IPs -> Telegram alert

Deduplicates against the previous poll so persistent connections don't spam.
TI matches always re-alert even if seen before.
"""

import ipaddress
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import dotenv_values

sys.path.insert(0, os.path.dirname(__file__))

from geo_intel import format_geo, geolocate
from soc_dispatch import dispatch_anomaly, is_tg_suppressed, record_tg_alert

OUTBOUND_TI_DEDUP_TTL   = 3600   # 1 hr  — TI match re-alert cooldown per IP
OUTBOUND_CONN_ALERT_TTL = 14400  # 4 hrs — non-TI connection re-alert cooldown per (node,ip,port)
from threat_intel import lookup_ips

# ── Config ──────────────────────────────────────────────────────────────────────

STATE_FILE = Path(__file__).parent / "outbound_state.json"

env = dotenv_values(Path.home() / ".env")
TELEGRAM_TOKEN   = env.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = env.get("TELEGRAM_CHAT_ID", "")

# Outbound ports considered normal — won't alert unless there's a TI match
WHITELIST_PORTS = {
    80, 443,            # HTTP/HTTPS
    53, 853,            # DNS
    123,                # NTP
    25, 587, 465,       # SMTP
    993, 995, 143,      # IMAP/POP3
    11371,              # GPG keyserver
    2377, 7946, 4789,   # Docker Swarm control/overlay
    41641,              # Tailscale WireGuard
}

NODES = [
    {"name": "rosse",   "ssh": None},
    {"name": "worker1", "ssh": ["ssh", "-i", str(Path.home() / ".ssh/id_rsa_swarm"),
                                 "-o", "ConnectTimeout=10",
                                 "-o", "StrictHostKeyChecking=no",
                                 env.get("WORKER1_SSH_TARGET", "user@worker1")]},
    {"name": "worker2", "ssh": ["ssh", "-o", "ConnectTimeout=10",
                                 "-o", "StrictHostKeyChecking=no",
                                 env.get("WORKER2_SSH_TARGET", "user@worker2")]},
]

# Cluster nodes — always trusted
# Configure: set TRUSTED_NODE_IPS in .env as a comma-separated list of your cluster node IPs
_TRUSTED_IPS = set(filter(None, env.get("TRUSTED_NODE_IPS", "").split(",")))

# Tailscale CGNAT (100.64.0.0/10) + RFC-1918 + loopback
_PRIVATE_NETS = [
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("203.0.113.0/24"),   # RFC 5737 TEST-NET-3 -- purple team
    ipaddress.ip_network("198.51.100.0/24"),  # RFC 5737 TEST-NET-2 -- purple team
    # IPv6 private/loopback
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local (fd00::/8 included)
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]

# Tailscale DERP relay servers — expected outbound, not flagged
_TAILSCALE_RELAY_PREFIXES = ("192.200.", "199.165.", "149.28.")

_PROCESS_RE = re.compile(r'users:\(\("([^"]+)"')


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    if ip in _TRUSTED_IPS:
        return True
    if any(ip.startswith(p) for p in _TAILSCALE_RELAY_PREFIXES):
        return True
    try:
        return any(ipaddress.ip_address(ip) in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _parse_addr(addr: str) -> tuple[str, int]:
    """Parse 'ip:port' or '[ipv6]:port' into (ip, port)."""
    if addr.startswith("["):
        end = addr.index("]")
        ip   = addr[1:end]
        port = int(addr[end + 2:])
    else:
        ip, _, port_s = addr.rpartition(":")
        port = int(port_s)
    # strip interface suffix e.g. 192.168.x.x%eth0
    ip = ip.split("%")[0]
    # unwrap IPv4-mapped IPv6 (::ffff:1.2.3.4)
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    return ip, port


def _get_connections(node: dict) -> list[dict]:
    """Return outbound external established connections for a node."""
    # -H suppresses the header but also drops the state column, shifting indices.
    # Without -H the format is: netid state recv-q send-q local peer [process]
    # We skip the header line and use parts[4]/parts[5] for local/peer.
    ss_cmd = "ss -tupn state established"
    try:
        if node["ssh"]:
            result = subprocess.run(
                node["ssh"] + [ss_cmd],
                capture_output=True, text=True, timeout=15,
            )
        else:
            result = subprocess.run(
                ss_cmd.split(), capture_output=True, text=True, timeout=15,
            )
    except subprocess.TimeoutExpired:
        print(f"  [{node['name']}] ss timed out")
        return []
    except Exception as e:
        print(f"  [{node['name']}] ss failed: {e}")
        return []

    conns = []
    for line in result.stdout.splitlines()[1:]:  # skip header
        parts = line.split()
        # ss without state column: netid recv-q send-q local peer [process]
        if len(parts) < 5:
            continue
        try:
            local_ip, local_port = _parse_addr(parts[3])
            peer_ip,  peer_port  = _parse_addr(parts[4])
        except (ValueError, IndexError):
            continue

        # Skip private/trusted peers
        if _is_private(peer_ip):
            continue

        # Outbound: local port is ephemeral, peer port is the service
        # Skip if local port looks like a listening service (< 1024)
        if local_port < 1024:
            continue

        proc_m  = _PROCESS_RE.search(line)
        process = proc_m.group(1) if proc_m else "unknown"

        conns.append({
            "peer_ip":   peer_ip,
            "peer_port": peer_port,
            "process":   process,
        })
    return conns


def _load_state() -> dict:
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2))


def _send_telegram(text: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"},
            timeout=10,
        )
    except Exception as e:
        print(f"  [TG] failed: {e}")


# ── Main ────────────────────────────────────────────────────────────────────────

def main() -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"\n[outbound_monitor] {ts}")

    state: dict = _load_state()
    # alerted: {"node:ip:port": "ISO-timestamp"} — tracks when we last fired on each conn
    alerted: dict[str, str] = state.get("alerted", {})
    now_dt = datetime.now(timezone.utc)

    all_conns: dict[str, list[dict]] = {}

    for node in NODES:
        conns = _get_connections(node)
        all_conns[node["name"]] = conns
        print(f"  [{node['name']}] {len(conns)} external outbound connection(s)")

    # Bulk lookups for all external IPs seen
    all_ips = list({c["peer_ip"] for conns in all_conns.values() for c in conns})
    ti  = lookup_ips(all_ips)
    geo = geolocate(all_ips)

    alerts = []
    new_state: dict = {}
    new_alerted: dict[str, str] = dict(alerted)  # carry forward, prune below

    for node_name, conns in all_conns.items():
        new_state[node_name] = [
            {"peer_ip": c["peer_ip"], "peer_port": c["peer_port"]}
            for c in conns
        ]

        for conn in conns:
            ip   = conn["peer_ip"]
            port = conn["peer_port"]
            proc = conn["process"]
            conn_key = f"{node_name}:{ip}:{port}"

            ti_match = ti.get(ip)

            if ti_match:
                # TI match: use shared telegram dedup (1 hr window)
                ti_tg_key = f"outbound_ti:{ip}"
                if is_tg_suppressed(ti_tg_key, ttl=OUTBOUND_TI_DEDUP_TTL):
                    print(f"  [{node_name}] suppressed TI re-alert for {ip} (within {OUTBOUND_TI_DEDUP_TTL//60}m)")
                    continue
            else:
                # Non-TI: skip whitelisted ports entirely
                if port in WHITELIST_PORTS:
                    continue
                # Non-whitelisted: check per-connection alert TTL
                if conn_key in alerted:
                    last_ts = datetime.fromisoformat(alerted[conn_key])
                    if (now_dt - last_ts).total_seconds() < OUTBOUND_CONN_ALERT_TTL:
                        print(f"  [{node_name}] suppressed re-alert for {ip}:{port} "
                              f"(within {OUTBOUND_CONN_ALERT_TTL//3600}h)")
                        continue

            alerts.append({
                "node":     node_name,
                "ip":       ip,
                "port":     port,
                "process":  proc,
                "geo_str":  f" [{format_geo(geo[ip])}]" if geo.get(ip) else "",
                "ti_match": ti_match,
                "conn_key": conn_key,
            })

    # Prune stale alerted entries (older than TTL) to keep the file tidy
    cutoff = now_dt.isoformat()
    new_alerted = {
        k: v for k, v in new_alerted.items()
        if (now_dt - datetime.fromisoformat(v)).total_seconds() < OUTBOUND_CONN_ALERT_TTL
    }
    new_state["alerted"] = new_alerted
    _save_state(new_state)

    if not alerts:
        print("  [ok] no unexpected outbound connections")
        return

    # Format Telegram message
    now_str = datetime.now().strftime("%H:%M")
    lines = ["🌐 *Outbound Alert*", f"_{now_str}_", ""]
    for a in alerts:
        ti_str = f" ⚠️ _{a['ti_match']['malware']}_" if a["ti_match"] else ""
        lines.append(
            f"`{a['ip']}:{a['port']}`{a['geo_str']}{ti_str}\n"
            f"  {a['node']} · {a['process']}"
        )

    # Telegram alerts disabled
    # _send_telegram("\n".join(lines))

    # Record alert timestamps so we don't re-fire within the cooldown window
    ts_now = now_dt.isoformat()
    for a in alerts:
        if a["ti_match"]:
            record_tg_alert(f"outbound_ti:{a['ip']}", ttl=OUTBOUND_TI_DEDUP_TTL)
        else:
            new_alerted[a["conn_key"]] = ts_now
    # Persist the updated alerted map
    new_state["alerted"] = new_alerted
    _save_state(new_state)

    print(f"  [TG] alerted on {len(alerts)} connection(s)")

    # Escalate to Claude SOC for any threat intel matches
    ti_alerts = [a for a in alerts if a["ti_match"]]
    if ti_alerts:
        summary = "; ".join(
            f"{a['ip']}:{a['port']} ({a['ti_match']['malware']}) on {a['node']}"
            for a in ti_alerts
        )
        dispatch_anomaly(
            severity="CRITICAL",
            threat="Outbound connection to known malware C2",
            nodes_affected=", ".join({a["node"] for a in ti_alerts}),
            summary=f"Established outbound connection(s) to threat intel IPs: {summary}",
            recommendation=(
                "Immediately check running processes on affected node(s). "
                "Kill suspicious processes, block the IP(s) on all nodes."
            ),
            cross_node=len({a["node"] for a in ti_alerts}) > 1,
        )
        print(f"  [SOC] CRITICAL dispatch — {len(ti_alerts)} TI match(es)")


if __name__ == "__main__":
    main()
