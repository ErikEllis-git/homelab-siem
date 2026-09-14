#!/usr/bin/env python3
"""
swarm_monitor.py — simple live health status page for the Docker Swarm.

Rebuilt 2026-09-14 — the original swarm-monitor had no surviving config or
description beyond its name/port, so this is a fresh design (Erik's best
recollection: "checking overall health of each machine in the swarm"), not a
restoration. Serves a plain HTML status page on :8080, no history, no alerts
— just current node up/down + CPU/RAM/disk, refreshed on every page load.

Run as a systemd service (matches the original's restart pattern).
"""

import json
import shutil
import subprocess
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8080
SWARM_KEY = "/home/rosee/.ssh/id_rsa_swarm"

# node name (as shown by `docker node ls`) -> ssh target, or None for local
NODE_SSH_TARGETS = {
    "optiplex7010": None,  # this machine (rosee) — queried locally, no SSH
    "OLDDELL": "rikdell@100.81.199.45",
    "LUBUNT": "rikbeans@100.69.79.119",
}


def run(cmd: list, timeout: int = 8) -> str:
    try:
        return subprocess.check_output(cmd, timeout=timeout, stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return ""


def get_swarm_nodes() -> list[dict]:
    out = run(["docker", "node", "ls", "--format", "{{.Hostname}}|{{.Status}}|{{.Availability}}|{{.ManagerStatus}}"])
    nodes = []
    for line in out.splitlines():
        parts = line.split("|")
        if len(parts) == 4:
            nodes.append({
                "hostname": parts[0],
                "status": parts[1],
                "availability": parts[2],
                "manager_status": parts[3] or "Worker",
            })
    return nodes


def local_health() -> dict:
    try:
        load1, load5, load15 = __import__("os").getloadavg()
    except Exception:
        load1 = load5 = load15 = None

    mem_total = mem_avail = None
    try:
        with open("/proc/meminfo") as f:
            meminfo = {}
            for line in f:
                k, v = line.split(":")
                meminfo[k.strip()] = int(v.strip().split()[0])
        mem_total = meminfo.get("MemTotal", 0) / 1024 / 1024
        mem_avail = meminfo.get("MemAvailable", 0) / 1024 / 1024
    except Exception:
        pass

    disk_pct = None
    try:
        du = shutil.disk_usage("/")
        disk_pct = round(du.used / du.total * 100, 1)
    except Exception:
        pass

    mem_pct = round((1 - mem_avail / mem_total) * 100, 1) if mem_total and mem_avail is not None else None

    return {
        "reachable": True,
        "load1": round(load1, 2) if load1 is not None else None,
        "mem_used_gb": round(mem_total - mem_avail, 1) if mem_total and mem_avail is not None else None,
        "mem_total_gb": round(mem_total, 1) if mem_total else None,
        "mem_pct": mem_pct,
        "disk_pct": disk_pct,
    }


def remote_health(ssh_target: str) -> dict:
    out = run([
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
        "-i", SWARM_KEY, ssh_target,
        "cat /proc/loadavg; free -m | awk '/Mem:/{print $2,$3}'; df / | awk 'NR==2{print $5}'",
    ])
    if not out:
        return {"reachable": False}

    lines = out.splitlines()
    result = {"reachable": True, "load1": None, "mem_used_gb": None, "mem_total_gb": None, "mem_pct": None, "disk_pct": None}
    try:
        result["load1"] = round(float(lines[0].split()[0]), 2)
        mem_total_mb, mem_used_mb = map(int, lines[1].split())
        result["mem_total_gb"] = round(mem_total_mb / 1024, 1)
        result["mem_used_gb"] = round(mem_used_mb / 1024, 1)
        result["mem_pct"] = round(mem_used_mb / mem_total_mb * 100, 1)
        result["disk_pct"] = float(lines[2].strip().rstrip("%"))
    except Exception:
        pass
    return result


def collect() -> list[dict]:
    nodes = get_swarm_nodes()
    for node in nodes:
        target = NODE_SSH_TARGETS.get(node["hostname"])
        health = local_health() if target is None else remote_health(target)
        node.update(health)
    return nodes


def render_html(nodes: list[dict]) -> str:
    rows = []
    for n in nodes:
        reachable = n.get("reachable", False)
        status_color = "#0ca30c" if n["status"] == "Ready" and reachable else "#d03b3b"
        row = f"""
        <tr>
          <td>{n['hostname']}</td>
          <td style="color:{status_color}">{n['status']}</td>
          <td>{n['availability']}</td>
          <td>{n['manager_status']}</td>
          <td>{n.get('load1', '—')}</td>
          <td>{n.get('mem_used_gb', '—')} / {n.get('mem_total_gb', '—')} GB ({n.get('mem_pct', '—')}%)</td>
          <td>{n.get('disk_pct', '—')}%</td>
        </tr>"""
        rows.append(row)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"""<!doctype html>
<html><head><title>Swarm Monitor</title>
<style>
body {{ font-family: monospace; background: #111; color: #eee; padding: 2rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ padding: 8px 12px; border: 1px solid #444; text-align: left; }}
th {{ background: #222; }}
</style></head>
<body>
<h2>Docker Swarm health</h2>
<p>Last checked: {now}</p>
<table>
<tr><th>Node</th><th>Status</th><th>Availability</th><th>Manager</th><th>Load (1m)</th><th>Memory</th><th>Disk</th></tr>
{"".join(rows)}
</table>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        nodes = collect()
        if self.path == "/json":
            body = json.dumps(nodes, indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return

        body = render_html(nodes).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print(f"[swarm-monitor] listening on 0.0.0.0:{PORT}")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
