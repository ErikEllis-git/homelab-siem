#!/usr/bin/env python3
"""
incident_responder.py — Autonomous incident response for Suricata IDS alerts.

When triggered by a sev1/sev2 alert:
  1. Investigates source IP (active connections, logged-in users, recent logins)
  2. Sends context to LiteLLM for a block/no-block decision
  3. Blocks via iptables if confidence is medium or high
  4. Reports the full chain to Telegram

Listens on 127.0.0.1:8766 — same JSON payload as the claude-telegram webhook.
"""

import json
import os
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import requests
from dotenv import dotenv_values

PORT = 8766
WEBHOOK_SECRET = os.environ.get("IR_WEBHOOK_SECRET", "")

# Suppress repeat investigations for the same (signature, src_ip) within this window
_DEDUP_FILE = Path(__file__).parent / "ir_dedup.json"
_ALERT_DEDUP_LOCK = threading.Lock()
ALERT_DEDUP_TTL = 1800  # 30 minutes


def _load_dedup() -> dict:
    try:
        return json.loads(_DEDUP_FILE.read_text())
    except Exception:
        return {}


def _is_alert_suppressed(sig: str, src_ip: str) -> bool:
    key = f"{sig}:{src_ip}"
    with _ALERT_DEDUP_LOCK:
        return (time.time() - _load_dedup().get(key, 0)) < ALERT_DEDUP_TTL


def _record_alert(sig: str, src_ip: str) -> None:
    key = f"{sig}:{src_ip}"
    now = time.time()
    with _ALERT_DEDUP_LOCK:
        state = _load_dedup()
        state = {k: v for k, v in state.items() if (now - v) < ALERT_DEDUP_TTL}
        state[key] = now
        try:
            _DEDUP_FILE.write_text(json.dumps(state))
        except Exception as e:
            print(f"[ir] could not write dedup file: {e}")

env = dotenv_values(Path.home() / ".env")
TELEGRAM_TOKEN = env.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = env.get("TELEGRAM_CHAT_ID", "")
LITELLM_URL = "http://localhost:4000"
LITELLM_KEY = env.get("LITELLM_KEY", "")

# IPs we will never block regardless of what Suricata says
# Configure: set TRUSTED_NODE_IPS in .env as a comma-separated list of your cluster node IPs
TRUSTED_IPS = set(filter(None, env.get("TRUSTED_NODE_IPS", "").split(",")))
TRUSTED_PREFIXES = ("127.", "::1", "10.", "192.168.", "100.64.", "203.0.113.", "198.51.100.")  # 192.168.=LAN; 100.64.=Tailscale CGNAT; last two: RFC 5737 purple team test nets


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_trusted(ip: str) -> bool:
    if ip in TRUSTED_IPS:
        return True
    return any(ip.startswith(p) for p in TRUSTED_PREFIXES)


def is_blocked(ip: str) -> bool:
    """Return True if ip already has a DROP rule in iptables INPUT chain."""
    try:
        result = subprocess.run(
            ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def run(cmd: list, timeout: int = 10) -> str:
    try:
        return subprocess.check_output(cmd, timeout=timeout, stderr=subprocess.DEVNULL).decode().strip()
    except Exception as e:
        return f"ERROR: {e}"


def investigate(src_ip: str) -> str:
    sections = []

    sections.append("$ ss -tupn\n" + run(["ss", "-tupn"]))
    sections.append("$ who\n" + run(["who"]))
    sections.append("$ last -n 15\n" + run(["last", "-n", "15"]))

    grep_out = run(["sh", "-c", f"ss -tupn | grep '{src_ip}' || echo '(none)'"])
    sections.append(f"$ ss -tupn | grep {src_ip}\n{grep_out}")

    sections.append("$ sudo iptables -L INPUT -n --line-numbers\n" +
                    run(["sudo", "iptables", "-L", "INPUT", "-n", "--line-numbers"]))

    return "\n\n".join(sections)


def llm_decide(alert: dict, investigation_text: str) -> dict:
    sig = alert.get("alert", {}).get("signature", "unknown")
    severity = alert.get("alert", {}).get("severity", 99)
    src = alert.get("src_ip", "?")
    dst = alert.get("dest_ip", "?")
    proto = alert.get("proto", "?")
    category = alert.get("alert", {}).get("category", "")

    prompt = (
        "You are a security analyst reviewing a live Suricata IDS alert.\n\n"
        "ALERT:\n"
        f"  Signature : {sig}\n"
        f"  Category  : {category}\n"
        f"  Severity  : {severity} (1=critical, 2=major, 3=minor)\n"
        f"  Flow      : {src} -> {dst} [{proto}]\n\n"
        "LIVE SYSTEM STATE AT TIME OF ALERT:\n"
        f"{investigation_text}\n\n"
        "Based on this data, decide:\n"
        "  1. Is this a genuine threat or likely a false positive?\n"
        f"  2. Should we block {src} immediately via iptables?\n"
        "  3. What is your confidence level (low/medium/high)?\n\n"
        "Respond ONLY with valid JSON, no extra text:\n"
        '{"block": true, "confidence": "high", "threat": true, "reason": "one sentence"}'
    )

    try:
        resp = requests.post(
            f"{LITELLM_URL}/chat/completions",
            json={
                "model": "openrouter/llama-3.3-70b",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 200,
            },
            headers={"Authorization": f"Bearer {LITELLM_KEY}"},
            timeout=45,
        )
        data = resp.json()
        if "choices" not in data:
            print(f"[llm] unexpected response: {str(data)[:300]}")
        else:
            content = data["choices"][0]["message"]["content"]
            match = re.search(r"\{[^{}]+\}", content, re.DOTALL)
            if match:
                return json.loads(match.group())
            print(f"[llm] could not parse JSON from: {content[:200]}")
    except Exception as e:
        print(f"[llm] error: {e}")

    return {"block": False, "confidence": "low", "threat": False, "reason": "LLM unavailable — no action taken"}


def block_ip(ip: str) -> str:
    results = []
    for chain in ("INPUT", "FORWARD"):
        out = run(["sudo", "iptables", "-I", chain, "-s", ip, "-j", "DROP"])
        results.append(f"{chain}: {'OK' if not out.startswith('ERROR') else out}")
    # best-effort persistence
    run(["sudo", "sh", "-c", "iptables-save > /etc/iptables/rules.v4"], timeout=5)
    return "Blocked " + ip + " (" + ", ".join(results) + ")"


def send_telegram(text: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[tg] not configured")
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"},
            timeout=15,
        )
    except Exception as e:
        print(f"[tg] {e}")


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def handle_alert(event: dict) -> None:
    severity = event.get("alert", {}).get("severity", 99)
    src_ip = event.get("src_ip", "")
    signature = event.get("alert", {}).get("signature", "unknown")

    if severity > 2:
        print(f"[ir] skipping sev{severity}: {signature}")
        return

    if not src_ip:
        print("[ir] no src_ip in event, skipping")
        return

    if is_trusted(src_ip):
        print(f"[ir] trusted IP {src_ip}, skipping")
        return

    if is_blocked(src_ip):
        print(f"[ir] {src_ip} already blocked — skipping investigation")
        return

    if _is_alert_suppressed(signature, src_ip):
        print(f"[ir] suppressed duplicate: {signature} from {src_ip} (within {ALERT_DEDUP_TTL//60}m window)")
        return

    print(f"[ir] responding to sev{severity}: {signature} from {src_ip}")
    send_telegram(f"*Investigating* (sev{severity})\n`{signature}`\nSrc: `{src_ip}`")

    inv = investigate(src_ip)
    decision = llm_decide(event, inv[:4000])  # cap to ~1k tokens

    should_block = decision.get("block") and decision.get("confidence") in ("medium", "high")
    action = block_ip(src_ip) if should_block else "Monitoring only (no block)"

    report = (
        f"*IR Report*\n"
        f"Sig: `{signature}`\n"
        f"Src: `{src_ip}` | Sev: {severity}\n\n"
        f"*Threat:* {'Yes' if decision.get('threat') else 'No'} | "
        f"*Confidence:* {decision.get('confidence', '?')}\n"
        f"*Reason:* {decision.get('reason', '?')}\n\n"
        f"*Action:* {action}"
    )
    send_telegram(report)
    print(f"[ir] done — {action}")
    _record_alert(signature, src_ip)


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence default access log

    def do_POST(self):
        if self.path != "/webhooks/suricata":
            self.send_response(404)
            self.end_headers()
            return

        auth = self.headers.get("Authorization", "")
        if WEBHOOK_SECRET and auth != f"Bearer {WEBHOOK_SECRET}":
            self.send_response(401)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return

        event = body.get("event", body)
        threading.Thread(target=handle_alert, args=(event,), daemon=True).start()

        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"accepted"}')


if __name__ == "__main__":
    if not WEBHOOK_SECRET:
        print("WARNING: IR_WEBHOOK_SECRET not set — accepting all requests on 127.0.0.1:8766")
    print(f"[ir] listening on 127.0.0.1:{PORT}")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
