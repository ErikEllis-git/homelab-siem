#!/usr/bin/env python3
"""
Web honeypot — Flask app faking Apache/2.4.57 + PHP/8.1.2, exposing common
attacker-bait endpoints and logging every request as JSON lines matching the
schema web_honeypot_analyzer.py expects (matched_rule, post_data, cmd, etc).

Reconstructed 2026-09-14 after the original VPS + app.py were destroyed —
only the endpoint list and header fakes survived (in the vault). Rule names
match web_honeypot_analyzer.py's HIGH_VALUE_RULES/NOISE_RULES exactly.
"""

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, Response

# gunicorn hardcodes its own "Server: gunicorn/x.y" response header
# regardless of what the WSGI app sets, which would blow the Apache
# disguise. Patch it to fake Apache directly instead.
try:
    from gunicorn.http import wsgi as _gunicorn_wsgi

    def _patched_default_headers(self):
        # gunicorn treats "server"/"date" as hop-by-hop and silently drops
        # them even if the WSGI app sets them, always injecting its own here
        # instead — so the Apache fake has to be hardcoded in this patch.
        connection = "upgrade" if self.upgrade else ("close" if self.should_close() else "keep-alive")
        headers = [
            "HTTP/%s.%s %s\r\n" % (self.req.version[0], self.req.version[1], self.status),
            "Server: Apache/2.4.57 (Ubuntu)\r\n",
            "Date: %s\r\n" % _gunicorn_wsgi.util.http_date(),
            "Connection: %s\r\n" % connection,
        ]
        if self.chunked:
            headers.append("Transfer-Encoding: chunked\r\n")
        return headers

    _gunicorn_wsgi.Response.default_headers = _patched_default_headers
except ImportError:
    pass

app = Flask(__name__)

LOG_DIR = Path("/app/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
ACCESS_LOG = LOG_DIR / "access.json"

logger = logging.getLogger("webhoneypot")
logger.setLevel(logging.INFO)
handler = logging.FileHandler(ACCESS_LOG)
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)

WEBSHELL_PATHS = {"/shell.php", "/wso.php", "/c99.php", "/cmd.php", "/webshell.php", "/b374k.php"}
CONFIG_PATHS = {"/.env", "/.git/config"}


def log_request(matched_rule: str, cmd: str = "") -> None:
    post_data = {}
    if request.form:
        post_data = {k: v for k, v in request.form.items()}
    elif request.is_json:
        try:
            post_data = request.get_json(silent=True) or {}
        except Exception:
            post_data = {}

    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        # P2-3: remote_addr is authoritative (XFF is attacker-spoofable).
        "src_ip": request.remote_addr,
        "xff_untrusted": request.headers.get("X-Forwarded-For", ""),
        "method": request.method,
        "path": request.path,
        "matched_rule": matched_rule,
        "user_agent": request.headers.get("User-Agent", ""),
        "query": request.query_string.decode("utf-8", "ignore"),
        "post_data": post_data,
    }
    if cmd:
        doc["cmd"] = cmd
    logger.info(json.dumps(doc))


@app.after_request
def fake_headers(resp):
    # Server header is faked in the gunicorn patch above (gunicorn discards
    # this one as hop-by-hop) — only X-Powered-By actually comes from here.
    resp.headers["X-Powered-By"] = "PHP/8.1.2"
    return resp


@app.route("/.env")
def env_file():
    log_request("env_file_exposure")
    return Response("Forbidden", status=403, mimetype="text/plain")


@app.route("/.git/config")
def git_config():
    log_request("git_config_exposure")
    return Response("Forbidden", status=403, mimetype="text/plain")


@app.route("/actuator/env")
def spring_actuator():
    log_request("spring_actuator")
    return Response("Forbidden", status=403, mimetype="text/plain")


@app.route("/wp-login.php", methods=["GET", "POST"])
def wp_login():
    log_request("wordpress_login")
    if request.method == "POST":
        return Response(
            "<html><body>ERROR: Invalid username or password.</body></html>",
            status=200, mimetype="text/html",
        )
    return Response(
        "<html><head><title>Log In</title></head><body>"
        "<form method='post'><input name='log'><input name='pwd' type='password'>"
        "<button type='submit'>Log In</button></form></body></html>",
        status=200, mimetype="text/html",
    )


@app.route("/xmlrpc.php", methods=["GET", "POST"])
def xmlrpc():
    log_request("wordpress_xmlrpc")
    return Response(
        "<?xml version=\"1.0\"?><methodResponse><fault>"
        "<value><struct><member><name>faultCode</name><value><int>-32601</int></value></member>"
        "</struct></value></fault></methodResponse>",
        status=200, mimetype="text/xml",
    )


@app.route("/wp-admin/")
@app.route("/wp-admin/<path:_sub>")
def wp_admin(_sub=None):
    log_request("admin_panel")
    return Response("", status=302, headers={"Location": "/wp-login.php"})


@app.route("/phpmyadmin/")
@app.route("/phpmyadmin/index.php", methods=["GET", "POST"])
def phpmyadmin():
    log_request("phpmyadmin_login")
    if request.method == "POST":
        return Response(
            "<html><body>#1045 Cannot log in to the MySQL server</body></html>",
            status=200, mimetype="text/html",
        )
    return Response(
        "<html><head><title>phpMyAdmin</title></head><body>"
        "<form method='post'><input name='pma_username'>"
        "<input name='pma_password' type='password'>"
        "<button type='submit'>Go</button></form></body></html>",
        status=200, mimetype="text/html",
    )


@app.route("/<path:catchall>", methods=["GET", "POST"])
def catchall(catchall):
    path_lower = "/" + catchall.lower()
    cmd = ""

    if path_lower in WEBSHELL_PATHS or any(path_lower.endswith(p) for p in WEBSHELL_PATHS):
        cmd = request.args.get("cmd", "") or (request.form.get("cmd", "") if request.form else "")
        log_request("webshell_attempt", cmd=cmd)
        return Response("Not Found", status=404, mimetype="text/plain")

    log_request("unknown_probe")
    return Response("Not Found", status=404, mimetype="text/plain")


@app.route("/")
def index():
    log_request("unknown_probe")
    return Response(
        "<html><body><h1>It works!</h1></body></html>",
        status=200, mimetype="text/html",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
