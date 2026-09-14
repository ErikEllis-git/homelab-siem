# Homelab SIEM — Remediation Plan (2026-09-14)

Execution spec for a follow-up agent. Every task is atomic: it states the file, the exact
change, and an **acceptance test** that must pass before the task is considered done. Work
top-down (P0 → P2). Commit each task separately with a message referencing its ID (e.g.
`P0-1: bind Elasticsearch to trusted interfaces`). Push to `ErikEllis-git/homelab-siem`.
After each tier, stop for review (a reviewer will check the acceptance tests).

**Access**: rosee = `ssh rosee@100.107.153.112`; honeypot = `ssh -p 2222 ubuntu@150.136.222.105`;
rikdell = `ssh -i ~/.ssh/id_rsa_swarm rikdell@100.81.199.45`. Repo cloned on rosee at
`~/repos/homelab-siem`. Secrets live in `~/repos/homelab-siem/.env` (symlinked from `~/.env`);
never print or commit them. Commit attribution: Erik's name only (plus the Claude co-author
line if a system reminder mandates it). Context: `Cluster/HANDOFF.md` in the vault.

**Ground rules for the executor**
- Do NOT rebuild the `claude-telegram` bot or route attacker text to any tool-enabled agent.
- Validate every change against its acceptance test on the live box before committing.
- If an acceptance test can't pass, STOP and report — do not force or fake it.
- Keep changes minimal and in-scope; no drive-by refactors.

---

## P0 — Security-critical (do first, review before P1)

### P0-1 — Lock down Elasticsearch (currently no auth, all interfaces)
**Problem**: `docker-compose.yml` runs ES with `xpack.security.enabled=false` and publishes
`9200:9200` (binds 0.0.0.0). Any LAN host can read/write/delete every index unauthenticated
(confirmed: `curl http://192.168.100.51:9200/_cat/indices` → 200).
**Change** (pick the low-friction path — firewall, not full auth, since this is single-node
and every client ships over Tailscale):
1. In `docker-compose.yml`, change the ES port publish from `"9200:9200"` to
   `"127.0.0.1:9200:9200"` AND add a second publish on the Tailscale IP:
   `"100.107.153.112:9200:9200"`. (Docker binds only those two, not the LAN/WiFi iface.)
2. Add host firewall belt-and-suspenders on rosee: allow tcp/9200 from `127.0.0.1` and
   `100.64.0.0/10` (Tailscale CGNAT), drop from everywhere else. Persist with
   `netfilter-persistent save`.
3. `docker compose up -d elasticsearch` to re-publish.
**Acceptance test**:
- `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9200/_cat/indices` → `200`
- from rikdell over Tailscale: `curl ... http://100.107.153.112:9200/_cat/indices` → `200`
- from the LAN IP: `curl --max-time 5 http://192.168.100.51:9200/` → connection refused/timeout (NOT 200)
- Filebeat on rikdell + honeypot still shipping (indices still growing).

### P0-2 — Fix the auto-block decision validation (string-truthiness bug)
**Problem**: `scripts/incident_responder.py:228`:
`should_block = decision.get("block") and decision.get("confidence") in ("medium","high")`.
If the model returns `"block": "false"` (a string), `decision.get("block")` is truthy → it
blocks. Also no guard against malformed/missing fields.
**Change**: replace with a strict parser. Treat `block` as True only if it is a real boolean
`True` (or the exact lowercased string `"true"`/`"yes"`), confidence must be exactly
`"medium"` or `"high"`, and `threat` must be truthy. Add a small helper `def _is_block(d)`
that coerces safely and defaults to False on anything unexpected. Log the raw decision when it
rejects.
**Acceptance test** (unit-style, run on rosee):
```
python3 -c "import sys; sys.path.insert(0,'scripts'); from incident_responder import _is_block as b; \
assert b({'block':'false','confidence':'high','threat':True}) is False; \
assert b({'block':False,'confidence':'high'}) is False; \
assert b({'block':'true','confidence':'low'}) is False; \
assert b({'block':True,'confidence':'high','threat':True}) is True; \
assert b({}) is False; print('OK')"
```

### P0-3 — Stop the phantom "BLOCKED" message
**Problem**: `scripts/soc_dispatch.py:226` hardcodes `action = "BLOCKED"` in the honeypot
Telegram message when an IP is cross-node, but nothing is actually blocked (the honeypot is a
separate VM; no iptables call happens).
**Change**: the message must reflect reality. Change the label to `MONITORING (cross-node)` or
`FLAGGED (cross-node)` — do NOT claim BLOCKED. If real blocking of honeypot-cross-node IPs is
desired later, that's a separate task; for now the message must not lie.
**Acceptance test**: `grep -n '"BLOCKED"' scripts/soc_dispatch.py` returns nothing; a dry-run
dispatch of a cross-node session prints `MONITORING`/`FLAGGED`, not `BLOCKED`.

---

## P1 — Correctness (broken features silently doing nothing)

### P1-1 — Fix the broken cross-node correlation queries (schema drift)
**Problem**: `scripts/honeypot_analyzer.py:255` and `scripts/web_honeypot_analyzer.py:198`
query `{"term": {"fields.log_type": "auth"}}` and aggregate on `field: "host_name"`. The live
data has **`log_type`** (top-level, no `fields.` prefix) and **`host.name`** (nested). These
queries silently match nothing, so honeypot↔cluster correlation never fires.
**Change**: in both files, replace `fields.log_type` → `log_type` and `host_name` → `host.name`.
**Root-cause fix (do this too)**: create `scripts/es_fields.py` exporting the canonical field
names (`LOG_TYPE = "log_type"`, `HOST_NAME = "host.name"`, `SRC_IP = "src_ip"`, …) and import
them in both analyzers + `anomaly_detector.py` so the schema can't drift again.
**Acceptance test**: run each analyzer with `--lookback 24h` on rosee; the cross-reference
query must execute without error AND, when given a known IP that appears in both `cowrie-*` and
`filebeat-*` auth, return that node list non-empty. Add a quick check:
```
curl -s localhost:9200/filebeat-*/_search -H 'Content-Type: application/json' \
 -d '{"size":0,"query":{"term":{"log_type":"auth"}}}' | grep -q '"value":[1-9]' && echo "field OK"
```

### P1-2 — Route outbound-monitor TI hits to a live destination
**Problem**: `scripts/outbound_monitor.py:317` sends threat-intel hits via `dispatch_anomaly()`
→ the retired `:8765` claude-telegram webhook (dead). The direct-Telegram line (`~:295`) is
commented out. Real outbound-to-malware alerts go nowhere.
**Change**: make `soc_dispatch`'s webhook functions **fall back to Telegram** when the webhook
is unreachable (connection refused / non-2xx / timeout) — this fixes P1-2 AND future-proofs
every dispatch path. Implement one helper in `soc_dispatch.py`:
`_post_webhook_or_telegram(payload, telegram_text)` that tries the webhook, and on any failure
sends `telegram_text` via the existing Telegram sender. Wire `dispatch_anomaly` (and the other
dispatchers that target `:8765`) through it. Do NOT re-enable the raw commented `_send_telegram`
in outbound_monitor — let the dispatcher own delivery.
**Acceptance test**: with `:8765` down (current state), trigger a synthetic TI hit (feed
`outbound_monitor` a known-bad IP via its test path or a crafted `ss` fixture) and confirm a
Telegram message actually arrives. `curl -s -o /dev/null -w '%{http_code}' localhost:8765/` is
`000`, yet the alert lands on Telegram.

### P1-3 — Reconstruct `morning_report.py` (missing; cron crashes daily)
**Problem**: crontab runs `morning_report.py` at 06:45 but the file doesn't exist (lost with
the SSD, never rebuilt). Every run errors.
**Change**: write `scripts/morning_report.py` producing a daily Telegram summary from ES over
the last 24h: counts of Suricata alerts by severity (excluding the disabled STUN SIDs
2016149/2016150), top 5 attacker IPs, SSH auth success/fail totals per node, honeypot session
+ login-success counts (`cowrie-*`), web honeypot request count (`webhoneypot-*`), and current
disk % + ES cluster health. Use `es_fields.py` from P1-1. Load `.env` the same way the other
scripts do. Keep it under ~150 lines, single Telegram message.
**Acceptance test**: `python3 scripts/morning_report.py` on rosee sends one well-formed Telegram
message with real non-zero numbers; exit code 0; no traceback in output.

### P1-4 — Actually limit Cowrie downloads
**Problem**: `download_limit_size = 0` means **unlimited** (confirmed against Cowrie docs), so
the honeypot stores attacker-uploaded files of any size — opposite of the documented intent.
**Change**: on the honeypot VM, set `download_limit_size = 1048576` (1 MB cap) in
`~/cowrie/etc/cowrie.cfg`, restart the cowrie container. Update `honeypot/` config copy in the
repo and the vault note in `Cluster/Honeypot.md` (which currently wrongly says 0 = disabled).
**Acceptance test**: `grep download_limit_size ~/cowrie/etc/cowrie.cfg` shows `1048576`; cowrie
container healthy after restart (`docker ps`, logs show "Ready to accept SSH connections").

---

## P2 — Hardening & recovery (lower urgency, real value)

### P2-1 — Fix honeypot config backup (silent failure)
**Problem**: `homelab-configs/backup_configs.sh` SSHes rosee→honeypot, but rosee's
`id_rsa_swarm` key is not authorized on the honeypot (and host key wasn't trusted) → the
honeypot section produces empty files.
**Change**: authorize rosee's `~/.ssh/id_rsa_swarm.pub` in the honeypot's
`~ubuntu/.ssh/authorized_keys`, and pre-seed the host key in rosee's `~/.ssh/known_hosts`
(`ssh-keyscan -p 2222 150.136.222.105`). Confirm `backup_configs.sh` now captures non-empty
honeypot files. (Alternative if key-sharing is undesirable: have the honeypot push its own
configs to the repo via its own cron — but the key approach is simpler.)
**Acceptance test**: run `bash backup_configs.sh`; `configs/honeypot/cowrie.cfg` and
`configs/honeypot/crontab.txt` are non-empty and current; commit shows real content.

### P2-2 — Configure an Elasticsearch snapshot repository + policy
**Problem**: no snapshot repo (`_snapshot/_all` → `{}`); a disk/ES failure loses all history.
**Change**: register a filesystem snapshot repo on a host path (add `path.repo` to the ES
container via compose env/volume, e.g. mount `~/swarm-data/es_snapshots`), then create an SLM
policy taking a daily snapshot, retaining ~14 days. Document the restore command.
**Acceptance test**: `curl localhost:9200/_snapshot/_all` shows the repo; a manual
`_slm/policy/<name>/_execute` produces a `SUCCESS` snapshot; `_snapshot/<repo>/_all` lists it.

### P2-3 — Don't trust `X-Forwarded-For` in the web honeypot
**Problem**: `honeypot/webhoneypot/app.py` reads `X-Forwarded-For` first for `src_ip`, which
an attacker can spoof to poison analytics / frame an innocent IP.
**Change**: use `request.remote_addr` as the authoritative source IP; keep XFF only as a
secondary/informational field clearly labeled untrusted. Rebuild + redeploy the container.
**Acceptance test**: `curl -H 'X-Forwarded-For: 1.2.3.4' http://150.136.222.105/.env` then check
the newest `webhoneypot-*` doc — `src_ip` is the real client IP, not `1.2.3.4`.

### P2-4 — Add container resource limits
**Problem**: ES/Kibana/LiteLLM/cowrie have no memory limits; one can OOM the box.
**Change**: add `deploy.resources.limits.memory` (compose) / `--memory` (docker run) to each
container sized to the host. ES already caps its heap (2g) — set container limit ~3g. Document.
**Acceptance test**: `docker stats --no-stream` shows a MEM LIMIT (not the host total) for each.

### P2-5 — Enable unattended security patching
**Change**: install/enable `unattended-upgrades` on rosee + honeypot for security updates only.
**Acceptance test**: `systemctl is-active unattended-upgrades` → active; dry-run shows it would
apply security updates.

### P2-6 — Add a pipeline self-test script
**Problem**: broken analyzers (P1-1) and the missing report (P1-3) went unnoticed because
nothing validates the pipeline end to end.
**Change**: write `scripts/selftest.py` that asserts: each expected index exists and grew in the
last hour; each analyzer runs without exception and its ES queries return the expected shape;
the block-decision parser rejects the P0-2 bad inputs; `:4000` LiteLLM answers a trivial prompt;
`:8766` incident-responder is listening. Wire it into `watchdog.py` or its own daily cron; alert
to Telegram on any failure.
**Acceptance test**: `python3 scripts/selftest.py` exits 0 now and prints a per-check PASS list;
temporarily breaking one thing makes it exit non-zero and send a Telegram alert.

---

## Known limitations to DOCUMENT (not fix now)

- **Suricata sees only WiFi-interface traffic** (`wlx…`); wired LAN traffic not traversing the
  AP is invisible. True whole-LAN IDS needs a mirror port/tap — out of scope. Note it in `SIEM.md`.
- **LAN-source Suricata alerts are suppressed** for Telegram/IR by design (avoids self-noise).
  Keep the suppression, but ensure P1-1 cross-node correlation covers LAN-pivot detection, and
  document the tradeoff in `SIEM.md`.

## Reviewer checklist (for the review pass after each tier)
- Every task's acceptance test actually run on the live box, output shown.
- No secrets printed/committed; `git log -p` clean of tokens/keys.
- Changes committed atomically with `P#-#:` prefixes and pushed.
- Vault (`Cluster/SIEM.md`, `Cluster/Honeypot.md`, `Cluster/Network.md`) updated where a task
  changes documented behavior (esp. P1-4 cowrie note, the ES lockdown, the LAN limitations).
- `homelab-configs` nightly backup now captures the honeypot (P2-1).
