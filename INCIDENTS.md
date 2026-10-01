# Real Incidents Caught by This SIEM

These are actual events captured by the honeypot and SIEM stack — not demos, not simulations.

---

## Incident 001 — Coordinated SSH Backdoor Campaign ("mdrfckr")

**Date:** 2026-03-17 through 2026-04-01 (ongoing)
**Source:** Cowrie SSH honeypot (VPS, port 22)
**Severity:** HIGH

### What Happened

Within hours of the honeypot going live, it began catching a large-scale coordinated campaign
targeting Linux servers with default or weak SSH credentials.

Once attackers got a shell (via password spray), every single one ran the same three commands:

```bash
# Step 1 — clear any existing SSH keys, disable immutable flags
cd ~; chattr -ia .ssh; lockr -ia .ssh

# Step 2 — implant a backdoor SSH public key
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAAB...mdrfckr" >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
```

The RSA key is labeled `mdrfckr` in the comment field. The same SHA-256 hash appeared in every
session's file download:

```
a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2
```

### Scale

| Metric | Value |
|--------|-------|
| Unique attacker IPs | 786 |
| Total honeypot sessions | 1,286 |
| Campaign duration | 15 days (still active) |
| Nodes targeted | Honeypot only — cluster nodes blocked all attempts |

### Sample Telegram Alert (real output)

```
🍯 102.208.34.7 [Nigeria]
Did: got shell (root/[REDACTED]), ran: chattr -ia .ssh → implanted mdrfckr SSH backdoor key
Action: BLOCKED
```

### What This Is

This is a botnet-driven SSH backdoor implant campaign. The goal is persistence: once the key
is in `authorized_keys`, the operator can SSH back in at any time without a password, even if
the victim changes their password. The consistent SHA-256 hash across all sessions confirms a
single coordinated actor (or toolkit) behind all 786 IPs.

The `chattr -ia` command is a defensive evasion technique — it removes the immutable and
append-only file attributes from `.ssh/` before overwriting it, preventing defenders from
using filesystem locks to protect authorized_keys.

### How the SIEM Caught It

1. **Cowrie** (honeypot) accepted the SSH connections and logged all commands
2. **Filebeat** shipped the logs to Elasticsearch (`cowrie-*` index) in real time
3. **cowrie_alerter.py** detected `cowrie.command.input` events and fired a webhook
4. **incident-responder** dispatched the alert to Telegram via the claude-telegram bot
5. **Claude AI SOC analyst** classified the session, identified the TTP, and confirmed block

Cluster nodes were never at risk — they require key-based auth only (no passwords) and are
behind Tailscale. The honeypot exists specifically to observe attacks like this.

---

## Incident 002 — SIEM blind for 5 days: Elasticsearch down after a hard reboot

**Date:** 2026-09-26 07:17 EDT (detected 2026-10-01)
**Source:** Operational failure, not an attack
**Severity:** HIGH (silent loss of the entire detection pipeline)

### What Happened

The rosee host (Optiplex 7010) lost power or hard-reset at 07:15:31 EDT on Sep 26. The journal
for the previous boot simply stops: no shutdown sequence, no kernel panic trace, no OOM. It was
off for ~2 minutes and came back on a newer kernel (6.14.0-27 → 7.0.0-34). The root cause of the
power loss was **not determined** (`/var/crash` empty; pstore not readable without root). The
box has a known history of a corroded/sticky power button and no UPS.

On the way back up, Elasticsearch died ~18 seconds after boot and **stayed dead for ~5 days**.
Every ES-dependent script (correlator, brute_watch, anomaly/ML detectors, honeypot analyzers,
morning report) ran from cron against a dead ES. Nothing alerted, because the watchdog did not
cover ES.

### Root Cause

A side effect of **P0-1** (REMEDIATION.md), which bound ES port 9200 to the Tailscale IP
`100.107.153.112`. At boot, `dockerd` started before `tailscaled` had brought `tailscale0` up, so
the publish failed:

```
failed to bind host port 100.107.153.112:9200/tcp: cannot assign requested address
```

Docker's `restart: unless-stopped` policy did **not** retry a container whose network setup
failed. A plain `docker start elasticsearch` then crash-looped: the half-created container's
hostname could not be resolved (`UnknownHostException`), so it had to be recreated.

### Recovery

```bash
cd ~/repos/homelab-siem
docker compose up -d --force-recreate elasticsearch   # data is on bind mounts, nothing lost
```

Cluster returned to yellow (single node; only replica shards unassigned, which is normal) with
all primaries started. Shippers resumed, but **the backfill was imperfect** (checked 2026-10-01):

- **Docker container logs** were backfilled with correct timestamps (~17.5k/day for 09-27..09-30).
- **Suricata (`eve.json`) and auth logs were re-ingested stamped with the ingest time**
  (`@timestamp` = 2026-10-01 18:10-18:15Z, ~311k docs in one 10-minute bucket). The real event
  time is only in the `timestamp` field (Suricata) or inside `message` (auth). Time-windowed
  queries over 09-27..10-01 will not see these events at their real times, and any "last 24h"
  view (e.g. tomorrow's morning report) is inflated by the backlog.
- **Gap: Suricata events from 2026-09-26 07:17 EDT to 2026-09-27 00:00 EDT never reached ES.** The
  log rotated at midnight into `/var/log/suricata/eve.json.1.gz`, and Filebeat only reads the live
  `eve.json`. The data still exists on rosee (34 MB) and can be re-ingested if wanted.
- **Auth log was re-read from 2026-09-20**, so ~6 days of auth events (09-20..09-26) that were
  already indexed now exist twice (the second copy stamped 10-01). Harmless for the 5-minute
  brute-force window, but it inflates counts that span the backlog.
- **No false alerts or blocks resulted:** the correlator ran twice after the flood and found no
  signals, nothing was dispatched, and there are no iptables DROP rules.

The last ES snapshot before the outage was 2026-09-26 02:30Z; the daily SLM policy resumes on
its own schedule.

**Remediation of the data impact (2026-10-01, later the same day):**

- The missing Suricata window was **re-ingested**: 37,550 events from `eve.json.1.gz` (diffed
  against ES first, 59 already-present events skipped) with `@timestamp` set from the event's own
  time. Each is tagged `reingested: true`, so they can be found or removed:
  `POST filebeat-*/_delete_by_query {"query":{"term":{"reingested":true}}}`.
- **Not rewritten in place:** the ~311k Suricata/auth docs stamped 2026-10-01 18:10Z, and the
  duplicated 09-20..09-26 auth events, are still as ingested. Rewriting them is possible but was
  left alone (it modifies production data).

### Fixes

1. **Boot ordering:** `systemd/docker.service.d/10-after-tailscale.conf` makes `docker.service`
   start after `tailscaled.service` and wait (max 60s) for the `tailscale0` address.
2. **Detection:** `scripts/watchdog.py` now checks Elasticsearch (HTTP 200, cluster not red)
   every 10 minutes and alerts on Telegram (DOWN / RECOVERED).
3. **Docs:** failure mode recorded in REMEDIATION.md (P0-1 side effect) and the README.
4. **Filebeat (`filebeat/filebeat.yml`, `docker-compose-filebeat.yml`):** `timestamp` processors
   so Suricata and auth events keep their real time (ISO rsyslog lines only; other formats fall
   back to read time), and a **persistent registry volume** (`filebeat_data`, one per node) so
   recreating the container no longer re-reads every log. Rolled out as Swarm config `v3`
   (configs are immutable: bump the version to change it); the live registry was copied into the
   volume first and a post-deploy check showed no re-read.
5. **Side fixes found while verifying:** `geo_intel.py` now sends ip-api.com lookups in chunks of
   100 (the batch endpoint rejects more, so runs with >100 new IPs lost all geo data); `selftest.py`
   (P2-6) committed and scheduled daily.

### Lessons

- A security change that adds a startup dependency (binding to a specific interface IP) needs a
  boot-order check, not just a live acceptance test. The P0-1 acceptance tests all passed while
  the system was running; none exercised a cold boot.
- A monitor that doesn't watch its own datastore isn't monitoring. The pipeline's single point of
  failure (ES) was the one thing the watchdog skipped.
- Filebeat only reads the live log file, so a long outage across a log rotation still loses the
  rotated (gzipped) data (recoverable by hand as above). The read-time stamping and the
  non-persistent registry were fixed afterwards (Fixes, item 4).
- Still open: a UPS, and finding out why the box lost power.

---

*More incidents will be added as the SIEM catches them.*
