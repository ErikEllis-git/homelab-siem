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
all primaries started. Filebeat/Cowrie/web-honeypot resumed shipping; shippers appear to have
backfilled from their saved offsets, but Suricata/auth gaps during the outage were not verified.

### Fixes

1. **Boot ordering:** `systemd/docker.service.d/10-after-tailscale.conf` makes `docker.service`
   start after `tailscaled.service` and wait (max 60s) for the `tailscale0` address.
2. **Detection:** `scripts/watchdog.py` now checks Elasticsearch (HTTP 200, cluster not red)
   every 10 minutes and alerts on Telegram (DOWN / RECOVERED).
3. **Docs:** failure mode recorded in REMEDIATION.md (P0-1 side effect) and the README.

### Lessons

- A security change that adds a startup dependency (binding to a specific interface IP) needs a
  boot-order check, not just a live acceptance test. The P0-1 acceptance tests all passed while
  the system was running; none exercised a cold boot.
- A monitor that doesn't watch its own datastore isn't monitoring. The pipeline's single point of
  failure (ES) was the one thing the watchdog skipped.
- Still open: a UPS, and finding out why the box lost power.

---

*More incidents will be added as the SIEM catches them.*
