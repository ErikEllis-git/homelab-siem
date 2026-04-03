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

*More incidents will be added as the SIEM catches them.*
