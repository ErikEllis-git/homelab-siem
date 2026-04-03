#!/usr/bin/env python3
"""
threat_intel.py — abuse.ch threat intelligence cache.

Downloads Feodo Tracker and ThreatFox IP feeds, caches to disk for 1 hour.
Import and call lookup_ips() to enrich a list of IPs before AI analysis.
"""

import csv
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import requests

CACHE_FILE = Path("/home/rosse/siem/scripts/threat_intel_cache.json")
CACHE_TTL  = timedelta(hours=1)

FEODO_URL     = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
THREATFOX_URL = "https://threatfox.abuse.ch/export/csv/ip-port/recent/"


def _fetch_feodo() -> dict[str, dict]:
    resp = requests.get(FEODO_URL, timeout=15)
    resp.raise_for_status()
    ips = {}
    for line in resp.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ips[line] = {"source": "Feodo Tracker", "malware": "Botnet C2", "confidence": 100}
    return ips


def _fetch_threatfox() -> dict[str, dict]:
    resp = requests.get(THREATFOX_URL, timeout=30)
    resp.raise_for_status()
    ips = {}
    header = None

    for line in resp.text.splitlines():
        # The header line looks like: # "first_seen_utc","ioc_id",...
        if line.startswith('# "first_seen_utc"'):
            header_line = line[2:]  # strip "# "
            reader = csv.reader([header_line], skipinitialspace=True)
            header = [c.strip() for c in next(reader)]
            continue
        if line.startswith("#") or not line.strip():
            continue
        if header is None:
            continue
        try:
            row     = next(csv.reader([line], skipinitialspace=True))
            cleaned = [c.strip() for c in row]
            d       = dict(zip(header, cleaned))
            ioc     = d.get("ioc_value", "")
            ip      = ioc.split(":")[0] if ":" in ioc else ioc
            if not ip:
                continue
            malware     = d.get("malware_printable", "Unknown malware")
            confidence  = int(d.get("confidence_level", 0))
            threat_type = d.get("threat_type", "")
            ips[ip] = {
                "source": "ThreatFox",
                "malware": malware,
                "threat_type": threat_type,
                "confidence": confidence,
            }
        except Exception:
            continue
    return ips


def _load_cache() -> Optional[dict]:
    if not CACHE_FILE.exists():
        return None
    try:
        data    = json.loads(CACHE_FILE.read_text())
        updated = datetime.fromisoformat(data["updated"])
        if datetime.now(timezone.utc) - updated < CACHE_TTL:
            return data["ips"]
    except Exception:
        pass
    return None


def _save_cache(ips: dict) -> None:
    CACHE_FILE.write_text(json.dumps({
        "updated": datetime.now(timezone.utc).isoformat(),
        "ips": ips,
    }))


def get_intel() -> dict[str, dict]:
    """Return full threat intel dict, refreshing from abuse.ch if cache is stale."""
    cached = _load_cache()
    if cached is not None:
        return cached

    print("[ti] cache stale — refreshing from abuse.ch...")
    ips = {}
    try:
        feodo = _fetch_feodo()
        ips.update(feodo)
        print(f"[ti] Feodo: {len(feodo)} IPs")
    except Exception as e:
        print(f"[ti] Feodo fetch failed: {e}")
    try:
        tf = _fetch_threatfox()
        ips.update(tf)
        print(f"[ti] ThreatFox: {len(tf)} IPs  (total: {len(ips)})")
    except Exception as e:
        print(f"[ti] ThreatFox fetch failed: {e}")

    if ips:
        _save_cache(ips)
    return ips


def lookup_ips(ip_list: list[str]) -> dict[str, dict]:
    """Return enrichment data for any IPs that appear in the threat intel db."""
    intel = get_intel()
    return {ip: intel[ip] for ip in ip_list if ip in intel}


def format_enrichment_block(hits: dict[str, dict]) -> str:
    """Format a threat intel hit dict into a human-readable block for AI prompts."""
    if not hits:
        return ""
    lines = ["=== THREAT INTEL MATCHES (abuse.ch) ==="]
    for ip, data in hits.items():
        lines.append(
            f"  {ip} — {data['malware']} "
            f"[{data['source']}, confidence: {data['confidence']}%"
            + (f", type: {data['threat_type']}" if data.get('threat_type') else "")
            + "]"
        )
    return "\n".join(lines)
