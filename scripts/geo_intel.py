#!/usr/bin/env python3
"""
geo_intel.py — GeoIP enrichment via ip-api.com batch endpoint.

No API key required. Results are cached per-IP for 24 hours.
Private/Tailscale ranges are skipped automatically.

Usage:
    from geo_intel import geolocate, format_geo
    geo = geolocate(["1.2.3.4", "5.6.7.8"])
    print(format_geo(geo["1.2.3.4"]))  # -> "CN · Beijing · ChinaNet"
"""

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests

CACHE_FILE = Path(__file__).parent / "geo_cache.json"
CACHE_TTL  = timedelta(hours=24)
API_URL    = "http://ip-api.com/batch"
FIELDS     = "status,country,countryCode,city,org,isp,query"

_PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "::1", "100.64.", "100.8")


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _load_cache() -> dict:
    if not CACHE_FILE.exists():
        return {}
    try:
        return json.loads(CACHE_FILE.read_text()).get("ips", {})
    except Exception:
        return {}


def _save_cache(ips: dict) -> None:
    CACHE_FILE.write_text(json.dumps({"ips": ips}, indent=2))


def _is_fresh(entry: dict) -> bool:
    try:
        ts = datetime.fromisoformat(entry["cached_at"])
        return datetime.now(timezone.utc) - ts < CACHE_TTL
    except Exception:
        return False


def geolocate(ip_list: list[str]) -> dict[str, dict]:
    """Return geo data for external IPs. Stale/missing entries fetched in one batch."""
    external = [ip for ip in ip_list if not _is_private(ip)]
    if not external:
        return {}

    cache    = _load_cache()
    to_fetch = [ip for ip in external if ip not in cache or not _is_fresh(cache[ip])]

    if to_fetch:
        try:
            resp = requests.post(
                API_URL,
                json=[{"query": ip, "fields": FIELDS} for ip in to_fetch],
                timeout=10,
            )
            resp.raise_for_status()
            now = datetime.now(timezone.utc).isoformat()
            for entry in resp.json():
                ip = entry.get("query")
                if ip and entry.get("status") == "success":
                    org = entry.get("org") or entry.get("isp", "")
                    if org and org.startswith("AS") and " " in org:
                        org = org.split(" ", 1)[1]
                    cache[ip] = {
                        "country":      entry.get("country", ""),
                        "country_code": entry.get("countryCode", ""),
                        "city":         entry.get("city", ""),
                        "org":          org,
                        "cached_at":    now,
                    }
            _save_cache(cache)
            print(f"[geo] fetched {len(to_fetch)} IP(s) from ip-api.com")
        except Exception as e:
            print(f"[geo] lookup failed: {e}")

    return {ip: cache[ip] for ip in external if ip in cache}


def format_geo(entry: dict) -> str:
    """Return a compact inline string: 'DE · Frankfurt · Hetzner'"""
    parts = []
    if entry.get("country_code"):
        parts.append(entry["country_code"])
    if entry.get("city"):
        parts.append(entry["city"])
    if entry.get("org"):
        parts.append(entry["org"])
    return " · ".join(parts)
