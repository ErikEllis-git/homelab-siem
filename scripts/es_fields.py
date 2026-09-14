#!/usr/bin/env python3
"""
es_fields.py — canonical Elasticsearch field-name constants.

Live index schema (filebeat-*, cowrie-*, webhoneypot-*) uses these exact
field names. Import from here instead of hardcoding strings so a schema
change only needs to be fixed in one place.

History: honeypot_analyzer.py and web_honeypot_analyzer.py used to query
"fields.log_type" / aggregate on "host_name" — stale names from an old
Filebeat config. Live data has top-level "log_type" and nested "host.name".
That drift silently broke cross-node correlation (P1-1). Use these
constants everywhere a query touches these fields.
"""

LOG_TYPE  = "log_type"
HOST_NAME = "host.name"
SRC_IP    = "src_ip"
DEST_IP   = "dest_ip"
EVENT_TYPE = "event_type"
CONTAINER_NAME = "container.name"
ALERT_SEVERITY = "alert.severity"
ALERT_SIGNATURE = "alert.signature"
ALERT_CATEGORY = "alert.category"
