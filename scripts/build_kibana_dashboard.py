#!/usr/bin/env python3
"""
Builds a "Homelab Security Overview" Kibana dashboard entirely via API —
data views + visualizations + dashboard — so Erik never has to click
through the Kibana UI himself.
"""
import json
import requests

KIBANA = "http://localhost:5601"
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}


def create_data_view(title, name):
    resp = requests.post(
        f"{KIBANA}/api/data_views/data_view",
        headers=HEADERS,
        json={"data_view": {"title": title, "name": name, "timeFieldName": "@timestamp"}},
    )
    resp.raise_for_status()
    return resp.json()["data_view"]["id"]


def create_visualization(vis_id, title, vis_state, index_pattern_id, extra_filters=None):
    search_source = {
        "query": {"query": "", "language": "kuery"},
        "filter": extra_filters or [],
    }
    body = {
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(search_source)},
        },
        "references": [
            {"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": index_pattern_id}
        ],
    }
    resp = requests.post(
        f"{KIBANA}/api/saved_objects/visualization/{vis_id}",
        headers=HEADERS,
        json=body,
        params={"overwrite": "true"},
    )
    resp.raise_for_status()
    return resp.json()["id"]


def main():
    fb_id = create_data_view("filebeat-*", "filebeat-*")
    cowrie_id = create_data_view("cowrie-*", "cowrie-*")
    web_id = create_data_view("webhoneypot-*", "webhoneypot-*")
    print(f"Data views: filebeat={fb_id} cowrie={cowrie_id} webhoneypot={web_id}")

    # Exclude the two disabled STUN noise signatures from historical view
    noise_filter = {
        "meta": {"negate": True, "type": "phrases", "key": "alert.signature_id",
                  "params": [2016149, 2016150], "index": fb_id},
        "query": {"bool": {"should": [
            {"match_phrase": {"alert.signature_id": 2016149}},
            {"match_phrase": {"alert.signature_id": 2016150}},
        ]}},
    }
    suricata_filter = {
        "meta": {"type": "phrase", "key": "log_type", "params": {"query": "suricata"}, "index": fb_id},
        "query": {"match_phrase": {"log_type": "suricata"}},
    }
    alert_filter = {
        "meta": {"type": "phrase", "key": "event_type", "params": {"query": "alert"}, "index": fb_id},
        "query": {"match_phrase": {"event_type": "alert"}},
    }
    auth_filter = {
        "meta": {"type": "phrase", "key": "log_type", "params": {"query": "auth"}, "index": fb_id},
        "query": {"match_phrase": {"log_type": "auth"}},
    }

    visualizations = []

    # 1. Suricata alerts over time
    visualizations.append(create_visualization(
        "vis-suricata-timeline", "Suricata alerts over time",
        {"title": "Suricata alerts over time", "type": "histogram",
         "params": {"grid": {}, "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True, "labels": {"show": True}, "title": {}}],
                    "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True, "labels": {"show": True}, "title": {"text": "Count"}}],
                    "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked", "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1"}],
                    "addTooltip": True, "addLegend": True, "legendPosition": "right"},
         "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
             "params": {"field": "@timestamp", "interval": "auto"}},
         ]},
        fb_id, [suricata_filter, alert_filter, noise_filter],
    ))

    # 2. Top suricata signatures
    visualizations.append(create_visualization(
        "vis-suricata-signatures", "Top Suricata signatures",
        {"title": "Top Suricata signatures", "type": "table",
         "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": False},
         "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
             "params": {"field": "alert.signature", "orderBy": "1", "order": "desc", "size": 10}},
         ]},
        fb_id, [suricata_filter, alert_filter, noise_filter],
    ))

    # 3. Suricata alerts by severity
    visualizations.append(create_visualization(
        "vis-suricata-severity", "Suricata alerts by severity",
        {"title": "Suricata alerts by severity", "type": "pie",
         "params": {"addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True},
         "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": "alert.severity", "orderBy": "1", "order": "desc", "size": 5}},
         ]},
        fb_id, [suricata_filter, alert_filter, noise_filter],
    ))

    # 4. Top external IPs generating suricata alerts
    visualizations.append(create_visualization(
        "vis-suricata-top-ips", "Top source IPs (Suricata alerts)",
        {"title": "Top source IPs (Suricata alerts)", "type": "table",
         "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": False},
         "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
             "params": {"field": "src_ip", "orderBy": "1", "order": "desc", "size": 10}},
         ]},
        fb_id, [suricata_filter, alert_filter, noise_filter],
    ))

    # 5. SSH auth events over time by node
    visualizations.append(create_visualization(
        "vis-auth-timeline", "SSH auth events over time by node",
        {"title": "SSH auth events over time by node", "type": "histogram",
         "params": {"grid": {}, "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True, "labels": {"show": True}, "title": {}}],
                    "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True, "labels": {"show": True}, "title": {"text": "Count"}}],
                    "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked", "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1"}],
                    "addTooltip": True, "addLegend": True, "legendPosition": "right"},
         "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
             "params": {"field": "@timestamp", "interval": "auto"}},
            {"id": "3", "enabled": True, "type": "terms", "schema": "group",
             "params": {"field": "host.name", "orderBy": "1", "order": "desc", "size": 5}},
         ]},
        fb_id, [auth_filter],
    ))

    # 6. Cowrie sessions over time
    visualizations.append(create_visualization(
        "vis-cowrie-timeline", "Cowrie sessions over time",
        {"title": "Cowrie sessions over time", "type": "histogram",
         "params": {"grid": {}, "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True, "labels": {"show": True}, "title": {}}],
                    "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True, "labels": {"show": True}, "title": {"text": "Sessions"}}],
                    "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked", "data": {"label": "Sessions", "id": "1"}, "valueAxis": "ValueAxis-1"}],
                    "addTooltip": True, "addLegend": False},
         "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
             "params": {"field": "timestamp", "interval": "auto"}},
         ]},
        cowrie_id,
        [{"meta": {"type": "phrase", "key": "eventid", "params": {"query": "cowrie.session.connect"}, "index": cowrie_id},
          "query": {"match_phrase": {"eventid": "cowrie.session.connect"}}}],
    ))

    # 7. Cowrie login success vs failed
    visualizations.append(create_visualization(
        "vis-cowrie-logins", "Cowrie login attempts (success vs failed)",
        {"title": "Cowrie login attempts (success vs failed)", "type": "pie",
         "params": {"addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True},
         "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": "eventid", "orderBy": "1", "order": "desc", "size": 5,
                        "include": {"pattern": "cowrie.login.*"}}},
         ]},
        cowrie_id, [],
    ))

    # 8. Top Cowrie attacker IPs
    visualizations.append(create_visualization(
        "vis-cowrie-top-ips", "Top Cowrie attacker IPs",
        {"title": "Top Cowrie attacker IPs", "type": "table",
         "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": False},
         "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
             "params": {"field": "src_ip", "orderBy": "1", "order": "desc", "size": 10}},
         ]},
        cowrie_id, [],
    ))

    # 9. Web honeypot requests by rule
    visualizations.append(create_visualization(
        "vis-webhoneypot-rules", "Web honeypot requests by rule",
        {"title": "Web honeypot requests by rule", "type": "pie",
         "params": {"addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True},
         "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": "matched_rule", "orderBy": "1", "order": "desc", "size": 10}},
         ]},
        web_id, [],
    ))

    # 10. Top web honeypot attacker IPs
    visualizations.append(create_visualization(
        "vis-webhoneypot-top-ips", "Top web honeypot attacker IPs",
        {"title": "Top web honeypot attacker IPs", "type": "table",
         "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": False},
         "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
             "params": {"field": "src_ip", "orderBy": "1", "order": "desc", "size": 10}},
         ]},
        web_id, [],
    ))

    print(f"Created {len(visualizations)} visualizations")

    # --- Dashboard, laid out in a 3-column-ish grid ---
    layout = [
        (0, 0, 24, 12, "vis-suricata-timeline"),
        (24, 0, 24, 12, "vis-auth-timeline"),
        (0, 12, 16, 12, "vis-suricata-signatures"),
        (16, 12, 16, 12, "vis-suricata-severity"),
        (32, 12, 16, 12, "vis-suricata-top-ips"),
        (0, 24, 24, 12, "vis-cowrie-timeline"),
        (24, 24, 24, 12, "vis-cowrie-logins"),
        (0, 36, 24, 12, "vis-cowrie-top-ips"),
        (24, 36, 24, 12, "vis-webhoneypot-rules"),
        (0, 48, 48, 12, "vis-webhoneypot-top-ips"),
    ]

    panels = []
    references = []
    for i, (x, y, w, h, panel_ref) in enumerate(layout):
        panel_index = str(i + 1)
        panels.append({
            "version": "8.15.0",
            "type": "visualization",
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": panel_index},
            "panelIndex": panel_index,
            "embeddableConfig": {},
            "panelRefName": f"panel_{panel_index}",
        })
        references.append({"name": f"panel_{panel_index}", "type": "visualization", "id": panel_ref})

    dashboard_body = {
        "attributes": {
            "title": "Homelab Security Overview",
            "description": "Suricata alerts, SSH auth, Cowrie + web honeypot activity. Built 2026-09-14.",
            "panelsJSON": json.dumps(panels),
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-7d",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        },
        "references": references,
    }

    resp = requests.post(
        f"{KIBANA}/api/saved_objects/dashboard/homelab-security-overview",
        headers=HEADERS, json=dashboard_body, params={"overwrite": "true"},
    )
    resp.raise_for_status()
    dash_id = resp.json()["id"]
    print(f"Dashboard created: {dash_id}")
    print(f"URL: {KIBANA}/app/dashboards#/view/{dash_id}")


if __name__ == "__main__":
    main()
