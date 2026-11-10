#!/usr/bin/env python3
"""
Builds the "Homelab Operations" Kibana dashboard via the API.

Companion to build_kibana_dashboard.py (the security overview). This one answers
"is the lab itself healthy?": are all nodes shipping logs, how hot is the laptop
worker, what does the LAN scan see, is the honeypot still producing data.

Safe to re-run:
  - data views are looked up by title and only created when missing
  - visualizations and the dashboard use fixed "ops-" ids and overwrite only those
  - nothing belonging to the security overview is modified (two of its
    visualizations are shown here by reference, not copied)
"""
import json

import requests

KIBANA = "http://localhost:5601"
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}
DASHBOARD_ID = "homelab-operations"


def get_or_create_data_view(title, time_field="@timestamp"):
    resp = requests.get(f"{KIBANA}/api/data_views", headers=HEADERS, timeout=30)
    resp.raise_for_status()
    for dv in resp.json().get("data_view", []):
        if dv.get("title") == title:
            return dv["id"]
    resp = requests.post(
        f"{KIBANA}/api/data_views/data_view",
        headers=HEADERS,
        json={"data_view": {"title": title, "name": title, "timeFieldName": time_field}},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["data_view"]["id"]


def create_visualization(vis_id, title, vis_state, data_view_id, filters=None):
    search_source = {"query": {"query": "", "language": "kuery"}, "filter": filters or []}
    body = {
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(search_source)},
        },
        "references": [
            {"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": data_view_id}
        ],
    }
    assert vis_id.startswith("ops-"), "this script only writes its own ops- objects"
    resp = requests.post(
        f"{KIBANA}/api/saved_objects/visualization/{vis_id}",
        headers=HEADERS, json=body, params={"overwrite": "true"}, timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["id"]


def xy(title, kind, metrics, y_label, split_field=None, time_field="@timestamp"):
    """A time chart. kind: 'histogram' or 'line'. metrics: [(agg, field, label)]."""
    aggs, series = [], []
    for i, (agg, field, label) in enumerate(metrics, start=1):
        params = {"customLabel": label}
        if field:
            params["field"] = field
        aggs.append({"id": str(i), "enabled": True, "type": agg, "schema": "metric", "params": params})
        s = {"show": True, "type": kind, "mode": "stacked" if kind == "histogram" else "normal",
             "data": {"label": label, "id": str(i)}, "valueAxis": "ValueAxis-1"}
        if kind == "line":
            s.update({"drawLinesBetweenPoints": True, "showCircles": False, "lineWidth": 2,
                      "interpolate": "linear"})
        series.append(s)
    n = len(metrics)
    aggs.append({"id": str(n + 1), "enabled": True, "type": "date_histogram", "schema": "segment",
                 "params": {"field": time_field, "interval": "auto", "min_doc_count": 1}})
    if split_field:
        aggs.append({"id": str(n + 2), "enabled": True, "type": "terms", "schema": "group",
                     "params": {"field": split_field, "orderBy": "1", "order": "desc", "size": 6}})
    return {
        "title": title, "type": kind,
        "params": {
            "grid": {},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                              "show": True, "labels": {"show": True}, "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left",
                           "show": True, "labels": {"show": True}, "title": {"text": y_label}}],
            "seriesParams": series,
            "addTooltip": True, "addLegend": True, "legendPosition": "right",
        },
        "aggs": aggs,
    }


def table(title, field, label, size=10):
    return {
        "title": title, "type": "table",
        "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": False},
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
             "params": {"field": field, "orderBy": "1", "order": "desc", "size": size, "customLabel": label}},
        ],
    }


def pie(title, field):
    return {
        "title": title, "type": "pie",
        "params": {"addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True},
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": field, "orderBy": "1", "order": "desc", "size": 8}},
        ],
    }


def main():
    # "filebeat-8.15.0*" is the data stream only. The broader "filebeat-*" also matches the
    # filebeat-purple-* test indices, which map host.name / log_type differently; keeping
    # them out means purple-team test data can never show up in or skew these panels.
    logs = get_or_create_data_view("filebeat-8.15.0*")
    thermal = get_or_create_data_view("thermal-*")
    nmap = get_or_create_data_view("nmap-scans*")
    print(f"Data views: logs={logs} thermal={thermal} nmap={nmap}")

    v = create_visualization
    v("ops-log-volume-by-host", "Log volume by node",
      xy("Log volume by node", "histogram", [("count", None, "Log events")], "Events",
         split_field="host.name"), logs)
    v("ops-log-types", "Log events by type", pie("Log events by type", "log_type"), logs)

    # node is mapped text; node.keyword is the aggregatable sub-field (see thermal_check.py)
    v("ops-thermal-cpu", "Worker CPU temperature (max per interval)",
      xy("Worker CPU temperature", "line", [("max", "cpu_pkg_c", "CPU package max (C)")], "deg C",
         split_field="node.keyword"), thermal)
    v("ops-thermal-hdd", "Worker HDD temperature (max per interval)",
      xy("Worker HDD temperature", "line", [("max", "hdd_c", "HDD max (C)")], "deg C",
         split_field="node.keyword"), thermal)
    v("ops-thermal-load", "Worker load average",
      xy("Worker load average", "line", [("avg", "load1", "load1 avg")], "load",
         split_field="node.keyword"), thermal)
    v("ops-thermal-throttle", "Worker thermal-throttle counter (cumulative, resets at boot)",
      xy("Worker thermal-throttle counter", "line", [("max", "throttle_pkg_count", "throttle events (cumulative)")],
         "count", split_field="node.keyword"), thermal)

    v("ops-lan-hosts-up", "LAN hosts up (network_scan)",
      xy("LAN hosts up", "line", [("max", "hosts_up", "hosts up (max)")], "hosts"), nmap)
    v("ops-new-port-alerts", "New open port alerts (network_scan)",
      table("New open port alerts", "new_port_alerts.keyword", "Alert"), nmap)

    # (x, y, w, h, visualization id) on Kibana's 48-column grid.
    # The two vis-* panels belong to the security overview and are only referenced here.
    layout = [
        (0, 0, 32, 12, "ops-log-volume-by-host"),
        (32, 0, 16, 12, "ops-log-types"),
        (0, 12, 24, 12, "ops-thermal-cpu"),
        (24, 12, 24, 12, "ops-thermal-hdd"),
        (0, 24, 24, 12, "ops-thermal-load"),
        (24, 24, 24, 12, "ops-thermal-throttle"),
        (0, 36, 24, 12, "ops-lan-hosts-up"),
        (24, 36, 24, 12, "ops-new-port-alerts"),
        (0, 48, 24, 12, "vis-cowrie-timeline"),
        (24, 48, 24, 12, "vis-suricata-timeline"),
    ]
    panels, references = [], []
    for i, (x, y, w, h, vis_id) in enumerate(layout, start=1):
        idx = str(i)
        panels.append({"version": "8.15.0", "type": "visualization",
                       "gridData": {"x": x, "y": y, "w": w, "h": h, "i": idx},
                       "panelIndex": idx, "embeddableConfig": {}, "panelRefName": f"panel_{idx}"})
        references.append({"name": f"panel_{idx}", "type": "visualization", "id": vis_id})

    body = {
        "attributes": {
            "title": "Homelab Operations",
            "description": "Node log shipping, worker temperature and load, LAN scan results, "
                           "honeypot and IDS activity. Built by scripts/build_ops_dashboard.py.",
            "panelsJSON": json.dumps(panels),
            "timeRestore": True, "timeTo": "now", "timeFrom": "now-7d",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                {"query": {"query": "", "language": "kuery"}, "filter": []})},
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        },
        "references": references,
    }
    resp = requests.post(f"{KIBANA}/api/saved_objects/dashboard/{DASHBOARD_ID}",
                         headers=HEADERS, json=body, params={"overwrite": "true"}, timeout=30)
    resp.raise_for_status()
    print(f"Dashboard: {KIBANA}/app/dashboards#/view/{resp.json()['id']}")


if __name__ == "__main__":
    main()
