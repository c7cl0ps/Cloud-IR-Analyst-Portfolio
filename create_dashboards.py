#!/usr/bin/env python3
"""
create_dashboards.py — Cloud SOC Lab :: Kibana dashboard provisioning

Creates saved-object visualizations and a dashboard over the
cloudtrail-logs-* data view via the Kibana Saved Objects REST API.
Idempotent (overwrite=true). Kibana only (http://localhost:5601).
"""
import json
import sys
import urllib.error
import urllib.request

KB = "http://localhost:5601"
ES = "http://localhost:9200"
DATA_VIEW_TITLE = "cloudtrail-logs-*"
DASHBOARD_ID = "soc-cloudtrail-dashboard"


def _req(method, path, body=None, ndjson=False):
    headers = {"kbn-xsrf": "true"}
    if body is not None and not ndjson:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    else:
        data = body
    req = urllib.request.Request(f"{KB}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw}


def find_data_view_id():
    code, resp = _req("GET", "/api/data_views")
    for dv in resp.get("data_view", []):
        if dv.get("title") == DATA_VIEW_TITLE:
            return dv["id"]
    return None


SEARCH_SRC = json.dumps({
    "query": {"query": "", "language": "kuery"},
    "filter": [],
    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
})


def _refs(dv_id):
    return [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
             "type": "index-pattern", "id": dv_id}]


def viz(dv_id, vid, title, vis_state):
    attrs = {
        "title": title,
        "visState": json.dumps(vis_state),
        "uiStateJSON": "{}",
        "description": "",
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": SEARCH_SRC},
    }
    code, resp = _req("POST", f"/api/saved_objects/visualization/{vid}?overwrite=true",
                      {"attributes": attrs, "references": _refs(dv_id)})
    print(f"[viz] {vid:28s} -> HTTP {code} {resp.get('error', '')}")
    return code < 300


def build_visualizations(dv_id):
    build = []

    # Metric: total events
    build.append((viz, dv_id, "soc-metric-total", "Total CloudTrail Events", {
        "title": "Total CloudTrail Events", "type": "metric",
        "aggs": [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}],
        "params": {"addTooltip": True, "addLegend": False, "type": "metric",
                   "metric": {"percentageMode": False, "useRanges": False,
                              "colorSchema": "Green to Red", "metricColorMode": "None",
                              "colorsRange": [{"from": 0, "to": 10000}],
                              "labels": {"show": True}, "invertColors": False,
                              "style": {"bgColor": False, "labelColor": False,
                                        "subText": "", "fontSize": 60}}}}))

    # Pie (donut): events by action
    build.append((viz, dv_id, "soc-pie-action", "Events by API Action", {
        "title": "Events by API Action", "type": "pie",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": "event.action", "orderBy": "1", "order": "desc",
                        "size": 10, "otherBucket": False, "missingBucket": False}},
        ],
        "params": {"type": "pie", "addTooltip": True, "addLegend": True,
                   "legendPosition": "right", "isDonut": True,
                   "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}}}))

    # Vertical bar: events by severity
    build.append((viz, dv_id, "soc-bar-severity", "Events by Severity", {
        "title": "Events by Severity", "type": "histogram",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": "severity", "orderBy": "1", "order": "desc",
                        "size": 5, "otherBucket": False, "missingBucket": False}},
        ],
        "params": {"type": "histogram", "grid": {"categoryLines": False},
                   "categoryAxes": [{"id": "CategoryAxis-1", "type": "category",
                                     "position": "bottom", "show": True,
                                     "scale": {"type": "linear"},
                                     "labels": {"show": True, "filter": True, "truncate": 100},
                                     "title": {}}],
                   "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                                  "position": "left", "show": True,
                                  "scale": {"type": "linear", "mode": "normal"},
                                  "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                                  "title": {"text": "Count"}}],
                   "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                     "data": {"label": "Count", "id": "1"},
                                     "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                                     "lineWidth": 2, "showCircles": True}],
                   "addTooltip": True, "addLegend": True, "legendPosition": "right",
                   "times": [], "addTimeMarker": False, "labels": {"show": False}}}))

    # Pie: events by attack pathway
    build.append((viz, dv_id, "soc-pie-pathway", "Events by Attack Pathway", {
        "title": "Events by Attack Pathway", "type": "pie",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": "pathway", "orderBy": "1", "order": "desc",
                        "size": 10, "otherBucket": False, "missingBucket": False}},
        ],
        "params": {"type": "pie", "addTooltip": True, "addLegend": True,
                   "legendPosition": "bottom", "isDonut": True,
                   "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}}}))

    # Data table: detections
    build.append((viz, dv_id, "soc-table-detections", "Detections by Source IP", {
        "title": "Detections by Source IP", "type": "table",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
             "params": {"field": "detection_name", "orderBy": "1", "order": "desc",
                        "size": 20, "otherBucket": False, "missingBucket": False}},
            {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
             "params": {"field": "severity", "orderBy": "1", "order": "desc",
                        "size": 5, "otherBucket": False, "missingBucket": False}},
            {"id": "4", "enabled": True, "type": "terms", "schema": "bucket",
             "params": {"field": "source.ip", "orderBy": "1", "order": "desc",
                        "size": 10, "otherBucket": False, "missingBucket": False}},
        ],
        "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
                   "showTotal": False, "totalFunc": "sum", "percentageCol": ""}}))

    # MITRE techniques bar
    build.append((viz, dv_id, "soc-bar-mitre", "MITRE ATT&CK Techniques", {
        "title": "MITRE ATT&CK Techniques", "type": "histogram",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": "mitre_technique", "orderBy": "1", "order": "desc",
                        "size": 10, "otherBucket": False, "missingBucket": False}},
        ],
        "params": {"type": "histogram", "grid": {"categoryLines": False},
                   "categoryAxes": [{"id": "CategoryAxis-1", "type": "category",
                                     "position": "bottom", "show": True,
                                     "scale": {"type": "linear"},
                                     "labels": {"show": True, "filter": True, "truncate": 100},
                                     "title": {}}],
                   "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                                  "position": "left", "show": True,
                                  "scale": {"type": "linear", "mode": "normal"},
                                  "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                                  "title": {"text": "Count"}}],
                   "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                     "data": {"label": "Count", "id": "1"},
                                     "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                                     "lineWidth": 2, "showCircles": True}],
                   "addTooltip": True, "addLegend": True, "legendPosition": "right",
                   "times": [], "addTimeMarker": False, "labels": {"show": False}}}))

    ok = True
    for fn, *args in build:
        ok = fn(*args) and ok
    return ok


def build_dashboard(dv_id):
    panels = [
        {"id": "soc-metric-total",     "x": 0,  "y": 0,  "w": 12, "h": 10, "i": "1"},
        {"id": "soc-pie-pathway",      "x": 12, "y": 0,  "w": 18, "h": 15, "i": "2"},
        {"id": "soc-bar-severity",     "x": 30, "y": 0,  "w": 18, "h": 15, "i": "3"},
        {"id": "soc-pie-action",       "x": 0,  "y": 15, "w": 16, "h": 15, "i": "4"},
        {"id": "soc-bar-mitre",        "x": 16, "y": 15, "w": 16, "h": 15, "i": "5"},
        {"id": "soc-table-detections", "x": 32, "y": 15, "w": 16, "h": 15, "i": "6"},
    ]

    panels_json, references = [], []
    for idx, p in enumerate(panels):
        ref = f"panel_{idx}"
        panels_json.append({
            "version": "8.15.0", "type": "visualization",
            "gridData": {"x": p["x"], "y": p["y"], "w": p["w"], "h": p["h"], "i": p["i"]},
            "panelIndex": p["i"], "embeddableConfig": {"enhancements": {}}, "panelRefName": ref,
        })
        references.append({"name": ref, "type": "visualization", "id": p["id"]})

    attrs = {
        "title": "SOC — CloudTrail Threat Detection",
        "hits": 0,
        "description": "Cloud SOC lab: simulated AWS breach detections over cloudtrail-logs-*",
        "panelsJSON": json.dumps(panels_json),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
        "version": 1,
        "timeRestore": True,
        "timeTo": "now",
        "timeFrom": "now-7d",
        "refreshInterval": {"pause": True, "value": 0},
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
        },
    }
    code, resp = _req("POST", f"/api/saved_objects/dashboard/{DASHBOARD_ID}?overwrite=true",
                      {"attributes": attrs, "references": references})
    print(f"[dashboard] {DASHBOARD_ID} -> HTTP {code} {resp.get('error', '')}")
    return code < 300


def main():
    dv_id = find_data_view_id()
    if not dv_id:
        print("Data view cloudtrail-logs-* not found — run ingest_cloudtrail.py + create data view first.")
        sys.exit(1)
    print(f"[data-view] {DATA_VIEW_TITLE} id={dv_id}")
    ok = build_visualizations(dv_id)
    ok = build_dashboard(dv_id) and ok
    print(f"\nDashboard URL: {KB}/app/dashboards#/view/{DASHBOARD_ID}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
