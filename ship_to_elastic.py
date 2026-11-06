#!/usr/bin/env python3
"""Ship soc_alerts.jsonl into Elasticsearch so they appear in Kibana."""
import json, sys, urllib.request

ES = "http://localhost:9200"
INDEX = "soc-alerts"
ALERT_LOG = "soc_alerts.jsonl"

def post(doc):
    req = urllib.request.Request(
        f"{ES}/{INDEX}/_doc",
        data=json.dumps(doc).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        return r.status

def main():
    try:
        lines = open(ALERT_LOG).read().splitlines()
    except FileNotFoundError:
        print("No soc_alerts.jsonl yet — run the lab first."); sys.exit(1)
    n = 0
    for line in lines:
        if line.strip():
            post(json.loads(line)); n += 1
    print(f"Shipped {n} alert(s) to Elasticsearch index '{INDEX}'")

if __name__ == "__main__":
    main()