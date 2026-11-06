#!/usr/bin/env python3
"""
ingest_cloudtrail.py — Cloud SOC Lab :: CloudTrail -> Elasticsearch ingestion

Generates synthetic CloudTrail telemetry for THREE multi-resource attack
pathways and indexes it into Elasticsearch so it is visible in the Kibana SIEM.

  Pathway 1 — Identity Token Theft to Storage Exfiltration
  Pathway 2 — Workload Exploit, IMDS Theft & DB Recon
  Pathway 3 — Unauthorized DB Snapshot Sharing

The "logs not visible in SIEM" fix: CloudTrail events carry highly variable
nested objects (requestParameters / responseElements / userIdentity). Default
Elasticsearch dynamic mapping inferred conflicting types across events and
dropped documents. We map those volatile sub-objects as `flattened` and add an
ingest pipeline that promotes eventTime -> @timestamp.

Elasticsearch only (http://localhost:9200). No real AWS, no real CloudTrail.
"""
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

ES = "http://localhost:9200"
INDEX = "cloudtrail-logs-v1"
PIPELINE = "cloudtrail-normalize"
ACCOUNT_ID = "000000000000"
ATTACKER_ACCOUNT = "999988887777"   # external account used for snapshot sharing
REGION = "us-east-1"

# Source IPs tell the story per pathway
IP_P1 = "203.0.113.47"    # external attacker (stolen identity)
IP_P2 = "198.51.100.23"   # compromised EC2 workload egress
IP_P3 = "192.0.2.88"      # exfil / snapshot-sharing destination


def _req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{ES}{path}", data=data,
        headers={"Content-Type": "application/json"}, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        return e.code, (json.loads(raw) if raw else {})


def create_pipeline():
    body = {
        "description": "Normalize synthetic CloudTrail events for SIEM",
        "processors": [
            {"set": {"field": "@timestamp", "value": "{{{eventTime}}}", "if": "ctx.eventTime != null"}},
            {"set": {"field": "event.provider", "value": "cloudtrail"}},
            {"set": {"field": "cloud.provider", "value": "aws"}},
            {"rename": {"field": "eventName", "target_field": "event.action", "ignore_missing": True}},
            {"rename": {"field": "sourceIPAddress", "target_field": "source.ip", "ignore_missing": True}},
        ],
    }
    code, _ = _req("PUT", f"/_ingest/pipeline/{PIPELINE}", body)
    print(f"[pipeline] {PIPELINE} -> HTTP {code}")
    return code


def create_index():
    mapping = {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "dynamic": "true",
            "properties": {
                "@timestamp": {"type": "date"},
                "eventVersion": {"type": "keyword"},
                "eventTime": {"type": "date"},
                "eventSource": {"type": "keyword"},
                "event": {"properties": {"action": {"type": "keyword"}, "provider": {"type": "keyword"}}},
                "awsRegion": {"type": "keyword"},
                "source": {"properties": {"ip": {"type": "ip"}}},
                "userAgent": {"type": "keyword"},
                "errorCode": {"type": "keyword"},
                "pathway": {"type": "keyword"},
                "mitre_technique": {"type": "keyword"},
                "detection_name": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "targetResource": {"type": "keyword"},
                "resourceType": {"type": "keyword"},
                "userIdentity": {"type": "flattened"},
                "requestParameters": {"type": "flattened"},
                "responseElements": {"type": "flattened"},
                "additionalEventData": {"type": "flattened"},
            },
        },
    }
    _req("DELETE", f"/{INDEX}")
    code, resp = _req("PUT", f"/{INDEX}", mapping)
    print(f"[index] {INDEX} -> HTTP {code} {resp.get('error', {}).get('reason', 'ok')}")
    return code


def _event(minutes_ago, name, source, identity, src_ip, request, response,
           detection, mitre, severity, pathway, resource_type, target, error=None, extra=None):
    ts = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
    doc = {
        "eventVersion": "1.08",
        "eventTime": ts,
        "eventSource": source,
        "eventName": name,
        "awsRegion": REGION,
        "sourceIPAddress": src_ip,
        "userAgent": "aws-cli/2.15.0 Python/3.11",
        "userIdentity": identity,
        "requestParameters": request,
        "responseElements": response,
        "recipientAccountId": ACCOUNT_ID,
        "pathway": pathway,
        "detection_name": detection,
        "mitre_technique": mitre,
        "severity": severity,
        "resourceType": resource_type,
        "targetResource": target,
    }
    if error:
        doc["errorCode"] = error
    if extra:
        doc["additionalEventData"] = extra
    return doc


def pathway1_events():
    """Identity Token Theft to Storage Exfiltration."""
    p = "P1: Identity Token Theft -> Storage Exfil"
    role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/FinancialTransactionProcessorRole"
    leaked_user = {"type": "IAMUser", "userName": "leaked-ci-key",
                   "accessKeyId": "AKIACILEAKED0KEY", "accountId": ACCOUNT_ID}
    # The stolen temporary session — note accessKeyId starts ASIA (short-lived) and MFA is false
    stolen_session = {
        "type": "AssumedRole",
        "arn": f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/FinancialTransactionProcessorRole/token-theft",
        "accessKeyId": "ASIATOKENTHEFT01",
        "sessionContext": {
            "sessionIssuer": {"type": "Role", "userName": "FinancialTransactionProcessorRole",
                              "arn": role_arn},
            "attributes": {"mfaAuthenticated": "false"},
        },
    }
    return [
        _event(34, "GetCallerIdentity", "sts.amazonaws.com", leaked_user, IP_P1,
               {}, {"account": ACCOUNT_ID, "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/leaked-ci-key"},
               "Identity Recon — GetCallerIdentity from new IP", "T1087", "LOW",
               p, "STS", "caller-identity"),
        _event(33, "AssumeRole", "sts.amazonaws.com", leaked_user, IP_P1,
               {"roleArn": role_arn, "roleSessionName": "token-theft", "durationSeconds": 3600},
               {"credentials": {"accessKeyId": "ASIATOKENTHEFT01", "expiration": "+60m"},
                "assumedRoleUser": {"arn": stolen_session["arn"]}},
               "Stolen Identity — Role Assumption", "T1552.005", "CRITICAL",
               p, "IAM", "FinancialTransactionProcessorRole"),
        _event(31, "ListBuckets", "s3.amazonaws.com", stolen_session, IP_P1,
               {}, {"buckets": ["bofa-soc-central-logs", "bofa-customer-pii"]},
               "S3 Bucket Discovery", "T1619", "MEDIUM", p, "S3", "all-buckets"),
        # SMOKING GUN: assumed-role session reads the most sensitive bucket from an external IP,
        # moving ~46 MB out (bytesTransferredOut).
        _event(29, "GetObject", "s3.amazonaws.com", stolen_session, IP_P1,
               {"bucketName": "bofa-customer-pii", "key": "exports/cardholder-2026.csv"}, {},
               "Sensitive Data Exfiltration — PII bucket read", "T1530", "CRITICAL",
               p, "S3", "bofa-customer-pii",
               extra={"bytesTransferredOut": 48210432, "AuthenticationMethod": "AuthHeader",
                      "SignatureVersion": "SigV4", "x-amz-server-side-encryption": "AES256"}),
        _event(28, "GetObject", "s3.amazonaws.com", stolen_session, IP_P1,
               {"bucketName": "bofa-soc-central-logs", "key": "AWSLogs/audit/cloudtrail.json"}, {},
               "Log Store Probe — AccessDenied on hardened bucket", "T1530", "MEDIUM",
               p, "S3", "bofa-soc-central-logs", error="AccessDenied"),
    ]


def pathway2_events():
    """Workload Exploit, IMDS Theft & DB Recon."""
    p = "P2: Workload Exploit + IMDS + DB Recon"
    role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/EC2-Web-InstanceRole"
    # The EC2 instance-profile session. The SAME session appears below from two very
    # different source IPs: the instance's private VPC IP (benign) and an external IP (theft).
    inst_session = {
        "type": "AssumedRole",
        "arn": f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/EC2-Web-InstanceRole/i-0abc123web",
        "accessKeyId": "ASIAIMDSSSRF002",
        "sessionContext": {
            "sessionIssuer": {"type": "Role", "userName": "EC2-Web-InstanceRole", "arn": role_arn},
            "ec2RoleDelivery": "2.0",
        },
    }
    return [
        # BASELINE (benign): the instance role used legitimately from inside the VPC (private IP).
        # This is what "normal" looks like — the contrast is the whole point.
        _event(50, "GetItem", "dynamodb.amazonaws.com", inst_session, "10.0.12.34",
               {"tableName": "TransactionsDB", "key": {"account": "ACME-0204"}},
               {"item": {"account": "ACME-0204"}},
               "Baseline — instance-role activity from VPC", "T1078", "INFO",
               p, "DynamoDB", "TransactionsDB"),
        _event(22, "AssumeRole", "sts.amazonaws.com",
               {"type": "AWSService", "invokedBy": "ec2.amazonaws.com"}, IP_P2,
               {"roleArn": role_arn, "roleSessionName": "i-0abc123web"},
               {"credentials": {"accessKeyId": "ASIAIMDSSSRF002"}},
               "IMDS Credential Theft via SSRF (workload exploit)", "T1552.005", "CRITICAL",
               p, "EC2", "i-0abc123web"),
        # SMOKING GUN: the instance-profile session now acting from an EXTERNAL IP (198.51.100.23)
        # instead of 10.0.12.34 — instance creds are being used off-instance.
        _event(21, "DescribeInstances", "ec2.amazonaws.com", inst_session, IP_P2,
               {}, {}, "Workload Reconnaissance — DescribeInstances (role off-instance)",
               "T1580", "MEDIUM", p, "EC2", "all-instances"),
        _event(20, "DescribeDBInstances", "rds.amazonaws.com", inst_session, IP_P2,
               {}, {}, "Database Reconnaissance — DescribeDBInstances", "T1580", "MEDIUM",
               p, "RDS", "all-db-instances"),
        # SMOKING GUN: full-table Scan (ALL_ATTRIBUTES, 48k rows) vs the single-key GetItem baseline.
        _event(17, "Scan", "dynamodb.amazonaws.com", inst_session, IP_P2,
               {"tableName": "TransactionsDB", "select": "ALL_ATTRIBUTES"},
               {"count": 48213, "scannedCount": 48213},
               "Bulk Database Read — DynamoDB Scan", "T1213", "HIGH",
               p, "DynamoDB", "TransactionsDB", extra={"requestId": "SCAN-EXFIL-48213"}),
    ]


def pathway3_events():
    """Unauthorized DB Snapshot Sharing."""
    p = "P3: Unauthorized DB Snapshot Sharing"
    attacker = {"type": "IAMUser", "userName": "rogue-admin-backdoor",
                "accessKeyId": "AKIAROGUEBACKDOOR", "accountId": ACCOUNT_ID}
    return [
        _event(11, "CreateDBSnapshot", "rds.amazonaws.com", attacker, IP_P3,
               {"dBInstanceIdentifier": "bank-core-db",
                "dBSnapshotIdentifier": "bank-core-db-exfil"},
               {"dBSnapshotIdentifier": "bank-core-db-exfil", "status": "creating"},
               "Snapshot Created of production DB", "T1074", "MEDIUM",
               p, "RDS", "bank-core-db"),
        # SMOKING GUN: valuesToAdd shares the snapshot with an UNKNOWN external account (999988887777).
        _event(10, "ModifyDBSnapshotAttribute", "rds.amazonaws.com", attacker, IP_P3,
               {"dBSnapshotIdentifier": "bank-core-db-exfil",
                "attributeName": "restore",
                "valuesToAdd": [ATTACKER_ACCOUNT]},
               {"dBSnapshotAttributesResult": {"attributeName": "restore",
                                               "attributeValues": [ATTACKER_ACCOUNT]}},
               "Unauthorized Snapshot Sharing to external account", "T1537", "CRITICAL",
               p, "RDS", f"bank-core-db-exfil -> acct {ATTACKER_ACCOUNT}"),
        # SMOKING GUN: valuesToAdd 'all' = restorable by EVERY AWS account (fully public).
        _event(9, "ModifyDBSnapshotAttribute", "rds.amazonaws.com", attacker, IP_P3,
               {"dBSnapshotIdentifier": "bank-core-db-exfil",
                "attributeName": "restore", "valuesToAdd": ["all"]},
               {"dBSnapshotAttributesResult": {"attributeName": "restore",
                                               "attributeValues": ["all"]}},
               "Snapshot Made Public (restore=all)", "T1537", "CRITICAL",
               p, "RDS", "bank-core-db-exfil"),
        _event(8, "ModifyImageAttribute", "ec2.amazonaws.com", attacker, IP_P3,
               {"imageId": "ami-0web0snapshot",
                "launchPermission": {"add": [{"userId": ATTACKER_ACCOUNT}]}}, {},
               "AMI Shared with external account", "T1537", "HIGH",
               p, "EC2-AMI", f"ami-0web0snapshot -> acct {ATTACKER_ACCOUNT}"),
        _event(6, "StopLogging", "cloudtrail.amazonaws.com", attacker, IP_P3,
               {"name": "bank-apac-cloudtrail"}, {},
               "Defense Evasion — CloudTrail logging disabled", "T1562.008", "CRITICAL",
               p, "CloudTrail", "bank-apac-cloudtrail"),
    ]


def all_events():
    return pathway1_events() + pathway2_events() + pathway3_events()


def bulk_index(events):
    lines = []
    for e in events:
        lines.append(json.dumps({"index": {"_index": INDEX}}))
        lines.append(json.dumps(e))
    payload = "\n".join(lines) + "\n"
    req = urllib.request.Request(
        f"{ES}/_bulk?pipeline={PIPELINE}&refresh=true",
        data=payload.encode(),
        headers={"Content-Type": "application/x-ndjson"}, method="POST")
    with urllib.request.urlopen(req) as r:
        resp = json.loads(r.read().decode())
    errors = [i for i in resp.get("items", []) if i.get("index", {}).get("status", 200) >= 300]
    print(f"[bulk] indexed {len(events) - len(errors)}/{len(events)} events (errors={len(errors)})")
    if errors:
        print(json.dumps(errors[0], indent=2))
    return len(errors) == 0


def main():
    print("=== CloudTrail -> Elasticsearch ingestion (3 attack pathways) ===")
    create_pipeline()
    create_index()
    events = all_events()
    ok = bulk_index(events)
    code, resp = _req("GET", f"/{INDEX}/_count")
    print(f"[verify] {INDEX}/_count -> HTTP {code} count={resp.get('count')}")
    sys.exit(0 if ok and resp.get("count", 0) > 0 else 1)


if __name__ == "__main__":
    main()
