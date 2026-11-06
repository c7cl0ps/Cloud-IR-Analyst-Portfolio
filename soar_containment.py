#!/usr/bin/env python3
"""
soar_containment.py — Cloud SOC Lab :: SOAR Automated Containment
Neutralises the three P1 vectors and emits high-severity JSON alerts.
LocalStack only.

APRA CPS 234 Para 27-29 (Incident management: detect, respond, restore).
"""
import json
import logging
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

LOCALSTACK_ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"
TRAIL_NAME = "bank-apac-cloudtrail"
ROGUE_MARKERS = ("backdoor", "rogue")
ALERT_LOG = "soc_alerts.jsonl"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("soar")


def guard_localstack():
    if not any(h in LOCALSTACK_ENDPOINT for h in ("localhost", "127.0.0.1")):
        log.error("Refusing to run SOAR containment outside LocalStack.")
        sys.exit(1)


def client(service):
    return boto3.client(
        service, endpoint_url=LOCALSTACK_ENDPOINT, region_name=REGION,
        aws_access_key_id="test", aws_secret_access_key="test",
    )


def emit_alert(severity, category, message):
    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "priority": "P1" if severity in ("CRITICAL", "HIGH") else "P3",
        "category": category,
        "message": message,
        "source": "soar_containment.py",
        "apra_cps234_ref": "Para 27-29 (Incident Management)",
    }
    with open(ALERT_LOG, "a") as fh:
        fh.write(json.dumps(alert) + "\n")
    log.critical("ALERT %s", json.dumps(alert))


def _nuke_user(iam, username):
    for p in iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", []):
        iam.detach_user_policy(UserName=username, PolicyArn=p["PolicyArn"])
    for pn in iam.list_user_policies(UserName=username).get("PolicyNames", []):
        iam.delete_user_policy(UserName=username, PolicyName=pn)
    for k in iam.list_access_keys(UserName=username).get("AccessKeyMetadata", []):
        iam.delete_access_key(UserName=username, AccessKeyId=k["AccessKeyId"])
    for g in iam.list_groups_for_user(UserName=username).get("Groups", []):
        iam.remove_user_from_group(GroupName=g["GroupName"], UserName=username)
    try:
        iam.delete_login_profile(UserName=username)
    except ClientError:
        pass
    iam.delete_user(UserName=username)


def hunt_and_contain_rogue_users():
    iam = client("iam")
    contained = []
    for u in iam.list_users().get("Users", []):
        name = u["UserName"]
        if any(m in name.lower() for m in ROGUE_MARKERS):
            log.warning("Rogue account detected: %s — containing", name)
            _nuke_user(iam, name)
            contained.append(name)
            emit_alert("HIGH", "IAM_PERSISTENCE", f"Detached policies and deleted rogue user {name}")
    if not contained:
        log.info("No rogue accounts found")
    return contained


def audit_and_restore_cloudtrail():
    ct = client("cloudtrail")
    status = ct.get_trail_status(Name=TRAIL_NAME)
    if not status.get("IsLogging", False):
        log.warning("CloudTrail %s is NOT logging — audit evasion suspected", TRAIL_NAME)
        ct.start_logging(Name=TRAIL_NAME)
        emit_alert("HIGH", "AUDIT_EVASION", f"Logging was disabled on {TRAIL_NAME}; auto-restarted")
        log.info("CloudTrail logging restored")
    else:
        log.info("CloudTrail %s logging healthy", TRAIL_NAME)


def main():
    guard_localstack()
    log.info("=== SOAR CONTAINMENT START ===")
    contained = hunt_and_contain_rogue_users()
    audit_and_restore_cloudtrail()
    log.info("=== SOAR CONTAINMENT COMPLETE — %d rogue account(s) removed ===", len(contained))


if __name__ == "__main__":
    main()