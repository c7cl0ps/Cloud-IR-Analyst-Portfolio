#!/usr/bin/env python3
"""
bofa_lab_setup.py — Cloud SOC Lab :: Architecture Provisioning
Targets LocalStack (http://localhost:4566). Never run against real AWS.

APRA CPS 234 mapping:
  Para 22-26 (Controls implementation) : S3 public-access block, SSE, central log store
  Para 27    (Incident detection)      : CloudTrail management-event capture
"""
import json
import logging
import sys

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

LOCALSTACK_ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"
ACCOUNT_ID = "000000000000"  # LocalStack default account

CENTRAL_LOG_BUCKET = "bofa-soc-central-logs"
PII_BUCKET = "bofa-customer-pii"
TRAIL_NAME = "bank-apac-cloudtrail"
APP_ROLE_NAME = "FinancialTransactionProcessorRole"
EC2_ROLE_NAME = "EC2-Web-InstanceRole"
DDB_TABLE = "TransactionsDB"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("bofa-provision")


def guard_localstack():
    if not any(h in LOCALSTACK_ENDPOINT for h in ("localhost", "127.0.0.1")):
        log.error("Refusing to run: endpoint is not LocalStack. This lab must never touch real AWS.")
        sys.exit(1)


def client(service):
    return boto3.client(
        service,
        endpoint_url=LOCALSTACK_ENDPOINT,
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 3, "mode": "standard"}),
    )


def provision_log_bucket():
    s3 = client("s3")
    try:
        s3.create_bucket(Bucket=CENTRAL_LOG_BUCKET)
        log.info("Created S3 bucket %s", CENTRAL_LOG_BUCKET)
    except ClientError as e:
        if e.response["Error"]["Code"] in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            log.info("Bucket %s already exists", CENTRAL_LOG_BUCKET)
        else:
            raise

    # CPS 234 Para 22: protect information assets — block ALL public access
    s3.put_public_access_block(
        Bucket=CENTRAL_LOG_BUCKET,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket=CENTRAL_LOG_BUCKET,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )

    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{CENTRAL_LOG_BUCKET}",
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{CENTRAL_LOG_BUCKET}/AWSLogs/{ACCOUNT_ID}/*",
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=CENTRAL_LOG_BUCKET, Policy=json.dumps(bucket_policy))
    log.info("Hardened %s (public access blocked, SSE-S3, CloudTrail delivery policy set)", CENTRAL_LOG_BUCKET)


def provision_pii_bucket():
    """A second data store: the sensitive 'customer PII' bucket (exfil target in Pathway 1)."""
    s3 = client("s3")
    try:
        s3.create_bucket(Bucket=PII_BUCKET)
        log.info("Created S3 bucket %s", PII_BUCKET)
    except ClientError as e:
        if e.response["Error"]["Code"] in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            log.info("Bucket %s already exists", PII_BUCKET)
        else:
            raise
    s3.put_public_access_block(
        Bucket=PII_BUCKET,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True},
    )
    s3.put_bucket_encryption(
        Bucket=PII_BUCKET,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
    )
    s3.put_object(Bucket=PII_BUCKET, Key="exports/cardholder-2026.csv",
                  Body=b"account,pan,balance\nVIP-0001,****-****-****-4242,982145.00\n")
    log.info("Seeded %s with mock PII object (SSE-S3, public access blocked)", PII_BUCKET)


def provision_ec2_workload():
    """A compute workload: EC2 instance + its instance-profile role (Pathway 2 IMDS target)."""
    iam = client("iam")
    ec2_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Principal": {"Service": "ec2.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    try:
        iam.create_role(RoleName=EC2_ROLE_NAME,
                        AssumeRolePolicyDocument=json.dumps(ec2_trust),
                        Description="Instance profile role for the web workload",
                        Tags=[{"Key": "Env", "Value": "soc-lab"}])
        log.info("Created IAM role %s", EC2_ROLE_NAME)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityAlreadyExists":
            raise
        log.info("Role %s already exists", EC2_ROLE_NAME)
    iam.put_role_policy(RoleName=EC2_ROLE_NAME, PolicyName="WebWorkloadPerms",
                        PolicyDocument=json.dumps({
                            "Version": "2012-10-17",
                            "Statement": [{"Effect": "Allow",
                                           "Action": ["dynamodb:GetItem", "dynamodb:Scan",
                                                      "s3:GetObject", "rds:DescribeDBInstances"],
                                           "Resource": "*"}]}))

    ec2 = client("ec2")
    try:
        imgs = ec2.describe_images().get("Images", [])
        ami = imgs[0]["ImageId"] if imgs else "ami-0web0snapshot"
        inst = ec2.run_instances(ImageId=ami, InstanceType="t3.micro",
                                 MinCount=1, MaxCount=1,
                                 TagSpecifications=[{"ResourceType": "instance",
                                                     "Tags": [{"Key": "Name", "Value": "bank-web-01"},
                                                              {"Key": "Env", "Value": "soc-lab"}]}])
        iid = inst["Instances"][0]["InstanceId"]
        log.info("Launched EC2 workload %s (role %s)", iid, EC2_ROLE_NAME)
    except ClientError as e:
        log.warning("EC2 workload provisioning limited in LocalStack: %s", e.response["Error"]["Code"])


def provision_database():
    """A database tier: DynamoDB transactions table (Pathway 2 recon / Pathway 3 snapshot)."""
    ddb = client("dynamodb")
    try:
        ddb.create_table(
            TableName=DDB_TABLE,
            KeySchema=[{"AttributeName": "account", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "account", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
            Tags=[{"Key": "DataClass", "Value": "PCI-Sensitive"}, {"Key": "Env", "Value": "soc-lab"}])
        log.info("Created DynamoDB table %s", DDB_TABLE)
    except ClientError as e:
        if e.response["Error"]["Code"] in ("ResourceInUseException",):
            log.info("Table %s already exists", DDB_TABLE)
        else:
            log.warning("DynamoDB provisioning limited: %s", e.response["Error"]["Code"])
            return
    try:
        ddb.put_item(TableName=DDB_TABLE,
                     Item={"account": {"S": "VIP-0001"}, "balance": {"N": "982145"}})
        log.info("Seeded %s with a mock transaction record", DDB_TABLE)
    except ClientError:
        pass


def provision_cloudtrail():
    """
    Best-effort. LocalStack Community does not implement the CloudTrail API
    (CreateTrail is a Pro feature), so this is allowed to degrade gracefully:
    the SIEM's CloudTrail telemetry is produced synthetically by
    ingest_cloudtrail.py, which does not depend on a real trail resource.
    """
    ct = client("cloudtrail")
    try:
        ct.create_trail(
            Name=TRAIL_NAME,
            S3BucketName=CENTRAL_LOG_BUCKET,
            IsMultiRegionTrail=True,
            IncludeGlobalServiceEvents=True,
            EnableLogFileValidation=True,
        )
        log.info("Created CloudTrail %s", TRAIL_NAME)
        ct.put_event_selectors(
            TrailName=TRAIL_NAME,
            EventSelectors=[{"ReadWriteType": "All", "IncludeManagementEvents": True, "DataResources": []}],
        )
        ct.start_logging(Name=TRAIL_NAME)
        log.info("CloudTrail %s logging all management events", TRAIL_NAME)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"].get("Message", "")
        if code == "TrailAlreadyExistsException":
            log.info("Trail %s already exists", TRAIL_NAME)
        elif code in ("InternalFailure", "NotImplemented") or "not yet implemented" in msg or "pro feature" in msg:
            log.warning(
                "CloudTrail API unavailable in LocalStack Community — skipping trail "
                "provisioning (synthetic events are supplied by ingest_cloudtrail.py)."
            )
        else:
            raise


def provision_app_role():
    iam = client("iam")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "ec2.amazonaws.com",        # realistic: instance profile (IMDS)
                    "AWS": f"arn:aws:iam::{ACCOUNT_ID}:root",
                },
                "Action": "sts:AssumeRole",
            }
        ],
    }
    try:
        iam.create_role(
            RoleName=APP_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Simulated sensitive banking transaction processor role",
            Tags=[{"Key": "DataClass", "Value": "PCI-Sensitive"}, {"Key": "Env", "Value": "soc-lab"}],
        )
        log.info("Created IAM role %s", APP_ROLE_NAME)
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            log.info("Role %s already exists", APP_ROLE_NAME)
        else:
            raise

    iam.put_role_policy(
        RoleName=APP_ROLE_NAME,
        PolicyName="TxnProcessorPerms",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "s3:GetObject"],
                "Resource": "*",
            }],
        }),
    )
    log.info("Attached least-privilege inline policy to %s", APP_ROLE_NAME)


def main():
    guard_localstack()
    log.info("=== BoFA Cloud SOC Lab :: Provisioning ===")
    provision_log_bucket()       # S3 central log store
    provision_pii_bucket()       # S3 sensitive data store
    provision_app_role()         # IAM: transaction processor role
    provision_ec2_workload()     # EC2 instance + instance-profile role
    provision_database()         # DynamoDB transactions table
    provision_cloudtrail()       # CloudTrail (best-effort; Community lacks API)
    log.info("=== Provisioning complete ===")


if __name__ == "__main__":
    main()