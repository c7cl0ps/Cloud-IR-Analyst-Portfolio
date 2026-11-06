#!/usr/bin/env python3
"""
list_resources.py — Cloud SOC Lab :: inventory of deployed LocalStack resources

Prints every mock AWS resource the lab has provisioned (S3, IAM, EC2,
DynamoDB, STS identity) plus the Elasticsearch indices, so you can see the
whole estate as a list. LocalStack only (http://localhost:4566).
"""
import json
import urllib.request

ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"
ES = "http://localhost:9200"

try:
    import boto3
except ImportError:
    boto3 = None


def client(service):
    return boto3.client(service, endpoint_url=ENDPOINT, region_name=REGION,
                        aws_access_key_id="test", aws_secret_access_key="test")


def section(title):
    print(f"\n=== {title} ===")


def main():
    if boto3 is None:
        print("boto3 not installed — run: pip install boto3")
        return

    section("LocalStack health")
    try:
        with urllib.request.urlopen(f"{ENDPOINT}/_localstack/health", timeout=5) as r:
            svc = json.load(r).get("services", {})
            running = sorted(k for k, v in svc.items() if v in ("available", "running"))
            print("services up:", ", ".join(running) or "(none)")
    except Exception as e:
        print("LocalStack not reachable:", e)
        return

    section("STS — caller identity")
    try:
        ident = client("sts").get_caller_identity()
        print("account:", ident.get("Account"), " arn:", ident.get("Arn"))
    except Exception as e:
        print("  n/a:", e)

    section("S3 — buckets")
    try:
        for b in client("s3").list_buckets().get("Buckets", []):
            print(" •", b["Name"])
    except Exception as e:
        print("  n/a:", e)

    section("IAM — roles")
    try:
        for r in client("iam").list_roles().get("Roles", []):
            print(" •", r["RoleName"], "—", r["Arn"])
    except Exception as e:
        print("  n/a:", e)

    section("IAM — users")
    try:
        users = client("iam").list_users().get("Users", [])
        print("\n".join(f" • {u['UserName']}" for u in users) or " (none)")
    except Exception as e:
        print("  n/a:", e)

    section("EC2 — instances")
    try:
        res = client("ec2").describe_instances().get("Reservations", [])
        inst = [i for r in res for i in r.get("Instances", [])]
        for i in inst:
            name = next((t["Value"] for t in i.get("Tags", []) if t["Key"] == "Name"), "-")
            print(f" • {i['InstanceId']}  ({name})  {i['State']['Name']}")
        if not inst:
            print(" (none — EC2 may be limited in LocalStack Community)")
    except Exception as e:
        print("  n/a:", e)

    section("DynamoDB — tables")
    try:
        tables = client("dynamodb").list_tables().get("TableNames", [])
        print("\n".join(f" • {t}" for t in tables) or " (none — may be limited in Community)")
    except Exception as e:
        print("  n/a:", e)

    section("Elasticsearch — indices")
    try:
        with urllib.request.urlopen(f"{ES}/_cat/indices?h=index,docs.count,store.size&format=json",
                                    timeout=5) as r:
            for idx in json.load(r):
                if not idx["index"].startswith("."):
                    print(f" • {idx['index']}  ({idx['docs.count']} docs, {idx['store.size']})")
    except Exception as e:
        print("  n/a:", e)

    print()


if __name__ == "__main__":
    main()
