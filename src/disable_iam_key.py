"""Deactivate an IAM user's access key when GuardDuty reports it as compromised.

Acts only when it is safe and possible:
- the principal is an IAM user (root, roles and federated sessions can't be fixed with UpdateAccessKey),
- the key is long-lived (AKIA...); temporary keys (ASIA...) expire on their own and belong to roles,
- the user lives in this account (member-account findings are reported for manual action).
Every decision, including "skipped", is published to the alert topic. DRY_RUN=true only reports.
"""
from __future__ import annotations

import json
import logging
import os

log = logging.getLogger()
log.setLevel(logging.INFO)


def decide(detail: dict, own_account: str) -> tuple[str, str]:
    """Return (action, reason): action is 'deactivate' or 'skip'."""
    key = (detail.get("resource") or {}).get("accessKeyDetails") or {}
    key_id, user, user_type = key.get("accessKeyId", ""), key.get("userName", ""), key.get("userType", "")
    if user_type != "IAMUser":
        return "skip", f"principal type {user_type or 'unknown'} cannot be fixed by deactivating a user key"
    if not key_id.startswith("AKIA"):
        return "skip", f"key {key_id or 'missing'} is not a long-lived user key"
    if not user:
        return "skip", "finding has no user name"
    if detail.get("accountId") != own_account:
        return "skip", f"user is in account {detail.get('accountId')}; deactivate it there"
    return "deactivate", f"{detail.get('type')} (severity {detail.get('severity')})"


def handle(event: dict, iam, sns, topic_arn: str, own_account: str, dry_run: bool) -> dict:
    detail = event.get("detail") or {}
    action, reason = decide(detail, own_account)
    key = (detail.get("resource") or {}).get("accessKeyDetails") or {}
    result = {"finding": detail.get("id"), "type": detail.get("type"), "account": detail.get("accountId"),
              "user": key.get("userName"), "accessKeyId": key.get("accessKeyId"),
              "action": action, "reason": reason, "dryRun": dry_run, "done": False}
    if action == "deactivate" and not dry_run:
        iam.update_access_key(UserName=key["userName"], AccessKeyId=key["accessKeyId"], Status="Inactive")
        result["done"] = True
    verb = {("deactivate", True): "DEACTIVATED", ("deactivate", False): "WOULD DEACTIVATE (dry run)"}.get(
        (action, result["done"]), "SKIPPED")
    subject = f"[security] {verb} key of {result['user'] or 'unknown'}"
    sns.publish(TopicArn=topic_arn, Subject=subject[:100], Message=json.dumps(result, indent=2))
    log.info(json.dumps(result))
    return result


def lambda_handler(event, context):  # pragma: no cover - thin AWS wrapper
    import boto3

    return handle(event, boto3.client("iam"), boto3.client("sns"), os.environ["TOPIC_ARN"],
                  os.environ["ACCOUNT_ID"], os.environ.get("DRY_RUN", "true").lower() != "false")
