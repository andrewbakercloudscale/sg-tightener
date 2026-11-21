#!/usr/bin/env python3
"""Real-time drift alerts: an AWS Lambda handler for EventBridge.

EventBridge delivers each successful ``AuthorizeSecurityGroupIngress`` and ``ModifySecurityGroupRules`` call
(CloudTrail's "AWS API Call via CloudTrail" events) within seconds. The handler judges the rule it added exactly
as ``sg_review.py`` does for **Rules opened wide** (``0.0.0.0/0`` or ``::/0``, a public ``/16`` or wider, a private
``/8`` on a risky port) and, at or above ``MIN_SEVERITY``, tells you at once: an SNS topic (email, chat, a pager),
a Slack webhook, and Security Hub, with the same finding id ``sg_review.py securityhub`` uses, so the batch run
later updates the finding instead of adding a copy. Optionally it takes the rule back out (``AUTO_REVOKE``).

Deploy it with ``deploy/drift-alerts`` (CloudFormation or Terraform). Configuration, all optional:

  MIN_SEVERITY        critical, high (default) or medium
  SNS_TOPIC_ARN       publish the alert to this topic
  SLACK_SECRET_ARN    Secrets Manager secret holding a Slack incoming-webhook URL
  SECURITY_HUB        "true" to send the finding to Security Hub in the event's region
  AUTO_REVOKE         off (default), critical or high: revoke a rule rated this or worse, unless its group is
                      tagged sg-tightener-allow-wide=true
  ACCOUNT_NAME        shown in the alert next to the account id

Try it without AWS: ``python sg_drift_lambda.py event.json`` prints the alert for a saved event.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time

import sg_review
import sg_securityhub

LOG = logging.getLogger("sg_drift_lambda")
LOG.setLevel(logging.INFO)

EVENTS = ("AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules")
ALLOW_TAG = "sg-tightener-allow-wide"
LEVELS = ("critical", "high", "medium")


def _boto3():
    import boto3

    return boto3


def _level(name: str, default: str, allowed=LEVELS) -> str:
    v = (os.environ.get(name) or default).strip().lower()
    if v not in allowed:
        raise ValueError(f"{name} must be one of {', '.join(allowed)}, not {v!r}")
    return v


def _group(ec2, gid: str, ev: dict) -> tuple[dict, bool]:
    """The group as sg_review's snapshot holds it, and whether it is exempt. When it cannot be read, the rules
    the event added stand in, so the change is still judged as present."""
    try:
        g = ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]
        tags = {t.get("Key"): str(t.get("Value", "")).lower() for t in g.get("Tags") or []}
        return ({"name": g.get("GroupName") or gid, "rules": [sg_review._rule(p) for p in g.get("IpPermissions") or []]},
                tags.get(ALLOW_TAG) == "true")  # fmt: skip
    except Exception as exc:  # noqa: BLE001 - deleted since, or no ec2:DescribeSecurityGroups
        LOG.warning("could not read %s (%s); judging the change from the event alone", gid, exc)
    rules = []
    for proto, lo, hi, cidr, *_ in (ev.get("added") or []) + (ev.get("added6") or []) + (ev.get("set") or []):
        v6 = ":" in str(cidr)
        rules.append({"proto": str(proto), "from": lo, "to": hi, "cidrs": [] if v6 else [cidr], "cidrs6": [cidr] if v6 else []})
    return {"name": gid, "rules": rules}, False


def findings(event: dict, ec2=None, now: float | None = None) -> tuple[list[dict], dict]:
    """The drift items for one EventBridge event (all severities), and {account, region, exempt}."""
    detail = event.get("detail") or {}
    region = event.get("region") or detail.get("awsRegion") or ""
    account = event.get("account") or detail.get("recipientAccountId") or ""
    meta = {"account": account, "region": region, "exempt": False}
    if detail.get("eventName") not in EVENTS:
        return [], meta
    ev = sg_review.parse_event({"CloudTrailEvent": json.dumps(detail)})
    if not ev:
        return [], meta  # a failed call, or no group in it
    if ec2 is None:
        ec2 = _boto3().client("ec2", region_name=region)
    group, meta["exempt"] = _group(ec2, ev["group"], ev)
    doc = {"regions": {region: {"snapshot": {"groups": {ev["group"]: group}}, "history": {"events": [ev]}}}}
    # The window only guards against replays of old events; EventBridge itself is seconds behind.
    return sg_review.drift_findings(doc, now or time.time(), window=7 * 86400), meta


def _revoke(ec2, gid: str, rule: dict) -> None:
    if rule.get("id"):
        ec2.revoke_security_group_ingress(GroupId=gid, SecurityGroupRuleIds=[rule["id"]])
        return
    proto = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}.get(rule["proto"], rule["proto"])
    perm: dict = {"IpProtocol": proto}
    if proto in ("tcp", "udp"):
        perm.update(FromPort=int(rule["from"]), ToPort=int(rule["to"]))
    elif proto != "-1":
        perm.update(FromPort=-1, ToPort=-1)
    perm["Ipv6Ranges" if ":" in rule["cidr"] else "IpRanges"] = [
        {"CidrIpv6" if ":" in rule["cidr"] else "CidrIp": rule["cidr"]}]
    ec2.revoke_security_group_ingress(GroupId=gid, IpPermissions=[perm])


def _slack_url(secret_arn: str) -> str:
    sm = _boto3().client("secretsmanager")
    raw = sm.get_secret_value(SecretId=secret_arn)["SecretString"].strip()
    if raw.startswith("{"):  # {"url": "..."} or {"webhook": "..."}
        d = json.loads(raw)
        raw = d.get("url") or d.get("webhook") or ""
    return raw


def handler(event: dict, context=None, *, ec2=None, session=None) -> dict:
    """The Lambda entry point. Returns what was found, sent and revoked. Raises only when every configured
    channel failed, so EventBridge's retry does not post twice to a channel that worked."""
    min_sev = _level("MIN_SEVERITY", "high")
    auto = _level("AUTO_REVOKE", "off", ("off", "critical", "high"))
    items, meta = findings(event, ec2)
    rank = sg_review.SEV_RANK
    items = [it for it in items if rank[it["sev"]] <= rank[min_sev]]
    out = {"found": len(items), "sent": [], "failed": [], "revoked": []}
    if not items:
        return out
    region, account = meta["region"], meta["account"]
    if auto != "off" and ec2 is None:
        ec2 = _boto3().client("ec2", region_name=region)
    for it in items:
        if auto == "off" or rank[it["sev"]] > rank[auto] or not it.get("still"):
            continue
        if meta["exempt"]:
            it["reason"] += f" Not revoked: the group is tagged {ALLOW_TAG}=true."
            continue
        try:
            _revoke(ec2, it["group"], it["rule"])
            out["revoked"].append(it["cli"])
            it["reason"] += " Revoked automatically (AUTO_REVOKE); add it again, narrowed, if it was meant."
            it["action"] = "Confirm with whoever made the change; nothing else to do unless it was meant."
            it["cli"] = ""
        except Exception as exc:  # noqa: BLE001
            LOG.error("could not revoke on %s: %s", it["group"], exc)
            it["reason"] += f" Automatic revoke FAILED ({exc}); take it out by hand."

    name = os.environ.get("ACCOUNT_NAME", "")
    text = sg_review.alert_text(account, name, items, markdown=True)
    plain = sg_review.alert_text(account, name, items, markdown=False)
    LOG.info("%s", plain)
    channels = []
    topic = os.environ.get("SNS_TOPIC_ARN")
    if topic:
        def sns():
            subject = f"sg_review: {items[0]['sev'].upper()} {items[0]['title']}"[:99]
            (session or _boto3()).client("sns", region_name=topic.split(":")[3]).publish(
                TopicArn=topic, Subject=subject, Message=plain)
        channels.append(("sns", sns))
    secret = os.environ.get("SLACK_SECRET_ARN")
    if secret:
        channels.append(("slack", lambda: sg_review.post_slack(_slack_url(secret), text)))
    if os.environ.get("SECURITY_HUB", "").lower() in ("1", "true", "yes"):
        def hub():
            fs = [sg_securityhub.from_review_item(account, it, f"{it['kind']}|{sg_review.attention_id(it)}")
                  for it in items]
            res = sg_securityhub.send(session or _boto3(), region, fs)
            if res["failed"]:
                raise RuntimeError("; ".join(res["errors"][:3]))
        channels.append(("securityhub", hub))
    for label, send in channels:
        try:
            send()
            out["sent"].append(label)
        except Exception as exc:  # noqa: BLE001
            LOG.error("%s: %s", label, exc)
            out["failed"].append(label)
    if channels and not out["sent"]:
        raise RuntimeError(f"every channel failed: {', '.join(out['failed'])}")
    return out


def main(argv=None) -> int:
    """Print the alert a saved EventBridge event (or bare CloudTrail record) would raise, without AWS."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: sg_drift_lambda.py EVENT.json", file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as fh:
        event = json.load(fh)
    if "detail" not in event:  # a CloudTrail record on its own
        event = {"detail": event, "region": event.get("awsRegion", ""), "account": event.get("recipientAccountId", "")}

    class _NoEC2:
        def describe_security_groups(self, **_):
            raise RuntimeError("offline")

    items, meta = findings(event, _NoEC2())
    if not items:
        print("no rule opened wide in this event")
        return 0
    print(sg_review.alert_text(meta["account"], "", items, markdown=False))
    return 1 if any(sg_review.SEV_RANK[it["sev"]] <= sg_review.SEV_RANK["high"] for it in items) else 0


if __name__ == "__main__":
    sys.exit(main())
