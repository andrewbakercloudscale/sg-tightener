"""sg_securityhub.py — send sg-tightener findings to AWS Security Hub (ASFF).

Findings land beside GuardDuty, Inspector and Config, with the same workflow, suppression and routing. Each
finding has a stable id, so a finding sent again updates the one already there. Findings that are no longer
open are archived (RecordState ARCHIVED, workflow RESOLVED) the next time findings are sent for that account
and region, from the ids kept in a small state dict.

Used by ``sg_review.py securityhub``, ``sg_review.py watch --securityhub``, ``sg_review.py org --securityhub``
and ``sg_ou_report.py --securityhub``. BatchImportFindings must be called by the account the findings are about,
so the org commands send each account's findings with the role they assume in it.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import logging

LOG = logging.getLogger("sg_securityhub")

SCHEMA = "2018-10-08"
BATCH = 100  # BatchImportFindings takes at most 100 findings a call
SEV_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFORMATIONAL",
             "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFO": "INFORMATIONAL"}
REACH = "Software and Configuration Checks/AWS Security Best Practices/Network Reachability"
TYPES = {
    "drift": ["Software and Configuration Checks/AWS Security Best Practices/Network Reachability",
              "Unusual Behaviors/User"],
    "refused": ["Unusual Behaviors/Network Flow"],
    "active": ["TTPs/Initial Access", "Unusual Behaviors/Network Flow"],
    "egress-bad": ["TTPs/Command and Control", "Unusual Behaviors/Network Flow"],
}


def _cut(text: str, n: int) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= n else text[: n - 1] + "…"


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def partition_of(region: str) -> str:
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"


def product_arn(account: str, region: str) -> str:
    """The account's own "default" product: the one any account may import custom findings into."""
    return f"arn:{partition_of(region)}:securityhub:{region}:{account}:product/{account}/default"


def finding_id(account: str, region: str, key: str) -> str:
    return f"sg-tightener/{account}/{region}/{hashlib.sha256(key.encode()).hexdigest()[:32]}"


def resource(account: str, region: str, group: str = "", name: str = "", kind: str = "") -> dict:
    if group.startswith("sg-"):
        return {"Type": "AwsEc2SecurityGroup", "Region": region, "Partition": partition_of(region),
                "Id": f"arn:{partition_of(region)}:ec2:{region}:{account}:security-group/{group}"}
    if name.startswith("vpce-svc-"):
        return {"Type": "AwsEc2VpcEndpointService", "Region": region, "Partition": partition_of(region),
                "Id": f"arn:{partition_of(region)}:ec2:{region}:{account}:vpc-endpoint-service/{name}"}
    if name.startswith("acl-"):
        return {"Type": "AwsEc2NetworkAcl", "Region": region, "Partition": partition_of(region),
                "Id": f"arn:{partition_of(region)}:ec2:{region}:{account}:network-acl/{name}"}
    return {"Type": "Other", "Region": region, "Partition": partition_of(region), "Id": _cut(name or kind or account, 512)}


def to_asff(account: str, region: str, key: str, sev: str, title: str, description: str, *, generator: str,
            recommendation: str = "", types: list[str] | None = None, group: str = "", name: str = "",
            kind: str = "", fields: dict | None = None, now: str | None = None) -> dict:
    """One ASFF finding. `key` makes the id: the same key is the same finding from one run to the next."""
    now = now or _now()
    f = {
        "SchemaVersion": SCHEMA,
        "Id": finding_id(account, region, key),
        "ProductArn": product_arn(account, region),
        "GeneratorId": _cut(f"sg-tightener/{generator}", 512),
        "AwsAccountId": account,
        "Types": types or [REACH],
        "CreatedAt": now,
        "UpdatedAt": now,
        "Severity": {"Label": SEV_LABEL.get(sev, "INFORMATIONAL")},
        "Title": _cut(title, 256),
        "Description": _cut(description, 1024),
        "ProductName": "sg-tightener",
        "CompanyName": "sg-tightener",
        "Resources": [resource(account, region, group, name, kind)],
        "RecordState": "ACTIVE",
        "Workflow": {"Status": "NEW"},
        "ProductFields": {k: _cut(v, 1024) for k, v in (fields or {}).items() if v not in (None, "")},
    }
    if recommendation:
        f["Remediation"] = {"Recommendation": {"Text": _cut(recommendation, 512)}}
    return f


def from_review_item(account: str, it: dict, key: str, now: str | None = None) -> dict:
    """An sg_review "Needs attention", PrivateLink, exposure or drift item as ASFF."""
    region = it.get("region") or "us-east-1"
    kind = it.get("kind", "")
    types = TYPES.get(it.get("key", "")) or TYPES.get(kind) or [REACH]
    desc = it.get("reason", "")
    if it.get("srcs"):
        desc += f" Sources: {', '.join(it['srcs'][:5])}" + (f" and {len(it['srcs']) - 5} more" if len(it["srcs"]) > 5 else "")
    rec = it.get("action", "")
    if it.get("cli"):
        rec += " Command: " + it["cli"].splitlines()[0]
    return to_asff(account, region, key, it["sev"], f"{it.get('label', '')}: {it['title']}", desc,
                   generator=f"sg_review/{kind}/{it.get('key', '')}", recommendation=rec, types=types,
                   group=it.get("group", ""), name=it.get("name", ""), kind=kind,
                   fields={"sg-tightener/kind": kind, "sg-tightener/key": it.get("key", ""),
                           "sg-tightener/target": it.get("target", ""), "sg-tightener/area": it.get("area", "")},
                   now=now)  # fmt: skip


def from_ou_finding(f: dict, now: str | None = None) -> dict:
    """An sg_ou_report finding (its JSON row) as ASFF."""
    key = "|".join(str(f.get(k, "")) for k in ("resource_type", "resource_id", "cidr", "port_range"))
    rtype = f.get("resource_type", "")
    title = f"{rtype} {f.get('resource_id', '')} allows {f.get('cidr', '')} on {f.get('port_range', '')}"
    if rtype.startswith("PrivateLink service"):
        title = f"{rtype} {f.get('resource_id', '')}: {f.get('cidr', '')}"
    desc = (f"sg_ou_report found {rtype} {f.get('resource_id', '')} in {f.get('region', '')} open to "
            f"{f.get('cidr', '')} on {f.get('port_range', '')}.")
    return to_asff(f["account_id"], f.get("region") or "us-east-1", "ou|" + key, f.get("severity", "MEDIUM").lower(),
                   title, desc, generator=f"sg_ou_report/{rtype}",
                   recommendation="Narrow the rule to the addresses that need it, or remove it.",
                   group=f.get("resource_id", "") if str(f.get("resource_id", "")).startswith("sg-") else "",
                   name=str(f.get("resource_id", "")), kind=rtype, now=now)  # fmt: skip


def archived(f: dict, now: str | None = None) -> dict:
    """The same finding, closed: no longer open at the last check."""
    return {**f, "UpdatedAt": now or _now(), "RecordState": "ARCHIVED", "Workflow": {"Status": "RESOLVED"}}


def plan(findings: list[dict], state: dict, scope: str, now: str | None = None) -> list[dict]:
    """What to send for one account and region (`scope`): today's findings, plus the ones sent before that are
    gone now, archived. `state` keeps, per scope, the findings sent last time; it is updated."""
    sent = state.setdefault("securityhub", {}).setdefault(scope, {})
    current = {f["Id"]: f for f in findings}
    gone = [archived(f, now) for fid, f in sent.items() if fid not in current and f.get("RecordState") == "ACTIVE"]
    state["securityhub"][scope] = {fid: _slim(f) for fid, f in current.items()}
    return list(current.values()) + gone


def _slim(f: dict) -> dict:
    """What is needed to archive the finding later (Security Hub needs the required fields again)."""
    keep = ("SchemaVersion", "Id", "ProductArn", "GeneratorId", "AwsAccountId", "Types", "CreatedAt", "Severity",
            "Title", "Description", "Resources", "RecordState")
    return {k: f[k] for k in keep if k in f}


def send(session, region: str, findings: list[dict]) -> dict:
    """BatchImportFindings in batches of 100: {"sent", "failed", "errors"}."""
    out = {"sent": 0, "failed": 0, "errors": []}
    if not findings:
        return out
    hub = session.client("securityhub", region_name=region)
    for i in range(0, len(findings), BATCH):
        part = findings[i: i + BATCH]
        res = hub.batch_import_findings(Findings=part)
        out["sent"] += int(res.get("SuccessCount", 0))
        out["failed"] += int(res.get("FailedCount", 0))
        out["errors"] += [f"{x.get('Id', '')}: {x.get('ErrorCode', '')} {x.get('ErrorMessage', '')}".strip()
                          for x in res.get("FailedFindings") or []][:10]
    return out


def by_region(findings: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for f in findings:
        region = f["ProductArn"].split(":")[3]
        out.setdefault(region, []).append(f)
    return out
