#!/usr/bin/env python3
"""sg_ou_report.py — OU-wide permissive rule scan and risk ranking.

Walks an AWS Organisation (or a fixed account list), assumes a cross-account
role in each active account, scans every requested region in parallel, and
emits a risk-ranked report sorted from most-permissive account to least.
Severity-weighted ranking is used so a single CRITICAL outranks many LOWs.

Network ACLs are scanned and labelled in the report alongside security
groups, but only security groups are tightened by the rest of the suite.

Exit codes, for use as a pipeline gate: 0 every account and region was
scanned and nothing is CRITICAL; 1 a CRITICAL finding; 2 the scan is
incomplete (a role could not be assumed or a region's scan failed) and
nothing CRITICAL was found in the part that was scanned. Accounts that
could not be scanned are listed in the report with status "failed" or
"incomplete" — they are never shown as clean.

Usage:
  sg_ou_report.py --regions us-east-1,eu-west-1
                  [--ou-id ou-xxxx | --accounts 111,222,333]
                  [--role-name OrganizationAccountAccessRole]
                  [--out report.xlsx] [--json report.json]
                  [--max-workers 16]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as dt
import ipaddress
import json
import logging
import sys
import threading
from typing import Sequence

from sg_tightener import add_profile_arg, friendly_login_errors, use_profile

try:
    import boto3
    from botocore.config import Config as BotoConfig
except ImportError:
    boto3 = None

try:
    import pandas as pd
except ImportError:
    pd = None

LOG = logging.getLogger("sg_ou_report")

# Severity weights — must satisfy:
#   1 CRITICAL > unbounded LOWs;  1 HIGH > unbounded MEDs;  1 MED > unbounded LOWs.
# Geometric weighting with a large base does that cleanly. Keep the base
# wide enough that even pathological account counts can't promote a lower
# severity past a higher one.
W_CRITICAL = 1_000_000
W_HIGH = 10_000
W_MEDIUM = 100
W_LOW = 1


def compute_risk_score(critical: int, high: int, medium: int, low: int) -> int:
    return (
        critical * W_CRITICAL
        + high * W_HIGH
        + medium * W_MEDIUM
        + low * W_LOW
    )


def parse_partition_from_arn(arn: str | None) -> str:
    """Return the AWS partition from an ARN (aws, aws-cn, aws-us-gov).

    Defaults to ``"aws"`` for unknown, malformed, or missing inputs."""
    if not arn or not isinstance(arn, str):
        return "aws"
    parts = arn.split(":")
    if len(parts) < 2:
        return "aws"
    candidate = parts[1]
    if candidate in ("aws", "aws-cn", "aws-us-gov"):
        return candidate
    return "aws"


# --------------------------------------------------------------------------- #
# Severity classification
# --------------------------------------------------------------------------- #

PUBLIC_ANY = ipaddress.ip_network("0.0.0.0/0")
PUBLIC_ANY_V6 = ipaddress.ip_network("::/0")
PUBLIC_NETS = (PUBLIC_ANY, PUBLIC_ANY_V6)
RFC1918_BLOCKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

CRITICAL_PUBLIC_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 9300, 11211}


def _ports_in_range(from_p: int | None, to_p: int | None) -> set[int]:
    if from_p is None or to_p is None:
        return set(range(0, 65536))
    return set(range(int(from_p), int(to_p) + 1))


def classify_sg_rule(cidr: str, from_p: int | None, to_p: int | None) -> str | None:
    """Return one of CRITICAL/HIGH/MEDIUM/LOW or None for in-scope rules."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None
    ports = _ports_in_range(from_p, to_p)
    if net in PUBLIC_NETS:
        if ports & CRITICAL_PUBLIC_PORTS:
            return "CRITICAL"
        return "HIGH"
    if isinstance(net, ipaddress.IPv4Network) and any(net.subnet_of(b) for b in RFC1918_BLOCKS):
        if net.prefixlen <= 16:
            return "HIGH"
        if net.prefixlen <= 20:
            return "MEDIUM"
        if net.prefixlen <= 23:
            return "LOW"
        return None
    return None


def classify_nacl_rule(cidr: str, port_range: dict | None) -> str | None:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None
    if net in PUBLIC_NETS:
        return "HIGH"
    if isinstance(net, ipaddress.IPv4Network) and any(net.subnet_of(b) for b in RFC1918_BLOCKS):
        if net.prefixlen <= 16:
            return "MEDIUM"
        if net.prefixlen <= 20:
            return "LOW"
    return None


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #

@dataclasses.dataclass
class Finding:
    account_id: str
    account_name: str
    region: str
    resource_type: str  # "SG", "NACL", "PrivateLink service", "PrivateLink NLB" or "PrivateLink endpoint"
    resource_id: str
    cidr: str
    port_range: str
    severity: str


def _require_aws():
    if boto3 is None:
        sys.stderr.write("boto3 is required. Activate the venv from ./install.sh\n")
        sys.exit(2)


def _assume(role_arn: str, session_name: str) -> "boto3.Session":
    sts = boto3.client("sts")
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


# boto3 Sessions are not thread-safe; clients are. Create clients under a lock.
_CLIENT_LOCK = threading.Lock()


def _session_client(session, service: str, region: str):
    cfg = BotoConfig(retries={"max_attempts": 10, "mode": "adaptive"})
    with _CLIENT_LOCK:
        return session.client(service, region_name=region, config=cfg)


def _port_label(from_p, to_p) -> str:
    return "all" if from_p is None else f"{from_p}-{to_p}"


def _scan_region(session, account_id: str, account_name: str, region: str
                 ) -> tuple[list[Finding], list[dict]]:
    """Findings for one account and region, and the parts that failed.

    A failed part is returned as an error, never swallowed: a region whose
    scan failed would otherwise look exactly like a clean one."""
    ec2 = _session_client(session, "ec2", region)
    out: list[Finding] = []
    errors: list[dict] = []

    try:
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page.get("SecurityGroups", []):
                for perm in sg.get("IpPermissions", []):
                    cidrs = [ip.get("CidrIp") for ip in perm.get("IpRanges", [])]
                    cidrs += [ip.get("CidrIpv6") for ip in perm.get("Ipv6Ranges", [])]
                    for cidr in filter(None, cidrs):
                        sev = classify_sg_rule(cidr, perm.get("FromPort"), perm.get("ToPort"))
                        if sev:
                            out.append(Finding(
                                account_id, account_name, region, "SG", sg["GroupId"], cidr,
                                _port_label(perm.get("FromPort"), perm.get("ToPort")), sev,
                            ))
    except Exception as exc:  # noqa: BLE001
        LOG.warning("SG scan failed in %s/%s: %s", account_id, region, exc)
        errors.append({"account_id": account_id, "region": region, "stage": "security-groups",
                       "error": str(exc)})

    try:
        for page in ec2.get_paginator("describe_network_acls").paginate():
            for nacl in page.get("NetworkAcls", []):
                for entry in nacl.get("Entries", []):
                    if entry.get("Egress") or entry.get("RuleAction") != "allow":
                        continue
                    cidr = entry.get("CidrBlock") or entry.get("Ipv6CidrBlock")
                    if not cidr:
                        continue
                    sev = classify_nacl_rule(cidr, entry.get("PortRange"))
                    if not sev:
                        continue
                    pr = entry.get("PortRange") or {}
                    port = "all" if not pr else f"{pr.get('From', '?')}-{pr.get('To', '?')}"
                    out.append(Finding(
                        account_id, account_name, region, "NACL",
                        nacl["NetworkAclId"], cidr, port, sev,
                    ))
    except Exception as exc:  # noqa: BLE001
        LOG.warning("NACL scan failed in %s/%s: %s", account_id, region, exc)
        errors.append({"account_id": account_id, "region": region, "stage": "network-acls",
                       "error": str(exc)})

    pl, pl_errors, endpoint_groups = scan_privatelink(session, ec2, account_id, account_name, region)
    for f in out:
        if f.resource_type == "SG" and f.resource_id in endpoint_groups:
            f.resource_type = "SG (PrivateLink endpoint)"
            f.resource_id = f"{f.resource_id} ({endpoint_groups[f.resource_id]})"
    return out + pl, errors + pl_errors


def classify_endpoint_service(principals: list[str], acceptance_required: bool) -> str | None:
    """CRITICAL: any AWS account may connect and connections are accepted without review. HIGH: any account may
    connect, each connection reviewed. LOW: named principals, accepted automatically. None otherwise."""
    anyone = any(p.strip() in ("*", "arn:aws:iam::*:root") for p in principals)
    if anyone:
        return "HIGH" if acceptance_required else "CRITICAL"
    if principals and not acceptance_required:
        return "LOW"
    return None


def scan_privatelink(session, ec2, account_id: str, account_name: str, region: str
                     ) -> tuple[list[Finding], list[dict], dict[str, str]]:
    """PrivateLink that is too open: endpoint services the account provides that any AWS account may connect to,
    or accept automatically; load balancers behind them that do not filter PrivateLink traffic (MEDIUM). Also returns
    {security group id: interface endpoint id}, so the security group findings on an endpoint's groups say so
    (they are rated like any other group's, and not counted twice)."""
    out: list[Finding] = []
    errors: list[dict] = []
    groups: dict[str, str] = {}
    try:
        lb_arns = []
        for page in ec2.get_paginator("describe_vpc_endpoint_service_configurations").paginate():
            for c in page.get("ServiceConfigurations", []):
                sid = c.get("ServiceId", "")
                principals = [p.get("Principal", "") for pg in ec2.get_paginator(
                    "describe_vpc_endpoint_service_permissions").paginate(ServiceId=sid)
                    for p in pg.get("AllowedPrincipals", [])]
                sev = classify_endpoint_service(principals, bool(c.get("AcceptanceRequired")))
                if sev:
                    who = "*" if sev in ("CRITICAL", "HIGH") else ",".join(principals[:3])
                    out.append(Finding(account_id, account_name, region, "PrivateLink service", sid,
                                       f"principal {who}" + ("" if c.get("AcceptanceRequired") else ", auto-accept"),
                                       "-", sev))
                lb_arns += [(sid, a) for a in c.get("NetworkLoadBalancerArns") or []]
        if lb_arns:
            elb = _session_client(session, "elbv2", region)
            arns = sorted({a for _, a in lb_arns})
            for i in range(0, len(arns), 20):
                for lb in elb.describe_load_balancers(LoadBalancerArns=arns[i:i + 20]).get("LoadBalancers", []):
                    off = str(lb.get("EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic", "on")).lower() == "off"
                    if off or not lb.get("SecurityGroups"):
                        out.append(Finding(account_id, account_name, region, "PrivateLink NLB",
                                           lb.get("LoadBalancerName", lb["LoadBalancerArn"]),
                                           "no security group" if not lb.get("SecurityGroups") else
                                           "security groups not applied to PrivateLink traffic", "-", "MEDIUM"))
    except Exception as exc:  # noqa: BLE001
        LOG.warning("PrivateLink service scan failed in %s/%s: %s", account_id, region, exc)
        errors.append({"account_id": account_id, "region": region, "stage": "privatelink-services",
                       "error": str(exc), "optional": True})
    try:
        for page in ec2.get_paginator("describe_vpc_endpoints").paginate(
                Filters=[{"Name": "vpc-endpoint-type", "Values": ["Interface"]}]):
            for v in page.get("VpcEndpoints", []):
                for g in v.get("Groups") or []:
                    groups.setdefault(g.get("GroupId", ""), v.get("VpcEndpointId", ""))
    except Exception as exc:  # noqa: BLE001
        LOG.warning("PrivateLink endpoint scan failed in %s/%s: %s", account_id, region, exc)
        errors.append({"account_id": account_id, "region": region, "stage": "privatelink-endpoints",
                       "error": str(exc), "optional": True})
    return out, errors, groups


def _list_org_accounts(ou_id: str | None) -> list[dict]:
    org = boto3.client("organizations")
    if not ou_id:
        accounts = []
        for page in org.get_paginator("list_accounts").paginate():
            accounts.extend(page.get("Accounts", []))
        return [a for a in accounts if a.get("Status") == "ACTIVE"]
    out = []
    queue = [ou_id]
    while queue:
        cur = queue.pop()
        for page in org.get_paginator("list_accounts_for_parent").paginate(ParentId=cur):
            out.extend(page.get("Accounts", []))
        for page in org.get_paginator("list_organizational_units_for_parent").paginate(ParentId=cur):
            queue.extend(o["Id"] for o in page.get("OrganizationalUnits", []))
    return [a for a in out if a.get("Status") == "ACTIVE"]


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #

def account_status(accounts: list[dict], errors: list[dict]) -> dict[str, str]:
    """{account id: "ok" | "incomplete" | "failed"}. "failed": the role could
    not be assumed, so nothing was scanned; "incomplete": part of a region's
    scan failed. A PrivateLink check that failed ("optional": an older role without the newer
    PrivateLink permissions) is listed with the errors but does not make the account incomplete."""
    out = {}
    for acct in accounts:
        mine = [e for e in errors if e["account_id"] == acct["Id"] and not e.get("optional")]
        if any(e["stage"] == "assume-role" for e in mine):
            out[acct["Id"]] = "failed"
        elif mine:
            out[acct["Id"]] = "incomplete"
        else:
            out[acct["Id"]] = "ok"
    return out


def _aggregate_by_account(findings: list[Finding], accounts: list[dict] | None = None,
                          status: dict[str, str] | None = None) -> list[dict]:
    """Per-account severity counts and risk score. Every account in
    ``accounts`` gets a row, so one with no findings is visibly scanned,
    and ``status`` says whether its scan was complete."""
    by_account: dict[str, dict] = {}
    for acct in accounts or []:
        by_account[acct["Id"]] = {
            "account_id": acct["Id"], "account_name": acct.get("Name", acct["Id"]),
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0,
        }
    for f in findings:
        slot = by_account.setdefault(f.account_id, {
            "account_id": f.account_id,
            "account_name": f.account_name,
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0,
        })
        slot[f.severity] += 1
    rows = list(by_account.values())
    for r in rows:
        r["risk_score"] = compute_risk_score(r["CRITICAL"], r["HIGH"], r["MEDIUM"], r["LOW"])
        r["scan_status"] = (status or {}).get(r["account_id"], "ok")
    # Unscanned accounts first among equals: an unknown is not a zero.
    rows.sort(key=lambda r: (r["risk_score"], r["scan_status"] != "ok"), reverse=True)
    return rows


def exit_code(summary: list[dict], errors: list[dict]) -> int:
    """1 on any CRITICAL finding, else 2 when the scan was incomplete, else 0."""
    total_critical = sum(r["CRITICAL"] for r in summary)
    if total_critical:
        LOG.error("%d CRITICAL findings across estate", total_critical)
        return 1
    if errors:
        failed = sorted({e["account_id"] for e in errors})
        LOG.error("scan INCOMPLETE: %d error(s) in %d account(s) (%s); those accounts are not "
                  "known to be clean", len(errors), len(failed), ", ".join(failed[:20]))
        return 2
    return 0


def assume_all(accounts: list[dict], regions: list[str], partition: str, role_name: str,
               session_name: str) -> tuple[list[tuple[str, str, str]], dict, list[dict]]:
    """Assume ``role_name`` in every account: (jobs, sessions, errors). An
    account whose role cannot be assumed is an error, not a skipped row."""
    jobs: list[tuple[str, str, str]] = []
    sessions: dict[str, "boto3.Session"] = {}
    errors: list[dict] = []
    for acct in accounts:
        role_arn = f"arn:{partition}:iam::{acct['Id']}:role/{role_name}"
        try:
            sessions[acct["Id"]] = _assume(role_arn, session_name)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("could not assume role into %s: %s", acct["Id"], exc)
            errors.append({"account_id": acct["Id"], "region": None, "stage": "assume-role",
                           "error": str(exc)})
            continue
        for region in regions:
            jobs.append((acct["Id"], acct.get("Name", acct["Id"]), region))
    return jobs, sessions, errors


@friendly_login_errors
def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    p = argparse.ArgumentParser(prog="sg_ou_report.py")
    p.add_argument("--regions", required=True, help="comma-separated AWS regions")
    p.add_argument("--ou-id", help="root OU or sub-OU id; default = list all org accounts")
    p.add_argument("--accounts", help="comma-separated explicit account ids")
    p.add_argument("--role-name", default="OrganizationAccountAccessRole")
    p.add_argument("--out", default="report.xlsx")
    p.add_argument("--json", default="report.json")
    p.add_argument("--max-workers", type=int, default=16)
    p.add_argument("--securityhub", action="store_true",
                   help="also send each account's findings to its AWS Security Hub (ASFF)")
    p.add_argument("--securityhub-state", default="securityhub-state.json",
                   help="what was sent last time, so findings no longer open are archived")
    add_profile_arg(p)
    args = p.parse_args(argv)
    use_profile(args.profile)

    _require_aws()
    regions = [r.strip() for r in args.regions.split(",") if r.strip()]

    sts_caller = boto3.client("sts").get_caller_identity()
    partition = parse_partition_from_arn(sts_caller.get("Arn"))

    if args.accounts:
        accounts = [{"Id": a.strip(), "Name": a.strip()} for a in args.accounts.split(",")]
    else:
        accounts = _list_org_accounts(args.ou_id)
    LOG.info("scanning %d accounts across %d regions", len(accounts), len(regions))

    jobs, sessions, errors = assume_all(accounts, regions, partition, args.role_name,
                                        "sg-tightener-ou-report")
    findings: list[Finding] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        futs = {
            pool.submit(_scan_region, sessions[aid], aid, aname, region): (aid, region)
            for aid, aname, region in jobs
        }
        for fut in concurrent.futures.as_completed(futs):
            aid, region = futs[fut]
            try:
                found, errs = fut.result()
                findings.extend(found)
                errors.extend(errs)
            except Exception as exc:  # noqa: BLE001
                LOG.warning("scan failed in %s/%s: %s", aid, region, exc)
                errors.append({"account_id": aid, "region": region, "stage": "scan",
                               "error": str(exc)})

    summary = _aggregate_by_account(findings, accounts, account_status(accounts, errors))
    report = {
        "schema": "sg-tightener.report/v1",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "regions": regions,
        "complete": not errors,
        "errors": errors,
        "findings": [dataclasses.asdict(f) for f in findings],
        "summary": summary,
    }
    with open(args.json, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    if pd is not None:
        with pd.ExcelWriter(args.out, engine="openpyxl") as writer:
            pd.DataFrame(summary).to_excel(writer, sheet_name="summary", index=False)
            pd.DataFrame([dataclasses.asdict(f) for f in findings]).to_excel(
                writer, sheet_name="findings", index=False
            )
            if errors:
                pd.DataFrame(errors).to_excel(writer, sheet_name="errors", index=False)
        LOG.info("wrote %s and %s", args.out, args.json)
    else:
        LOG.info("pandas not installed; wrote JSON only at %s", args.json)

    if args.securityhub:
        send_to_securityhub(report["findings"], sessions, args.securityhub_state, regions)
    return exit_code(summary, errors)


def send_to_securityhub(rows: list[dict], sessions: dict, state_path: str, regions: Sequence[str] = ()) -> dict:
    """Each account's findings to its own Security Hub (BatchImportFindings must come from that account), with
    the session assumed in it; findings sent last time that are gone are archived."""
    import sg_securityhub

    try:
        with open(state_path, encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        state = {}
    now = sg_securityhub._now()
    by_acct: dict[str, list[dict]] = {}
    for r in rows:
        by_acct.setdefault(r["account_id"], []).append(sg_securityhub.from_ou_finding(r, now))
    total = {"sent": 0, "failed": 0, "archived": 0}
    for aid, sess in sessions.items():
        grouped = sg_securityhub.by_region(by_acct.get(aid, []))
        for region in sorted(set(grouped) | set(regions)):
            todo = sg_securityhub.plan(grouped.get(region, []), state, f"{aid}/{region}", now)
            if not todo:
                continue
            try:
                res = sg_securityhub.send(sess, region, todo)
            except Exception as exc:  # noqa: BLE001 - one account's Security Hub must not stop the others
                LOG.warning("%s/%s: not sent to Security Hub: %s", aid, region, exc)
                continue
            total["sent"] += res["sent"]
            total["failed"] += res["failed"]
            total["archived"] += sum(1 for f in todo if f["RecordState"] == "ARCHIVED")
    with open(state_path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=1)
    LOG.info("Security Hub: %d finding(s) sent, %d archived, %d refused", total["sent"], total["archived"],
             total["failed"])
    return total


if __name__ == "__main__":
    sys.exit(main())
