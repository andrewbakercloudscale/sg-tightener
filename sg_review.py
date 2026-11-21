#!/usr/bin/env python3
"""sg_review.py — every inbound security group rule in an account, set against the traffic its flow logs carried.

Read-only. Answers, over 24 hours to 6 months, for one account at a time:

* refused sources: who the rules (or a network ACL) turned away, which need a rule only if wanted;
* over-provisioned addresses: per logged security group, the addresses its rules let in at each time that
  were never seen anywhere in the account, worked back through CloudTrail's record of rule changes;
* active sources: who was let in, with those not seen in the last 24 hours apart (DR tests, failovers,
  month-end batches: the sources a tightening would hurt without warning).

Every source is named: this account's VPCs and the ranges you call internal, data centres (named ranges,
VPN routes, other private space), AWS (and which service), SaaS providers, or any other network by AS number.
Partners and other networks you know can be named in a names file (``~/.sg-tightener/names.yaml``, or
``--names``): ranges and AS numbers, each with a name and a type.
The naming lists download to ``~/.sg-tightener/ipintel`` and are looked up locally: no address leaves the machine.

Modes:
  read      Read the account's security groups, interfaces, network ACLs, VPN routes, flow logs and 90 days
            of rule changes, then its VPC flow logs in CloudWatch Logs by Logs Insights, a slice at a time
            (hourly for the last day, six-hourly for the last week, daily beyond). Slices are kept in
            ``~/.sg-tightener/review/<account>.json.gz``, so a later read fills only the gap. Logs Insights
            bills about US$0.005 a GB scanned: the cost is estimated and confirmed before reading.
  report    Write one self-contained HTML page (no server, no network) with the three timelines, the rules
            table and what to change, the CSV and an approved.json per region to download.
  approved  Write sg-tightener's approved.json (v2) for one region from what was read.
  demo      Write the report for a made-up account, to see it without AWS.
  names     Check the names file, or write an example one if there is none.
  forget    Delete what was read for an account.

Usage:
  sg_review.py read     --regions eu-west-1[,us-east-1] [--days 1|7|30|90|180] [--profile P] [--yes]
  sg_review.py report   [--account ID] [--onprem "10.200.0.0/16 Johannesburg DC, ..."]
                        [--internal "10.40.0.0/16 Payments prod, ..."] [--names FILE] [--offline] [--out FILE]
  sg_review.py approved --region R [--account ID] [--out approved.json]
  sg_review.py demo     [--offline] [--out sg-review-demo.html]
  sg_review.py names    [--out FILE]
  sg_review.py forget   --account ID
"""

from __future__ import annotations

import argparse
import gzip
import html
import ipaddress
import json
import logging
import os
import random
import re
import signal
import sys
import tempfile
import threading
import time
from bisect import bisect_right
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Sequence

from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError

import sg_ipintel
import sg_tightener

LOG = logging.getLogger("sg_review")
log = LOG

ASSETS = Path(__file__).resolve().parent / "assets"
BOTO_CONFIG = BotoConfig(retries={"max_attempts": 10, "mode": "adaptive"}, connect_timeout=10, read_timeout=60,
                         max_pool_connections=32, user_agent_extra="sg-tightener-review")  # fmt: skip
DEFAULT_FORMAT = ("${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} "
                  "${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}")  # fmt: skip
_THROTTLE_MARKS = ("throttl", "toomanyrequests", "requestlimitexceeded", "slowdown", "ratelimit")


def _is_throttle(exc: BaseException) -> bool:
    if not isinstance(exc, ClientError):
        return False
    err = exc.response.get("Error", {})
    code = str(err.get("Code", "")).replace(" ", "").lower()
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return status == 429 or any(m in code for m in _THROTTLE_MARKS)


def with_backoff(fn: Callable, attempts: int = 7, sleep: Callable = time.sleep):
    """fn(), retried on throttling after 1, 2, 4 ... seconds (capped at 30), with jitter."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if not _is_throttle(exc) or attempt == attempts - 1:
                raise
            wait = min(30.0, 2.0**attempt) * random.uniform(0.5, 1.0)
            LOG.debug("throttled, retrying in %.1fs", wait)
            sleep(wait)
    raise AssertionError("unreachable")


def describe_error(exc: BaseException) -> str:
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        return f"{err.get('Code', 'Error')}: {err.get('Message', '')}".strip()
    return f"{type(exc).__name__}: {exc}"


def vpc_cidrs(vpcs: list[dict]) -> list[str]:
    out = []
    for v in vpcs:
        for a in v.get("CidrBlockAssociationSet") or [
            {"CidrBlock": v.get("CidrBlock"), "CidrBlockState": {"State": "associated"}}
        ]:
            if a.get("CidrBlock") and (a.get("CidrBlockState") or {}).get("State", "associated") == "associated":
                out.append(a["CidrBlock"])
    return sorted(set(out))


def eni_kind(eni: dict) -> str:
    """What a network interface belongs to, in a few words."""
    desc = eni.get("Description") or ""
    kind = eni.get("InterfaceType") or ""
    if kind == "nat_gateway" or desc.startswith("Interface for NAT Gateway"):
        return "NAT gateway"
    if desc.startswith("ELB "):
        return "load balancer"
    if (eni.get("Attachment") or {}).get("InstanceId"):
        return "EC2 instance"
    if desc.startswith("RDSNetworkInterface"):
        return "RDS database"
    if desc.startswith("arn:aws:ecs") or eni.get("RequesterId") == "ecs":
        return "ECS task"
    if kind and kind != "interface":
        return kind.replace("_", " ")
    return desc[:40] or "network interface"


def parse_ranges(text: str, default: str) -> list[tuple]:
    """Named IPv4 ranges, one per comma or line: "10.200.0.0/16 Johannesburg DC" (the name is optional)."""
    out = []
    for part in (text or "").replace("\n", ",").split(","):
        words = part.split()
        if not words:
            continue
        try:
            net = ipaddress.ip_network(words[0], strict=False)
        except ValueError:
            continue
        if net.version == 4 and net.prefixlen:
            out.append((net, " ".join(words[1:]) or f"{default} {net}"))
    return out


# ------------------------------------------------------------------------------------------ names file
NAME_TYPES = ("partner", "internal", "datacentre", *[g for g in sg_ipintel.GROUPS if g != "partner"])
NAMES_EXAMPLE = """\
# sg-tightener names: networks you know, shown by name on the Security Group Review page.
# type: partner (default), internal, datacentre, saas, security, cdn, hosting, scanner, anon or other.
- name: Acme payroll
  type: partner
  ranges: [203.0.113.0/24]
  asn: [64500]
  note: SFTP drop, contract 2024-17
"""


def names_path() -> Path:
    return sg_ipintel.DATA_DIR / "names.yaml"


def parse_names(doc) -> list[dict]:
    """The entries of a names file, checked: [{name, type, ranges: [IPv4Network], asn: [int], note}]."""
    if isinstance(doc, dict):
        doc = doc.get("names", doc.get("networks"))
    if doc is None:
        return []
    if not isinstance(doc, list):
        raise TypeError("a names file is a list of entries, each with a name and ranges or asn")
    out = []
    for i, e in enumerate(doc, 1):
        if not isinstance(e, dict) or not str(e.get("name") or "").strip():
            raise ValueError(f"entry {i}: needs a name")
        name = str(e["name"]).strip()
        typ = str(e.get("type") or "partner").strip().lower()
        if typ not in NAME_TYPES:
            raise ValueError(f"{name}: type {typ!r} is not one of {', '.join(NAME_TYPES)}")
        ranges, asns = [], []
        for c in e.get("ranges") or e.get("cidrs") or []:
            try:
                net = ipaddress.ip_network(str(c).strip(), strict=False)
            except ValueError:
                raise ValueError(f"{name}: {c!r} is not a range") from None
            if net.version == 4:
                ranges.append(net)
        for a in e.get("asn") or []:
            try:
                asns.append(int(str(a).strip().upper().removeprefix("AS")))
            except ValueError:
                raise ValueError(f"{name}: {a!r} is not an AS number") from None
        if typ in ("internal", "datacentre") and asns:
            raise ValueError(f"{name}: an {typ} entry takes ranges, not AS numbers")
        if not ranges and not asns:
            raise ValueError(f"{name}: needs ranges or asn")
        out.append({"name": name, "type": typ, "ranges": ranges, "asn": asns, "note": str(e.get("note") or "").strip()})
    return out


def load_names(path=None) -> list[dict]:
    """The names file at path (YAML or JSON), or the default one if it exists; [] when there is none."""
    p = Path(path).expanduser() if path else names_path()
    if not p.exists():
        if path:
            raise SystemExit(f"names file {p} not found")
        return []
    text = p.read_text()
    bad: tuple = (ValueError, TypeError)
    try:
        if p.suffix.lower() == ".json":
            doc = json.loads(text)
        else:
            try:
                import yaml
            except ImportError:
                raise SystemExit("reading a YAML names file needs PyYAML: pip install pyyaml (or use .json)") from None
            bad = (*bad, yaml.YAMLError)
            doc = yaml.safe_load(text)
        return parse_names(doc)
    except bad as exc:
        raise SystemExit(f"names file {p}: {exc}") from None


# ------------------------------------------------------------------------------------- flow-log reads

ROWS = 10000  # the most rows one Logs Insights query returns
EPHEMERAL = 32768  # ports from here up are folded into one: replies to the account's own connections land there
PRIVATE_V4 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
NEEDED = ("srcaddr", "dstaddr", "dstport", "protocol", "action", "interface_id")
HISTORY_DAYS = 90
HISTORY_EVENTS = ("AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress", "ModifySecurityGroupRules")
HISTORY_PAGES = 20  # 50 events a page, per event name and region
VPC_FILTER_MAX = 40  # more VPC ranges than this and the inbound filter is left to the report


def _pages(client, op: str, key: str, **kw) -> list:
    out = []
    pager = client.get_paginator(op)
    for page in with_backoff(lambda: list(pager.paginate(**kw))):
        out += page.get(key) or []
    return out


def _name(tags) -> str:
    return next((t.get("Value", "") for t in tags or [] if t.get("Key") == "Name"), "")


def fields_of(log_format: str | None) -> list[str]:
    return [f.strip("${}").replace("-", "_") for f in (log_format or DEFAULT_FORMAT).split()]


def readable(log_format: str | None) -> bool:
    return set(NEEDED) <= set(fields_of(log_format))


def _private(field: str) -> str:
    return "(" + " or ".join(f'isIpv4InSubnet({field}, "{c}")' for c in PRIVATE_V4) + ")"


def _base(log_format: str | None, vpc_ranges: list[str]) -> tuple[str, str, str, bool] | None:
    """The parse and the inbound filter for a format: (query head, source field, target field, filtered by
    direction). Inbound is the flow-direction field when the format has it, else a target inside the
    account's VPCs (the report drops the interface's own outbound records)."""
    fields = fields_of(log_format)
    if not set(NEEDED) <= set(fields):
        return None
    src = "f_pkt_srcaddr" if "pkt_srcaddr" in fields else "f_srcaddr"
    dst = "f_pkt_dstaddr" if "pkt_dstaddr" in fields else "f_dstaddr"
    head = f'parse @message "{" ".join("*" for _ in fields)}" as {", ".join("f_" + f for f in fields)}'
    head += f' | filter {src} != "-" and {dst} != "-"'
    by_dir = "flow_direction" in fields
    if by_dir:
        head += ' and f_flow_direction = "ingress"'
    elif vpc_ranges and len(vpc_ranges) <= VPC_FILTER_MAX:
        head += " and (" + " or ".join(f'isIpv4InSubnet({dst}, "{c}")' for c in vpc_ranges) + ")"
    return head, src, dst, by_dir


def detail_query(log_format: str | None, vpc_ranges: list[str], fold: bool = True) -> str | None:
    """Accepted inbound connections, and refused ones from private addresses, by source, target, interface,
    protocol, port (ports from EPHEMERAL up folded into one when ``fold``) and action."""
    b = _base(log_format, vpc_ranges)
    if not b:
        return None
    head, src, dst, _ = b
    port = f"least(f_dstport, {EPHEMERAL})" if fold else "f_dstport"
    return (
        f'{head} and (f_action = "ACCEPT" or {_private(src)})'
        f" | fields {port} as dport"
        f" | stats count(*) as flows, sum(f_bytes) as bytes by {src} as src, {dst} as dst,"
        f" f_interface_id as eni, f_protocol as proto, dport, f_action as action | limit {ROWS}"
    )


def public_query(log_format: str | None, vpc_ranges: list[str]) -> str | None:
    """Refused inbound connections from internet addresses, one row per source: how many, on how many ports
    and targets, and the last target, interface, port and protocol (exact when there was only one)."""
    b = _base(log_format, vpc_ranges)
    if not b:
        return None
    head, src, dst, _ = b
    return (
        f'{head} and f_action = "REJECT" and not {_private(src)}'
        f" | stats count(*) as flows, count_distinct(f_dstport) as ports, count_distinct({dst}) as dsts,"
        f" latest({dst}) as dst, latest(f_interface_id) as eni, latest(f_dstport) as port,"
        f" latest(f_protocol) as proto by {src} as src | sort flows desc | limit {ROWS}"
    )


def run_query(logs, groups: list[str], query: str, start: int, end: int, wait: float = 900,
              cancelled=lambda: False) -> tuple[list[dict] | None, int, str]:  # fmt: skip
    """(rows or None, bytes scanned, status) of one Logs Insights query over [start, end)."""
    qid = with_backoff(
        lambda: logs.start_query(
            logGroupNames=groups[:50], startTime=int(start), endTime=int(end) - 1, queryString=query, limit=ROWS
        )  # fmt: skip
    )["queryId"]
    waited, pause = 0.0, 1.0
    while waited < wait and not cancelled():
        res = with_backoff(lambda: logs.get_query_results(queryId=qid))
        status = res.get("status")
        scanned = int(float((res.get("statistics") or {}).get("bytesScanned") or 0))
        if status == "Complete":
            return [{c["field"]: c.get("value") for c in row} for row in res.get("results") or []], scanned, status
        if status in ("Failed", "Cancelled", "Timeout", "Unknown"):
            return None, scanned, status
        time.sleep(pause)
        waited += pause
        pause = min(pause * 1.5, 10)
    try:
        logs.stop_query(queryId=qid)
    except (ClientError, BotoCoreError) as exc:
        log.debug("could not stop query %s: %s", qid, exc)
    return None, 0, "Cancelled" if cancelled() else "Timeout"


# ------------------------------------------------------------------------------------------- snapshot
def _rule(perm: dict) -> dict:
    proto = str(perm.get("IpProtocol", "-1"))
    proto = {"tcp": "6", "udp": "17", "icmp": "1", "icmpv6": "58"}.get(proto, proto)
    lo, hi = perm.get("FromPort"), perm.get("ToPort")
    if proto == "-1" or lo in (None, -1):
        lo, hi = 0, 65535
    return {
        "proto": proto,
        "from": int(lo),
        "to": int(hi if hi not in (None, -1) else 65535),
        "cidrs": [r["CidrIp"] for r in perm.get("IpRanges") or [] if r.get("CidrIp")],
        "descs": {r["CidrIp"]: r["Description"] for r in perm.get("IpRanges") or [] if r.get("Description")},
        "pls": [p["PrefixListId"] for p in perm.get("PrefixListIds") or [] if p.get("PrefixListId")],
        "refs": [p.get("GroupId", "") for p in perm.get("UserIdGroupPairs") or []],
        "any6": any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges") or []),
    }


def snapshot(session, region: str) -> dict:
    ec2 = session.client("ec2", region_name=region, config=BOTO_CONFIG)
    out: dict = {"errors": []}
    vpcs = _pages(ec2, "describe_vpcs", "Vpcs")
    out["vpcs"] = [{"id": v["VpcId"], "name": _name(v.get("Tags")), "cidrs": vpc_cidrs([v])} for v in vpcs]
    out["groups"] = {
        g["GroupId"]: {
            "name": g.get("GroupName", ""),
            "vpc": g.get("VpcId", ""),
            "tag": _name(g.get("Tags")),
            "rules": [_rule(p) for p in g.get("IpPermissions") or []],
        }  # fmt: skip
        for g in _pages(ec2, "describe_security_groups", "SecurityGroups")
    }
    enis = {}
    for e in _pages(ec2, "describe_network_interfaces", "NetworkInterfaces"):
        ips = [a["PrivateIpAddress"] for a in e.get("PrivateIpAddresses") or [] if a.get("PrivateIpAddress")]
        enis[e["NetworkInterfaceId"]] = {
            "ips": ips,
            "prefixes": [p["Ipv4Prefix"] for p in e.get("Ipv4Prefixes") or [] if p.get("Ipv4Prefix")],
            "groups": [g["GroupId"] for g in e.get("Groups") or []],
            "subnet": e.get("SubnetId", ""),
            "vpc": e.get("VpcId", ""),
            "kind": eni_kind(e),
            "desc": (e.get("Description") or "")[:80],
            "instance": (e.get("Attachment") or {}).get("InstanceId", ""),
            "public": (e.get("Association") or {}).get("PublicIp", ""),
        }
    out["enis"] = enis
    pls: dict = {}
    for pid in sorted({p for g in out["groups"].values() for r in g["rules"] for p in r["pls"]}):
        try:
            pls[pid] = [x["Cidr"] for x in _pages(ec2, "get_managed_prefix_list_entries", "Entries", PrefixListId=pid)
                        if x.get("Cidr") and ":" not in x["Cidr"]]  # fmt: skip
        except (ClientError, BotoCoreError) as exc:
            out["errors"].append(f"prefix list {pid}: {exc}")
    out["prefix_lists"] = pls
    nacls = {}
    for n in _pages(ec2, "describe_network_acls", "NetworkAcls"):
        entries = sorted(
            (
                {"n": x.get("RuleNumber", 32767), "proto": str(x.get("Protocol", "-1")),
                 "allow": x.get("RuleAction") == "allow", "cidr": x.get("CidrBlock", ""),
                 "from": (x.get("PortRange") or {}).get("From", 0),
                 "to": (x.get("PortRange") or {}).get("To", 65535)}
                for x in n.get("Entries") or [] if not x.get("Egress") and x.get("CidrBlock")
            ),
            key=lambda x: x["n"],
        )  # fmt: skip
        for a in n.get("Associations") or []:
            nacls[a.get("SubnetId", "")] = {"id": n.get("NetworkAclId", ""), "entries": entries}
    out["nacls"] = nacls
    try:
        out["vpns"] = [{"name": _name(v.get("Tags")) or v["VpnConnectionId"],
                        "routes": [r["DestinationCidrBlock"] for r in v.get("Routes") or []
                                   if r.get("DestinationCidrBlock")]}
                       for v in with_backoff(lambda: ec2.describe_vpn_connections())["VpnConnections"]
                       if v.get("State") != "deleted"]  # fmt: skip
    except (ClientError, BotoCoreError) as exc:
        out["vpns"] = []
        out["errors"].append(f"VPN connections: {exc}")
    out["flow_logs"] = [
        {"id": f.get("FlowLogId", ""), "resource": f.get("ResourceId", ""), "traffic": f.get("TrafficType", ""),
         "dest": f.get("LogDestinationType", "cloud-watch-logs"), "group": f.get("LogGroupName", ""),
         "format": f.get("LogFormat") or DEFAULT_FORMAT, "status": f.get("FlowLogStatus", ""),
         "created": f["CreationTime"].timestamp() if hasattr(f.get("CreationTime"), "timestamp") else None}
        for f in _pages(ec2, "describe_flow_logs", "FlowLogs")
    ]  # fmt: skip
    return out


# -------------------------------------------------------------------------------------------- history
def _items(x) -> list:
    if isinstance(x, dict):
        return x.get("items") or []
    return x or []


def _perm_entries(perms) -> list[list]:
    """[proto, from, to, source] for each IPv4 range and prefix list in CloudTrail's ipPermissions."""
    out = []
    for p in _items(perms):
        r = _rule({"IpProtocol": p.get("ipProtocol"), "FromPort": p.get("fromPort"), "ToPort": p.get("toPort")})
        for x in _items(p.get("ipRanges")):
            if x.get("cidrIp"):
                out.append([r["proto"], r["from"], r["to"], x["cidrIp"]])
        for x in _items(p.get("prefixListIds")):
            if x.get("prefixListId"):
                out.append([r["proto"], r["from"], r["to"], x["prefixListId"]])
    return out


def parse_event(ev: dict) -> dict | None:
    """One CloudTrail record as {t, group, added, removed, unknown, who, name}; None for a failed call."""
    try:
        doc = json.loads(ev.get("CloudTrailEvent") or "{}")
    except ValueError:
        return None
    if doc.get("errorCode"):
        return None
    name = doc.get("eventName") or ev.get("EventName", "")
    req = doc.get("requestParameters") or {}
    t = ev.get("EventTime")
    t = t.timestamp() if hasattr(t, "timestamp") else None
    if t is None:
        try:
            t = datetime.fromisoformat(doc.get("eventTime", "").replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    ident = doc.get("userIdentity") or {}
    who = (ident.get("arn") or ident.get("principalId") or "").split("/")[-1][:80]
    out = {"t": t, "name": name, "who": who, "added": [], "removed": [], "unknown": False}
    if name == "ModifySecurityGroupRules":
        inner = req.get("ModifySecurityGroupRulesRequest") or req
        out["group"] = inner.get("GroupId") or inner.get("groupId") or ""
        out["unknown"] = True  # the rule's earlier value is not in the event
        return out
    out["group"] = req.get("groupId") or ""
    entries = _perm_entries(req.get("ipPermissions"))
    if name == "RevokeSecurityGroupIngress" and _items(req.get("securityGroupRuleIds")) and not entries:
        out["unknown"] = True  # revoked by rule id: which range it was is not in the event
    out["added" if name == "AuthorizeSecurityGroupIngress" else "removed"] = entries
    return out if out["group"] else None


def rule_history(session, region: str, now: datetime, days: int = HISTORY_DAYS) -> dict:
    """Inbound rule changes in ``region``, oldest first, and from when the list is whole."""
    ct = session.client("cloudtrail", region_name=region, config=BOTO_CONFIG)
    since = now - timedelta(days=days)
    events, whole_since = [], since.timestamp()
    for name in HISTORY_EVENTS:
        token, pages = None, 0
        while True:
            kw = {"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": name}], "StartTime": since,
                  "EndTime": now, "MaxResults": 50}  # fmt: skip
            if token:
                kw["NextToken"] = token
            page = with_backoff(lambda kw=kw: ct.lookup_events(**kw))
            for ev in page.get("Events") or []:
                parsed = parse_event(ev)
                if parsed:
                    events.append(parsed)
            token, pages = page.get("NextToken"), pages + 1
            if not token:
                break
            if pages >= HISTORY_PAGES:  # too many to read: the history is whole only back to the oldest read
                oldest = min((e["t"] for e in events if e["name"] == name), default=now.timestamp())
                whole_since = max(whole_since, oldest)
                break
    events.sort(key=lambda e: e["t"])
    return {"events": events, "whole_since": whole_since, "read": True}


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


# ------------------------------------------------------------------------------------------- review

SCHEMA = 1
HOUR, SIX, DAY = 3600, 6 * 3600, 86400
READ_DAYS = (1, 7, 30, 90, 180)
RANGES = {
    "24h": (DAY, HOUR),
    "1w": (7 * DAY, SIX),
    "1m": (30 * DAY, DAY),
    "3m": (90 * DAY, DAY),
    "6m": (180 * DAY, DAY),
}
LAG = 900  # flow logs reach CloudWatch up to ~10 minutes late: the newest quarter hour is left for the next read
WORKERS = 4
EVIDENCE_DAYS = 30  # fewer days of flow logs than this and no rule is called unused or ready to tighten
INSIGHTS_PER_GB = 0.005
TOP = 400  # sources listed per table (the charts count all of them)
CATS = ("internal", "datacentre", "aws", "saas", "internet")
CAT_NAME = {"internal": "Internal (your VPCs)", "datacentre": "Data centre and other private",
            "aws": "AWS", "saas": "External: SaaS and partners", "internet": "External: other networks"}  # fmt: skip
PRIVATE = [sg_ipintel.cidr_iv(c) for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]
ALL = [(0, 2**32 - 1)]
_ACCT_RE = re.compile(r"^[0-9]{12}$")


# ------------------------------------------------------------------------------------------- cache
def _dir():
    d = sg_ipintel.DATA_DIR / "review"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def cached_accounts() -> list[str]:
    return sorted(p.name.split(".")[0] for p in _dir().glob("*.json.gz") if _ACCT_RE.fullmatch(p.name.split(".")[0]))


def _path(account: str):
    if not _ACCT_RE.fullmatch(account or ""):
        raise KeyError(account)
    return _dir() / f"{account}.json.gz"


def load(account: str) -> dict | None:
    try:
        with gzip.open(_path(account), "rt") as f:
            doc = json.load(f)
    except (OSError, ValueError, EOFError):
        return None
    return doc if doc.get("schema") == SCHEMA else None


def save(doc: dict) -> None:
    path = _path(doc["account"])
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    with os.fdopen(fd, "wb") as raw, gzip.open(raw, "wt") as f:
        json.dump(doc, f, separators=(",", ":"))
    os.replace(tmp, path)


def forget(account: str) -> bool:
    try:
        _path(account).unlink()
        return True
    except FileNotFoundError:
        return False


def new_doc(account: str, name: str, mode: str = "live") -> dict:
    return {"schema": SCHEMA, "account": account, "name": name, "mode": mode, "regions": {}, "chunks": [],
            "reads": []}  # fmt: skip


# ---------------------------------------------------------------------------------------- planning
def _floor(t: float, step: int) -> int:
    return int(t // step * step)


def read_end(now: float) -> int:
    return _floor(now - LAG, HOUR)


def plan(now: float, days: int, have=()) -> list[tuple[int, int]]:
    """The slices still to read for the last ``days``, newest first: hourly back to the six-hour boundary
    before a day ago, six-hourly back to the midnight before a week ago, then daily (all UTC). ``have`` is
    the (start, end) of slices already read; only what they leave uncovered is planned."""
    end = read_end(now)
    h0 = _floor(end - DAY, SIX)
    s0 = _floor(end - 7 * DAY, DAY)
    d0 = _floor(end - days * DAY, DAY)
    want = [(t, min(t + HOUR, end)) for t in range(h0, end, HOUR)]
    if days > 1:
        want += [(t, t + SIX) for t in range(s0, h0, SIX)]
    if days > 7:
        want += [(t, t + DAY) for t in range(d0, s0, DAY)]
    covered = sg_ipintel.merge([(s, e - 1) for s, e in have if e > s])
    out = []
    for s, e in want:
        for a, b in sg_ipintel.subtract([(s, e - 1)], covered):
            out.append((a, b + 1))
    return sorted(out, reverse=True)


def query_sets(snap: dict) -> list[dict]:
    """The flow logs one region's queries read: CloudWatch Logs destinations, active, in a format that has
    the fields needed, grouped by format (one query per format)."""
    by_fmt: dict[str, set] = {}
    for f in snap.get("flow_logs") or []:
        if (
            f["dest"] == "cloud-watch-logs"
            and f["group"]
            and f["status"] in ("ACTIVE", "")
            and readable(f["format"])
        ):
            by_fmt.setdefault(f["format"], set()).add(f["group"])  # fmt: skip
    return [{"format": k, "groups": sorted(v)} for k, v in sorted(by_fmt.items())]


def _vpc_ranges(snap: dict) -> list[str]:
    return sorted({c for v in snap.get("vpcs") or [] for c in v.get("cidrs") or [] if ":" not in c})


def _stamp(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%d %b %H:%M")


def read_chunk(logs, region: str, s: int, e: int, qsets: list, vpcs: list, cancelled=lambda: False) -> list[dict]:
    """One slice read (split in halves, down to an hour, while the detail query hits the row limit)."""
    rows, pub, nbytes, cut, pub_cut, errors = [], [], 0, False, False, []
    for q in qsets:
        rs, b, status = None, 0, ""
        for fold in (True, False):
            query = detail_query(q["format"], vpcs, fold=fold)
            rs, b, status = run_query(logs, q["groups"], query, s, e, cancelled=cancelled)
            nbytes += b
            if rs is not None or status in ("Cancelled", "Timeout"):
                break
        if rs is None:
            errors.append(f"detail query {status}")
            continue
        if len(rs) >= ROWS:
            if e - s > HOUR:
                mid = s + _floor((e - s) // 2, HOUR) if e - s >= 2 * HOUR else (s + e) // 2
                parts = [
                    *read_chunk(logs, region, mid, e, qsets, vpcs, cancelled),
                    *read_chunk(logs, region, s, mid, qsets, vpcs, cancelled),
                ]
                parts[0]["b"] += nbytes  # the full slice's query was billed too
                return parts  # fmt: skip
            cut = True
        rows += [[r.get("src"), r.get("dst"), r.get("eni"), r.get("proto"), _int(r.get("dport")), r.get("action"),
                  _int(r.get("flows"))] for r in rs]  # fmt: skip
        ps, b, status = run_query(logs, q["groups"], public_query(q["format"], vpcs), s, e,
                                           cancelled=cancelled)  # fmt: skip
        nbytes += b
        if ps is None:
            errors.append(f"refused-internet query {status}")
            continue
        pub_cut = pub_cut or len(ps) >= ROWS
        pub += [[r.get("src"), _int(r.get("flows")), _int(r.get("ports")), _int(r.get("dsts")), r.get("dst"),
                 r.get("eni"), _int(r.get("port")), r.get("proto")] for r in ps]  # fmt: skip
    st = "failed" if errors and not rows and not pub else ("cut" if cut else "ok")
    return [{"r": region, "s": s, "e": e, "st": st, "b": nbytes, "rows": rows, "pub": pub, "pc": pub_cut,
             "err": "; ".join(errors)}]  # fmt: skip


def _int(v) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def estimate(doc: dict | None, account: str, regions: list[str] = (), now: float | None = None) -> dict:
    """What each read range would cost, from the bytes per second of log earlier reads scanned."""
    now = now or time.time()
    doc = doc or new_doc(account, "")
    secs = sum(c["e"] - c["s"] for c in doc["chunks"] if c["st"] in ("ok", "cut"))
    nbytes = sum(c["b"] for c in doc["chunks"])
    rate = nbytes / secs if secs else None
    out = []
    regions = [r for r, x in doc["regions"].items() if x.get("query_sets")] or list(regions)
    for days in READ_DAYS:
        missing = 0
        for r in regions:
            have = [(c["s"], c["e"]) for c in doc["chunks"] if c["r"] == r and c["st"] in ("ok", "cut")]
            missing += sum(e - s for s, e in plan(now, days, have))
        est = rate * missing if rate is not None else None
        out.append({"days": days, "missing_hours": round(missing / HOUR, 1), "bytes": est,
                    "cost": round(est / 1e9 * INSIGHTS_PER_GB, 2) if est is not None else None})  # fmt: skip
    return {
        "rate": rate,
        "ranges": out,
        "regions": len(regions),
        "spent_bytes": nbytes,
        "spent": round(nbytes / 1e9 * INSIGHTS_PER_GB, 2),
    }


# ---------------------------------------------------------------------------------------- labelling
def _iv(cidrs) -> list[tuple[int, int]]:
    return sg_ipintel.merge([x for x in map(sg_ipintel.cidr_iv, cidrs) if x])


class Labeller:
    """Category and name of a source address; one lookup per address."""

    def __init__(self, doc: dict, onprem: str = "", internal: str = "", names: list[dict] | None = None):
        self.intel = sg_ipintel.get()
        # (first, last, category, name, cidr, extra fields), narrowest first
        self.nets: list[tuple[int, int, str, str, str, dict]] = []
        own = []
        for snap in (x.get("snapshot") or {} for x in doc["regions"].values()):
            for v in snap.get("vpcs") or []:
                for c in v.get("cidrs") or []:
                    iv = sg_ipintel.cidr_iv(c)
                    if iv and ":" not in c:
                        own.append(iv)
                        self.nets.append((*iv, "internal", f"This account, {v.get('name') or v['id']}", c, {}))
        others = []
        for net, name in parse_ranges(internal, "Your network"):
            iv = (int(net.network_address), int(net.broadcast_address))
            others.append(iv)
            self.nets.append((*iv, "internal", name, str(net), {}))
        dc = []
        for net, name in parse_ranges(onprem, "On-premises"):
            iv = (int(net.network_address), int(net.broadcast_address))
            dc.append(iv)
            self.nets.append((*iv, "datacentre", name, str(net), {}))
        for snap in (x.get("snapshot") or {} for x in doc["regions"].values()):
            for v in snap.get("vpns") or []:
                for c in v.get("routes") or []:
                    iv = sg_ipintel.cidr_iv(c)
                    if iv:
                        dc.append(iv)
                        self.nets.append((*iv, "datacentre", f"Behind VPN {v['name']}", c, {}))
        # the names file: internal and data centre ranges join those above; anything else is an external network,
        # named by range (before AWS's and the providers' lists) or by AS number (after AWS's)
        named = {"saas": [], "internet": []}
        self.name_asn: dict[int, dict] = {}
        for e in names or []:
            kind = e["type"] if e["type"] in ("internal", "datacentre") else sg_ipintel.GROUPS[e["type"]][1]
            extra = {} if kind in ("internal", "datacentre") else self._named(e)
            for net in e["ranges"]:
                iv = (int(net.network_address), int(net.broadcast_address))
                (others if kind == "internal" else dc if kind == "datacentre" else named[kind]).append(iv)
                self.nets.append((*iv, kind, e["name"], str(net), extra))
            for a in e["asn"]:
                self.name_asn[a] = {"cat": kind, **extra}
        self.nets.sort(key=lambda n: n[1] - n[0])
        M, S = sg_ipintel.merge, sg_ipintel.subtract
        internal = M(own + others)
        taken = internal
        named_saas = S(M(named["saas"]), taken)
        named_inet = S(M(named["internet"]), M(taken + named_saas))
        private = S(M(PRIVATE + dc), M(taken + named_saas + named_inet))
        taken = M(taken + named_saas + named_inet + private)
        aws = S(self.intel.aws_intervals(), taken)
        taken = M(taken + aws)
        by_asn = {"saas": [], "internet": []}
        if self.name_asn:
            ia = self.intel
            for i, (asn, _cc, _owner) in enumerate(ia.asn_meta):
                if asn in self.name_asn:
                    by_asn[self.name_asn[asn]["cat"]].append((ia.asn_start[i], ia.asn_end[i]))
        asn_saas, asn_inet = S(M(by_asn["saas"]), taken), S(M(by_asn["internet"]), taken)
        saas = M(named_saas + asn_saas + S(S(self.intel.saas_intervals(), taken), asn_inet))
        rest = S(ALL, M(taken + saas))
        self.cat_iv = {"internal": internal, "datacentre": private, "aws": aws, "saas": saas, "internet": rest}
        self._memo: dict[str, dict] = {}

    @staticmethod
    def _named(e: dict) -> dict:
        typ = e["type"]
        return {"group": typ, "provider": e["name"], "what": e["note"] or sg_ipintel.GROUPS[typ][0], "named": True}

    def __call__(self, ip: str) -> dict:
        hit = self._memo.get(ip)
        if hit:
            return hit
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return {"cat": "internet", "name": str(ip)}
        out = None
        for first, last, cat, name, cidr, extra in self.nets:
            if first <= n <= last:
                out = {"cat": cat, "name": name, "range": cidr, **extra}
                a = self.intel.asn(n) if extra else None
                if a:  # a named external range: what the AS list knows too
                    out.update(as_num=a["asn"], owner=a["owner"], cc=a["country"], block=a["block"],
                               asn=f"AS{a['asn']} {a['owner']}".strip() + (f" ({a['country']})" if a["country"] else ""))  # fmt: skip
                break
        if out is None:
            for (a, b), cidr in zip(PRIVATE, PRIVATE_V4):
                if a <= n <= b:
                    out = {"cat": "datacentre", "name": "Private address outside every scanned VPC", "range": cidr}
                    break
        if out is None:
            lab = self.intel.label(ip)
            mine = self.name_asn.get(lab.get("asn")) if lab["kind"] != "aws" and lab.get("group") != "anon" else None
            if mine:  # an AS number in the names file: its name and type, over the built-in lists
                lab = {k: v for k, v in lab.items() if k not in ("prefix", "what")}
                lab.update(kind=mine["cat"], name=mine["provider"], **{k: v for k, v in mine.items() if k != "cat"})
            out = {"cat": lab["kind"], "name": lab["name"]}
            if mine:
                out["named"] = True
            if lab.get("asn"):
                out["asn"] = f"AS{lab['asn']} {lab.get('owner', '')}".strip() + (
                    f" ({lab['country']})" if lab.get("country") else ""
                )
                out.update(as_num=lab["asn"], owner=lab.get("owner", ""), cc=lab.get("country", ""),
                           block=lab.get("block", ""))  # fmt: skip
            if lab.get("prefix"):
                out["range"] = lab["prefix"]
            if lab.get("service"):
                out.update(service=lab["service"], aws_region=lab.get("region", ""))
            for k in ("group", "provider", "what"):
                if lab.get(k):
                    out[k] = lab[k]
        out.setdefault("group", out["cat"])  # internal, datacentre and aws are their own type
        out["net"] = f"{out['cat']}|{out['name']}"
        self._memo[ip] = out
        return out


# ------------------------------------------------------------------------------------------- rules
def _ip(s) -> int | None:
    try:
        return int(ipaddress.IPv4Address(s))
    except (ValueError, TypeError):
        return None


def port_matches(rule: dict, proto: str, port: int) -> bool:
    rp = str(rule["proto"])
    if rp == "-1":
        return True
    if rp != str(proto):
        return False
    if rp not in ("6", "17"):
        return True
    if port >= EPHEMERAL:  # folded: any port from here up
        return rule["to"] >= EPHEMERAL
    return rule["from"] <= port <= rule["to"]


def ports_label(rule: dict) -> str:
    p = {"6": "tcp", "17": "udp", "1": "icmp", "-1": "all"}.get(str(rule["proto"]), f"proto {rule['proto']}")
    if p in ("all", "icmp") or (rule["from"], rule["to"]) == (0, 65535):
        return p if p != "all" else "all traffic"
    return f"{p} {rule['from']}" if rule["from"] == rule["to"] else f"{p} {rule['from']}-{rule['to']}"


# --------------------------------------------------------------------------------- port classification
# Each class: (name, what a reviewer should know before letting a new source in on it). Risky classes give
# control of a host or its data when reached; the page warns harder when such a source is not internal.
PORT_CLASSES = {
    "web": ("Web", "Web traffic. From the internet, it is best behind a load balancer, CloudFront or a WAF."),
    "admin": ("Remote admin", "Remote administration gives control of the host. Allow only named admin hosts or a "
              "bastion, never the internet; Systems Manager Session Manager needs no inbound rule at all."),
    "database": ("Database", "A database should be reached only by its own application tier and admin hosts."),
    "windows": ("Windows and directory", "SMB, RPC, NetBIOS, LDAP and Kerberos beyond the domain are a common "
                "ransomware and credential-theft path. Allow only domain members and controllers."),
    "containers": ("Containers", "Container and cluster control planes (Docker, etcd, kubelet, the Kubernetes "
                   "API) give control of every workload on the host when reached."),
    "transfer": ("File transfer and storage", "File transfer and network storage carry data out as easily as in: "
                 "allow only the partners or hosts that exchange files."),
    "mail": ("Mail", "Mail relays reached from new sources can be used to send spam as you."),
    "messaging": ("Messaging and streaming", "Brokers and queues: producers and consumers only."),
    "network": ("Network and monitoring", "Name, time, VPN, routing and monitoring services."),
    "low": ("Other well-known port (1-1023)", "A well-known port with no common service named here."),
    "registered": ("Other port (1024-32767)", "A registered port: name the application before allowing it."),
    "high": ("High port (32768+)", "Ports from 32768 up are mostly replies to the account's own connections."),
    "range": ("Port range", "More than one port: list the ports the traffic needs instead, where you can."),
    "all": ("All traffic", "Every protocol and port. Rarely needed: list the ports the traffic needs instead."),
}  # fmt: skip
RISKY_CLASSES = frozenset({"admin", "database", "windows", "containers"})
_TCP, _UDP, _BOTH = ("6",), ("17",), ("6", "17")
PORT_SERVICES = {
    # (protocols, port) -> (class, service)
    **{(p, n): ("web", svc) for p, n, svc in (
        (_TCP, 80, "HTTP"), (_BOTH, 443, "HTTPS"), (_TCP, 8080, "HTTP (alternative)"),
        (_TCP, 8443, "HTTPS (alternative)"), (_TCP, 8000, "HTTP (alternative)"), (_TCP, 8888, "HTTP (alternative)"),
        (_TCP, 9443, "HTTPS (alternative)"), (_TCP, 3000, "Web application (development)"),
        (_TCP, 5000, "Web application (development)"), (_TCP, 8081, "HTTP (alternative)"))},
    **{(p, n): ("admin", svc) for p, n, svc in (
        (_TCP, 22, "SSH, SFTP"), (_TCP, 2222, "SSH (alternative)"), (_TCP, 23, "Telnet (unencrypted)"),
        (_BOTH, 3389, "RDP, Windows Remote Desktop"), (_TCP, 5985, "WinRM, PowerShell remoting (HTTP)"),
        (_TCP, 5986, "WinRM, PowerShell remoting (HTTPS)"), (_TCP, 5900, "VNC"), (_TCP, 5901, "VNC"),
        (_TCP, 513, "rlogin (unencrypted)"), (_TCP, 512, "rexec (unencrypted)"), (_TCP, 10000, "Webmin"))},
    **{(p, n): ("database", svc) for p, n, svc in (
        (_TCP, 1433, "Microsoft SQL Server"), (_UDP, 1434, "SQL Server Browser"), (_TCP, 1521, "Oracle"),
        (_TCP, 2484, "Oracle (TLS)"), (_TCP, 3306, "MySQL, MariaDB, Aurora MySQL"),
        (_TCP, 5432, "PostgreSQL, Aurora PostgreSQL"), (_TCP, 5439, "Redshift"), (_TCP, 6379, "Redis, Valkey"),
        (_TCP, 6380, "Redis (TLS)"), (_BOTH, 11211, "Memcached"), (_TCP, 27017, "MongoDB, DocumentDB"),
        (_TCP, 27018, "MongoDB"), (_TCP, 9042, "Cassandra, Keyspaces"), (_TCP, 7000, "Cassandra cluster"),
        (_TCP, 9200, "Elasticsearch, OpenSearch"), (_TCP, 9300, "Elasticsearch cluster"),
        (_TCP, 8086, "InfluxDB"), (_TCP, 7474, "Neo4j"), (_TCP, 8182, "Neptune, Gremlin"),
        (_TCP, 26257, "CockroachDB"), (_TCP, 50000, "Db2"), (_TCP, 1830, "Oracle (alternative)"))},
    **{(p, n): ("windows", svc) for p, n, svc in (
        (_TCP, 135, "Microsoft RPC"), (_UDP, 137, "NetBIOS name"), (_UDP, 138, "NetBIOS datagram"),
        (_TCP, 139, "NetBIOS session, SMB"), (_TCP, 445, "SMB, Windows file sharing"),
        (_BOTH, 389, "LDAP"), (_TCP, 636, "LDAPS"), (_TCP, 3268, "Active Directory global catalog"),
        (_TCP, 3269, "Active Directory global catalog (TLS)"), (_BOTH, 88, "Kerberos"),
        (_BOTH, 464, "Kerberos password change"), (_TCP, 9389, "Active Directory Web Services"))},
    **{(p, n): ("containers", svc) for p, n, svc in (
        (_TCP, 2375, "Docker API (unencrypted)"), (_TCP, 2376, "Docker API (TLS)"), (_TCP, 2379, "etcd"),
        (_TCP, 2380, "etcd peers"), (_TCP, 6443, "Kubernetes API"), (_TCP, 10250, "kubelet API"),
        (_TCP, 10255, "kubelet (read-only)"), (_UDP, 4789, "VXLAN overlay"), (_UDP, 8472, "Flannel VXLAN"))},
    **{(p, n): ("transfer", svc) for p, n, svc in (
        (_TCP, 20, "FTP data"), (_TCP, 21, "FTP"), (_TCP, 990, "FTPS"), (_UDP, 69, "TFTP"),
        (_BOTH, 2049, "NFS, EFS"), (_BOTH, 111, "RPC portmapper (NFS)"), (_TCP, 873, "rsync"),
        (_TCP, 3260, "iSCSI"), (_TCP, 988, "FSx for Lustre"))},
    **{(p, n): ("mail", svc) for p, n, svc in (
        (_TCP, 25, "SMTP"), (_TCP, 465, "SMTPS"), (_TCP, 587, "SMTP submission"), (_TCP, 110, "POP3"),
        (_TCP, 995, "POP3S"), (_TCP, 143, "IMAP"), (_TCP, 993, "IMAPS"))},
    **{(p, n): ("messaging", svc) for p, n, svc in (
        (_TCP, 5672, "AMQP, RabbitMQ"), (_TCP, 5671, "AMQP (TLS)"), (_TCP, 9092, "Kafka, MSK"),
        (_TCP, 9094, "Kafka, MSK (TLS)"), (_TCP, 9096, "MSK (SASL)"), (_TCP, 9098, "MSK (IAM)"),
        (_TCP, 2181, "ZooKeeper"), (_TCP, 1883, "MQTT"), (_TCP, 8883, "MQTT (TLS)"), (_TCP, 61616, "ActiveMQ"),
        (_TCP, 61617, "ActiveMQ (TLS)"), (_TCP, 4222, "NATS"), (_TCP, 6650, "Pulsar"), (_TCP, 15672, "RabbitMQ admin"))},
    **{(p, n): ("network", svc) for p, n, svc in (
        (_BOTH, 53, "DNS"), (_UDP, 123, "NTP"), (_UDP, 67, "DHCP"), (_UDP, 68, "DHCP"), (_UDP, 161, "SNMP"),
        (_UDP, 162, "SNMP traps"), (_BOTH, 514, "Syslog"), (_TCP, 6514, "Syslog (TLS)"), (_UDP, 500, "IPsec IKE"),
        (_UDP, 4500, "IPsec NAT traversal"), (_BOTH, 1194, "OpenVPN"), (_UDP, 51820, "WireGuard"),
        (_TCP, 179, "BGP"), (_UDP, 1812, "RADIUS"), (_UDP, 1813, "RADIUS accounting"), (_TCP, 49, "TACACS+"),
        (_TCP, 9090, "Prometheus"), (_TCP, 9100, "Prometheus node exporter"), (_TCP, 10050, "Zabbix agent"),
        (_TCP, 10051, "Zabbix server"), (_UDP, 8125, "StatsD"), (_TCP, 2003, "Graphite"),
        (_TCP, 5044, "Logstash Beats"), (_TCP, 8126, "Datadog APM"), (_UDP, 6081, "GENEVE (Gateway Load Balancer)"))},
}  # fmt: skip
PORT_SERVICES = {(p, n): v for (ps, n), v in PORT_SERVICES.items() for p in ps}
PROTO_NAME = {"6": "tcp", "17": "udp", "1": "icmp", "-1": "all", "58": "icmpv6", "50": "esp", "47": "gre"}


def port_class(proto, port: int) -> dict:
    """{cls, name, svc, risky} for one protocol and destination port."""
    proto = str(proto)
    if proto == "-1":
        cls, svc = "all", "Every protocol and port"
    elif proto in ("1", "58"):
        cls, svc = "network", "ICMP (ping, unreachable, path MTU)"
    elif proto not in ("6", "17"):
        cls, svc = "network", f"IP protocol {PROTO_NAME.get(proto, proto)}"
    elif (proto, port) in PORT_SERVICES:
        cls, svc = PORT_SERVICES[(proto, port)]
    elif port >= EPHEMERAL:
        cls, svc = "high", "High port (replies, or an application's own)"
    elif 30000 <= port <= 32767 and proto == "6":
        cls, svc = "containers", "Kubernetes NodePort range"
    elif port < 1024:
        cls, svc = "low", "Well-known port, no common service"
    else:
        cls, svc = "registered", "Registered port, no common service"
    return {"cls": cls, "name": PORT_CLASSES[cls][0], "svc": svc, "risky": cls in RISKY_CLASSES or port == 23}


def rule_port_class(rule: dict) -> dict:
    """port_class for a rule: one port, all traffic, or a range (with the named services inside it)."""
    proto, lo, hi = str(rule["proto"]), rule["from"], rule["to"]
    if proto == "-1" or (proto in ("6", "17") and (lo, hi) == (0, 65535)):
        out = port_class("-1", 0)
        if proto != "-1":
            out["svc"] = f"Every {PROTO_NAME[proto]} port"
        out["risky"] = True
        return out
    if proto not in ("6", "17") or lo == hi:
        return port_class(proto, lo)
    inside = sorted((n, *v) for (p, n), v in PORT_SERVICES.items() if p == proto and lo <= n <= hi)
    named = ", ".join(f"{svc} ({n})" for n, _c, svc in inside[:4]) + (
        f" and {len(inside) - 4} more" if len(inside) > 4 else "")
    return {"cls": "range", "name": PORT_CLASSES["range"][0],
            "svc": f"{hi - lo + 1:,} ports" + (f", including {named}" if named else ""),
            "risky": any(c in RISKY_CLASSES for _n, c, _s in inside)}  # fmt: skip


def _entries(rule: dict) -> list[str]:
    return list(rule.get("cidrs") or []) + list(rule.get("pls") or [])


def nacl_verdict(nacl: dict | None, src: int, proto: str, port: int) -> dict | None:
    """The first inbound network ACL entry matching, when it denies; None when the ACL allows."""
    for x in (nacl or {}).get("entries") or []:
        iv = sg_ipintel.cidr_iv(x["cidr"])
        if not iv or not iv[0] <= src <= iv[1]:
            continue
        if x["proto"] not in ("-1", str(proto)):
            continue
        if x["proto"] in ("6", "17") and not (x["from"] <= port <= x["to"]):
            continue
        return None if x["allow"] else {"acl": nacl["id"], "rule": x["n"]}
    return None


# ------------------------------------------------------------------------------------------- report
def _coverage(snap: dict) -> dict:
    """Interface id -> (covered for accepted traffic, covered for refused, earliest such flow log)."""
    out = {}
    logs = [f for f in snap.get("flow_logs") or [] if f["dest"] == "cloud-watch-logs" and f["status"] in ("ACTIVE", "")
            and readable(f["format"])]  # fmt: skip
    for eid, e in (snap.get("enis") or {}).items():
        mine = [f for f in logs if f["resource"] in (eid, e.get("subnet"), e.get("vpc"))]
        acc = [f for f in mine if f["traffic"] in ("ALL", "ACCEPT")]
        rej = [f for f in mine if f["traffic"] in ("ALL", "REJECT")]
        created = min((f["created"] for f in acc if f.get("created")), default=None)
        out[eid] = (bool(acc), bool(rej), created)
    return out


def _state_at(now_entries: set, events: list, t: float) -> tuple[set, bool]:
    """A group's inbound entries at time t, worked back from today's through the changes after t."""
    state, known = set(now_entries), True
    for ev in reversed(events):
        if ev["t"] <= t:
            break
        if ev["unknown"]:
            known = False
            break
        state -= {tuple(x) for x in ev["added"]}
        state |= {tuple(x) for x in ev["removed"]}
    return state, known


def build(doc: dict, range_key: str = "1m", onprem: str = "", internal: str = "", names: list | None = None) -> dict:
    span, step = RANGES.get(range_key, RANGES["1m"])
    chunks = [c for c in doc["chunks"] if c["st"] in ("ok", "cut")]
    lab = Labeller(doc, onprem, internal, names)
    end = max((c["e"] for c in chunks), default=read_end(time.time()))
    start = _floor(end - span, step)
    nbins = max(1, -(-(end - start) // step))
    bins = [start + i * step for i in range(nbins)]
    today = end - DAY

    enis, groups, snaps = {}, {}, {}
    for region, x in doc["regions"].items():
        snap = x.get("snapshot") or {}
        snaps[region] = snap
        cov = _coverage(snap)
        for eid, e in (snap.get("enis") or {}).items():
            enis[eid] = {**e, "region": region, "cov": cov.get(eid, (False, False, None))}
        for gid, g in (snap.get("groups") or {}).items():
            groups[gid] = {**g, "id": gid, "region": region, "enis": []}
    for eid, e in enis.items():
        for gid in e["groups"]:
            if gid in groups:
                groups[gid]["enis"].append(eid)
    own_ips = {ip for e in enis.values() for ip in e["ips"]}

    def relevant(eni_id, src, dst) -> bool:
        if src in own_ips and (eni_id not in enis or src in enis[eni_id]["ips"]):
            return False  # the interface's own outbound record
        e = enis.get(eni_id)
        if e is None:
            return True  # a deleted interface: kept, as unattributed
        if not e["groups"]:
            return False  # NAT gateways, transit gateway attachments: no security group decides
        return dst in e["ips"] or any(sg_ipintel.cidr_iv(p) and _in(dst, p) for p in e.get("prefixes") or [])

    seen: set[str] = set()
    rej: dict[str, dict] = {}
    act: dict[str, dict] = {}
    by_class: dict[str, dict] = {"refused": {}, "active": {}}  # kind -> (class, category) -> bin -> sources
    port_use: dict[tuple, dict] = {}  # (proto, port) -> kind -> category -> sources

    def note_port(kind: str, src: str, b: int, proto, port: int) -> None:
        cat = lab(src)["cat"]
        by_class[kind].setdefault((_port_cls(str(proto), port), cat), {}).setdefault(b, set()).add(src)
        use = port_use.setdefault((str(proto), port), {"refused": {}, "active": {}})
        use[kind].setdefault(cat, set()).add(src)
    accepted_rows = []  # (src, dst, eni, proto, dport, flows, chunk)
    region_first: dict[str, int] = {}
    cut_regions, pub_cut = set(), 0
    for c in chunks:
        region_first[c["r"]] = min(region_first.get(c["r"], c["s"]), c["s"])
        if c["st"] == "cut":
            cut_regions.add(c["r"])
        pub_cut += bool(c.get("pc"))
        b = (c["s"] - start) // step if c["s"] >= start else None
        in_view = b is not None and 0 <= b < nbins
        for src, dst, eni, proto, dport, action, flows in c["rows"]:
            if not src:
                continue
            seen.add(src)
            if not relevant(eni, src, dst):
                continue
            if action == "ACCEPT":
                accepted_rows.append((src, dst, eni, str(proto), dport, flows, c))
                if dport >= EPHEMERAL and not _rule_covers(groups, enis.get(eni), proto, dport):
                    continue  # replies to the account's own connections
                a = act.setdefault(src, {"bins": set(), "flows": 0, "first": c["s"], "last": c["e"], "days": set(),
                                         "targets": {}, "today": False})  # fmt: skip
                a["days"].add(c["s"] // DAY)
                a["first"], a["last"] = min(a["first"], c["s"]), max(a["last"], c["e"])
                a["today"] = a["today"] or c["s"] >= today
                if in_view:
                    a["bins"].add(b)
                    a["flows"] += flows
                    k = (eni, str(proto), dport)
                    a["targets"][k] = a["targets"].get(k, 0) + flows
                    note_port("active", src, b, proto, dport)
            elif in_view and dport < EPHEMERAL:
                _refused(rej, src, b, c, flows, (eni, str(proto), dport, dst))
                note_port("refused", src, b, proto, dport)
        for src, flows, ports, dsts, dst, eni, port, proto in c.get("pub") or []:
            if not src:
                continue
            seen.add(src)
            if in_view and (port < EPHEMERAL or ports > 1):
                r = _refused(rej, src, b, c, flows, (eni, str(proto), port, dst))
                r["ports"] = max(r.get("ports", 1), ports)
                r["dsts"] = max(r.get("dsts", 1), dsts)
                note_port("refused", src, b, proto, port)

    seen_iv = sg_ipintel.merge([(n, n) for n in map(_ip, seen) if n is not None])

    # ---- the three series
    def zeros():
        return {k: [0] * nbins for k in CATS}

    rej_series = zeros()
    act_today, act_older = zeros(), zeros()
    for src, r in rej.items():
        cat = lab(src)["cat"]
        for b in r["bins"]:
            rej_series[cat][b] += 1
    for src, a in act.items():
        cat = lab(src)["cat"]
        for b in a["bins"]:
            (act_today if a["today"] else act_older)[cat][b] += 1
    class_series = {
        kind: {f"{cls}|{cat}": [len(bs.get(i, ())) for i in range(nbins)] for (cls, cat), bs in m.items()}
        for kind, m in by_class.items()
    }
    net_series = {"refused": _net_series(rej, lab, nbins), "active": _net_series(act, lab, nbins)}
    group_series = {"refused": _group_series(rej, lab, nbins), "active": _group_series(act, lab, nbins)}
    ports = []
    for (proto, port), use in port_use.items():
        pc = port_class(proto, port)
        ports.append({"proto": proto, "port": port, "label": _port_label(proto, port), **pc,
                      "refused": {k: len(v) for k, v in use["refused"].items()},
                      "active": {k: len(v) for k, v in use["active"].items()}})  # fmt: skip
    ports.sort(key=lambda x: -(sum(x["refused"].values()) + sum(x["active"].values())))

    # ---- rules: today's, worked back through the changes for the over-provisioned line
    hist = {r: (x.get("history") or {}) for r, x in doc["regions"].items()}
    ev_by_group: dict[str, list] = {}
    for h in hist.values():
        for ev in h.get("events") or []:
            ev_by_group.setdefault(ev["group"], []).append(ev)
    for evs in ev_by_group.values():
        evs.sort(key=lambda e: e["t"])

    def logged(g) -> bool:
        return bool(g["enis"]) and g["region"] in region_first and all(enis[e]["cov"][0] for e in g["enis"])

    def expand(entry: str, region: str) -> list[tuple[int, int]]:
        if entry.startswith("pl-"):
            return _iv((snaps.get(region, {}).get("prefix_lists") or {}).get(entry, []))
        return _iv([entry])

    over_series = zeros()
    frozen_groups = set()
    logged_groups = [g for g in groups.values() if logged(g)]
    now_entries = {
        g["id"]: {(r["proto"], r["from"], r["to"], s) for r in g["rules"] for s in _entries(r)} for g in logged_groups
    }
    memo: dict[tuple, list] = {}
    for i, t0 in enumerate(bins):
        t = min(t0 + step, end)
        total = [0] * len(CATS)
        for g in logged_groups:
            state, known = _state_at(now_entries[g["id"]], ev_by_group.get(g["id"], []), t)
            if not known:
                frozen_groups.add(g["id"])
            key = (g["region"], frozenset(x[3] for x in state if x[3] != "0.0.0.0/0"))
            if key not in memo:
                iv = sg_ipintel.merge([v for src in key[1] for v in expand(src, key[0])])
                over = sg_ipintel.subtract(iv, seen_iv)
                memo[key] = [sg_ipintel.size(sg_ipintel.intersect(over, lab.cat_iv[k])) for k in CATS]
            total = [a + b for a, b in zip(total, memo[key])]
        for k, n in zip(CATS, total):
            over_series[k][i] = n
    markers = [
        {"t": ev["t"], "bin": int((ev["t"] - start) // step), "group": ev["group"],
         "name": groups.get(ev["group"], {}).get("name", ev["group"]), "event": ev["name"], "who": ev["who"],
         "added": [x[3] for x in ev["added"]], "removed": [x[3] for x in ev["removed"]], "unknown": ev["unknown"]}
        for evs in ev_by_group.values() for ev in evs if start <= ev["t"] < end
    ]  # fmt: skip

    rules = _rules_table(doc, groups, enis, accepted_rows, seen, seen_iv, lab, region_first, cut_regions, end)
    open_rules = [r for r in rules if r["status"] == "open"]

    # ---- tables
    def src_row(src, x):
        lb = lab(src)
        return {"src": src, **lb, "flows": x["flows"], "bins": sorted(x["bins"]), "first": x["first"],
                "last": x["last"]}  # fmt: skip

    refused = []
    for src, r in sorted(rej.items(), key=lambda kv: -kv[1]["flows"])[:TOP]:
        row = src_row(src, r)
        targets = []
        for (eni, proto, port, dst), flows in sorted(r["targets"].items(), key=lambda kv: -kv[1])[:5]:
            e = enis.get(eni) or {}
            targets.append({"eni": eni, "dst": dst, "proto": proto, "port": port, "flows": flows,
                            "kind": e.get("kind", "deleted interface"), "groups": e.get("groups", []),
                            "region": e.get("region", ""), "vpc": e.get("vpc", ""), "subnet": e.get("subnet", ""),
                            "desc": e.get("desc", ""), "public": e.get("public", ""), "pc": port_class(proto, port),
                            "by": _refused_by(src, e, groups, snaps, proto, port)})  # fmt: skip
        row.update(targets=targets, ports=r.get("ports", len({t[2] for t in r["targets"]})), dsts=r.get("dsts", 1))
        row["sweep"] = row["ports"] >= 10 or row["dsts"] >= 5
        refused.append(row)
    suggestions = _suggest(rej, enis, groups, snaps, lab)

    active = []
    for src, a in sorted(act.items(), key=lambda kv: -kv[1]["flows"])[:TOP]:
        if not a["bins"]:
            continue
        row = src_row(src, a)
        row.update(today=a["today"], days=len(a["days"]),
                   targets=[{"eni": k[0], "proto": k[1], "port": k[2], "flows": v, "pc": port_class(k[1], k[2]),
                             "groups": (enis.get(k[0]) or {}).get("groups", [])}
                            for k, v in sorted(a["targets"].items(), key=lambda kv: -kv[1])[:5]])  # fmt: skip
        active.append(row)

    regions = {}
    for region, x in doc["regions"].items():
        snap = x.get("snapshot") or {}
        regions[region] = {
            "error": x.get("error"),
            "taken": x.get("taken"),
            "query_sets": x.get("query_sets") or [],
            "flow_logs": len(snap.get("flow_logs") or []),
            "unreadable": [f["id"] for f in snap.get("flow_logs") or []
                           if f["dest"] != "cloud-watch-logs" or not readable(f["format"])],
            "history": {"read": (x.get("history") or {}).get("read", False),
                        "since": (x.get("history") or {}).get("whole_since"),
                        "error": (x.get("history") or {}).get("error")},
            "first": region_first.get(region),
            "cut": region in cut_regions,
            "groups": sum(1 for g in groups.values() if g["region"] == region),
        }  # fmt: skip
    not_logged = [g for g in groups.values() if g["enis"] and not logged(g)]
    last = len(bins) - 1
    return {
        "account": doc["account"],
        "name": doc.get("name", ""),
        "mode": doc.get("mode", "live"),
        "range": range_key if range_key in RANGES else "1m",
        "step": step,
        "bins": bins,
        "end": end,
        "categories": [{"key": k, "name": CAT_NAME[k]} for k in CATS],
        "series": {"refused": rej_series, "over": over_series, "active_today": act_today, "active_older": act_older,
                   "by_class": class_series, "by_net": net_series,
                   "by_group": group_series},
        "ports": ports[:60],
        "groups": {gid: {"name": g["name"], "region": g["region"], "vpc": g["vpc"],
                         "rules": [{"ports": ports_label(r), "sources": _entries(r)} for r in g["rules"]]}
                   for gid, g in groups.items()},
        "markers": markers,
        "summary": {
            "refused": len(rej),
            "refused_internal": sum(1 for s in rej if lab(s)["cat"] in ("internal", "datacentre")),
            "active": sum(1 for a in act.values() if a["bins"]),
            "active_older": sum(1 for a in act.values() if a["bins"] and not a["today"]),
            "over_now": sum(over_series[k][last] for k in CATS),
            "over_by_cat": {k: over_series[k][last] for k in CATS},
            "tighten": sum(1 for r in rules if r["status"] == "tighten"),
            "unused": sum(1 for r in rules if r["status"] == "unused"),
            "watch": sum(1 for r in rules if r["status"] == "watch"),
            "open": len(open_rules),
            "not_logged": len(not_logged),
            "not_logged_groups": [{"id": g["id"], "name": g["name"], "region": g["region"]} for g in not_logged][:50],
            "frozen": sorted(frozen_groups),
            "seen": len(seen),
            "evidence_since": min(region_first.values(), default=None),
            "cut": sorted(cut_regions),
            "public_cut": pub_cut,
            "slices": len(chunks),
            "failed": sum(1 for c in doc["chunks"] if c["st"] == "failed"),
            "intel_seed": sg_ipintel.get().counts.get("seed", []),
        },
        "regions": regions,
        "rules": rules,
        "refused": refused,
        "suggestions": suggestions,
        "active": active,
    }


_PCLS: dict[tuple, str] = {}


def _port_cls(proto: str, port: int) -> str:
    k = (proto, port)
    if k not in _PCLS:
        _PCLS[k] = port_class(proto, port)["cls"]
    return _PCLS[k]


def _port_label(proto: str, port: int) -> str:
    p = PROTO_NAME.get(str(proto), f"proto {proto}")
    if p in ("icmp", "icmpv6", "all") or str(proto) not in ("6", "17"):
        return p
    return f"{p} {port}+" if port >= EPHEMERAL else f"{p} {port}"


NET_TOP = 150  # networks listed per series; the rest are summed per kind of source


def _net_series(srcs: dict, lab, nbins: int) -> list[dict]:
    """Distinct sources per period for each network a source belongs to (an AS number, an AWS service, a named
    range), busiest first."""
    nets: dict[str, dict] = {}
    for src, x in srcs.items():
        if not x["bins"]:
            continue
        lb = lab(src)
        n = nets.setdefault(lb["net"], {"key": lb["net"], "name": lb["name"], "cat": lb["cat"], "group": lb["group"],
                                        "asn": lb.get("asn", ""), "data": [0] * nbins, "sources": 0})  # fmt: skip
        n["sources"] += 1
        for b in x["bins"]:
            n["data"][b] += 1
    out = sorted(nets.values(), key=lambda n: -n["sources"])
    rest = out[NET_TOP:]
    out = out[:NET_TOP]
    for cat in CATS:
        mine = [n for n in rest if n["cat"] == cat]
        if mine:
            out.append({"key": f"{cat}|*", "name": f"{len(mine)} more {CAT_NAME[cat]} networks", "cat": cat,
                        "group": "", "asn": "", "sources": sum(n["sources"] for n in mine),
                        "data": [sum(n["data"][i] for n in mine) for i in range(nbins)]})  # fmt: skip
    return out


# Source types, in the order the page stacks them: the three kinds that need no provider, then the providers'
# groups (see sg_ipintel.GROUPS).
SOURCE_TYPES = {"internal": (CAT_NAME["internal"], "internal"), "datacentre": (CAT_NAME["datacentre"], "datacentre"),
                "aws": (CAT_NAME["aws"], "aws"), **sg_ipintel.GROUPS}  # fmt: skip


def _group_series(srcs: dict, lab, nbins: int) -> dict[str, list[int]]:
    """Distinct sources per period for each source type (a CDN, a scanner, anyone's hosting, ...)."""
    out: dict[str, list[int]] = {}
    for src, x in srcs.items():
        if x["bins"]:
            d = out.setdefault(lab(src)["group"], [0] * nbins)
            for b in x["bins"]:
                d[b] += 1
    return {g: out[g] for g in SOURCE_TYPES if g in out}


def _in(ip: str, cidr: str) -> bool:
    n, iv = _ip(ip), sg_ipintel.cidr_iv(cidr)
    return n is not None and iv is not None and iv[0] <= n <= iv[1]


def _rule_covers(groups: dict, eni: dict | None, proto, port: int) -> bool:
    if not eni:
        return False
    return any(port_matches(r, str(proto), port) and _entries(r) for g in eni["groups"]
               for r in (groups.get(g) or {}).get("rules") or [])  # fmt: skip


def _refused(rej: dict, src: str, b: int, c: dict, flows: int, target: tuple) -> dict:
    r = rej.setdefault(src, {"bins": set(), "flows": 0, "first": c["s"], "last": c["e"], "targets": {}})
    r["bins"].add(b)
    r["flows"] += flows
    r["first"], r["last"] = min(r["first"], c["s"]), max(r["last"], c["e"])
    r["targets"][target] = r["targets"].get(target, 0) + flows
    return r


def _allows_now(groups: dict, e: dict, src: str, proto: str, port: int) -> list[str]:
    n = _ip(src)
    out = []
    for gid in e.get("groups") or []:
        for r in (groups.get(gid) or {}).get("rules") or []:
            if not port_matches(r, proto, port):
                continue
            ivs = _iv(r.get("cidrs") or [])
            if n is not None and any(a <= n <= b for a, b in ivs):
                out.append(gid)
    return out


def _refused_by(src: str, e: dict, groups: dict, snaps: dict, proto: str, port: int) -> str:
    if not e:
        return "Interface since deleted"
    n = _ip(src)
    nacl = (snaps.get(e["region"], {}).get("nacls") or {}).get(e.get("subnet", ""))
    if n is not None and nacl_verdict(nacl, n, proto, port):
        v = nacl_verdict(nacl, n, proto, port)
        return f"Network ACL {v['acl']} rule {v['rule']}"
    if _allows_now(groups, e, src, proto, port):
        return "Security group (a rule added since allows it)"
    return "Security group"


def _suggest(rej: dict, enis: dict, groups: dict, snaps: dict, lab) -> list[dict]:
    """Rules that would let in the refused private sources, per group, protocol and port: only to add if
    the traffic is wanted."""
    want: dict[tuple, dict] = {}
    for src, r in rej.items():
        lb = lab(src)
        if lb["cat"] not in ("internal", "datacentre"):
            continue
        for (eni, proto, port, _dst), flows in r["targets"].items():
            e = enis.get(eni)
            if not e or not e["groups"] or _refused_by(src, e, groups, snaps, proto, port) != "Security group":
                continue
            k = (e["groups"][0], proto, port)
            w = want.setdefault(k, {"srcs": set(), "flows": 0, "names": set()})
            w["srcs"].add(src)
            w["flows"] += flows
            w["names"].add(lb["name"])
    out = []
    for (gid, proto, port), w in sorted(want.items(), key=lambda kv: -kv[1]["flows"])[:100]:
        g = groups.get(gid) or {}
        out.append({"group": gid, "name": g.get("name", ""), "region": g.get("region", ""),
                    "ports": ports_label({"proto": proto, "from": port, "to": port}), "sources": len(w["srcs"]),
                    "flows": w["flows"], "from": sorted(w["names"])[:5], "pc": port_class(proto, port),
                    "cidrs": sg_tightener.collapse_ips_to_cidrs(sorted(w["srcs"]), sg_tightener.DEFAULT_MAX_RULES, 0.0)})  # fmt: skip
    return out


def _rules_table(doc, groups, enis, accepted_rows, seen, seen_iv, lab, region_first, cut_regions, end) -> list[dict]:
    by_eni: dict[str, list] = {}
    deleted: list = []
    for row in accepted_rows:
        if row[2] in enis:
            by_eni.setdefault(row[2], []).append(row)
        else:
            deleted.append(row)
    seen_ints = sorted(n for n in map(_ip, seen) if n is not None)
    out = []
    for g in groups.values():
        if not g["enis"]:
            continue
        snap = (doc["regions"].get(g["region"]) or {}).get("snapshot") or {}
        vpc_iv = _iv(next((v["cidrs"] for v in snap.get("vpcs") or [] if v["id"] == g["vpc"]), []))
        logged = g["region"] in region_first and all(enis[e]["cov"][0] for e in g["enis"])
        created = [enis[e]["cov"][2] for e in g["enis"] if enis[e]["cov"][2]]
        since = max([region_first.get(g["region"], end)] + created)
        days = max(0, (end - since) / DAY)
        rows = [r for e in g["enis"] for r in by_eni.get(e, [])]
        for rule in g["rules"]:
            for entry in _entries(rule):
                ivs = (_iv((snap.get("prefix_lists") or {}).get(entry, [])) if entry.startswith("pl-")
                       else _iv([entry]))  # fmt: skip
                if not ivs:
                    continue
                allowed = sg_ipintel.size(ivs)

                def inside(ip, ivs=ivs):
                    n = _ip(ip)
                    return n is not None and any(a <= n <= b for a, b in ivs)

                here: dict[str, list] = {}
                for src, _dst, _eni, proto, dport, flows, c in rows:
                    if port_matches(rule, proto, dport) and inside(src):
                        h = here.setdefault(src, [0, 0])
                        h[0] += flows
                        h[1] = max(h[1], c["e"])
                unattr = {src for src, dst, _e, proto, dport, _f, _c in deleted
                          if port_matches(rule, proto, dport) and inside(src)
                          and (n := _ip(dst)) is not None and any(a <= n <= b for a, b in vpc_iv)}  # fmt: skip
                n_seen = sum(bisect_right(seen_ints, b) - bisect_right(seen_ints, a - 1) for a, b in ivs)
                never = sg_ipintel.size(sg_ipintel.subtract(ivs, seen_iv))
                row = {"region": g["region"], "group": g["id"], "gname": g["name"], "vpc": g["vpc"],
                       "enis": len(g["enis"]), "ports": ports_label(rule), "proto": rule["proto"],
                       "from": rule["from"], "to": rule["to"], "source": entry,
                       "desc": (rule.get("descs") or {}).get(entry, ""), "allowed": allowed, "here": len(here),
                       "elsewhere": max(0, n_seen - len(here) - len(unattr - set(here))),
                       "unattributed": len(unattr - set(here)), "never": never,
                       "last_used": max((h[1] for h in here.values()), default=None), "since": since,
                       "days": round(days, 1), "suggest": [], "suggest_size": None, "note": "",
                       "pc": rule_port_class(rule)}  # fmt: skip
                row["top"] = [{"src": s, **lab(s), "flows": h[0]}
                              for s, h in sorted(here.items(), key=lambda kv: -kv[1][0])[:8]]  # fmt: skip
                row["status"], row["note"] = _status(row, rule, entry, logged, g, cut_regions, days)
                if row["status"] == "tighten":
                    keep = sorted(set(here) | unattr)
                    within = ipaddress.IPv4Network(entry, strict=False) if not entry.startswith("pl-") else None
                    cidrs = sg_tightener.collapse_ips_to_cidrs(keep, sg_tightener.DEFAULT_MAX_RULES, sg_tightener.DEFAULT_TOLERANCE)
                    if within is not None:
                        cidrs = [c if ipaddress.IPv4Network(c).subnet_of(within) else str(within) for c in cidrs]
                        cidrs = [str(n) for n in ipaddress.collapse_addresses(map(ipaddress.IPv4Network, cidrs))]
                    row["suggest"] = cidrs
                    row["suggest_size"] = sg_ipintel.size(_iv(cidrs))
                    if row["suggest_size"] >= allowed:
                        row["status"], row["note"] = "used", "In use across the range: nothing to take away"
                        row["suggest"], row["suggest_size"] = [], None
                out.append(row)
    rank = {"tighten": 0, "unused": 1, "open": 2, "watch": 3, "incomplete": 4, "not logged": 5, "used": 6}
    out.sort(key=lambda r: (rank.get(r["status"], 9), -r["never"]))
    return out


def _status(row, rule, entry, logged, g, cut_regions, days) -> tuple[str, str]:
    if entry == "0.0.0.0/0":
        return "open", "Open to every address: the users are listed; a prefix list or narrower range may do"
    if not logged:
        return "not logged", "Some of this group's interfaces have no flow log (accepted traffic) in CloudWatch Logs"
    if g["region"] in cut_regions:
        return "incomplete", "Some slices hit the 10,000 row limit even at an hour: not safe to act on"
    if days < EVIDENCE_DAYS:
        return "watch", f"Only {days:.0f} days of flow logs: read a longer range before changing this rule"
    if not row["here"] and not row["unattributed"]:
        return "unused", f"No connection matched this rule in {days:.0f} days"
    private = not entry.startswith("pl-") and any(
        sg_ipintel.cidr_iv(entry) and a <= sg_ipintel.cidr_iv(entry)[0] and sg_ipintel.cidr_iv(entry)[1] <= b
        for a, b in PRIVATE[:3]
    )
    plen = int(entry.split("/")[1]) if "/" in entry else 32
    if private and plen < sg_tightener.DEFAULT_PREFIX_THRESHOLD and row["never"]:
        return "tighten", "Wider than needed: the suggested ranges keep every address seen, with 30% headroom"
    if not private and not entry.startswith("pl-") and plen < 32 and row["never"]:
        return "tighten", "Public range: the suggestion keeps only the addresses seen; check with the partner first"
    return "used", ""


def approved(doc: dict, region: str) -> dict:
    """sg-tightener's approved list (v2) for one region, from the accepted connections read."""
    snap = (doc["regions"].get(region) or {}).get("snapshot") or {}
    enis = snap.get("enis") or {}
    own = {ip for e in enis.values() for ip in e["ips"]}
    flows, warnings = set(), []
    folded = 0
    for c in doc["chunks"]:
        if c["r"] != region or c["st"] not in ("ok", "cut"):
            continue
        for src, dst, eni, proto, dport, action, _f in c["rows"]:
            if action != "ACCEPT" or not src or src in own:
                continue
            e = enis.get(eni)
            if e is not None and dst not in e["ips"]:
                continue
            if dport >= EPHEMERAL:
                folded += 1
                continue
            flows.add((src, dst, dport, int(proto) if str(proto).isdigit() else proto, eni))
    if folded:
        warnings.append(f"{folded} records to ports {EPHEMERAL} and up were read folded together and left out")
    qsets = (doc["regions"].get(region) or {}).get("query_sets") or []
    first = min((c["s"] for c in doc["chunks"] if c["r"] == region), default=None)
    return {
        "schema": "sg-tightener.approved/v2",
        "region": region,
        "days": round((time.time() - first) / DAY) if first else 0,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "sg_review",
        "flow_log_check": {"verified": True, "fields": fields_of(qsets[0]["format"]) if qsets else [],
                           "warnings": warnings,
                           "resources": sorted({f["resource"] for f in snap.get("flow_logs") or []})},  # fmt: skip
        "ips": sorted({f[0] for f in flows}, key=lambda s: _ip(s) or 0),
        "flows": [{"src": a, "dst": b, "dstport": p, "protocol": pr, "interface": i}
                  for a, b, p, pr, i in sorted(flows, key=str)],
    }  # fmt: skip


# ------------------------------------------------------------------------------------------- reading
def plan_read(sess, doc: dict, regions: Sequence[str], days: int, now: float, say=LOG.info) -> list[tuple]:
    """Take each region's snapshot and rule history into ``doc`` and return the slices still to read."""
    tasks = []
    for region in regions:
        say(f"reading security groups, interfaces and flow logs in {region}")
        entry = doc["regions"].setdefault(region, {})
        try:
            entry["snapshot"] = snapshot(sess, region)
            entry["taken"] = now
            entry.pop("error", None)
        except (ClientError, BotoCoreError) as exc:  # one region out of reach must not stop the others
            entry["error"] = describe_error(exc)[:300]
            LOG.warning("%s not read: %s", region, entry["error"])
            continue
        try:
            entry["history"] = rule_history(sess, region, utcnow())
        except (ClientError, BotoCoreError) as exc:  # the report says history is unknown
            entry["history"] = {"events": [], "whole_since": now, "read": False, "error": describe_error(exc)[:300]}
            LOG.warning("%s: rule changes not read from CloudTrail: %s", region, entry["history"]["error"])
        qsets = query_sets(entry["snapshot"])
        entry["query_sets"] = qsets
        if not qsets:
            LOG.warning("%s: no VPC flow log in CloudWatch Logs with source, target, port, action and interface", region)
            continue
        have = [(c["s"], c["e"]) for c in doc["chunks"] if c["r"] == region and c["st"] in ("ok", "cut")]
        vpcs = _vpc_ranges(entry["snapshot"])
        tasks += [(region, s, e, qsets, vpcs) for s, e in plan(now, days, have)]
    return tasks


def run_read(sess, doc: dict, tasks: list[tuple], days: int, now: float, cancelled=lambda: False) -> dict:
    """Read the slices into ``doc`` (saved every dozen slices and at the end)."""
    lock = threading.Lock()
    clients: dict = {}
    state = {"done": 0, "bytes": 0}

    def one(task):
        region, s, e, qsets, vpcs = task
        if cancelled():
            return
        with lock:
            logs = clients.get(region) or clients.setdefault(
                region, sess.client("logs", region_name=region, config=BOTO_CONFIG)
            )
        for chunk in read_chunk(logs, region, s, e, qsets, vpcs, cancelled):
            with lock:
                doc["chunks"].append(chunk)
                state["bytes"] += chunk["b"]
        with lock:
            state["done"] += 1
            done = state["done"]
            if done % 12 == 0:
                save(doc)
        print(f"\r  {done} of {len(tasks)} slices · {_gb(state['bytes'])} scanned, "
              f"{_cost(state['bytes'] / 1e9 * INSIGHTS_PER_GB)}   ", end="", file=sys.stderr, flush=True)  # fmt: skip

    try:
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            list(pool.map(one, tasks))
    finally:
        print(file=sys.stderr)
        doc["reads"].append({"at": now, "days": days, "bytes": state["bytes"], "slices": state["done"]})
        save(doc)
    return state


def _gb(n: float) -> str:
    return f"{n / 1e9:.2f} GB" if n >= 1e8 else f"{n / 1e6:.1f} MB"


def _cost(c: float | None) -> str:
    if c is None:
        return "cost unknown until a first read measures it"
    return "under US$0.01" if c < 0.01 else f"about US${c:.2f}"


# ------------------------------------------------------------------------------------------- the page
def _evidence(doc: dict) -> tuple[int | None, int | None]:
    ok = [c for c in doc["chunks"] if c["st"] in ("ok", "cut")]
    if not ok:
        return None, None
    return min(c["s"] for c in ok), max(c["e"] for c in ok)


def page_data(doc: dict, onprem: str = "", internal: str = "", now: float | None = None,
              names: list | None = None) -> dict:  # fmt: skip
    """Everything the page shows: each timeline the read covers, built in full, so the page needs no server."""
    first, end = _evidence(doc)
    days = (end - first) / DAY if first is not None else 0
    keys = [k for k, (span, _) in RANGES.items() if span <= (days + 0.5) * DAY] or ["24h"]
    ranges = {k: build(doc, k, onprem, internal, names) for k in keys}
    regions = [r for r, x in doc["regions"].items() if x.get("query_sets")]
    return {
        "schema": "sg-tightener.review/v1",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "account": doc["account"],
        "name": doc.get("name", ""),
        "mode": doc.get("mode", "live"),
        "first": first,
        "end": end,
        "default": keys[-1],
        "ranges": ranges,
        "names": len(names or []),
        "source_types": [{"key": k, "name": n, "kind": kind, "note": sg_ipintel.GROUP_NOTE.get(k, "")}
                         for k, (n, kind) in SOURCE_TYPES.items()],
        "port_classes": [{"key": k, "name": n, "note": note, "risky": k in RISKY_CLASSES}
                         for k, (n, note) in PORT_CLASSES.items()],
        "estimate": estimate(doc, doc["account"], list(doc["regions"]), now),
        "regions": sorted(doc["regions"]),
        "approved": {r: approved(doc, r) for r in regions if any(c["r"] == r for c in doc["chunks"])},
    }


def _script_json(obj) -> str:
    """JSON safe inside a <script> element: nothing in it can close the element or open a comment."""
    s = json.dumps(obj, separators=(",", ":"))
    return s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render_page(data: dict) -> str:
    page = (ASSETS / "sg_review.html").read_text(encoding="utf-8")
    chart_js = (ASSETS / "chart.umd.js").read_text(encoding="utf-8")
    title = f"Security Group Review · {data.get('name') or data['account']}"
    fill = {"{{TITLE}}": html.escape(title), "/*{{CHART_JS}}*/": chart_js, "{{DATA}}": _script_json(data)}
    # One pass, so nothing inserted (an AWS tag, the chart library) is itself searched for placeholders.
    return re.sub("|".join(map(re.escape, fill)), lambda m: fill[m.group(0)], page)


def write_page(data: dict, out: str) -> None:
    path = Path(out)
    fd, tmp = tempfile.mkstemp(dir=path.resolve().parent, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(render_page(data))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


# ------------------------------------------------------------------------------------------------ CLI
def _session(profile: str | None):
    import boto3

    return boto3.Session(profile_name=profile) if profile else boto3.Session()


def _pick_account(given: str | None) -> str:
    if given:
        if not _ACCT_RE.fullmatch(given):
            raise SystemExit(f"--account must be a 12-digit account id, not {given!r}")
        return given
    have = cached_accounts()
    if len(have) == 1:
        return have[0]
    if not have:
        raise SystemExit("nothing read yet: run `sg_review.py read --regions ...` first")
    raise SystemExit(f"several accounts read ({', '.join(have)}): choose one with --account")


def _confirm(prompt: str) -> bool:
    try:
        return input(f"{prompt} Type yes to continue: ").strip().lower() == "yes"
    except EOFError:
        return False


def cmd_read(args) -> int:
    if args.days not in READ_DAYS:
        raise SystemExit(f"--days must be one of {', '.join(map(str, READ_DAYS))}")
    regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    sess = _session(args.profile)
    ident = with_backoff(lambda: sess.client("sts", config=BOTO_CONFIG).get_caller_identity())
    account = ident["Account"]
    name = args.name or ""
    if not name:
        try:
            aliases = sess.client("iam", config=BOTO_CONFIG).list_account_aliases().get("AccountAliases") or []
            name = aliases[0] if aliases else ""
        except (ClientError, BotoCoreError):
            name = ""
    doc = load(account) or new_doc(account, name)
    doc["name"] = name or doc.get("name", "")
    now = time.time()
    tasks = plan_read(sess, doc, regions, args.days, now)
    save(doc)
    if not tasks:
        LOG.info("nothing to read: the last %d days are already read in %s", args.days, ", ".join(regions))
        return 0
    est = estimate(doc, account, regions, now)
    hours = sum(e - s for _, s, e, _, _ in tasks) / HOUR
    cost = est["rate"] * hours * HOUR / 1e9 * INSIGHTS_PER_GB if est["rate"] is not None else None
    LOG.info("account %s%s: %d slices, %.0f hours of flow logs in %d region(s), %s (Logs Insights, about "
             "US$0.005 a GB scanned)", account, f" ({name})" if name else "", len(tasks), hours,
             len({t[0] for t in tasks}), _cost(cost))  # fmt: skip
    if cost is None and args.days > 1:
        LOG.warning("no read has measured this account's flow logs yet: `--days 1` first estimates what longer reads cost")
    if not args.yes and not _confirm("Read the flow logs?"):
        LOG.info("not read")
        return 1
    stop = threading.Event()
    previous = signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        state = run_read(sess, doc, tasks, args.days, now, stop.is_set)
    finally:
        signal.signal(signal.SIGINT, previous)
    failed = sum(1 for c in doc["chunks"] if c["st"] == "failed")
    LOG.info("%s %d of %d slices, %s scanned, %s", "stopped after" if stop.is_set() else "read", state["done"],
             len(tasks), _gb(state["bytes"]), _cost(state["bytes"] / 1e9 * INSIGHTS_PER_GB))  # fmt: skip
    if failed:
        LOG.warning("%d slice(s) failed and will be read again next time", failed)
    LOG.info("next: python sg_review.py report --account %s", account)
    return 130 if stop.is_set() else 0


def cmd_report(args) -> int:
    account = _pick_account(args.account)
    doc = load(account)
    if not doc or not doc["chunks"]:
        raise SystemExit(f"nothing read for {account}: run `sg_review.py read` first")
    if not args.offline:
        got = sg_ipintel.refresh()
        if got:
            LOG.info("address lists updated: %s", ", ".join(got))
    names = load_names(args.names)
    if names:
        LOG.info("names file: %d networks named", len(names))
    out = args.out or f"sg-review-{account}.html"
    write_page(page_data(doc, args.onprem, args.internal, names=names), out)
    LOG.info("wrote %s", out)
    return 0


def cmd_approved(args) -> int:
    account = _pick_account(args.account)
    doc = load(account)
    if not doc or args.region not in doc["regions"]:
        raise SystemExit(f"{args.region} was not read for {account}")
    body = approved(doc, args.region)
    Path(args.out).write_text(json.dumps(body, indent=2) + "\n")
    LOG.info("wrote %s: %d sources, %d flows", args.out, len(body["ips"]), len(body["flows"]))
    for w in body["flow_log_check"]["warnings"]:
        LOG.warning("%s", w)
    return 0


def cmd_demo(args) -> int:
    import sg_review_demo

    if not args.offline:
        sg_ipintel.refresh()
    now = time.time()
    doc = sg_review_demo.build_doc(sg_review_demo.ACCOUNT, now, 180)
    write_page(page_data(doc, "", sg_review_demo.INTERNAL, now, parse_names(sg_review_demo.NAMES)), args.out)
    LOG.info("wrote %s (a made-up account: no AWS call was made)", args.out)
    return 0


def cmd_names(args) -> int:
    p = Path(args.out).expanduser() if args.out else names_path()
    if p.exists():
        names = load_names(p)
        LOG.info("%s: %d networks named, all valid", p, len(names))
        for e in names:
            LOG.info("  %s (%s): %s", e["name"], e["type"], ", ".join([str(n) for n in e["ranges"]] + [f"AS{a}" for a in e["asn"]]))
        return 0
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(NAMES_EXAMPLE)
    LOG.info("wrote an example names file to %s: edit it, then run report", p)
    return 0


def cmd_forget(args) -> int:
    account = _pick_account(args.account)
    LOG.info("deleted what was read for %s" if forget(account) else "nothing was read for %s", account)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sg_review.py", description=__doc__.splitlines()[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter)  # fmt: skip
    p.add_argument("--data-dir", default=str(sg_ipintel.DATA_DIR),
                   help="where reads and address lists are kept (default ~/.sg-tightener)")  # fmt: skip
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("read", help="read an account's flow logs (live, read-only, cost confirmed first)")
    r.add_argument("--regions", required=True, help="comma-separated regions")
    r.add_argument("--days", type=int, default=1, help="read back this far: 1, 7, 30, 90 or 180 (default 1)")
    r.add_argument("--profile", help="AWS profile (default: the usual credential chain)")
    r.add_argument("--name", help="a name for the account in the report (default: its alias)")
    r.add_argument("--yes", action="store_true", help="skip the typed confirmation")
    r.set_defaults(fn=cmd_read)
    o = sub.add_parser("report", help="write the self-contained HTML page")
    o.add_argument("--account", help="the account read (default: the only one)")
    o.add_argument("--onprem", default="", help='data centre ranges to name, e.g. "10.200.0.0/16 Johannesburg DC"')
    o.add_argument("--internal", default="", help='your other accounts\' ranges, e.g. "10.40.0.0/16 Payments prod"')
    o.add_argument("--names", help="names file (YAML or JSON) naming partners and other networks by range or AS "
                   "number (default ~/.sg-tightener/names.yaml if it exists; `sg_review.py names` writes an example)")
    o.add_argument("--offline", action="store_true", help="do not refresh the public address lists")
    o.add_argument("--out", help="output file (default sg-review-<account>.html)")
    o.set_defaults(fn=cmd_report)
    a = sub.add_parser("approved", help="write sg-tightener's approved.json for one region")
    a.add_argument("--region", required=True)
    a.add_argument("--account")
    a.add_argument("--out", default="approved.json")
    a.set_defaults(fn=cmd_approved)
    d = sub.add_parser("demo", help="write the report for a made-up account")
    d.add_argument("--out", default="sg-review-demo.html")
    d.add_argument("--offline", action="store_true", help="do not refresh the public address lists")
    d.set_defaults(fn=cmd_demo)
    n = sub.add_parser("names", help="check the names file, or write an example one if there is none")
    n.add_argument("--out", help="the names file (default ~/.sg-tightener/names.yaml)")
    n.set_defaults(fn=cmd_names)
    f = sub.add_parser("forget", help="delete what was read for an account")
    f.add_argument("--account")
    f.set_defaults(fn=cmd_forget)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = _build_parser().parse_args(argv)
    sg_ipintel.set_data_dir(args.data_dir)
    try:
        return args.fn(args)
    except (ClientError, BotoCoreError) as exc:
        LOG.error("%s", describe_error(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
