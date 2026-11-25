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
The naming lists download into the database (sg_store.py) and are looked up locally: no address leaves the machine.

Modes:
  read      Read the account's security groups, interfaces, network ACLs, VPN routes, flow logs and 90 days
            of rule changes, then its VPC flow logs in CloudWatch Logs by Logs Insights, a slice at a time
            (hourly for the last day, six-hourly for the last week, daily beyond). Slices are kept in
            the database (sg_store.py), 12 months at most, so a later read fills only the gap. Logs Insights
            bills about US$0.005 a GB scanned: the cost is estimated and confirmed before reading.
  report    Write one self-contained HTML page (no server, no network) with the three timelines, the rules
            table and what to change, the CSV and an approved.json per region to download.
  approved  Write sg-tightener's approved.json (v2) for one region from what was read.
  demo      Write the report for a made-up account, to see it without AWS.
  names     Check the names file, or write an example one if there is none.
  forget    Delete what was read for an account.

Usage:
  sg_review.py read     --regions eu-west-1[,us-east-1] [--days 1|7|30|90|180|365] [--profile P] [--yes]
  sg_review.py report   [--account ID] [--onprem "10.200.0.0/16 Johannesburg DC, ..."]
                        [--internal "10.40.0.0/16 Payments prod, ..."] [--names FILE] [--offline] [--out FILE]
  sg_review.py approved --region R [--account ID] [--out approved.json]
  sg_review.py demo     [--offline] [--out sg-review-demo.html]
  sg_review.py names    [--out FILE]
  sg_review.py forget   --account ID
"""

from __future__ import annotations

import argparse
import bisect
import functools
import gzip
import html
import ipaddress
import json
import logging
import os
import random
import re
import shlex
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

try:
    from botocore.config import Config as BotoConfig
    from botocore.exceptions import (BotoCoreError, ClientError, ConnectionClosedError, ConnectTimeoutError,
                                     EndpointConnectionError, ReadTimeoutError)
except ImportError:  # run outside the venv: say how to install, not a traceback
    sys.exit("sg-tightener's Python packages are not installed: run ./install.sh, then source .venv/bin/activate")

import sg_ipintel
import sg_securityhub
import sg_store
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


TRANSIENT = (ReadTimeoutError, ConnectTimeoutError, EndpointConnectionError, ConnectionClosedError)


def with_backoff(fn: Callable, attempts: int = 7, sleep: Callable = time.sleep):
    """fn(), retried on throttling, and on a network timeout or dropped connection, after 1, 2, 4 ... seconds
    (capped at 30), with jitter."""
    for attempt in range(attempts):
        try:
            return fn()
        except (ClientError, *TRANSIENT) as exc:
            if (isinstance(exc, ClientError) and not _is_throttle(exc)) or attempt == attempts - 1:
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


def vpc_cidrs6(vpcs: list[dict]) -> list[str]:
    return sorted({a["Ipv6CidrBlock"] for v in vpcs for a in v.get("Ipv6CidrBlockAssociationSet") or []
                   if a.get("Ipv6CidrBlock")
                   and (a.get("Ipv6CidrBlockState") or {}).get("State", "associated") == "associated"})  # fmt: skip


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
    """Named ranges (IPv4 or IPv6), one per comma or line: "10.200.0.0/16 Johannesburg DC" (the name is optional)."""
    out = []
    for part in (text or "").replace("\n", ",").split(","):
        words = part.split()
        if not words:
            continue
        try:
            net = ipaddress.ip_network(words[0], strict=False)
        except ValueError:
            continue
        if net.prefixlen:
            out.append((net, " ".join(words[1:]) or f"{default} {net}"))
    return out


# ------------------------------------------------------------------------------------------ names file
NAME_TYPES = ("partner", "internal", "datacentre", *[g for g in sg_ipintel.GROUPS if g != "partner"])
NAMES_EXAMPLE = """\
# sg-tightener names: networks you know, shown by name on the Security Group Review page.
# type: partner (default), internal, datacentre, saas, security, cdn, hosting, scanner, anon, threat or other.
- name: Acme payroll
  type: partner
  ranges: [203.0.113.0/24]
  asn: [64500]
  note: SFTP drop, contract 2024-17
"""


def names_path() -> Path:
    return sg_ipintel.DATA_DIR / "names.yaml"


def parse_names(doc) -> list[dict]:
    """The entries of a names file, checked: [{name, type, ranges: [IPv4Network | IPv6Network], asn: [int], note}]."""
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
MIN_SPLIT = 60  # a slice that hits ROWS is halved while longer than this (the busiest VPCs read: under 4 minutes)
EPHEMERAL = 32768  # ports from here up are folded into one: replies to the account's own connections land there
PRIVATE_V4 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
PRIVATE_V6 = ("fc00::/7", "fe80::/10")  # unique local and link-local: never routed on the internet
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


def _has_needed(fields: list[str]) -> bool:
    """Every NEEDED field is there; pkt-srcaddr and pkt-dstaddr stand in for srcaddr and dstaddr (custom formats
    often log only the packet addresses, which are the better ones behind a NAT or transit gateway)."""
    have = set(fields) | {f[4:] for f in fields if f in ("pkt_srcaddr", "pkt_dstaddr")}
    return set(NEEDED) <= have


def readable(log_format: str | None) -> bool:
    return _has_needed(fields_of(log_format))


def _private(field: str) -> str:
    return "(" + " or ".join([f'isIpv4InSubnet({field}, "{c}")' for c in PRIVATE_V4]
                             + [f'isIpv6InSubnet({field}, "{c}")' for c in PRIVATE_V6]) + ")"


def _in_any(field: str, cidrs: list[str]) -> str:
    """A Logs Insights test that ``field`` is inside one of ``cidrs`` (IPv4 or IPv6)."""
    return "(" + " or ".join(f'isIpv{6 if ":" in c else 4}InSubnet({field}, "{c}")' for c in cidrs) + ")"


def _base(log_format: str | None, vpc_ranges: list[str]) -> tuple[str, str, str, bool] | None:
    """The parse and the inbound filter for a format: (query head, source field, target field, filtered by
    direction). Inbound is the flow-direction field when the format has it, else a target inside the
    account's VPCs (the report drops the interface's own outbound records)."""
    fields = fields_of(log_format)
    if not _has_needed(fields):
        return None
    src = "f_pkt_srcaddr" if "pkt_srcaddr" in fields else "f_srcaddr"
    dst = "f_pkt_dstaddr" if "pkt_dstaddr" in fields else "f_dstaddr"
    head = f'parse @message "{" ".join("*" for _ in fields)}" as {", ".join("f_" + f for f in fields)}'
    head += f' | filter {src} != "-" and {dst} != "-"'
    by_dir = "flow_direction" in fields
    if by_dir:
        head += ' and f_flow_direction = "ingress"'
    elif vpc_ranges and len(vpc_ranges) <= VPC_FILTER_MAX:
        head += " and " + _in_any(dst, vpc_ranges)
    return head, src, dst, by_dir


def reply_port(fields: list[str]) -> str | None:
    """A Logs Insights expression for the destination port with replies folded into EPHEMERAL, or None when the
    format lacks srcport. A reply is a record to a port from 1024 up that either carries SYN-ACK (tcp-flags 18:
    the source answered a connection) or has no SYN and comes from a lower port than it goes to (the middle of
    a connection the target opened to the source's service). A Kubernetes NodePort answering clients on their
    random ports 1024 to 65535 gave one source and target 17,000 ports a day; replies need no inbound rule,
    since security groups are stateful. Insights has no if(), so it is arithmetic on 0 and 1."""
    if "srcport" not in fields:
        return None
    hi = "least(1, floor(f_dstport / 1024))"
    lower = "(f_srcport < f_dstport)"
    if "tcp_flags" in fields:
        reply = f"greatest(floor(f_tcp_flags / 16) % 2, (1 - floor(f_tcp_flags / 2) % 2) * {lower})"
    else:
        reply = lower
    return f"least(f_dstport + {hi} * {reply} * ({EPHEMERAL} - f_dstport), {EPHEMERAL})"


REPLY_PORTS = 20  # a source and target with more ports than this from 1024 up, in a read made before replies were folded


def fold_replies(doc: dict) -> int:
    """Rows saved before the detail query folded replies (5.24.0): a source and target seen on more than
    REPLY_PORTS ports from 1024 up are replies, so those ports become EPHEMERAL, as a read now gives them.
    Each region's learned slice length is forgotten too: it was learned while replies filled the row limit.
    Returns the rows dropped. Once per read: marked ``replies_folded``."""
    if doc.get("replies_folded"):
        return 0
    ports: dict = {}
    for c in doc.get("chunks") or []:
        for src, dst, eni, proto, dport, action, _ in c.get("rows") or []:
            if 1024 <= dport < EPHEMERAL:
                ports.setdefault((src, dst, eni, proto, action), set()).add(dport)
    noisy = {k for k, v in ports.items() if len(v) > REPLY_PORTS}
    dropped = 0
    for c in doc.get("chunks") or []:
        rows = c.get("rows") or []
        if not rows:
            continue
        merged: dict = {}
        for src, dst, eni, proto, dport, action, flows in rows:
            if 1024 <= dport < EPHEMERAL and (src, dst, eni, proto, action) in noisy:
                dport = EPHEMERAL
            k = (src, dst, eni, proto, dport, action)
            merged[k] = merged.get(k, 0) + (flows or 0)
        if len(merged) < len(rows):
            dropped += len(rows) - len(merged)
            c["rows"] = [[*k, n] for k, n in merged.items()]
            c.pop("k", None)  # a saved slice is only written again without its row id
    for entry in (doc.get("regions") or {}).values():
        entry.pop("slice", None)
    doc["replies_folded"] = 1
    return dropped


def detail_query(log_format: str | None, vpc_ranges: list[str], fold: bool | str = True) -> str | None:
    """Accepted inbound connections, and refused ones from private addresses, by source, target, interface,
    protocol, port and action. ``fold`` True: replies and ports from EPHEMERAL up folded into one; "high": only
    ports from EPHEMERAL up; False: every port."""
    b = _base(log_format, vpc_ranges)
    if not b:
        return None
    head, src, dst, _ = b
    port = (fold is True and reply_port(fields_of(log_format))) or (f"least(f_dstport, {EPHEMERAL})" if fold else "f_dstport")
    # every connection, refused internet ones included: one scan of the log gives both who connected and who
    # was turned away (``public_rows`` splits those out), where a second query would scan it all again
    return (
        f"{head}"
        f" | fields {port} as dport"
        f" | stats count(*) as flows, sum(f_bytes) as bytes by {src} as src, {dst} as dst,"
        f" f_interface_id as eni, f_protocol as proto, dport, f_action as action | sort flows desc | limit {ROWS}"
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


def egress_query(log_format: str | None, vpc_ranges: list[str]) -> str | None:
    """Accepted outbound connections from the account's interfaces, by source, target, interface, protocol and
    port. Only with `read --egress`: it is a third query per slice. Ports from EPHEMERAL up are left out (they are
    replies to inbound connections when the format has no flow direction)."""
    fields = fields_of(log_format)
    if not _has_needed(fields):
        return None
    src = "f_pkt_srcaddr" if "pkt_srcaddr" in fields else "f_srcaddr"
    dst = "f_pkt_dstaddr" if "pkt_dstaddr" in fields else "f_dstaddr"
    head = f'parse @message "{" ".join("*" for _ in fields)}" as {", ".join("f_" + f for f in fields)}'
    head += f' | filter {src} != "-" and {dst} != "-" and f_action = "ACCEPT" and f_dstport < {EPHEMERAL}'
    if "flow_direction" in fields:
        head += ' and f_flow_direction = "egress"'
    elif vpc_ranges and len(vpc_ranges) <= VPC_FILTER_MAX:
        head += " and " + _in_any(src, vpc_ranges)
    else:
        return None  # no way to tell outbound from inbound
    return (f"{head} | stats count(*) as flows by {src} as src, {dst} as dst, f_interface_id as eni,"
            f" f_protocol as proto, f_dstport as dport | limit {ROWS}")


def run_query(logs, groups: list[str], query: str, start: int, end: int, wait: float = 900,
              cancelled=lambda: False) -> tuple[list[dict] | None, int, str]:  # fmt: skip
    """(rows or None, bytes scanned, status) of one Logs Insights query over [start, end). A slice before the
    log group existed, or older than its retention, holds nothing: no rows, not an error."""
    try:
        qid = with_backoff(
            lambda: logs.start_query(
                logGroupNames=groups[:50], startTime=int(start), endTime=int(end) - 1, queryString=query, limit=ROWS
            )  # fmt: skip
        )["queryId"]
    except ClientError as exc:
        msg = str(exc)
        if exc.response.get("Error", {}).get("Code") == "MalformedQueryException" and (
            "creation time" in msg or "retention" in msg
        ):
            return [], 0, "Complete"
        raise
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
        "cidrs6": [r["CidrIpv6"] for r in perm.get("Ipv6Ranges") or [] if r.get("CidrIpv6")],
        "xrefs": [{"group": p.get("GroupId", ""), "account": p.get("UserId", ""), "peering": p.get("VpcPeeringConnectionId", "")}
                  for p in perm.get("UserIdGroupPairs") or [] if p.get("UserId")],
    }


def _internet_routes(ec2, errors: list) -> dict:
    """Which subnets route the internet to an internet gateway: {"subnets": {id: {...}}, "main": {vpc: {...}}},
    each {"igw4": bool, "igw6": bool, "table": id}. Subnets with no table of their own use their VPC's main one."""
    out: dict = {"subnets": {}, "main": {}, "read": True}
    try:
        tables = _pages(ec2, "describe_route_tables", "RouteTables")
    except (ClientError, BotoCoreError) as exc:
        errors.append(f"route tables: {describe_error(exc)}")
        return {"subnets": {}, "main": {}, "read": False}
    for t in tables:
        igw4 = igw6 = False
        for r in t.get("Routes") or []:
            gw = r.get("GatewayId") or ""
            if not gw.startswith("igw-") or r.get("State", "active") != "active":
                continue
            igw4 = igw4 or r.get("DestinationCidrBlock") == "0.0.0.0/0"
            igw6 = igw6 or r.get("DestinationIpv6CidrBlock") == "::/0"
        row = {"igw4": igw4, "igw6": igw6, "table": t.get("RouteTableId", "")}
        for a in t.get("Associations") or []:
            if a.get("Main"):
                out["main"][t.get("VpcId", "")] = row
            elif a.get("SubnetId"):
                out["subnets"][a["SubnetId"]] = row
    return out


def _stale_refs(ec2, vpc_ids: list[str], errors: list) -> list[dict]:
    """Rules that reference a security group which no longer exists (or a peer that went away)."""
    out = []
    for vpc in vpc_ids:
        try:
            sets = _pages(ec2, "describe_stale_security_groups", "StaleSecurityGroupSet", VpcId=vpc)
        except (ClientError, BotoCoreError) as exc:
            errors.append(f"stale security group references in {vpc}: {describe_error(exc)}")
            return out
        for g in sets:
            for direction, key in (("in", "StaleIpPermissions"), ("out", "StaleIpPermissionsEgress")):
                for p in g.get(key) or []:
                    for pair in p.get("UserIdGroupPairs") or []:
                        out.append({"group": g.get("GroupId", ""), "name": g.get("GroupName", ""), "vpc": vpc,
                                    "direction": direction, "proto": str(p.get("IpProtocol", "-1")),
                                    "from": p.get("FromPort"), "to": p.get("ToPort"),
                                    "ref": pair.get("GroupId", ""), "account": pair.get("UserId", ""),
                                    "peering": pair.get("VpcPeeringConnectionId", "")})  # fmt: skip
    return out


def _instances(ec2, ids: list[str], errors: list) -> dict:
    """What each attached instance is, for the page to say what sits behind an address: its Name tag, operating
    system (Linux/UNIX, Windows, Red Hat …), type and launch time."""
    out: dict = {}
    for i in range(0, len(ids), 100):
        try:
            for res in ec2.describe_instances(InstanceIds=ids[i:i + 100]).get("Reservations", []):
                for inst in res.get("Instances", []):
                    launched = inst.get("LaunchTime")
                    out[inst["InstanceId"]] = {
                        "name": _name(inst.get("Tags")),
                        "os": inst.get("PlatformDetails") or ("Windows" if inst.get("Platform") == "windows" else "Linux/UNIX"),
                        "type": inst.get("InstanceType", ""),
                        "launched": launched.timestamp() if hasattr(launched, "timestamp") else None,
                        "image": inst.get("ImageId", ""),
                    }  # fmt: skip
        except (ClientError, BotoCoreError) as exc:
            errors.append(f"instances: {exc}")
            break
    return out


def hosts_model(doc: dict) -> dict:
    """Every address of the account's own interfaces, and what is behind each: so a refused source inside your
    VPCs, or a destination, is named down to the instance, its name and operating system, and its groups."""
    by_ip: dict[str, str] = {}
    enis: dict[str, list] = {}
    for region, x in doc["regions"].items():
        snap = x.get("snapshot") or {}
        groups, insts = snap.get("groups") or {}, snap.get("instances") or {}
        for eid, e in (snap.get("enis") or {}).items():
            inst = insts.get(e.get("instance") or "") or {}
            enis[eid] = [e.get("kind", ""), e.get("instance", ""), inst.get("name", ""), inst.get("os", ""),
                         inst.get("type", ""), [groups.get(g, {}).get("name") or g for g in e.get("groups") or []],
                         region, e.get("desc", "")]  # fmt: skip
            for ip in (e.get("ips") or []) + (e.get("ipv6") or []) + ([e["public"]] if e.get("public") else []):
                by_ip.setdefault(ip, eid)
    return {"by_ip": by_ip, "enis": enis}


def snapshot(session, region: str) -> dict:
    ec2 = session.client("ec2", region_name=region, config=BOTO_CONFIG)
    out: dict = {"errors": []}
    vpcs = _pages(ec2, "describe_vpcs", "Vpcs")
    out["vpcs"] = [{"id": v["VpcId"], "name": _name(v.get("Tags")), "cidrs": vpc_cidrs([v]), "cidrs6": vpc_cidrs6([v])}
                   for v in vpcs]  # fmt: skip
    out["groups"] = {
        g["GroupId"]: {
            "name": g.get("GroupName", ""),
            "vpc": g.get("VpcId", ""),
            "tag": _name(g.get("Tags")),
            "owner": g.get("OwnerId", ""),
            "rules": [_rule(p) for p in g.get("IpPermissions") or []],
            "egress": [_rule(p) for p in g.get("IpPermissionsEgress") or []],
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
            "ipv6": [a["Ipv6Address"] for a in e.get("Ipv6Addresses") or [] if a.get("Ipv6Address")],
            "prefixes6": [p["Ipv6Prefix"] for p in e.get("Ipv6Prefixes") or [] if p.get("Ipv6Prefix")],
        }
    out["enis"] = enis
    out["instances"] = _instances(ec2, sorted({e["instance"] for e in enis.values() if e["instance"]}), out["errors"])
    out["routes"] = _internet_routes(ec2, out["errors"])
    out["stale"] = _stale_refs(ec2, [v["id"] for v in out["vpcs"]], out["errors"])
    pls: dict = {}
    pls6: dict = {}
    for pid in sorted({p for g in out["groups"].values() for r in g["rules"] for p in r["pls"]}):
        try:
            got = [x["Cidr"] for x in _pages(ec2, "get_managed_prefix_list_entries", "Entries", PrefixListId=pid)
                   if x.get("Cidr")]  # fmt: skip
            pls[pid] = [c for c in got if ":" not in c]
            pls6[pid] = [c for c in got if ":" in c]
        except (ClientError, BotoCoreError) as exc:
            out["errors"].append(f"prefix list {pid}: {exc}")
    out["prefix_lists"] = pls
    out["prefix_lists6"] = pls6
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
        entries6 = sorted(
            ({"n": x.get("RuleNumber", 32767), "proto": str(x.get("Protocol", "-1")),
              "allow": x.get("RuleAction") == "allow", "cidr": x["Ipv6CidrBlock"],
              "from": (x.get("PortRange") or {}).get("From", 0), "to": (x.get("PortRange") or {}).get("To", 65535)}
             for x in n.get("Entries") or [] if not x.get("Egress") and x.get("Ipv6CidrBlock")),
            key=lambda x: x["n"],
        )  # fmt: skip
        for a in n.get("Associations") or []:
            nacls[a.get("SubnetId", "")] = {"id": n.get("NetworkAclId", ""), "entries": entries, "entries6": entries6}
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
    out["privatelink"] = privatelink_snapshot(session, ec2, region, out["errors"])
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


def _perm_entries6(perms) -> list[list]:
    """[proto, from, to, range] for each IPv6 range in CloudTrail's ipPermissions (kept apart from the IPv4
    entries the rule history works back through)."""
    out = []
    for p in _items(perms):
        r = _rule({"IpProtocol": p.get("ipProtocol"), "FromPort": p.get("fromPort"), "ToPort": p.get("toPort")})
        for x in _items(p.get("ipv6Ranges")):
            if x.get("cidrIpv6"):
                out.append([r["proto"], r["from"], r["to"], x["cidrIpv6"]])
    return out


def _modified_to(inner: dict) -> list[list]:
    """What ModifySecurityGroupRules set each rule to: [proto, from, to, range, rule id]."""
    out = []
    v = inner.get("SecurityGroupRule") or inner.get("securityGroupRule")
    rows = _items(v) if isinstance(v, dict) and "items" in v else v if isinstance(v, list) else [v] if v else []
    for x in rows:
        rule = x.get("SecurityGroupRule") or x.get("securityGroupRule") or {}
        cidr = rule.get("CidrIpv4") or rule.get("CidrIpv6") or rule.get("cidrIpv4") or rule.get("cidrIpv6")
        if not cidr:
            continue
        r = _rule({"IpProtocol": rule.get("IpProtocol") or rule.get("ipProtocol"),
                   "FromPort": rule.get("FromPort", rule.get("fromPort")), "ToPort": rule.get("ToPort", rule.get("toPort"))})
        out.append([r["proto"], r["from"], r["to"], cidr, x.get("SecurityGroupRuleId") or x.get("securityGroupRuleId") or ""])
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
    out = {"t": t, "name": name, "who": who, "added": [], "removed": [], "unknown": False,
           "ip": (doc.get("sourceIPAddress") or "")[:60]}
    if name == "ModifySecurityGroupRules":
        inner = req.get("ModifySecurityGroupRulesRequest") or req
        out["group"] = inner.get("GroupId") or inner.get("groupId") or ""
        out["unknown"] = True  # the rule's earlier value is not in the event
        out["set"] = _modified_to(inner)
        return out
    out["group"] = req.get("groupId") or ""
    entries = _perm_entries(req.get("ipPermissions"))
    if name == "RevokeSecurityGroupIngress" and _items(req.get("securityGroupRuleIds")) and not entries:
        out["unknown"] = True  # revoked by rule id: which range it was is not in the event
    out["added" if name == "AuthorizeSecurityGroupIngress" else "removed"] = entries
    out["added6" if name == "AuthorizeSecurityGroupIngress" else "removed6"] = _perm_entries6(req.get("ipPermissions"))
    return out if out["group"] else None


# --------------------------------------------------------------------------------------------- drift
DRIFT_WINDOW = 86400  # rule changes this recent are "new" (watch --alerts all posts each once)


def drift_findings(doc: dict, now: float, window: float = DRIFT_WINDOW) -> list[dict]:
    """Rules opened wide in the last ``window``: 0.0.0.0/0 or ::/0 (critical on a risky port, high on others,
    medium on a web port), an internet range of a /16 or wider (high on a risky port, else medium), or a private
    /8 on a risky port (medium). Each names who, from where, and the command that takes it back out."""
    out = []
    for region, x in sorted(doc["regions"].items()):
        groups = (x.get("snapshot") or {}).get("groups") or {}
        for ev in (x.get("history") or {}).get("events") or []:
            if ev["t"] < now - window:
                continue
            entries = [(*e, "") for e in ev.get("added") or []] + [(*e, "") for e in ev.get("added6") or []]
            entries += [tuple(e) for e in ev.get("set") or []]
            for proto, lo, hi, cidr, rule_id in entries:
                if str(cidr).startswith("pl-"):
                    continue
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    continue
                rule = {"proto": str(proto), "from": lo, "to": hi}
                pc = rule_port_class(rule)
                risky = pc["risky"] or pc["cls"] == "all"
                if net.prefixlen == 0:
                    sev = "critical" if risky else "medium" if pc["cls"] == "web" else "high"
                elif not net.is_private and net.num_addresses >= (65536 if net.version == 4 else 2 ** 96):
                    sev = "high" if risky else "medium"
                elif net.is_private and net.version == 4 and net.prefixlen <= 8 and risky:
                    sev = "medium"
                else:
                    continue
                gid = ev["group"]
                gname = (groups.get(gid) or {}).get("name") or gid
                ports = ports_label(rule)
                cli = db_exec(f"aws ec2 revoke-security-group-ingress --region {region} --group-id {gid} "
                              f"--security-group-rule-ids {rule_id}" if rule_id else
                              f"aws ec2 revoke-security-group-ingress --region {region} --group-id {gid} "
                              f"--ip-permissions '{_perm_arg(str(proto), lo, hi, cidr)}'",
                              f"sg_review: {ports} opened to {cidr} by {ev.get('who') or 'unknown'}")  # fmt: skip
                still = any(cidr in (r.get("cidrs") or []) + (r.get("cidrs6") or []) and r["from"] <= lo <= r["to"]
                            for r in (groups.get(gid) or {}).get("rules") or [])  # fmt: skip
                if not still:
                    sev = "low"  # already taken back out: shown, not alerted
                out.append({
                    **_pl_item("drift-wide", sev, "Opened wide",
                               f"{ev['who'] or 'Someone'} opened {gname} to {cidr} on {ports}",
                               f"{ev['name']} at {_stamp(ev['t'])} UTC by {ev['who'] or 'an unknown principal'}"
                               + (f" from {ev['ip']}" if ev.get("ip") else "")
                               + f": {cidr} ({net.num_addresses:,} IP addresses) on {pc['svc']}."
                               + (" It is still there." if still else " It has since been removed."),
                               "Ask whoever made the change why; take it out unless it is meant and approved, and "
                               "narrow it to the IP addresses that need it.",
                               region, gname, cli if still else "", group=gid, target=f"{ports} from {cidr}"),
                    "kind": "drift", "event": {"t": ev["t"], "group": gid, "who": ev["who"]}, "still": still,
                    "rule": {"proto": str(proto), "from": lo, "to": hi, "cidr": cidr, "id": rule_id}})
    out.sort(key=lambda it: (SEV_RANK[it["sev"]], -it["event"]["t"]))
    return out


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
READ_DAYS = (1, 7, 30, 90, 180, 365)
RANGES = {
    "24h": (DAY, HOUR),
    "1w": (7 * DAY, SIX),
    "1m": (30 * DAY, DAY),
    "3m": (90 * DAY, DAY),
    "6m": (180 * DAY, DAY),
    "1y": (365 * DAY, 7 * DAY),  # a bar a week
}
LAG = 900  # flow logs reach CloudWatch up to ~10 minutes late: the newest quarter hour is left for the next read
TAIL_LAG = 300  # watch also reads from the last full hour up to five minutes ago ("tail" slices), to alert in minutes
WORKERS = 8  # slices of one account read at once: well inside the Logs Insights concurrent-query quota
REGION_WORKERS = 8  # regions read at once in one account: each region has its own API limits
EVIDENCE_DAYS = 0  # fewer days of flow logs than this and no rule is called unused or ready to tighten. Owner's
# decision (2026-11-24): act on whatever was read; what runs less often than the read (monthly jobs, DR tests)
# shows on Rejected traffic, where Fix… lets it in again. It was 30.
NEW_DAYS = 7  # a source first seen this recently is new...
NEW_HISTORY_DAYS = 14  # ...when at least this many days of flow logs before it were read without it
INSIGHTS_PER_GB = 0.005
TOP = 400  # sources listed per table (the charts count all of them)
FIT_CAP = 1500  # sources one rule may carry into the page's Tighten panel; more and sg_tightener plan is the tool
CATS = ("internal", "datacentre", "aws", "saas", "internet")
EXTERNAL_CATS = ("aws", "saas", "internet")  # public IP addresses: anyone's AWS, SaaS and partners, everyone else
CAT_NAME = {"internal": "Internal (your VPCs)", "datacentre": "Data centre and other private",
            "aws": "AWS", "saas": "External: SaaS and partners", "internet": "External: other networks"}  # fmt: skip
PRIVATE = [sg_ipintel.cidr_iv(c) for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]
ALL = [(0, 2**32 - 1)]
_ACCT_RE = re.compile(r"^[0-9]{12}$")


# ------------------------------------------------------------------------------------------- cache
# Each account's read is kept in the database (sg_store: review_accounts, review_regions, review_slices), so a
# later read fills only the gap. Slices older than 12 months are deleted on every save.
def _dir():
    """Where the reads' companion state is keyed (watch, Security Hub, the VPC index): no longer a folder on disk."""
    return sg_ipintel.DATA_DIR / "review"


def cached_accounts() -> list[str]:
    return [a for a in sg_store.review_accounts() if _ACCT_RE.fullmatch(a)]


def _check(account: str) -> str:
    if not _ACCT_RE.fullmatch(account or ""):
        raise KeyError(account)
    return account


def stamp(account: str) -> float | None:
    """When the account's read was last saved, or None when it has never been read."""
    return sg_store.review_stamp(_check(account))


def stamps() -> dict[str, float]:
    """{account: when its read was last saved} for every account read."""
    return {a: t for a, t in sg_store.review_stamps().items() if _ACCT_RE.fullmatch(a)}


def load(account: str, rows: bool = True) -> dict | None:
    """An account's read; ``rows=False`` leaves out the flow-log rows (never save a doc loaded that way)."""
    doc = sg_store.review_load(_check(account), doc_schema=SCHEMA, rows=rows)
    if doc and rows:
        fold_replies(doc)  # saved with the account's next read; `sg_review.py fold-replies` saves every account now
    return doc


def save(doc: dict) -> None:
    _check(doc["account"])
    doc.setdefault("reads", [])
    sg_store.review_save(doc)
    if doc.get("mode") != "demo":
        idx = vpc_index(build_missing=False)
        idx[doc["account"]] = _vpcs_of(doc)
        _save_index(idx)


# ------------------------------------------------------------------------------------------- every account's VPCs
# Each account read is remembered with its VPC ranges (vpcs.json beside the reads), so a source in another of
# your accounts is named by that account and VPC in every review, without listing it in --internal.
def _vpcs_of(doc: dict) -> dict:
    return {"name": doc.get("name", ""),
            "vpcs": [[region, v["id"], v.get("name") or "", v.get("cidrs") or [], v.get("cidrs6") or []]
                     for region, x in sorted(doc["regions"].items())
                     for v in (x.get("snapshot") or {}).get("vpcs") or []]}  # fmt: skip


def _save_index(idx: dict) -> None:
    sg_store.File(_dir() / "vpcs.json").write_text(json.dumps(idx, separators=(",", ":")))


def vpc_index(build_missing: bool = True) -> dict:
    """{account: {name, vpcs: [[region, vpc id, vpc name, IPv4 ranges, IPv6 ranges]]}} for every account read."""
    try:
        idx = json.loads(sg_store.File(_dir() / "vpcs.json").read_text())
        if not isinstance(idx, dict):
            idx = {}
    except (OSError, ValueError):
        idx = {}
    if build_missing:  # reads saved before the index existed; reads deleted since
        cached = cached_accounts()
        gone = [a for a in idx if a not in cached]
        for a in gone:
            del idx[a]
        missing = [a for a in cached if a not in idx]
        for a in missing:
            doc = load(a)
            idx[a] = _vpcs_of(doc) if doc and doc.get("mode") != "demo" else None  # null: not looked at again
        if gone or missing:
            _save_index(idx)
        idx = {a: x for a, x in idx.items() if x}
    return idx


def siblings(doc: dict) -> list[dict]:
    """Your other accounts and their VPCs: [{account, name, vpcs}]. The demo carries its own."""
    if doc.get("mode") == "demo":
        return doc.get("siblings") or []
    return [{"account": a, **x} for a, x in sorted(vpc_index().items()) if a != doc["account"]]


def forget(account: str) -> bool:
    idx = vpc_index(build_missing=False)
    if idx.pop(account, None) is not None:  # a forgotten account no longer names sources in other reviews
        _save_index(idx)
    gone = sg_store.review_forget(_check(account))
    for p in (_watch_path(account), _hub_path(account)):
        sg_store.File(p).unlink()
    return gone


def new_doc(account: str, name: str, mode: str = "live") -> dict:
    return {"schema": SCHEMA, "account": account, "name": name, "mode": mode, "regions": {}, "chunks": [],
            "reads": [], "replies_folded": 1}  # fmt: skip


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
    """The VPCs' IPv4 ranges, then their IPv6 ranges."""
    v4 = sorted({c for v in snap.get("vpcs") or [] for c in v.get("cidrs") or [] if ":" not in c})
    return v4 + sorted({c for v in snap.get("vpcs") or [] for c in v.get("cidrs6") or []})


def _stamp(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%d %b %H:%M")


def read_chunk(logs, region: str, s: int, e: int, qsets: list, vpcs: list, cancelled=lambda: False,
               egress: bool = False, tick=None, hint: dict | None = None) -> list[dict]:
    """One slice read (split in halves, down to a few minutes, while the detail query hits the row limit).

    ``hint`` (shared by the slices of one read) holds, per region, the longest span known to hit the row limit:
    a slice longer than it is split at once instead of being queried whole first (each of those queries is
    billed and thrown away). ``tick(nbytes, seconds)`` is called as each piece is read, for live progress.
    A read stopped part way returns no chunk for what it did not finish."""
    if cancelled():
        return []
    whole = hint is not None and region in hint.get("_whole", ())
    if not whole and hint is not None and hint.get(region) and e - s >= hint[region] and e - s > MIN_SPLIT:
        mid = s + _floor((e - s) // 2, HOUR) if e - s >= 2 * HOUR else (s + e) // 2
        return [*read_chunk(logs, region, mid, e, qsets, vpcs, cancelled, egress, tick, hint),
                *read_chunk(logs, region, s, mid, qsets, vpcs, cancelled, egress, tick, hint)]  # fmt: skip
    rows, pub, egr, nbytes, cut, pub_cut, errors = [], [], [], 0, False, False, []
    for q in qsets:
        rs, b, status = None, 0, ""
        for fold in (True, "high", False):
            query = detail_query(q["format"], vpcs, fold=fold)
            rs, b, status = run_query(logs, q["groups"], query, s, e, cancelled=cancelled)
            nbytes += b
            if rs is not None or status in ("Cancelled", "Timeout"):
                break
        if rs is None:
            if cancelled():
                if tick:
                    tick(nbytes, 0)
                return []
            errors.append(f"detail query {status}")
            continue
        if len(rs) >= ROWS:
            if e - s <= MIN_SPLIT and hint is not None:  # a minute still overflows: splitting cannot fit this region
                hint.setdefault("_whole", set()).add(region)
            if e - s > MIN_SPLIT and not whole and region not in (hint or {}).get("_whole", ()):
                if hint is not None:
                    hint[region] = min(hint.get(region) or e - s, e - s)
                mid = s + _floor((e - s) // 2, HOUR) if e - s >= 2 * HOUR else (s + e) // 2
                if tick:
                    tick(nbytes, 0)
                parts = [
                    *read_chunk(logs, region, mid, e, qsets, vpcs, cancelled, egress, tick, hint),
                    *read_chunk(logs, region, s, mid, qsets, vpcs, cancelled, egress, tick, hint),
                ]
                if parts:
                    parts[0]["b"] += nbytes  # the full slice's query was billed too
                return parts  # fmt: skip
            cut = True
        got = [[r.get("src"), r.get("dst"), r.get("eni"), r.get("proto"), _int(r.get("dport")), r.get("action"),
                _int(r.get("flows"))] for r in rs]  # fmt: skip
        kept, refused = public_rows(got)
        rows += kept
        pub_cut = pub_cut or len(rs) >= ROWS
        pub += refused
        eq = egress_query(q["format"], vpcs) if egress else None
        if eq:
            es, b, status = run_query(logs, q["groups"], eq, s, e, cancelled=cancelled)
            nbytes += b
            if es is None:
                errors.append(f"outbound query {status}")
            else:
                egr += [[r.get("src"), r.get("dst"), r.get("eni"), r.get("proto"), _int(r.get("dport")),
                         _int(r.get("flows"))] for r in es]  # fmt: skip
    if cancelled() and errors:  # stopped part way: not recorded, so the next read asks for these hours again
        if tick:
            tick(nbytes, 0)
        return []
    if tick:
        tick(nbytes, e - s)
    st = "failed" if errors and not rows and not pub else ("cut" if cut else "ok")
    top = cut and hint is not None and region in hint.get("_whole", ())
    out = {"r": region, "s": s, "e": e, "st": st, "b": nbytes, "rows": rows, "pub": pub, "pc": pub_cut,
           "err": "; ".join(errors)}
    out["q1"] = 1  # one scan per slice (before, a second query scanned it all again for refused internet sources)
    if top:
        out["top"] = 1  # the busiest 10,000 rows of a slice no split can fit: not read again finer
    if egress:
        out["egr"] = egr
    return [out]


def _is_public(ip) -> bool:
    """An internet address: outside PRIVATE_V4 / PRIVATE_V6 (the same test ``_private`` makes in a query)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(a in ipaddress.ip_network(c) for c in (PRIVATE_V4 if a.version == 4 else PRIVATE_V6))


def public_rows(rows: list[list]) -> tuple[list[list], list[list]]:
    """Split one query's rows into the connection rows (accepted, or refused from a private address) and one row
    per refused internet source, as the refused-internet query gave them: [src, flows, ports, targets, and the
    target, interface, port and protocol it hit most]."""
    kept: list = []
    by: dict = {}
    for r in rows:
        if r[5] == "REJECT" and _is_public(r[0]):
            by.setdefault(r[0], []).append(r)
        else:
            kept.append(r)
    pub = []
    for src, rs in by.items():
        top = max(rs, key=lambda x: x[6] or 0)
        pub.append([src, sum(x[6] or 0 for x in rs), len({(x[3], x[4]) for x in rs}), len({x[1] for x in rs}),
                    top[1], top[2], top[4], top[3]])  # fmt: skip
    pub.sort(key=lambda x: -x[1])
    return kept, pub


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
    def billed(c):  # what reading it again costs now: slices read with two queries scanned each hour twice
        return c["b"] if c.get("q1") else c["b"] / 2

    nbytes = sum(billed(c) for c in doc["chunks"])
    # minute-long pieces (a busy region split as far as it goes) scan several times the bytes per hour that
    # longer slices do, and busy regions are no longer read that way: price from the longer slices when known
    big = [c for c in doc["chunks"] if c["e"] - c["s"] > MIN_SPLIT]
    big_secs = sum(c["e"] - c["s"] for c in big if c["st"] in ("ok", "cut"))
    rate = (sum(billed(c) for c in big) / big_secs if big_secs >= HOUR else nbytes / secs) if secs else None
    if rate is not None and doc.get("egress") and not any("egr" in c for c in doc["chunks"]):
        rate *= 1.5  # measured without the outbound query, which scans the same log again
    out = []
    regions = [r for r, x in doc["regions"].items() if x.get("query_sets")] or list(regions)
    for days in READ_DAYS:
        missing = 0
        for r in regions:
            have = [(c["s"], c["e"]) for c in doc["chunks"] if c["r"] == r and c["st"] in ("ok", "cut")
                    and not coarse_cut(c)]  # cut hours are read again
            missing += sum(e - s for s, e in plan(now, days, have))
        est = rate * missing if rate is not None else None
        out.append({"days": days, "missing_hours": round(missing / HOUR, 1), "bytes": est,
                    "cost": round(est / 1e9 * INSIGHTS_PER_GB, 2) if est is not None else None})  # fmt: skip
    return {
        "rate": rate,
        "ranges": out,
        "regions": len(regions),
        "spent_bytes": sum(c["b"] for c in doc["chunks"]),  # what was actually billed
        "spent": round(sum(c["b"] for c in doc["chunks"]) / 1e9 * INSIGHTS_PER_GB, 2),
    }


# ---------------------------------------------------------------------------------------- labelling
def _iv(cidrs) -> list[tuple[int, int]]:
    return sg_ipintel.merge([x for x in map(sg_ipintel.cidr_iv, cidrs) if x])


class Labeller:
    """Category and name of a source IP address; one lookup per IP address."""

    def __init__(self, doc: dict, onprem: str = "", internal: str = "", names: list[dict] | None = None,
                 accounts: list[dict] | None = None):  # fmt: skip
        self.intel = sg_ipintel.get()
        # (first, last, category, name, cidr, extra fields), narrowest first
        self.nets: list[tuple[int, int, str, str, str, dict]] = []
        # IPv6: (network, category, name, extra fields), narrowest first. No address-space counts for IPv6.
        self.nets6: list[tuple[ipaddress.IPv6Network, str, str, dict]] = []
        own = []
        for snap in (x.get("snapshot") or {} for x in doc["regions"].values()):
            for v in snap.get("vpcs") or []:
                vname = f"This account, {v.get('name') or v['id']}"
                for c in v.get("cidrs") or []:
                    iv = sg_ipintel.cidr_iv(c)
                    if iv and ":" not in c:
                        own.append(iv)
                        self.nets.append((*iv, "internal", vname, c, {}))
                for c in v.get("cidrs6") or []:
                    if _net6(c):
                        self.nets6.append((_net6(c), "internal", vname, {}))
            for eid, e in (snap.get("enis") or {}).items():  # an interface's own IPv6 address, even outside a VPC range read
                for a in e.get("ipv6") or []:
                    if _net6(a):
                        self.nets6.append((_net6(a + "/128"), "internal", f"This account, {e.get('kind') or eid}", {}))
        others = []
        for net, name in parse_ranges(internal, "Your network"):
            if net.version == 6:
                self.nets6.append((net, "internal", name, {}))
                continue
            iv = (int(net.network_address), int(net.broadcast_address))
            others.append(iv)
            self.nets.append((*iv, "internal", name, str(net), {}))
        # your other accounts' VPCs (named ranges win on the same range)
        # The same range in several accounts (every default VPC is 172.31.0.0/16) cannot say which one a source is
        # in, so it is named for all of them rather than for whichever was read first.
        by_cidr: dict[str, list] = {}
        sib: list = []  # added after every range you named (--internal, --onprem, VPNs, the names file): those win
        sib6: list = []
        for acc in siblings(doc) if accounts is None else accounts:
            who = f"{acc.get('name') or 'Account'} ({acc['account']})"
            for region, vid, vname, cidrs, cidrs6 in acc.get("vpcs") or []:
                for c in [*cidrs, *cidrs6]:
                    by_cidr.setdefault(c, []).append((who, acc["account"], vid, vname, region))
        for c, hits in by_cidr.items():
            if len(hits) == 1:
                who, acct, vid, vname, region = hits[0]
                label, extra = f"{who}, {vname or vid}", {"account": acct, "vpc": vid, "vpc_region": region}
            else:
                accts = sorted({h[0] for h in hits})
                label = f"One of {len(accts)} accounts ({', '.join(accts)})" if len(accts) > 1 else \
                    f"{accts[0]}, one of {len(hits)} VPCs"  # fmt: skip
                extra = {"account": "" if len(accts) > 1 else hits[0][1], "vpc": "", "vpc_region": "",
                         "accounts": sorted({h[1] for h in hits})}  # fmt: skip
            iv = sg_ipintel.cidr_iv(c) if ":" not in c else None
            if iv:
                others.append(iv)
                sib.append((*iv, "internal", label, c, extra))
            elif _net6(c):
                sib6.append((_net6(c), "internal", label, extra))
        dc = []
        for net, name in parse_ranges(onprem, "On-premises"):
            if net.version == 6:
                self.nets6.append((net, "datacentre", name, {}))
                continue
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
                    elif _net6(c):
                        self.nets6.append((_net6(c), "datacentre", f"Behind VPN {v['name']}", {}))
        # the names file: internal and data centre ranges join those above; anything else is an external network,
        # named by range (before AWS's and the providers' lists) or by AS number (after AWS's)
        named = {"saas": [], "internet": []}
        self.name_asn: dict[int, dict] = {}
        for e in names or []:
            kind = e["type"] if e["type"] in ("internal", "datacentre") else sg_ipintel.GROUPS[e["type"]][1]
            extra = {} if kind in ("internal", "datacentre") else self._named(e)
            for net in e["ranges"]:
                if net.version == 6:
                    self.nets6.append((net, kind, e["name"], extra))
                    continue
                iv = (int(net.network_address), int(net.broadcast_address))
                (others if kind == "internal" else dc if kind == "datacentre" else named[kind]).append(iv)
                self.nets.append((*iv, kind, e["name"], str(net), extra))
            for a in e["asn"]:
                self.name_asn[a] = {"cat": kind, **extra}
        self.nets += sib
        self.nets6 += sib6
        self.nets.sort(key=lambda n: n[1] - n[0])
        self.nets6.sort(key=lambda n: -n[0].prefixlen)
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
        if is_v6(ip):
            out = self._v6(ip)
            out.setdefault("group", out["cat"])
            out["net"] = f"{out['cat']}|{out['name']}"
            self._memo[ip] = out
            return out
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return {"cat": "internet", "name": str(ip)}
        out = None
        for first, last, cat, name, cidr, extra in self.nets:
            if first <= n <= last:
                out = {"cat": cat, "name": name, "range": cidr, **extra}
                a = self.intel.asn(n) if extra and "account" not in extra else None
                if a:  # a named external range: what the AS list knows too
                    out.update(as_num=a["asn"], owner=a["owner"], cc=a["country"], block=a["block"],
                               asn=f"AS{a['asn']} {a['owner']}".strip() + (f" ({a['country']})" if a["country"] else ""))  # fmt: skip
                break
        if out is None:
            for (a, b), cidr in zip(PRIVATE, PRIVATE_V4):
                if a <= n <= b:
                    out = {"cat": "datacentre", "name": "Private IP address outside every scanned VPC", "range": cidr}
                    break
        if out is None:
            out = self._external(ip)
        out.setdefault("group", out["cat"])  # internal, datacentre and aws are their own type
        out["net"] = f"{out['cat']}|{out['name']}"
        self._memo[ip] = out
        return out

    def _external(self, ip: str) -> dict:
        """A public IP address, IPv4 or IPv6, from the published lists (and the names file's AS numbers)."""
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
        for k in ("group", "provider", "what", "threat"):
            if lab.get(k):
                out[k] = lab[k]
        return out

    def _v6(self, ip: str) -> dict:
        """An IPv6 address: your VPCs' and named ranges first (narrowest wins), then unique local and link-local
        addresses (private, like 10.0.0.0/8), then the published lists."""
        a = _addr6(ip)
        if a is None:
            return {"cat": "internet", "name": str(ip), "v6": True}
        for net, cat, name, extra in self.nets6:
            if a in net:
                out = {"cat": cat, "name": name, "range": str(net), "v6": True, **extra}
                if extra and "account" not in extra:
                    got = self.intel.asn(int(a), 6)
                    if got:
                        out.update(as_num=got["asn"], owner=got["owner"], cc=got["country"], block=got["block"],
                                   asn=f"AS{got['asn']} {got['owner']}".strip()
                                   + (f" ({got['country']})" if got["country"] else ""))  # fmt: skip
                return out
        for c in PRIVATE_V6:
            if a in _net6(c):
                what = "Unique local IPv6 address" if c.startswith("fc") else "Link-local IPv6 address"
                return {"cat": "datacentre", "name": f"{what} outside every scanned VPC", "range": c, "v6": True}
        return {**self._external(ip), "v6": True}


# ------------------------------------------------------------------------------------------- rules
@functools.lru_cache(maxsize=1 << 18)
def _ip(s) -> int | None:
    # called for every flow row of every rule: the same few thousand IP addresses parsed a million times
    try:
        return sg_ipintel._v4(s)
    except (ValueError, TypeError):
        return None


_ADDR6: dict = {}
_NET6: dict = {}


def _addr6(s) -> ipaddress.IPv6Address | None:
    if s not in _ADDR6:
        try:
            _ADDR6[s] = ipaddress.IPv6Address(s) if s and ":" in str(s) else None
        except ValueError:
            _ADDR6[s] = None
    return _ADDR6[s]


def _net6(c) -> ipaddress.IPv6Network | None:
    if c not in _NET6:
        try:
            _NET6[c] = ipaddress.IPv6Network(c, strict=False) if c and ":" in str(c) else None
        except ValueError:
            _NET6[c] = None
    return _NET6[c]


def _in6(ip: str, cidr: str) -> bool:
    a, n = _addr6(ip), _net6(cidr)
    return a is not None and n is not None and a in n


def is_v6(ip) -> bool:
    return ":" in str(ip or "")


def rule_sources(rule: dict, ip: str) -> list[str]:
    """The ranges of a rule that ``ip``'s family could match: IPv4 ranges for an IPv4 address, IPv6 for IPv6."""
    return list(rule.get("cidrs6") or []) if is_v6(ip) else list(rule.get("cidrs") or [])


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


def nacl_verdict(nacl: dict | None, src, proto: str, port: int) -> dict | None:
    """The first inbound network ACL entry matching, when it denies; None when the ACL allows. ``src`` is an
    IPv4 address as a number, or an IPv6 address as text (matched against the ACL's IPv6 entries)."""
    v6 = isinstance(src, str)
    for x in (nacl or {}).get("entries6" if v6 else "entries") or []:
        if v6:
            if not _in6(src, x["cidr"]):
                continue
        elif not (iv := sg_ipintel.cidr_iv(x["cidr"])) or not iv[0] <= src <= iv[1]:
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


def build(doc: dict, range_key: str = "1m", onprem: str = "", internal: str = "", names: list | None = None,
          assets: bool = False) -> dict:
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
    own_ips = {ip for e in enis.values() for ip in [*e["ips"], *(e.get("ipv6") or [])]}
    eni_ips = {eid: {*e["ips"], *(e.get("ipv6") or [])} for eid, e in enis.items()}  # built once, not per row
    covers: dict[tuple, bool] = {}  # (interface, protocol, port) -> whether a rule lets it in; ports fold, so few

    def relevant(eni_id, src, dst) -> bool:
        if src in own_ips and (eni_id not in enis or src in eni_ips[eni_id]):
            return False  # the interface's own outbound record
        e = enis.get(eni_id)
        if e is None:
            return True  # a deleted interface: kept, as unattributed
        if not e["groups"]:
            return False  # NAT gateways, transit gateway attachments: no security group decides
        if dst in e["ips"] or dst in (e.get("ipv6") or ()):
            return True
        if is_v6(dst):
            return any(_in6(dst, p) for p in e.get("prefixes6") or [])
        return any(sg_ipintel.cidr_iv(p) and _in(dst, p) for p in e.get("prefixes") or [])

    seen: set[str] = set()
    first_seen: dict[str, int] = {}  # source -> start of the earliest slice holding it, any range
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
    egress_seen: dict[str, dict] = {}  # eni -> (proto, port) -> destination -> flows, from `read --egress`
    egress_read = 0
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
            if c["s"] < first_seen.get(src, c["s"] + 1):
                first_seen[src] = c["s"]
            if not relevant(eni, src, dst):
                continue
            if action == "ACCEPT":
                accepted_rows.append((src, dst, eni, str(proto), dport, flows, c))
                if dport >= EPHEMERAL and not (
                        covers[k] if (k := (eni, proto, dport)) in covers
                        else covers.setdefault(k, _rule_covers(groups, enis.get(eni), proto, dport))):
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
        if in_view and "egr" in c:
            egress_read += 1
            for src, dst, eni, proto, dport, flows in c["egr"]:
                if src and dst and eni:
                    d = egress_seen.setdefault(eni, {}).setdefault((str(proto), dport), {})
                    d[dst] = d.get(dst, 0) + flows
        for src, flows, ports, dsts, dst, eni, port, proto in c.get("pub") or []:
            if not src:
                continue
            seen.add(src)
            if c["s"] < first_seen.get(src, c["s"] + 1):
                first_seen[src] = c["s"]
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
    networks = _networks(act, rej, lab, enis)
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
    over_attr: dict[tuple, list] = {}  # (cat, type, name) -> never-seen addresses allowed in, per period
    frozen_groups = set()
    logged_groups = [g for g in groups.values() if logged(g)]
    now_entries = {
        g["id"]: {(r["proto"], r["from"], r["to"], s) for r in g["rules"] for s in _entries(r)} for g in logged_groups
    }
    memo: dict[tuple, list] = {}
    # Per asset (network interface): never-seen addresses that can reach it through any of its groups, per period.
    logged_ids = {g["id"] for g in logged_groups}
    asset_enis = [e for e, x in enis.items() if x["groups"]] if assets else []
    asset_over: dict[str, list] = {e: [0] * nbins for e in asset_enis}
    asset_memo: dict[tuple, int] = {}
    for i, t0 in enumerate(bins):
        t = min(t0 + step, end)
        total = [0] * len(CATS)
        gkeys: dict[str, frozenset] = {}
        for g in logged_groups:
            state, known = _state_at(now_entries[g["id"]], ev_by_group.get(g["id"], []), t)
            if not known:
                frozen_groups.add(g["id"])
            key = (g["region"], frozenset(x[3] for x in state if x[3] != "0.0.0.0/0"))
            gkeys[g["id"]] = key[1]
            if key not in memo:
                iv = sg_ipintel.merge([v for src in key[1] for v in expand(src, key[0])])
                over = sg_ipintel.subtract(iv, seen_iv)
                memo[key] = ([sg_ipintel.size(sg_ipintel.intersect(over, lab.cat_iv[k])) for k in CATS],
                             _over_attr(over, lab))
            total = [a + b for a, b in zip(total, memo[key][0])]
            for nk, n in memo[key][1].items():
                over_attr.setdefault(nk, [0] * nbins)[i] += n
        for k, n in zip(CATS, total):
            over_series[k][i] = n
        for e in asset_enis:
            akey = (enis[e]["region"], frozenset().union(*(gkeys.get(gid, frozenset()) for gid in enis[e]["groups"])))
            if akey not in asset_memo:
                iv = sg_ipintel.merge([v for src in akey[1] for v in expand(src, akey[0])])
                asset_memo[akey] = sg_ipintel.size(sg_ipintel.subtract(iv, seen_iv))
            asset_over[e][i] = asset_memo[akey]
    markers = [
        {"t": ev["t"], "bin": int((ev["t"] - start) // step), "group": ev["group"],
         "name": groups.get(ev["group"], {}).get("name", ev["group"]), "event": ev["name"], "who": ev["who"],
         "added": [x[3] for x in ev["added"]], "removed": [x[3] for x in ev["removed"]], "unknown": ev["unknown"]}
        for evs in ev_by_group.values() for ev in evs if start <= ev["t"] < end
    ]  # fmt: skip

    rules = _rules_table(doc, groups, enis, accepted_rows, seen, seen_iv, lab, region_first, cut_regions, end)
    fit = fit_model(rules, lab)
    open_rules = [r for r in rules if r["status"] == "open"]
    asset_rows = _asset_rows(asset_enis, asset_over, enis, groups, snaps, rules, logged_ids) if assets else None

    # ---- verdicts: why each source was refused, and which let-in sources look wrong
    ctx = _Ctx(lab, enis, groups, snaps, ev_by_group, accepted_rows, rej, end)
    ctx.act, ctx.start = act, start
    read_since = min(region_first.values(), default=end)
    history_days = (end - read_since) / DAY

    def novelty(src: str) -> dict:
        first = first_seen.get(src)
        if first is None:
            return {"first_ever": None, "seen_before": False, "new": False}
        return {"first_ever": first, "seen_before": first < start,
                "new": first >= end - NEW_DAYS * DAY and first - read_since >= NEW_HISTORY_DAYS * DAY}  # fmt: skip

    nov = {src: novelty(src) for src in set(rej) | set(act)}
    verdicts = {src: refused_verdict(ctx, src, r) for src, r in rej.items()}
    let_in = {src: v for src, a in act.items() if a["bins"] and (v := active_verdict(ctx, src, a))}
    for src, v in [*verdicts.items(), *let_in.items()]:
        _note_novelty(v, nov[src], read_since)
    attention = needs_attention(ctx, verdicts, let_in)
    for it in attention:
        it["new"] = sum(1 for s in it["srcs"] if nov.get(s, {}).get("new"))
    privatelink = privatelink_findings(doc, rules)
    pl_inventory = _pl_inventory(snaps, act, rej, lab, groups)
    inet_in: dict[tuple, set] = {}
    for src, a in act.items():
        if lab(src)["cat"] in ("internal", "datacentre"):
            continue
        for (eni, proto, port) in a["targets"]:
            inet_in.setdefault((eni, proto, port), set()).add(src)
    posture = posture_findings(doc, inet_in, egress_seen, lab)
    drift = drift_findings(doc, end + LAG)
    attention = sorted([p for p in drift if p["sev"] in ATTENTION] + attention
                       + [p for p in privatelink + posture if p["sev"] in ATTENTION],
                       key=lambda it: SEV_RANK[it["sev"]])  # fmt: skip
    for m in markers:
        m["caused"] = sorted({src for src, v in verdicts.items() if (v.get("event") or {}).get("t") == m["t"]
                              and v["event"]["group"] == m["group"]})[:50]  # fmt: skip

    # ---- tables
    def src_row(src, x):
        lb = lab(src)
        return {"src": src, **lb, "flows": x["flows"], "bins": sorted(x["bins"]), "first": x["first"],
                "last": x["last"], **nov[src], "v6": is_v6(src)}  # fmt: skip

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
        row.update(targets=targets, ports=_n_ports(r), dsts=_n_dsts(r))
        row["sweep"] = _sweeps(r, enis)
        row["verdict"] = verdicts[src]
        refused.append(row)
    suggestions = _suggest(rej, enis, groups, snaps, lab)

    active = []
    for src, a in sorted(act.items(), key=lambda kv: -kv[1]["flows"])[:TOP]:
        if not a["bins"]:
            continue
        row = src_row(src, a)
        if src in let_in:
            row["verdict"] = let_in[src]
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
    covered = _covered(chunks, bins, step, end)
    return {
        "account": doc["account"],
        "name": doc.get("name", ""),
        "mode": doc.get("mode", "live"),
        "range": range_key if range_key in RANGES else "1m",
        "step": step,
        "bins": bins,
        "covered": covered,
        "end": end,
        "categories": [{"key": k, "name": CAT_NAME[k]} for k in CATS],
        "series": {"refused": rej_series, "over": over_series, "active_today": act_today, "active_older": act_older,
                   "by_class": class_series, "by_net": net_series,
                   "by_group": group_series, **_over_by(over_attr, nbins)},
        "ports": ports[:60],
        "networks": networks,
        "groups": {gid: {"name": g["name"], "region": g["region"], "vpc": g["vpc"],
                         "rules": [{"ports": ports_label(r), "sources": _entries(r)} for r in g["rules"]]}
                   for gid, g in groups.items()},
        "markers": markers,
        "attention": attention,
        "privatelink": privatelink,
        **({"assets": asset_rows} if assets else {}),
        "pl_inventory": pl_inventory,
        "posture": posture,
        "drift": drift,
        "egress_read": {"slices": egress_read, "on": bool(doc.get("egress"))},
        "summary": {
            "privatelink": {k: sum(1 for p in privatelink if p["sev"] == k) for k in SEVERITIES},
            "posture": {k: sum(1 for p in posture if p["sev"] == k) for k in SEVERITIES},
            "verdicts": {k: sum(1 for v in verdicts.values() if v["sev"] == k) for k in SEVERITIES},
            "attention": {k: sum(1 for a in attention if a["sev"] == k) for k in SEVERITIES},
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
            "new_refused": sum(1 for s in rej if nov[s]["new"]),
            "new_active": sum(1 for s, a in act.items() if a["bins"] and nov[s]["new"]),
            "new_possible": history_days >= NEW_DAYS + NEW_HISTORY_DAYS,
            "history_days": round(history_days, 1),
            "refused_v6": sum(1 for s in rej if is_v6(s)),
            "active_v6": sum(1 for s, a in act.items() if a["bins"] and is_v6(s)),
            "evidence_since": min(region_first.values(), default=None),
            "cut": sorted(cut_regions),
            "public_cut": pub_cut,
            "slices": len(chunks),
            "failed": sum(1 for c in doc["chunks"] if c["st"] == "failed"),
            "intel_seed": sg_ipintel.get().counts.get("seed", []),
        },
        "regions": regions,
        "rules": rules,
        "fit": fit,
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


NETWORKS_MAX = 400  # networks in the "Where traffic comes from" table
NET_BLOCKS = 12  # CIDR blocks listed per network


def _cidrs_of(block: str) -> list[str]:
    """A range as CIDR blocks: "165.225.0.0-165.225.13.255" (an announced block) becomes 165.225.0.0/21 and
    165.225.8.0/22 and 165.225.12.0/23."""
    if not block or "-" not in block:
        return [block] if block else []
    try:
        a, b = (ipaddress.ip_address(x.strip()) for x in block.split("-", 1))
        return [str(n) for n in ipaddress.summarize_address_range(a, b)]
    except (ValueError, TypeError):
        return [block]


def _networks(act: dict, rej: dict, lab, enis: dict) -> list[dict]:
    """Every network traffic came from in the window, one row each: its kind and type, the CIDR blocks its sources
    fall in (the published, named or announced range), how many sources were let in and refused, their flows, the
    ports and interfaces they reached or tried, and when."""
    nets: dict[str, dict] = {}

    def row(src: str) -> dict:
        lb = lab(src)
        n = nets.get(lb["net"])
        if n is None:
            n = nets[lb["net"]] = {
                "name": lb["name"], "cat": lb["cat"], "group": lb.get("group", lb["cat"]), "asn": lb.get("asn", ""),
                "provider": lb.get("provider", ""), "service": lb.get("service", ""),
                "region": lb.get("aws_region", "") or lb.get("vpc_region", ""), "account": lb.get("account", ""),
                "what": lb.get("what", ""), "threat": bool(lb.get("threat")), "blocks": {}, "in": 0, "out": 0,
                "fin": 0, "fout": 0, "pin": {}, "pout": {}, "dst": set(), "first": None, "last": None, "v6": 0}  # fmt: skip
        # a source in no published, named or announced range is shown as its own address, not as "none named"
        for blk in _cidrs_of(lb.get("range") or lb.get("block") or "") or [f"{src}/{128 if is_v6(src) else 32}"]:
            n["blocks"][blk] = n["blocks"].get(blk, 0) + 1
        if is_v6(src):
            n["v6"] += 1
        return n

    def seen(n, first, last):
        n["first"] = first if n["first"] is None else min(n["first"], first)
        n["last"] = last if n["last"] is None else max(n["last"], last)

    for src, x in act.items():
        if not x["bins"]:
            continue
        n = row(src)
        n["in"] += 1
        n["fin"] += x["flows"]
        seen(n, x["first"], x["last"])
        for (eni, proto, port), f in x["targets"].items():
            k = _port_label(proto, min(EPHEMERAL, port))
            n["pin"][k] = n["pin"].get(k, 0) + f
            n["dst"].add(eni)
    for src, r in rej.items():
        if not r["bins"]:
            continue
        n = row(src)
        n["out"] += 1
        n["fout"] += r["flows"]
        seen(n, r["first"], r["last"])
        for t, f in r["targets"].items():
            k = _port_label(t[1], t[2])
            n["pout"][k] = n["pout"].get(k, 0) + f
            if t[0]:
                n["dst"].add(t[0])
    out = []
    for n in nets.values():
        blocks = sorted(n["blocks"].items(), key=lambda kv: -kv[1])
        top = lambda d: [k for k, _ in sorted(d.items(), key=lambda kv: -kv[1])[:6]]
        out.append({**{k: v for k, v in n.items() if k not in ("blocks", "pin", "pout", "dst")},
                    "blocks": [b for b, _ in blocks[:NET_BLOCKS]], "more_blocks": max(0, len(blocks) - NET_BLOCKS),
                    "ports_in": top(n["pin"]), "ports_out": top(n["pout"]), "interfaces": len(n["dst"])})  # fmt: skip
    order = {c: i for i, c in enumerate(CATS)}
    out.sort(key=lambda n: (order.get(n["cat"], 9), -(n["in"] + n["out"]), n["name"]))
    return out[:NETWORKS_MAX]



OVER_NETS = 3  # networks of each kind named on the over-provisioned graph; the rest are summed per kind
OVER_STEPS = 4000  # owners' blocks looked up per set of rules; beyond that the rest is summed per kind


def _over_attr(over: list, lab) -> dict[tuple, int]:
    """Who the never-seen addresses a rule lets in belong to: {(kind, source type, name): addresses}. Your VPCs,
    your other accounts' VPCs, VPN routes and named ranges first (narrowest first), then what is left by the owner
    of each piece: private space in no VPC or named range, an AWS service and region, a SaaS provider, an AS."""
    out: dict[tuple, int] = {}
    rem = list(over)
    ends = [e for _s, e in rem]  # kept beside rem: each net touches only the pieces it overlaps (bisect), not all
    for f, last, cat, name, _c, extra in lab.nets:
        if not rem:
            break
        i = bisect.bisect_left(ends, f)
        k = i
        while k < len(rem) and rem[k][0] <= last:
            k += 1
        if i == k:
            continue
        window = rem[i:k]
        part = sg_ipintel.intersect(window, [(f, last)])
        n = sg_ipintel.size(part)
        if n:
            key = (cat, extra.get("group", cat), name)
            out[key] = out.get(key, 0) + n
            left = sg_ipintel.subtract(window, part)
            rem[i:k] = left
            ends[i:k] = [e for _s, e in left]
    steps = OVER_STEPS
    for cat in CATS:
        for a, b in sg_ipintel.intersect(rem, lab.cat_iv[cat]):
            while a <= b:  # piece by piece: each owner's published, named or announced block
                if steps <= 0:
                    k = (cat, cat, f"{CAT_NAME[cat]}, not split further")
                    out[k] = out.get(k, 0) + b - a + 1
                    break
                steps -= 1
                lb = lab(str(ipaddress.IPv4Address(a)))
                ext = _extent(lb.get("range") or lb.get("prefix") or lb.get("block") or "")
                hi = min(b, ext[1]) if ext and ext[0] <= a <= ext[1] else b
                same = lb["cat"] == cat
                k = (cat, lb.get("group", cat) if same else cat, lb["name"] if same else CAT_NAME[cat])
                out[k] = out.get(k, 0) + hi - a + 1
                a = hi + 1
    return out


def _extent(block: str) -> tuple[int, int] | None:
    """A CIDR block or an "a-b" range as (first, last)."""
    if "-" in block:
        try:
            lo, hi = (int(ipaddress.IPv4Address(x.strip())) for x in block.split("-", 1))
            return lo, hi
        except ValueError:
            return None
    return sg_ipintel.cidr_iv(block) if block and ":" not in block else None


def _over_by(over_attr: dict, nbins: int) -> dict:
    """The over-provisioned series by source type (over_by_group) and by network (over_by_net: the biggest few of
    each kind now, then "N more" per kind)."""
    by_group: dict[str, list] = {}
    for (_cat, grp, _name), data in over_attr.items():
        d = by_group.setdefault(grp, [0] * nbins)
        for i, v in enumerate(data):
            d[i] += v
    nets = [{"key": f"{c}|{n}", "name": n, "cat": c, "group": g, "data": d, "now": d[-1] if d else 0,
             "peak": max(d) if d else 0} for (c, g, n), d in over_attr.items()]  # fmt: skip
    nets.sort(key=lambda n: (-n["now"], -n["peak"], n["name"]))
    top, rest = [], []
    for n in nets:  # the biggest few of each kind, so your VPCs and data centres are not crowded out by AWS
        (top if sum(1 for t in top if t["cat"] == n["cat"]) < OVER_NETS else rest).append(n)
    for cat in CATS:
        mine = [n for n in rest if n["cat"] == cat]
        if mine:
            d = [sum(n["data"][i] for n in mine) for i in range(nbins)]
            top.append({"key": f"{cat}|*", "name": f"{len(mine)} more networks ({CAT_NAME[cat]})", "cat": cat,
                        "group": "", "data": d, "now": d[-1] if d else 0, "peak": max(d) if d else 0})  # fmt: skip
    return {"over_by_group": {g: by_group[g] for g in SOURCE_TYPES if g in by_group}, "over_by_net": top}


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
            out.append({"key": f"{cat}|*", "name": f"{len(mine)} more networks ({CAT_NAME[cat]})", "cat": cat,
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
    if is_v6(ip):
        return _in6(ip, cidr)
    n, iv = _ip(ip), sg_ipintel.cidr_iv(cidr)
    return n is not None and iv is not None and iv[0] <= n <= iv[1]


def _rule_covers(groups: dict, eni: dict | None, proto, port: int) -> bool:
    if not eni:
        return False
    return any(port_matches(r, str(proto), port) and (_entries(r) or r.get("cidrs6")) for g in eni["groups"]
               for r in (groups.get(g) or {}).get("rules") or [])  # fmt: skip


def _refused(rej: dict, src: str, b: int, c: dict, flows: int, target: tuple) -> dict:
    r = rej.setdefault(src, {"bins": set(), "flows": 0, "first": c["s"], "last": c["e"], "targets": {}, "tt": {}})
    r["bins"].add(b)
    r["flows"] += flows
    r["first"], r["last"] = min(r["first"], c["s"]), max(r["last"], c["e"])
    r["targets"][target] = r["targets"].get(target, 0) + flows
    tt = r["tt"].get(target)
    r["tt"][target] = (min(tt[0], c["s"]), max(tt[1], c["e"])) if tt else (c["s"], c["e"])
    return r


def _n_ports(r: dict) -> int:
    return r.get("ports", len({t[2] for t in r["targets"]}))


def _n_dsts(r: dict) -> int:
    return r.get("dsts", len({t[3] for t in r["targets"]}))


def _sweeps(r: dict, enis: dict | None = None) -> bool:
    """Many ports, or many IP addresses. One port on several interfaces that all carry the same security groups is
    a client of one service spread over them (a cache or database behind endpoints, a fleet behind a load
    balancer), not a scan."""
    if _n_ports(r) >= 10:
        return True
    if _n_dsts(r) < 5:
        return False
    if enis is not None and _n_ports(r) == 1 and isinstance(r.get("targets"), dict):
        es = [enis.get(t[0]) or {} for t in r["targets"]]
        sets = {tuple(sorted(e.get("groups") or [])) for e in es}
        if len(sets) == 1 and () not in sets:
            return False
        if all(str(e.get("kind", "")) in SERVICE_FRONTS for e in es):  # a service's endpoints in every zone
            return False
    return True


# Interfaces in front of one AWS service: a client reaches several of them (one per zone, or per node) on one port.
SERVICE_FRONTS = frozenset({"vpc endpoint", "load balancer", "gateway load balancer endpoint", "gateway load balancer",
                            "network load balancer", "RDS database"})


# ---------------------------------------------------------------------------------------------- verdicts
# Why a source was refused, read from what was collected anyway: the flows (let in before? refused since?), the
# rule history (what changed, when, by whom), the network ACLs, and who the source is. A verdict is a severity,
# a chip label, one line of reason with the evidence, and one action.
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_RANK = {k: i for i, k in enumerate(SEVERITIES)}
ATTENTION = ("critical", "high", "medium")
WANTED = frozenset({"changed", "stopped", "moved", "provider", "partner", "service", "internal", "health"})
HEALTH_SERVICES = frozenset({"ROUTE53_HEALTHCHECKS", "ROUTE53_HEALTHCHECKS_PUBLISHING"})
MOVE_WINDOW = 2 * DAY  # a source let in that stopped within this of a new one being refused on the same port


class _Ctx:
    """What the verdicts look up, built once per timeline."""

    def __init__(self, lab, enis, groups, snaps, ev_by_group, accepted_rows, rej, end):
        self.lab, self.enis, self.groups, self.snaps, self.evs, self.rej, self.end = (
            lab, enis, groups, snaps, ev_by_group, rej, end)  # fmt: skip
        self.acc: dict[tuple, list] = {}  # (src, eni, proto, port) -> [first, last, flows]
        self.by_tgt: dict[tuple, dict] = {}  # (eni, proto, port) -> src -> [first, last, flows]
        for src, _dst, eni, proto, dport, flows, c in accepted_rows:
            k = (eni, str(proto), dport)
            x = self.by_tgt.setdefault(k, {}).get(src)
            if x is None:
                x = self.by_tgt[k][src] = [c["s"], c["e"], 0]
                self.acc[(src, *k)] = x
            x[0], x[1], x[2] = min(x[0], c["s"]), max(x[1], c["e"]), x[2] + flows
        self.ip_eni = {ip: eid for eid, e in enis.items() for ip in [*e["ips"], *(e.get("ipv6") or [])]}

    def gname(self, gid: str) -> str:
        return (self.groups.get(gid) or {}).get("name") or gid

    def where(self, eni: str) -> str:
        e = self.enis.get(eni) or {}
        g = (e.get("groups") or [""])[0]
        return f"{self.gname(g)} ({e.get('kind', 'deleted interface')})" if g else e.get("kind", "deleted interface")


def _day(t: float) -> str:
    d = datetime.fromtimestamp(t, timezone.utc)
    return f"{d.day} {d:%b}"


def _restore(ctx, ev: dict, entry) -> dict | None:
    """The revoked entry as the AWS CLI's --ip-permissions, to put it back exactly."""
    if not entry:
        return None
    proto, lo, hi, source = entry
    perm = {"IpProtocol": {"6": "tcp", "17": "udp", "1": "icmp"}.get(str(proto), str(proto))}
    if str(proto) in ("6", "17", "1", "58"):
        perm.update(FromPort=lo, ToPort=hi)
    desc = f"restored by sg_review: revoked {_day(ev['t'])} by {ev.get('who') or 'unknown'}"[:255]
    if str(source).startswith("pl-"):
        perm["PrefixListIds"] = [{"PrefixListId": source, "Description": desc}]
    elif ":" in str(source):
        perm["Ipv6Ranges"] = [{"CidrIpv6": source, "Description": desc}]
    else:
        perm["IpRanges"] = [{"CidrIp": source, "Description": desc}]
    g = ctx.groups.get(ev["group"]) or {}
    return {"group": ev["group"], "group_name": g.get("name", ""), "region": g.get("region", ""), "perms": [perm],
            "entry": f"{ports_label({'proto': str(proto), 'from': lo, 'to': hi})} from {source}"}  # fmt: skip


def _removal(ctx, groups_of: list, src: str, proto: str, port: int, lo: float, hi: float):
    """The rule change on one of the interface's groups, between lo and hi, that took away what let src in:
    (event, the revoked entry) or (event, None) for a change whose detail CloudTrail does not give."""
    vague = None
    for gid in groups_of:
        for ev in ctx.evs.get(gid, []):
            if not lo <= ev["t"] <= hi:
                continue
            for x in ev.get("removed6" if is_v6(src) else "removed") or []:
                rp, a, b, source = x
                if not port_matches({"proto": str(rp), "from": a, "to": b}, proto, port):
                    continue
                if str(source).startswith("pl-") or _in(src, source):
                    return ev, x
            if ev["unknown"] and vague is None:
                vague = (ev, None)
    return vague or (None, None)


def refused_verdict(ctx, src: str, r: dict) -> dict:
    lb = ctx.lab(src)
    cat, group, name = lb["cat"], lb.get("group", lb["cat"]), lb["name"]
    tgts = sorted(r["targets"].items(), key=lambda kv: -kv[1])
    periods, flows = len(r["bins"]), r["flows"]
    since = f"{_day(r['first'])}" + (f" to {_day(r['last'])}" if r["last"] - r["first"] > DAY else "")
    retries = f"{flows:,} flows in {periods} period{'s' if periods != 1 else ''}, {since}"
    if _sweeps(r, ctx.enis):
        if cat in ("internal", "datacentre"):
            return {"key": "internal-scan", "sev": "critical", "label": "Internal scan",
                    "title": "A host inside your network is scanning",
                    "reason": f"{src}{f' ({name})' if name != src else ''} tried {_n_ports(r)} ports on {_n_dsts(r)} IP addresses ({retries}). Refused, "
                              "but scanning from inside is how a compromised host looks for its next step.",
                    "action": f"Find out what runs on {src}. If nothing there should scan, isolate it and look for "
                              "compromise.", "wanted": False}  # fmt: skip
        who = {"scanner": "a known internet scanner", "anon": "a Tor or VPN exit",
               "threat": f"a known malicious IP address ({name})"}.get(group, "a scan")  # fmt: skip
        return {"key": "scan", "sev": "info", "label": "Defence working", "title": "Scan refused",
                "reason": f"{who[0].upper() + who[1:]} sweeping {_n_ports(r)} ports on {_n_dsts(r)} addresses: "
                          "refused, nothing got in.", "action": "None.", "wanted": False}  # fmt: skip
    if group in ("scanner", "anon", "threat"):
        what = {"scanner": "A known internet scanner", "anon": "A Tor or VPN exit",
                "threat": "A known malicious IP address, on a threat list"}[group]  # fmt: skip
        return {"key": "scan", "sev": "info", "label": "Defence working",
                "title": "Known malicious IP address refused" if group == "threat" else "Scanner refused",
                "reason": f"{what} ({name}): refused, nothing got in.", "action": "None.", "wanted": False}
    for (eni, proto, port, dst), _f in tgts[:5]:
        e = ctx.enis.get(eni)
        if not e:
            continue
        by = _refused_by(src, e, ctx.groups, ctx.snaps, proto, port)
        tf, tl = r["tt"][(eni, proto, port, dst)]
        plabel, where = _port_label(proto, port), ctx.where(eni)
        if "added since" in by:
            return {"key": "resolved", "sev": "info", "label": "Fixed since", "title": "Refused, since let in",
                    "reason": f"Refused on {plabel} to {where} until {_day(tl)}; a rule added since lets it in.",
                    "action": "None: check it is let in now.", "wanted": False}  # fmt: skip
        a = ctx.acc.get((src, eni, proto, port))
        if a and a[1] <= tf + DAY:
            ev, entry = _removal(ctx, e["groups"], src, proto, port, a[1] - DAY, tf + DAY)
            base = f"Let in on {plabel} to {where} until {_day(a[1])}, refused since {_day(tf)} ({retries})"
            if by.startswith("Network ACL"):
                return {"key": "stopped", "sev": "high", "label": "Stopped working", "title": "Was let in, now the network ACL refuses it",
                        "reason": f"{base}. {by} refuses it now.", "action": f"Check recent changes to {by.split(' rule')[0]}.",
                        "wanted": True}  # fmt: skip
            if ev:
                who = ev.get("who") or "unknown"
                change = f"{ev['name']} by {who} on {_day(ev['t'])}"
                rest = _restore(ctx, ev, entry)
                return {"key": "changed", "sev": "high", "label": "Broken by a change",
                        "title": "Stopped working after a rule change",
                        "reason": f"{base}, right after {change}" + (f" removed {rest['entry']}." if rest else "."),
                        "action": "Restore the revoked rule if the change was not meant to cut this off; otherwise "
                                  "tell the owner of the source.",
                        "event": {"t": ev["t"], "group": ev["group"], "name": ev["name"], "who": who},
                        "restore": rest, "wanted": True}  # fmt: skip
            return {"key": "stopped", "sev": "high", "label": "Stopped working", "title": "Was let in, now refused",
                    "reason": f"{base}. No rule change in the history explains it (an interface or group swap?).",
                    "action": f"Compare {where}'s security groups with what they were on {_day(a[1])}.",
                    "wanted": True}  # fmt: skip
        if by.startswith("Network ACL"):
            wanted = cat in ("internal", "datacentre") or group in ("partner", "saas", "security")
            return {"key": "nacl", "sev": "medium" if wanted else "info", "label": "Network ACL",
                    "title": "Refused by a network ACL", "wanted": False,
                    "reason": f"{by} refuses {name} on {plabel} to {where} ({retries}). A security group rule would "
                              "not change that.",
                    "action": f"If it is wanted, change {by.split(' rule')[0]}, not the security group."}  # fmt: skip
        mover = _mover(ctx, src, (eni, proto, port), tf)
        if mover:
            m, (_mf, ml, _mfl) = mover
            mn = ctx.lab(m)["name"]
            return {"key": "moved", "sev": "high", "label": "New IP address?",
                    "title": "A client that is let in may have moved IP address",
                    "reason": f"{mn} ({m}) was let in on {plabel} to {where} until {_day(ml)}; {name} ({src}) "
                              f"started being refused there {_day(tf)} ({retries}).",
                    "action": f"Confirm with {mn}, then add {src}/32 and remove {m} once it is gone.",
                    "wanted": True, "moved_from": m}  # fmt: skip
        kin = _same_provider(ctx, src, lb, (eni, proto, port))
        if kin:
            return {"key": "provider", "sev": "medium", "label": "Same provider let in",
                    "title": "Another IP address of a provider that is let in",
                    "reason": f"{lb.get('provider') or name} is let in on {plabel} to {where} from {kin}, but not from "
                              f"{src} ({retries}).",
                    "action": f"If {lb.get('provider') or name} added an IP address, add it (prefer its published "
                              "ranges, or a prefix list).", "wanted": True}  # fmt: skip
        if cat == "aws" and lb.get("service") in HEALTH_SERVICES:
            return {"key": "health", "sev": "medium", "label": "Health check refused",
                    "title": "AWS health checks are refused",
                    "reason": f"Route 53 health checkers are refused on {plabel} to {where} ({retries}): to them the "
                              "target looks down.",
                    "action": f"Allow Route 53's health-check ranges on {plabel}, or point the check at a port that "
                              "is open.", "wanted": True}  # fmt: skip
        if cat in ("internal", "datacentre"):
            mine = ctx.enis.get(ctx.ip_eni.get(src, "")) or {}
            allow = (f"its security group {ctx.gname(mine['groups'][0])} ({mine['groups'][0]})"
                     if mine.get("groups") else f"{src}/32")  # fmt: skip
            return {"key": "internal", "sev": "medium", "label": "Own traffic blocked",
                    "title": "Your own traffic is refused",
                    "reason": f"{name} ({src}) keeps trying {plabel} on {where} ({retries}).",
                    "action": f"If it is a new or moved service, allow {allow} on {plabel}; if not, find what is "
                              "calling.", "wanted": True}  # fmt: skip
        if group == "partner":
            return {"key": "partner", "sev": "high", "label": "Partner refused", "title": "A named partner is refused",
                    "reason": f"{name} ({src}, from your names file) is refused on {plabel} to {where} ({retries}).",
                    "action": f"Add {src}/32 if {name} should reach {plabel}; check their IP addresses with them.",
                    "wanted": True}  # fmt: skip
        if group in ("saas", "security") and periods >= 2:
            return {"key": "service", "sev": "medium", "label": "Service refused",
                    "title": "A known service is refused",
                    "reason": f"{name} ({lb.get('what') or 'a known service'}) keeps trying {plabel} on {where} "
                              f"({retries}): a webhook or integration may be failing.",
                    "action": f"If you use {name} with this host, allow its published ranges on {plabel}.",
                    "wanted": True}  # fmt: skip
        break
    if periods >= 3 and len(r["targets"]) == 1 and cat == "internet":
        return {"key": "retry", "sev": "low", "label": "Keeps retrying", "title": "An internet client keeps retrying",
                "reason": f"{name} tries one port on one IP address again and again ({retries}): it behaves like a "
                          "client, not a scanner.", "action": "Find out who it is before letting it in.",
                "wanted": False}  # fmt: skip
    return {"key": "refused", "sev": "info", "label": "Refused", "title": "Refused",
            "reason": f"Nothing suggests it was wanted ({retries}).", "action": "None.", "wanted": False}


NOVELTY_SKIP = frozenset({"scan", "resolved"})  # a refused scanner being new tells nothing


def _note_novelty(v: dict, nov: dict, read_since: float) -> None:
    """Add to a verdict whether its source is new: first seen in the last NEW_DAYS days, never in the flow logs
    read before. A "New IP address?" verdict whose source was seen weeks ago says so."""
    v.update(nov)
    first = nov.get("first_ever")
    if first is None or v["key"] in NOVELTY_SKIP:
        return
    days = max(0, round((first - read_since) / DAY))
    if nov["new"]:
        v["reason"] = v["reason"].rstrip() + f" First seen {_day(first)}: never before in {days} days of flow logs."
    elif v["key"] == "moved" and nov["seen_before"]:
        v["reason"] = v["reason"].rstrip() + f" Not a new IP address though: first seen {_day(first)}."


def _mover(ctx, src: str, tgt: tuple, tf: float):
    """A source let in on the same interface and port that stopped about when src started being refused."""
    best = None
    for m, x in (ctx.by_tgt.get(tgt) or {}).items():
        if m == src or x[1] > ctx.end - DAY or abs(x[1] - tf) > MOVE_WINDOW:
            continue
        if best is None or abs(x[1] - tf) < abs(best[1][1] - tf):
            best = (m, x)
    return best


def _same_provider(ctx, src: str, lb: dict, tgt: tuple) -> str:
    if lb.get("group") not in ("partner", "saas", "security", "cdn"):
        return ""
    key = lb.get("provider") or lb["name"]
    for m in ctx.by_tgt.get(tgt) or {}:
        if m != src and (ctx.lab(m).get("provider") or ctx.lab(m)["name"]) == key:
            return m
    return ""


def _allowed_by(ctx, e: dict, src: str, proto: str, port: int) -> list[str]:
    """The entries of the interface's groups that let src in on the port."""
    out = []
    for gid in e.get("groups") or []:
        for rule in (ctx.groups.get(gid) or {}).get("rules") or []:
            if port_matches(rule, proto, port):
                out += [f"{ctx.gname(gid)}: {ports_label(rule)} from {c}" for c in rule_sources(rule, src)
                        if _in(src, c)]  # fmt: skip
    return out


def active_verdict(ctx, src: str, a: dict) -> dict | None:
    """A let-in source that looks wrong: a scanner, a Tor exit, an address on a threat list or anyone's server on a
    port that is not the public web, or a source that swept refused ports and found one let in."""
    lb = ctx.lab(src)
    group, name = lb.get("group", lb["cat"]), lb["name"]
    swept = src in ctx.rej and _sweeps(ctx.rej[src], ctx.enis)
    if not (group in ("scanner", "anon", "threat") or swept or (group == "hosting" and lb["cat"] == "internet")):
        return None
    worst = None
    for (eni, proto, port), flows in sorted(a["targets"].items(), key=lambda kv: -kv[1]):
        pc = port_class(proto, port)
        if pc["cls"] == "web":
            continue  # a public site is meant to be reached by anyone
        if group == "hosting" and not pc["risky"]:
            continue
        sev = "critical" if pc["risky"] else "high"
        if worst is None or SEV_RANK[sev] < SEV_RANK[worst[0]]:
            worst = (sev, eni, proto, port, flows, pc)
    if not worst:
        return None
    sev, eni, proto, port, flows, pc = worst
    e = ctx.enis.get(eni) or {}
    rules = _allowed_by(ctx, e, src, proto, port)
    who = {"scanner": "A known internet scanner", "anon": "A Tor or VPN exit", "threat": "A known malicious IP address",
           "hosting": "A server on anyone's hosting"}.get(group, "A source that scanned refused ports")  # fmt: skip
    label = {"hosting": "Let in: unknown server", "threat": "Known malicious let in"}.get(group, "Scan got in")
    return {"key": "let-in", "sev": sev, "label": label,
            "title": f"{who} was let in on {pc['name'].lower()}",
            "reason": f"{who} ({name}) was let in on {_port_label(proto, port)} ({pc['svc']}) to {ctx.where(eni)}, "
                      f"{flows:,} flows" + (f", by {rules[0]}" if rules else "") + ".",
            "action": "Narrow that rule to the sources that need it (Rules, and what to change), or remove it.",
            "rule": rules[0] if rules else "", "target": f"{_port_label(proto, port)} to {ctx.where(eni)}",
            "wanted": False}  # fmt: skip


def needs_attention(ctx, verdicts: dict, let_in: dict) -> list[dict]:
    """The verdicts that look like something broke, or got in that should not have: one item per kind of verdict,
    named source and target, busiest and longest first."""
    items: dict[tuple, dict] = {}
    for kind, vs in (("refused", verdicts), ("active", let_in)):
        for src, v in vs.items():
            if v["sev"] not in ATTENTION:
                continue
            lb = ctx.lab(src)
            x = ctx.rej.get(src) if kind == "refused" else ctx.act.get(src)
            tgt = max(x["targets"].items(), key=lambda kv: kv[1])[0] if x and kind == "refused" else None
            who = (f"{v['event']['group']}@{v['event']['t']}" if v["key"] == "changed"
                   else src if v["key"] in ("internal", "moved", "internal-scan", "stopped")
                   else lb.get("provider") or lb["name"])  # fmt: skip
            key = (kind, v["key"], who, (ctx.where(tgt[0]), tgt[1], tgt[2]) if tgt else v.get("target"))
            it = items.get(key)
            if it is None:
                it = items[key] = {**{k: v[k] for k in ("key", "sev", "label", "title", "reason", "action")},
                                   "kind": kind, "name": lb["name"], "cat": lb["cat"], "group": lb.get("group", ""),
                                   "srcs": [], "flows": 0, "first": None, "last": None,
                                   "target": "" if v["key"] == "internal-scan" else
                                   f"{_port_label(tgt[1], tgt[2])} to {ctx.where(tgt[0])}" if tgt else v.get("target", ""),
                                   "restore": v.get("restore"), "event": v.get("event")}  # fmt: skip
            it["srcs"].append(src)
            it["flows"] += x["flows"] if x else 0
            if x:
                it["first"] = min(filter(None, (it["first"], max(x["first"], ctx.start))))
                it["last"] = max(filter(None, (it["last"], x["last"])))
    out = list(items.values())
    for it in out:
        it["srcs"].sort(key=lambda s: -(ctx.rej[s]["flows"] if s in ctx.rej else 0))
        dur = ((it["last"] or 0) - (it["first"] or 0)) / DAY
        it["days"] = max(1, round(dur))
        it["weight"] = it["flows"] * max(1.0, dur) + len(it["srcs"])
    out.sort(key=lambda it: (SEV_RANK[it["sev"]], -it["weight"]))
    for it in out:
        it["srcs"] = it["srcs"][:25]
    return out[:60]


def _allows_now(groups: dict, e: dict, src: str, proto: str, port: int) -> list[str]:
    out = []
    v6 = is_v6(src)
    n = None if v6 else _ip(src)
    for gid in e.get("groups") or []:
        for r in (groups.get(gid) or {}).get("rules") or []:
            if not port_matches(r, proto, port):
                continue
            if v6:
                if any(_in6(src, c) for c in r.get("cidrs6") or []):
                    out.append(gid)
                continue
            ivs = _iv(r.get("cidrs") or [])
            if n is not None and any(a <= n <= b for a, b in ivs):
                out.append(gid)
    return out


# ------------------------------------------------------------------------------------------ PrivateLink
def privatelink_snapshot(session, ec2, region: str, errors: list) -> dict:
    """The endpoint services this account provides (who may connect, whether connections are accepted
    automatically, the load balancers behind them and whether they apply security groups to PrivateLink
    traffic), and the interface endpoints in its VPCs with their security groups. Read-only."""
    out: dict = {"services": [], "endpoints": [], "read": True}
    try:
        cfgs = _pages(ec2, "describe_vpc_endpoint_service_configurations", "ServiceConfigurations")
    except (ClientError, BotoCoreError) as exc:
        errors.append(f"PrivateLink endpoint services: {describe_error(exc)[:200]}")
        out["read"], cfgs = False, []
    lb_arns = sorted({a for c in cfgs for a in c.get("NetworkLoadBalancerArns") or []})
    lbs: dict = {}
    if lb_arns:
        try:
            elb = session.client("elbv2", region_name=region, config=BOTO_CONFIG)
            for i in range(0, len(lb_arns), 20):
                part = lb_arns[i:i + 20]
                for lb in with_backoff(lambda part=part: elb.describe_load_balancers(LoadBalancerArns=part))[
                        "LoadBalancers"]:  # fmt: skip
                    lbs[lb["LoadBalancerArn"]] = {
                        "name": lb.get("LoadBalancerName", ""), "groups": lb.get("SecurityGroups") or [],
                        "enforce": str(lb.get("EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic", "on")).lower(),
                        "scheme": lb.get("Scheme", "")}  # fmt: skip
        except (ClientError, BotoCoreError) as exc:
            errors.append(f"load balancers behind endpoint services: {describe_error(exc)[:200]}")
    for c in cfgs:
        sid = c.get("ServiceId", "")
        try:
            principals = [p.get("Principal", "") for p in _pages(ec2, "describe_vpc_endpoint_service_permissions",
                                                                  "AllowedPrincipals", ServiceId=sid)]  # fmt: skip
        except (ClientError, BotoCoreError) as exc:
            principals = None
            errors.append(f"who may connect to {sid}: {describe_error(exc)[:200]}")
        try:
            conns = [{"id": x.get("VpcEndpointId", ""), "owner": x.get("VpcEndpointOwner", ""),
                      "state": x.get("VpcEndpointState", "")}
                     for x in _pages(ec2, "describe_vpc_endpoint_connections", "VpcEndpointConnections",
                                     Filters=[{"Name": "service-id", "Values": [sid]}])]  # fmt: skip
        except (ClientError, BotoCoreError) as exc:
            conns = None
            errors.append(f"connections to {sid}: {describe_error(exc)[:200]}")
        out["services"].append({
            "id": sid, "name": _name(c.get("Tags")) or c.get("ServiceName", sid), "service": c.get("ServiceName", ""),
            "state": c.get("ServiceState", ""), "acceptance": bool(c.get("AcceptanceRequired")),
            "principals": principals, "connections": conns,
            "nlbs": [{"arn": a, **lbs.get(a, {"name": a.rsplit("/", 2)[-2] if "/" in a else a, "groups": [],
                                               "enforce": "unknown", "scheme": ""})}
                     for a in c.get("NetworkLoadBalancerArns") or []],
            "gwlbs": c.get("GatewayLoadBalancerArns") or []})  # fmt: skip
    try:
        for v in _pages(ec2, "describe_vpc_endpoints", "VpcEndpoints",
                        Filters=[{"Name": "vpc-endpoint-type", "Values": ["Interface"]}]):  # fmt: skip
            out["endpoints"].append({
                "id": v.get("VpcEndpointId", ""), "service": v.get("ServiceName", ""), "vpc": v.get("VpcId", ""),
                "name": _name(v.get("Tags")), "state": v.get("State", ""),
                "groups": [g.get("GroupId", "") for g in v.get("Groups") or []],
                "enis": v.get("NetworkInterfaceIds") or []})  # fmt: skip
    except (ClientError, BotoCoreError) as exc:
        errors.append(f"interface endpoints: {describe_error(exc)[:200]}")
        out["read"] = False
    return out


def _pl_inventory(snaps: dict, act: dict, rej: dict, lab, groups: dict) -> dict:
    """Every endpoint service this account provides and every interface endpoint in its VPCs, open or not, with
    the traffic through each endpoint's interfaces in the window: sources let in and refused, by network, ports."""
    by_eni: dict[str, dict] = {}
    for src, x in act.items():
        if x["bins"]:
            for (eni, proto, port), f in x["targets"].items():
                d = by_eni.setdefault(eni, {"in": {}, "out": {}, "ports": {}})
                d["in"][src] = d["in"].get(src, 0) + f
                k = _port_label(proto, port)
                d["ports"][k] = d["ports"].get(k, 0) + f
    for src, r in rej.items():
        if r["bins"]:
            for t, f in r["targets"].items():
                if t[0]:
                    d = by_eni.setdefault(t[0], {"in": {}, "out": {}, "ports": {}})
                    d["out"][src] = d["out"].get(src, 0) + f
    services, endpoints = [], []
    for region, snap in sorted(snaps.items()):
        pl = snap.get("privatelink") or {}
        for sv in pl.get("services") or []:
            services.append({"region": region, "id": sv["id"], "name": sv.get("name", ""), "service": sv.get("service", ""),
                             "state": sv.get("state", ""), "acceptance": sv.get("acceptance"),
                             "principals": sv.get("principals"), "connections": sv.get("connections"),
                             "nlbs": [{"name": n.get("name", ""), "enforce": n.get("enforce", ""),
                                       "groups": [groups.get(g, {}).get("name") or g for g in n.get("groups") or []]}
                                      for n in sv.get("nlbs") or []]})  # fmt: skip
        for e in pl.get("endpoints") or []:
            ins, outs, ports = {}, {}, {}
            for eni in e.get("enis") or []:
                d = by_eni.get(eni) or {}
                for k, v in (d.get("in") or {}).items():
                    ins[k] = ins.get(k, 0) + v
                for k, v in (d.get("out") or {}).items():
                    outs[k] = outs.get(k, 0) + v
                for k, v in (d.get("ports") or {}).items():
                    ports[k] = ports.get(k, 0) + v
            nets: dict[str, list] = {}
            for src, f in ins.items():
                lb = lab(src)
                n = nets.setdefault(lb["name"], [lb["cat"], 0, 0])
                n[1] += 1
                n[2] += f
            rules = [f"{ports_label(r)} from {', '.join(_entries(r)[:4]) or 'a group'}"
                     for g in e.get("groups") or [] for r in (groups.get(g) or {}).get("rules") or []]  # fmt: skip
            endpoints.append({"region": region, "id": e["id"], "name": e.get("name", ""), "service": e.get("service", ""),
                              "vpc": e.get("vpc", ""), "state": e.get("state", ""),
                              "groups": [groups.get(g, {}).get("name") or g for g in e.get("groups") or []],
                              "rules": rules[:8], "enis": len(e.get("enis") or []),
                              "sources": len(ins), "refused": len(outs), "flows": sum(ins.values()),
                              "ports": [k for k, _ in sorted(ports.items(), key=lambda kv: -kv[1])[:5]],
                              "networks": sorted(([k, *v] for k, v in nets.items()), key=lambda r: -r[2])[:8]})  # fmt: skip
    read = all((snap.get("privatelink") or {}).get("read", False) for snap in snaps.values()) if snaps else False
    return {"services": services, "endpoints": endpoints, "read": read}


PL_WIDE = 65536  # a source block this size (a /16) or larger on an interface endpoint is a whole network


def _pl_item(key, sev, label, title, reason, action, region, name, cli="", group="", target="", extra=None) -> dict:
    return {"key": key, "sev": sev, "label": label, "title": title, "reason": reason, "action": action,
            "kind": "privatelink", "name": name, "cat": "", "group": group, "srcs": [], "flows": 0, "first": None,
            "last": None, "target": target, "restore": None, "event": None, "days": 0, "weight": 0,
            "region": region, "cli": cli, **(extra or {})}  # fmt: skip


def privatelink_findings(doc: dict, rules: list[dict]) -> list[dict]:
    """PrivateLink that is too open, on both sides.

    Provider: an endpoint service any AWS account may connect to (critical when connections are also accepted
    without review), one that accepts connections automatically (low), and a load balancer behind it that does not
    apply its security groups to PrivateLink traffic or has none (medium). Consumer: an interface endpoint whose
    security group lets in every address (high) or a whole network, a /16 or wider (medium), with the callers the
    flow logs saw and the narrower ranges from the rules table."""
    out = []
    by_rule = {(r["group"], r["source"], r["ports"]): r for r in rules}
    for region, x in sorted(doc["regions"].items()):
        snap = x.get("snapshot") or {}
        pl = snap.get("privatelink") or {}
        for s in pl.get("services") or []:
            owners = sorted({c["owner"] for c in s.get("connections") or [] if c.get("owner")})
            conn = f"{len(s.get('connections') or [])} endpoint(s) connected" + (
                f", from account(s) {', '.join(owners[:5])}" if owners else "")
            principals = s.get("principals")
            anyone = principals is not None and any(p.strip() in ("*", "arn:aws:iam::*:root") for p in principals)
            if anyone:
                sev = "high" if s["acceptance"] else "critical"
                grant = " ".join(f"arn:aws:iam::{o}:root" for o in owners) or "arn:aws:iam::<consumer-account>:root"
                cli = (f"aws ec2 modify-vpc-endpoint-service-permissions --region {region} --service-id {s['id']} "
                       f"--remove-allowed-principals '*' --add-allowed-principals {grant}")  # fmt: skip
                if not s["acceptance"]:
                    cli += (f"\naws ec2 modify-vpc-endpoint-service-configuration --region {region} "
                            f"--service-id {s['id']} --acceptance-required")  # fmt: skip
                out.append(_pl_item(
                    "pl-service-anyone", sev, "PrivateLink open to all",
                    f"Any AWS account may connect to endpoint service {s['name']}",
                    f"{s['service'] or s['id']} allows principal '*'"
                    + ("" if s["acceptance"] else ", and accepts connections without review")
                    + f": any AWS account can create an endpoint to it and reach its load balancer. {conn}.",
                    "Allow only the accounts that should connect"
                    + ("" if s["acceptance"] else ", and require acceptance") + ".",
                    region, s["name"], cli, target=s["id"], extra={"service": s}))
            elif not s["acceptance"] and principals:
                out.append(_pl_item(
                    "pl-auto-accept", "low", "Accepted automatically",
                    f"Endpoint service {s['name']} accepts connections without review",
                    f"{len(principals)} principal(s) may connect, and each endpoint they create is accepted at once. "
                    f"{conn}.", "Require acceptance if a new consumer should be approved first.", region, s["name"],
                    f"aws ec2 modify-vpc-endpoint-service-configuration --region {region} --service-id {s['id']} "
                    "--acceptance-required", target=s["id"], extra={"service": s}))  # fmt: skip
            elif principals is None:
                out.append(_pl_item(
                    "pl-unread", "info", "Not read", f"Who may connect to {s['name']} was not read",
                    "ec2:DescribeVpcEndpointServicePermissions was refused, so it is not known who may connect.",
                    "Grant the permission to the role sg_review runs as.", region, s["name"], target=s["id"]))
            for lb in s.get("nlbs") or []:
                if lb.get("enforce") == "off" or (lb.get("enforce") != "unknown" and not lb.get("groups")):
                    none = not lb.get("groups")
                    out.append(_pl_item(
                        "pl-nlb-no-sg", "medium", "PrivateLink not filtered",
                        f"Load balancer {lb['name']} behind {s['name']} does not filter PrivateLink traffic",
                        ("It has no security group, so " if none else
                         "It does not apply its security groups to PrivateLink traffic, so ")
                        + "every endpoint an allowed account creates reaches every listener; only the allowed "
                          "principals stand in the way.",
                        "Create the load balancer with a security group (one cannot be added later)" if none else
                        "Turn on security group enforcement for PrivateLink traffic, with rules for the consumers' "
                        "ranges.", region, lb["name"],
                        "" if none else
                        f"aws elbv2 set-security-groups --region {region} --load-balancer-arn {lb['arn']} "
                        f"--security-groups {' '.join(lb['groups'])} "
                        "--enforce-security-group-inbound-rules-on-private-link-traffic on",
                        target=s["id"], extra={"service": s}))  # fmt: skip
        groups = snap.get("groups") or {}
        for e in pl.get("endpoints") or []:
            svc = e["service"].rsplit(".", 1)[-1] if e["service"] else e["id"]
            for gid in e["groups"]:
                g = groups.get(gid) or {}
                for r in g.get("rules") or []:
                    for c in r.get("cidrs") or []:
                        try:
                            net = ipaddress.ip_network(c, strict=False)
                        except ValueError:
                            continue
                        if net.num_addresses < PL_WIDE:
                            continue
                        ports = ports_label(r)
                        row = by_rule.get((gid, c, ports)) or {}
                        everyone = net.prefixlen == 0
                        seen = row.get("here")
                        sugg = row.get("suggest") or []
                        what = (f"Flow logs saw {seen} source(s) reach it" if seen is not None else
                                "No flow log covers it, so its callers are not known")  # fmt: skip
                        out.append(_pl_item(
                            "pl-endpoint-open", "high" if everyone else "medium", "Endpoint too open",
                            f"Interface endpoint {e['name'] or e['id']} ({svc}) lets in "
                            + ("every address" if everyone else c),
                            f"Its security group {g.get('name') or gid} allows {c} on {ports}: {net.num_addresses:,} "
                            f"addresses may call {e['service'] or 'the service'} through it. {what}"
                            + (f"; {', '.join(sugg[:6])} would cover them." if sugg else
                               f". {row['note']}." if row.get("note") else "."),
                            (f"Narrow the rule to {', '.join(sugg[:6])} (Rules, and what to change)." if sugg else
                             "Narrow the rule to the subnets that call this service, or to the callers' security "
                             "group."),
                            region, e["name"] or e["id"], group=gid, target=f"{ports} to {e['id']}",
                            extra={"endpoint": e, "source": c}))  # fmt: skip
    out.sort(key=lambda it: (SEV_RANK[it["sev"]], it["region"], it["name"]))
    return out


# --------------------------------------------------------------------------------- exposure and hygiene
# Checks on the configuration itself, read alongside the flow logs: is an open rule actually reachable from the
# internet, IPv6 rules (which IPv4-only reviews miss), outbound rules, and group hygiene. Each item has the same
# shape as a "Needs attention" item (kind "posture", and an "area"), so the medium and worse ones join that list.
WIDE_V6 = 32  # a global IPv6 range this wide or wider is an ISP-sized allocation
SAMPLE_INTERNET = int(ipaddress.IPv4Address("8.8.8.8"))  # a typical internet address, for the network ACL check
EGRESS_FIT_MAX = 15  # more fitted outbound rules than this and the fit is offered, not urged
POSTURE_AREAS = {"exposure": "Internet exposure", "ipv6": "IPv6", "egress": "Outbound", "hygiene": "Group hygiene"}


def _pt_item(area, key, sev, label, title, reason, action, region, name, cli="", group="", target="", extra=None):
    return {**_pl_item(key, sev, label, title, reason, action, region, name, cli, group, target, extra),
            "kind": "posture", "area": area}  # fmt: skip


def _perm_arg(proto: str, lo: int, hi: int, cidr: str = "", ref: str = "") -> str:
    p = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}.get(str(proto), str(proto))
    ports = "" if p == "-1" else f",FromPort={lo if p in ('tcp', 'udp') else -1},ToPort={hi if p in ('tcp', 'udp') else -1}"
    if ref:
        src = f",UserIdGroupPairs=[{{GroupId={ref}}}]"
    elif ":" in cidr:
        src = f",Ipv6Ranges=[{{CidrIpv6={cidr}}}]"
    else:
        src = f",IpRanges=[{{CidrIp={cidr}}}]"
    return f"IpProtocol={p}{ports}{src}"


def db_exec(cmd: str, reason: str) -> str:
    """A security group change, run through the database so it is recorded with who and why
    (sg_db.py exec). Security groups are changed only through the database: never in the console,
    never in Terraform."""
    return f"python sg_db.py exec --reason {shlex.quote(reason)} -- {cmd}"


def _revoke_cli(region: str, gid: str, rule: dict, cidr: str = "", ref: str = "", egress: bool = False,
                reason: str = "") -> str:  # fmt: skip
    verb = "revoke-security-group-egress" if egress else "revoke-security-group-ingress"
    src = cidr or ref or "?"
    return db_exec(f"aws ec2 {verb} --region {region} --group-id {gid} "
                   f"--ip-permissions '{_perm_arg(rule['proto'], rule['from'], rule['to'], cidr, ref)}'",
                   reason or f"sg_review: remove {ports_label(rule)} {'to' if egress else 'from'} {src}")  # fmt: skip


def _route(snap: dict, eni: dict) -> dict | None:
    routes = snap.get("routes") or {}
    if not routes.get("read", "subnets" in routes):
        return None
    return (routes.get("subnets") or {}).get(eni.get("subnet", "")) or (routes.get("main") or {}).get(eni.get("vpc", ""))


def internet_path(snap: dict, eni: dict, rule: dict, v6: bool = False) -> tuple[bool | None, str]:
    """Whether the internet can reach `eni` on `rule`'s first port: a public address, a route to an internet
    gateway, and a network ACL that lets it in. (None, why) when that cannot be told."""
    if v6:
        if not eni.get("ipv6"):
            return False, "it has no IPv6 address"
    elif not eni.get("public"):
        return False, "it has no public IP address"
    r = _route(snap, eni)
    if r is None:
        return None, "the route tables were not read"
    if not r.get("igw6" if v6 else "igw4"):
        return False, f"its subnet has no {'::/0' if v6 else '0.0.0.0/0'} route to an internet gateway"
    if not v6:
        nacl = (snap.get("nacls") or {}).get(eni.get("subnet", ""))
        if nacl and nacl_verdict(nacl, SAMPLE_INTERNET, str(rule["proto"]), rule["from"]):
            v = nacl_verdict(nacl, SAMPLE_INTERNET, str(rule["proto"]), rule["from"])
            return False, f"network ACL {v['acl']} rule {v['rule']} refuses the internet"
    addr = eni["ipv6"][0] if v6 else eni["public"]
    return True, f"{addr} is public and routed to an internet gateway"


def _wide_v6(c: str) -> ipaddress.IPv6Network | None:
    try:
        net = ipaddress.ip_network(c, strict=False)
    except ValueError:
        return None
    if net.version != 6 or net.prefixlen > WIDE_V6 or (net.prefixlen and net.is_private):
        return None
    return net


def posture_findings(doc: dict, inet_in: dict | None = None, egress_seen: dict | None = None, lab=None) -> list[dict]:
    """Internet exposure, IPv6, outbound and group hygiene, from each region's snapshot.

    `inet_in` is (interface, protocol, port) -> internet sources let in during the range, the evidence that an
    exposed rule is used. `egress_seen` is interface -> {(protocol, port): {destination: flows}} from
    `read --egress`; without it the outbound checks are on the rules alone."""
    inet_in = inet_in or {}
    out: list[dict] = []
    account = doc.get("account", "")
    for region, x in sorted(doc["regions"].items()):
        snap = x.get("snapshot") or {}
        groups = snap.get("groups") or {}
        enis = snap.get("enis") or {}
        members: dict[str, list[str]] = {}
        for eid, e in enis.items():
            for gid in e.get("groups") or []:
                members.setdefault(gid, []).append(eid)
        stale_seen = set()
        for gid, g in sorted(groups.items()):
            gname = g.get("name") or gid
            mine = members.get(gid, [])
            for rule in g.get("rules") or []:
                pc = rule_port_class(rule)
                ports = ports_label(rule)
                opens = [c for c in rule.get("cidrs") or [] if c == "0.0.0.0/0"]
                opens += [c for c in rule.get("cidrs6") or [] if c == "::/0"]
                for c in opens:
                    v6 = ":" in c
                    paths = [(eid, *internet_path(snap, enis[eid], rule, v6)) for eid in mine]
                    live = [(eid, why) for eid, ok, why in paths if ok]
                    unknown = [eid for eid, ok, _ in paths if ok is None]
                    used = sum(len(inet_in.get((eid, str(rule["proto"]), p), ()))
                               for eid in mine for p in {rule["from"], rule["to"]})
                    kinds = sorted({enis[eid]["kind"] for eid, _ in live})
                    if live:
                        if pc["cls"] == "web" and kinds == ["load balancer"]:
                            continue  # a public load balancer on a web port: what it is for
                        sev = "critical" if pc["risky"] or pc["cls"] == "all" else "low" if pc["cls"] == "web" else "high"
                        ex = live[0]
                        out.append(_pt_item(
                            "exposure", "exposed", sev, "Reachable from the internet",
                            f"{gname} lets the internet reach {len(live)} interface(s) on {ports}"
                            + (f" ({pc['svc']})" if pc.get("svc") else ""),
                            f"The rule allows {c}, and the path is open: {ex[1]} ({enis[ex[0]]['kind']} {ex[0]})"
                            + (f", and {len(live) - 1} more" if len(live) > 1 else "")
                            + (f". {used} internet source(s) connected in the range." if used else
                               ". No internet source connected in the range, so nothing would notice it closing."),
                            "Remove the open rule, or narrow it to the IP addresses that need it (a VPN, a bastion's "
                            "group, or the partner's range)." if pc["cls"] != "web" else
                            "Put the service behind a load balancer, or narrow the rule if it is not public.",
                            region, gname, _revoke_cli(region, gid, rule, c), group=gid, target=ports,
                            extra={"interfaces": [e for e, _ in live][:20], "source": c, "v6": v6}))
                    elif pc["risky"] or pc["cls"] == "all":
                        why = (f"{len(unknown)} interface(s) could not be checked" if unknown else
                               paths[0][2] if paths else "no interface uses the group yet")
                        out.append(_pt_item(
                            "ipv6" if v6 else "exposure", "latent-open", "medium" if v6 and mine else "low",
                            "Open, not reachable yet",
                            f"{gname} allows {c} on {ports}, but nothing is reachable today",
                            f"The rule allows {c} on {pc['svc']}; {why}. "
                            + ("Turning on IPv6 for the subnet, or giving an interface an IPv6 address, exposes it "
                               "at once, and reviews that look only at IPv4 miss it." if v6 else
                               "A public IP address or a route to an internet gateway later exposes it at once."),
                            "Remove the rule now, while nothing depends on it.", region, gname,
                            _revoke_cli(region, gid, rule, c), group=gid, target=ports, extra={"source": c, "v6": v6}))
                for c in rule.get("cidrs6") or []:
                    net = _wide_v6(c)
                    if net is None or net.prefixlen == 0:
                        continue
                    out.append(_pt_item(
                        "ipv6", "v6-wide", "medium" if pc["risky"] or pc["cls"] == "all" else "low", "Wide IPv6 range",
                        f"{gname} lets in {c} on {ports}",
                        f"{c} is a global IPv6 range of 2^{128 - net.prefixlen} IP addresses (an ISP-sized "
                        f"allocation or wider) on {pc['svc']}. IPv6 rules are easy to miss in an IPv4 review.",
                        "Narrow it to the /64s or /56s that need it.", region, gname,
                        _revoke_cli(region, gid, rule, c), group=gid, target=ports, extra={"source": c, "v6": True}))
                for xr in rule.get("xrefs") or []:
                    if not xr["account"] or xr["account"] in (account, g.get("owner")):
                        continue
                    out.append(_pt_item(
                        "hygiene", "cross-account", "medium", "Trusts another account",
                        f"{gname} lets in group {xr['group']} from account {xr['account']} on {ports}",
                        f"Every interface account {xr['account']} puts in {xr['group']} reaches this group on "
                        f"{pc['svc']}" + (f", over peering {xr['peering']}" if xr.get("peering") else "")
                        + ". Who joins that group is decided in the other account.",
                        "Check the other account is still meant to have this; narrow it to its subnets if its "
                        "group is broad.", region, gname, _revoke_cli(region, gid, rule, ref=xr["group"]),
                        group=gid, target=ports, extra={"account": xr["account"]}))
            # default group
            if gname == "default" and g.get("name") == "default":
                others = [r for r in g.get("rules") or []
                          if r.get("cidrs") or r.get("cidrs6") or r.get("pls") or any(ref != gid for ref in r.get("refs") or [])]
                if mine or others:
                    sev = "medium" if mine and others else "low"
                    out.append(_pt_item(
                        "hygiene", "default-group", sev, "Default group",
                        f"The default security group of {g.get('vpc') or 'its VPC'} "
                        + (f"is used by {len(mine)} interface(s)" if mine else "has rules"),
                        ("Anything launched without a group chosen lands in it, and " if mine else
                         "Anything launched without a group chosen will land in it, and ")
                        + ("it lets in more than its own members" if others else
                           "its members reach each other on every port")
                        + ". CIS AWS 5.4: the default group should allow nothing.",
                        "Move the interfaces to groups made for them, then remove every rule from the default group.",
                        region, gname,
                        f"python sg_db.py remove --region {region} --group {gid} --all "
                        f"--reason 'CIS AWS 5.4: the default group allows nothing' && "
                        f"python sg_db.py apply --region {region} --group {gid}",
                        group=gid, extra={"interfaces": mine[:20]}))  # fmt: skip
            # one group across unrelated tiers
            tiers = sorted({enis[e]["kind"] for e in mine} & {"EC2 instance", "RDS database", "load balancer",
                                                              "ECS task", "lambda", "vpc endpoint"})
            if len(tiers) >= 2 and gname != "default":
                out.append(_pt_item(
                    "hygiene", "shared-tiers", "low", "One group, several tiers",
                    f"{gname} is used by {', '.join(tiers)}",
                    f"Every rule in it applies to all of them: a port opened for one tier is open on the others "
                    f"({len(mine)} interfaces). Separate groups per tier keep a database port off the web servers.",
                    "Give each tier its own group, and let tiers in by group reference.", region, gname,
                    group=gid, extra={"interfaces": mine[:20]}))
            # unused but open
            if not mine and gname != "default":
                risky = [r for r in g.get("rules") or [] if ("0.0.0.0/0" in (r.get("cidrs") or [])
                         or "::/0" in (r.get("cidrs6") or [])) and (rule_port_class(r)["risky"])]
                if risky:
                    out.append(_pt_item(
                        "hygiene", "unused-open", "low", "Unused, but open",
                        f"{gname} is not used, and lets the internet in on {ports_label(risky[0])}",
                        "Whatever is put in it next is exposed on the day it is launched.",
                        "Delete the group if nothing needs it.", region, gname,
                        f"aws ec2 delete-security-group --region {region} --group-id {gid}", group=gid))
            # outbound
            out += _egress_items(region, gid, g, mine, enis, groups, (egress_seen or {}), lab)
        if lab is not None:
            out += _egress_bad(region, enis, groups, egress_seen or {}, lab)
        for st in snap.get("stale") or []:
            k = (st["group"], st["ref"], st["direction"], st["proto"], st["from"])
            if k in stale_seen:
                continue
            stale_seen.add(k)
            rule = {"proto": st["proto"], "from": st["from"] if st["from"] is not None else 0,
                    "to": st["to"] if st["to"] is not None else 65535}
            out.append(_pt_item(
                "hygiene", "stale-ref", "low", "Stale reference",
                f"{st['name'] or st['group']} {'lets in' if st['direction'] == 'in' else 'sends to'} group "
                f"{st['ref']}, which no longer exists",
                "The referenced group was deleted, or its peering connection went away. The rule does nothing "
                "today, but a new group or peering can bring it back to life.",
                "Remove the stale rule.", region, st["name"] or st["group"],
                _revoke_cli(region, st["group"], rule, ref=st["ref"], egress=st["direction"] == "out"),
                group=st["group"]))  # fmt: skip
    out.sort(key=lambda it: (SEV_RANK[it["sev"]], it["area"], it["region"], it["name"]))
    return out


def _bad_dest(lab, d: str) -> dict | None:
    lb = lab(d) if lab is not None else {}
    return lb if lb.get("group") in ("anon", "scanner", "threat") else None


def _egress_bad(region, enis, groups, egress_seen, lab) -> list[dict]:
    """One item per interface that connected out to a Tor or VPN exit, a scanner or an address on a threat list
    (critical: a botnet command server or a compromised host is how malware calls home)."""
    out = []
    for eid in sorted(egress_seen):
        e = enis.get(eid)
        if e is None:
            continue
        bad: dict = {}
        for (_proto, port), dsts in egress_seen[eid].items():
            for d, n in dsts.items():
                lb = _bad_dest(lab, d)
                if lb:
                    b = bad.setdefault(d, [lb, set(), 0])
                    b[1].add(port)
                    b[2] += n
        if not bad:
            continue
        ds = sorted(bad, key=lambda d: -bad[d][2])
        threat = [d for d in ds if bad[d][0].get("group") == "threat"]
        if threat:  # the malicious destinations first: they are the reason this is critical
            ds = threat + [d for d in ds if d not in threat]
        lb = bad[ds[0]][0]
        names = ", ".join((groups.get(g) or {}).get("name") or g for g in e.get("groups") or [])
        out.append(_pt_item(
            "egress", "egress-bad", "critical" if threat else "high",
            "Outbound to a known malicious IP address" if threat else "Outbound to Tor or a scanner",
            (f"{e['kind']} {eid} connected out to {len(threat)} address(es) on a threat list" if threat else
             f"{e['kind']} {eid} connected out to {len(ds)} Tor, VPN or scanner address(es)"),
            f"{ds[0]} ({lb.get('name', '')}) on port(s) {', '.join(map(str, sorted(bad[ds[0]][1])))}, "
            f"{sum(b[2] for b in bad.values()):,} flows" + (f", and {len(ds) - 1} more address(es)" if len(ds) > 1 else "")
            + f". Groups: {names}. Servers rarely have reason to; it is how malware calls home and how data leaves.",
            "Find the process on the host that made the connection, and restrict outbound rules to what the "
            "workload needs.", region, eid, group=(e.get("groups") or [""])[0], target=", ".join(ds[:3]),
            extra={"dests": ds[:20], "interfaces": [eid]}))  # fmt: skip
    return out


def _egress_items(region, gid, g, mine, enis, groups, egress_seen, lab) -> list[dict]:
    out: list[dict] = []
    gname = g.get("name") or gid
    eg = g.get("egress") or []
    open_all = [r for r in eg if str(r["proto"]) == "-1" and ("0.0.0.0/0" in (r.get("cidrs") or [])
                                                             or "::/0" in (r.get("cidrs6") or []))]
    if not mine:
        return out
    seen: dict = {}
    for eid in mine:
        for k, dsts in (egress_seen.get(eid) or {}).items():
            for d, n in dsts.items():
                if _bad_dest(lab, d):
                    continue  # never fitted into a rule: reported on its own
                seen.setdefault(k, {})[d] = seen.setdefault(k, {}).get(d, 0) + n
    if not open_all:
        return out
    if not seen:
        if any(enis[e]["kind"] == "RDS database" for e in mine):
            out.append(_pt_item(
                "egress", "egress-open", "low", "Outbound open",
                f"{gname} (used by a database) may connect anywhere",
                "Its outbound rule allows every protocol to every IP address. A database seldom needs more than its "
                "replicas and AWS services; open outbound is how stolen data leaves.",
                "Read with --egress to see what it connects to, then narrow the outbound rule.", region, gname,
                group=gid))
        return out
    rules = []
    for (proto, port), dsts in sorted(seen.items(), key=lambda kv: (str(kv[0][0]), kv[0][1])):
        pub = [d for d in dsts if _ip(d) is not None and not any(a <= _ip(d) <= b for a, b in PRIVATE)]
        if port in (80, 443) and len(pub) > 10:
            rules.append((proto, port, ["0.0.0.0/0"], f"{len(pub)} internet destinations"))
            continue
        v4 = sorted(d for d in dsts if _ip(d) is not None)
        if not v4:
            continue
        cidrs = sg_tightener.collapse_ips_to_cidrs(v4, 10, sg_tightener.DEFAULT_TOLERANCE)
        rules.append((proto, port, cidrs, f"{len(dsts)} destination(s)"))
    if not rules:
        return out
    n = sum(len(c) for *_, c, _ in rules)
    also = sorted({(groups.get(o) or {}).get("name") or o for e in mine for o in enis[e]["groups"] if o != gid
                   and any(str(r["proto"]) == "-1" and "0.0.0.0/0" in (r.get("cidrs") or [])
                           for r in (groups.get(o) or {}).get("egress") or [])})  # fmt: skip
    desc = "; ".join(f"{PROTO_NAME.get(str(p), p)} {port} to {', '.join(c[:3])}{' …' if len(c) > 3 else ''}"
                     for p, port, c, _ in rules[:6])  # fmt: skip
    cli = "\n".join(db_exec(f"aws ec2 authorize-security-group-egress --region {region} --group-id {gid} --ip-permissions "
                            f"'{_perm_arg(str(p), port, port, c)}'", "sg_review: outbound fitted to what was seen")
                    for p, port, cs, _ in rules for c in cs)  # fmt: skip
    for r in open_all:
        for c in [*(r.get("cidrs") or []), *(r.get("cidrs6") or [])]:
            if c in ("0.0.0.0/0", "::/0"):
                cli += "\n" + _revoke_cli(region, gid, r, c, egress=True, reason="sg_review: outbound fitted to what was seen")
    out.append(_pt_item(
        "egress", "egress-fit", "medium" if n <= EGRESS_FIT_MAX else "low", "Outbound wider than used",
        f"{gname} may connect anywhere, but used {len(rules)} port(s)",
        f"Its outbound rule allows every protocol to every IP address. Flow logs saw: {desc}"
        + (f", and {len(rules) - 6} more port(s)" if len(rules) > 6 else "")
        + ". Amazon DNS, the time service and instance metadata are not logged and not filtered, so narrowing "
          "leaves them alone."
        + (f" Its interfaces are also in {', '.join(also)}, whose outbound is open too: outbound rules add up, so "
           "narrow those as well." if also else ""),
        f"Replace the open outbound rule with these {n} rule(s), after checking a full business cycle was read "
        "(month-end jobs, backups).", region, gname, cli, group=gid,
        extra={"fit": [{"proto": str(p), "port": port, "cidrs": c, "note": note} for p, port, c, note in rules]}))
    return out


def _refused_by(src: str, e: dict, groups: dict, snaps: dict, proto: str, port: int) -> str:
    if not e:
        return "Interface since deleted"
    n = src if is_v6(src) else _ip(src)
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
        v4 = sorted(x for x in w["srcs"] if not is_v6(x))
        v6 = sorted(x for x in w["srcs"] if is_v6(x))
        out.append({"group": gid, "name": g.get("name", ""), "region": g.get("region", ""),
                    "ports": ports_label({"proto": proto, "from": port, "to": port}), "sources": len(w["srcs"]),
                    "flows": w["flows"], "from": sorted(w["names"])[:5], "pc": port_class(proto, port),
                    "cidrs": sg_tightener.collapse_ips_to_cidrs(v4, sg_tightener.DEFAULT_MAX_RULES, 0.0)
                    + sg_tightener.collapse_ipv6_to_cidrs(v6, sg_tightener.DEFAULT_MAX_RULES, 0.0)})  # fmt: skip
    return out


def _external(here: dict) -> int:
    """Connections through a rule from public (internet) addresses: not RFC 1918, 100.64/10, ULA or the like."""
    return sum(h[0] for src, h in here.items() if _is_public(src))  # documentation ranges count too: not private


def _mix(here: dict, lab) -> dict:
    """Connections through a rule by where they came from (internal, data centre, AWS, SaaS, internet)."""
    out: dict = {}
    for src, h in here.items():
        cat = lab(src)["cat"]
        out[cat] = out.get(cat, 0) + h[0]
    return out


def _rules_table(doc, groups, enis, accepted_rows, seen, seen_iv, lab, region_first, cut_regions, end) -> list[dict]:
    by_eni: dict[str, list] = {}
    deleted: list = []
    for row in accepted_rows:
        if row[2] in enis:
            by_eni.setdefault(row[2], []).append(row)
        else:
            deleted.append(row)
    # the refused-or-accepted rows of deleted interfaces, by (protocol, port): a rule looks only at its own ports
    deleted_by_port: dict[tuple, list] = {}
    for src, dst, _e, proto, dport, _f, _c in deleted:
        deleted_by_port.setdefault((proto, dport), []).append((_ip(src), src, _ip(dst)))
    seen_ints = sorted(n for n in map(_ip, seen) if n is not None)
    seen6 = {a for a in map(_addr6, seen) if a is not None}
    ext_iv = {k: lab.cat_iv[k] for k in EXTERNAL_CATS}  # the public internet: AWS, SaaS and partners, everyone else
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
        by_port: dict[tuple, list] = {}  # (protocol, port) -> (source as a number, source, flows, end)
        for src, _dst, _eni, proto, dport, flows, c in rows:
            by_port.setdefault((proto, dport), []).append((_ip(src), src, flows, c["e"]))
        own6 = next((v.get("cidrs6") or [] for v in snap.get("vpcs") or [] if v["id"] == g["vpc"]), [])
        lb_public = public_lb(g, snap)
        for rule in g["rules"]:
            for entry in rule.get("cidrs6") or []:
                row = _rule_row6(g, rule, entry, rows, deleted, own6, seen6, lab, logged, cut_regions, since, days,
                                 lb_public)  # fmt: skip
                if row:
                    out.append(row)
            for entry in _entries(rule):
                ivs = (_iv((snap.get("prefix_lists") or {}).get(entry, [])) if entry.startswith("pl-")
                       else _iv([entry]))  # fmt: skip
                if not ivs:
                    continue
                allowed = sg_ipintel.size(ivs)

                here: dict[str, list] = {}
                dports: set = set()
                for (proto, dport), got in by_port.items():
                    if not port_matches(rule, proto, dport):
                        continue
                    hit = False
                    for n, src, flows, e in got:
                        if n is not None and any(a <= n <= b for a, b in ivs):
                            h = here.setdefault(src, [0, 0])
                            h[0] += flows
                            h[1] = max(h[1], e)
                            hit = True
                    if hit:
                        dports.add((str(proto), int(dport)))
                unattr = {src for (proto, dport), got in deleted_by_port.items() if port_matches(rule, proto, dport)
                          for n, src, d in got
                          if n is not None and any(a <= n <= b for a, b in ivs)
                          and d is not None and any(a <= d <= b for a, b in vpc_iv)}  # fmt: skip
                n_seen = sum(bisect_right(seen_ints, b) - bisect_right(seen_ints, a - 1) for a, b in ivs)
                never_iv = sg_ipintel.subtract(ivs, seen_iv)
                never = sg_ipintel.size(never_iv)
                never_ext = {k: sg_ipintel.size(sg_ipintel.intersect(never_iv, iv)) for k, iv in ext_iv.items()}
                row = {"region": g["region"], "group": g["id"], "gname": g["name"], "vpc": g["vpc"],
                       "enis": len(g["enis"]), "ports": ports_label(rule), "proto": rule["proto"],
                       "from": rule["from"], "to": rule["to"], "source": entry,
                       "desc": (rule.get("descs") or {}).get(entry, ""), "allowed": allowed, "here": len(here),
                       "elsewhere": max(0, n_seen - len(here) - len(unattr - set(here))),
                       "unattributed": len(unattr - set(here)), "never": never,
                       "never_ext": sum(never_ext.values()), "never_ext_by": never_ext,
                       "last_used": max((h[1] for h in here.values()), default=None), "since": since,
                       "days": round(days, 1), "suggest": [], "suggest_size": None, "note": "",
                       "pc": rule_port_class(rule)}  # fmt: skip
                row["top"] = [{"src": s, **lab(s), "flows": h[0]}
                              for s, h in sorted(here.items(), key=lambda kv: -kv[1][0])[:8]]  # fmt: skip
                row["mix"] = _mix(here, lab)
                row["ext"] = _external(here)
                row["ports_used"] = sorted(dports)[:200]  # (protocol, port) seen through the rule: narrows a port range
                row["status"], row["note"] = _status(row, rule, entry, logged, g, cut_regions, days, lb_public)
                _mark_cut(row, g, cut_regions)
                if not entry.startswith("pl-"):  # for the Tighten panel: who used it, and when last
                    row["keep_src"] = [[s, h[1]] for s, h in here.items()] + [[s, None] for s in sorted(unattr - set(here))]
                    row["fit_ok"] = logged and g["region"] not in cut_regions and days >= EVIDENCE_DAYS
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
    rank = {"tighten": 0, "unused": 1, "open": 2, "watch": 3, "not logged": 5, "used": 6}
    out.sort(key=lambda r: (rank.get(r["status"], 9), -r["never"]))
    return out


FIT_STATUSES = ("tighten", "used", "unused", "open")


def fit_model(rules: list[dict], lab) -> dict:
    """What the page's Tighten panel needs: every IPv4 rule that is safe to fit (its group fully logged, enough
    days read), the sources that used it with when each was last seen, and each source's kind, type, name and
    published or named range, so a reader can choose how much room to leave for each kind, or each name, and see
    at once what the change takes away and whom it would turn away. Takes keep_src and fit_ok out of each row."""
    labels: dict[str, list] = {}
    out = []
    for r in rules:
        keep, ok = r.pop("keep_src", None), r.pop("fit_ok", False)
        if keep is None or not ok or r["status"] not in FIT_STATUSES:
            continue
        base = {k: r[k] for k in ("region", "group", "gname", "proto", "from", "to", "ports", "source", "desc",
                                  "allowed", "never", "status")}  # fmt: skip
        net = r["source"].split("/")[0]
        base["kind"] = "open" if r["source"] == "0.0.0.0/0" else lab(net)["cat"]
        if len(keep) > FIT_CAP:
            out.append({**base, "too_many": len(keep), "srcs": []})
            continue
        for src, _last in keep:
            if src not in labels:
                lb = lab(src)
                labels[src] = [lb["cat"], lb.get("group", lb["cat"]), lb.get("name", ""), lb.get("range", "")]
        out.append({**base, "srcs": sorted(keep, key=lambda x: _ip(x[0]) or 0)})
    return {"rules": out, "labels": labels, "cap": FIT_CAP}


def reach_model(doc: dict) -> dict:
    """Every inbound rule in the account and the interfaces each group is on, for "what can this address reach":
    the blast radius of one compromised host. A rule reaches an address when one of its ranges holds it, or
    when it lets in a group the address's own interface is in."""
    rules, assets = [], {}
    for region, x in sorted(doc["regions"].items()):
        snap = x.get("snapshot") or {}
        for eni, e in sorted((snap.get("enis") or {}).items()):
            for g in e.get("groups") or []:
                assets.setdefault(g, []).append([eni, e.get("kind", ""), (e.get("ips") or [""])[0], e.get("public", ""),
                                                 list(e.get("ipv6") or [])])  # fmt: skip
        for gid, g in sorted((snap.get("groups") or {}).items()):
            for r in g.get("rules") or []:
                cidrs = list(r.get("cidrs") or []) + list(r.get("cidrs6") or []) + (["::/0"] if r.get("any6") and "::/0" not in (r.get("cidrs6") or []) else [])
                refs = list(r.get("refs") or [])
                if not cidrs and not refs:
                    continue
                pc = rule_port_class(r)
                rules.append({"region": region, "group": gid, "gname": g.get("name", ""), "proto": str(r["proto"]),
                              "from": r["from"], "to": r["to"], "ports": ports_label(r), "cidrs": cidrs, "refs": refs,
                              "cls": pc.get("cls", ""), "svc": pc.get("svc", ""), "risky": bool(pc.get("risky"))})  # fmt: skip
    return {"rules": rules, "assets": assets}


def reach(model: dict, address: str) -> dict:
    """What one address can reach: each rule that lets it in (by range, or by a group its interface is in), with
    the interfaces behind it. Answers "if this host were compromised, how far could it get?"."""
    try:
        ip = ipaddress.ip_address(address.strip())
    except ValueError:
        raise SystemExit(f"not an IP address: {address!r}")
    own = {g for g, xs in model["assets"].items() for a in xs if str(ip) in ([a[2]] + list(a[4]))}
    rows = []
    for r in model["rules"]:
        via = next((c for c in r["cidrs"] if _in_cidr(ip, c)), None)
        if via is None:
            via = next((f"member of {g}" for g in r["refs"] if g in own), None)
        if via is None:
            continue
        rows.append({**{k: r[k] for k in ("region", "group", "gname", "proto", "from", "to", "ports", "cls", "svc",
                                          "risky")}, "via": via, "assets": model["assets"].get(r["group"], [])})  # fmt: skip
    rows.sort(key=lambda x: (not x["risky"], -len(x["assets"]), x["gname"], x["from"]))
    enis = {a[0] for x in rows for a in x["assets"]}
    return {"address": str(ip), "groups_in": sorted(own), "rows": rows,
            "summary": {"groups": len({x["group"] for x in rows}), "interfaces": len(enis),
                        "risky": len({(x["group"], x["ports"]) for x in rows if x["risky"]}),
                        "open_to_all": sum(x["via"] in ("0.0.0.0/0", "::/0") for x in rows)}}


def _in_cidr(ip, cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return ip.version == net.version and ip in net


def _subnets(ips) -> set[int]:
    """The /64 subnets (top 64 bits) of IPv6 addresses."""
    return {int(a) >> 64 for a in ips}


def _rule_row6(g, rule, entry, rows, deleted, own6, seen6, lab, logged, cut_regions, since, days,
               lb_public=False) -> dict | None:
    """One IPv6 range of a rule, counted in /64 subnets (one client network each)."""
    net = _net6(entry)
    if net is None:
        return None
    width = max(0, sg_tightener.V6_SUBNET - net.prefixlen)
    allowed = 1 << width if net.prefixlen <= sg_tightener.V6_SUBNET else 1
    here: dict[str, list] = {}
    for src, _dst, _eni, proto, dport, flows, c in rows:
        if is_v6(src) and port_matches(rule, proto, dport) and _in6(src, entry):
            h = here.setdefault(src, [0, 0])
            h[0] += flows
            h[1] = max(h[1], c["e"])
    unattr = {src for src, dst, _e, proto, dport, _f, _c in deleted
              if is_v6(src) and port_matches(rule, proto, dport) and _in6(src, entry)
              and any(_in6(dst, o) for o in own6)}  # fmt: skip
    inside = {a for a in seen6 if a in net}
    seen_nets = _subnets(inside)
    row = {"region": g["region"], "group": g["id"], "gname": g["name"], "vpc": g["vpc"], "enis": len(g["enis"]),
           "ports": ports_label(rule), "proto": rule["proto"], "from": rule["from"], "to": rule["to"], "source": entry,
           "desc": (rule.get("descs") or {}).get(entry, ""), "v6": True, "unit": "/64", "allowed": allowed,
           "here": len(here), "elsewhere": max(0, len(inside) - len(here) - len(unattr - set(here))),
           "unattributed": len(unattr - set(here)), "never": max(0, allowed - len(seen_nets)),
           "last_used": max((h[1] for h in here.values()), default=None), "since": since, "days": round(days, 1),
           "suggest": [], "suggest_size": None, "note": "", "pc": rule_port_class(rule)}  # fmt: skip
    row["top"] = [{"src": s, **lab(s), "flows": h[0]} for s, h in sorted(here.items(), key=lambda kv: -kv[1][0])[:8]]
    row["mix"] = _mix(here, lab)
    row["ext"] = _external(here)
    private = net.subnet_of(sg_tightener.ULA) or any(_net6(o) and net.subnet_of(_net6(o)) for o in own6)
    if entry.endswith("::/0") and net.prefixlen == 0 and lb_public and serves_web(rule):
        row["status"], row["note"] = "open", OPEN_WEB_NOTE
    elif not logged:
        row["status"], row["note"] = "not logged", "Some of this group's interfaces have no flow log (accepted traffic) in CloudWatch Logs"
    elif days < EVIDENCE_DAYS:
        row["status"], row["note"] = "watch", f"Only {days:.0f} days of flow logs: read a longer range before changing this rule"
    elif not here and not unattr:
        row["status"], row["note"] = "unused", f"No connection matched this rule in {days:.0f} days"
    elif net.prefixlen < sg_tightener.DEFAULT_V6_PREFIX_THRESHOLD and row["never"]:
        row["status"] = "tighten"
        row["note"] = ("Wider than needed: the suggestion keeps the /64 of every IP address seen, with 30% headroom"
                       if private else OPEN_NARROW_NOTE if net.prefixlen == 0
                       else "Public IPv6 range: the suggestion keeps only the /64s seen; check with the partner first")
    else:
        row["status"] = "used"
    _mark_cut(row, g, cut_regions)
    if row["status"] == "tighten":
        cidrs = sg_tightener.collapse_ipv6_to_cidrs(sorted(set(here) | unattr), sg_tightener.DEFAULT_MAX_RULES,
                                                    sg_tightener.DEFAULT_TOLERANCE, within=entry)  # fmt: skip
        size = sum(1 << max(0, sg_tightener.V6_SUBNET - _net6(c).prefixlen) for c in cidrs)
        if size >= allowed or not cidrs:
            row["status"], row["note"] = "used", "In use across the range: nothing to take away"
        else:
            row["suggest"], row["suggest_size"] = cidrs, size
    return row


CUT_NOTE = "Some hours read were cut at the 10,000 row limit: sources only in the missing rows are not kept. If one is refused it shows on Rejected traffic; reading those hours again in shorter slices fills them in"


def _mark_cut(row, g, cut_regions) -> None:
    """Hours cut at the row limit still narrow a rule, to the sources they hold (owner's decision 2026-11-25:
    Remediate always shows the least exposure the evidence allows, and the person proposing decides when to
    act). The rule is marked so the page says its evidence was cut."""
    if g["region"] in cut_regions and row["status"] in ("tighten", "unused", "used"):
        row["cut"] = True
        row["note"] = (row["note"] + ". " if row["note"] else "") + CUT_NOTE


WEB_PORTS = (80, 443)
OPEN_WEB_NOTE = "Internet-facing load balancer on 80/443: kept open to everyone, since its users cannot be listed"
OPEN_NARROW_NOTE = ("Open to every address, but not an internet-facing load balancer's web port: the suggestion keeps only the sources seen. "
                    "Anyone else refused shows on Rejected traffic")


def public_lb(g: dict, snap: dict) -> bool:
    """Whether the group sits on an internet-facing load balancer: an ELB interface with a public address."""
    enis = snap.get("enis") or {}
    return any(str((enis.get(e) or {}).get("kind")).lower() == "load balancer" and (enis.get(e) or {}).get("public")
               for e in g.get("enis") or [])  # fmt: skip


def serves_web(rule: dict) -> bool:
    """Whether a rule lets in TCP 80 or 443."""
    proto, lo, hi = str(rule["proto"]), int(rule.get("from") or 0), int(rule.get("to") or 65535)
    return proto == "-1" or (proto == "6" and any(lo <= p <= hi for p in WEB_PORTS))


def _status(row, rule, entry, logged, g, cut_regions, days, lb_public=False) -> tuple[str, str]:
    """Owner, 2026-11-25: 0.0.0.0/0 is kept only on an internet-facing load balancer's web ports, whose users
    cannot be listed. Everywhere else it narrows to the sources seen, like any other public range."""
    if entry == "0.0.0.0/0" and lb_public and serves_web(rule):
        return "open", OPEN_WEB_NOTE
    if not logged:
        return "not logged", "Some of this group's interfaces have no flow log (accepted traffic) in CloudWatch Logs"
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
        return "tighten", "Wider than needed: the suggested ranges keep every IP address seen, with 30% headroom"
    if not private and not entry.startswith("pl-") and plen < 32 and row["never"]:
        return "tighten", (OPEN_NARROW_NOTE if plen == 0
                           else "Public range: the suggestion keeps only the IP addresses seen; check with the partner first")
    return "used", ""


def approved(doc: dict, region: str) -> dict:
    """sg-tightener's approved list (v2) for one region, from the accepted connections read."""
    snap = (doc["regions"].get(region) or {}).get("snapshot") or {}
    enis = snap.get("enis") or {}
    own = {ip for e in enis.values() for ip in [*e["ips"], *(e.get("ipv6") or [])]}
    flows, warnings = set(), []
    folded = 0
    for c in doc["chunks"]:
        if c["r"] != region or c["st"] not in ("ok", "cut"):
            continue
        for src, dst, eni, proto, dport, action, _f in c["rows"]:
            if action != "ACCEPT" or not src or src in own:
                continue
            e = enis.get(eni)
            if e is not None and dst not in e["ips"] and dst not in (e.get("ipv6") or ()):
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
        "ips": sorted({f[0] for f in flows}, key=_addr_key),
        "flows": [{"src": a, "dst": b, "dstport": p, "protocol": pr, "interface": i}
                  for a, b, p, pr, i in sorted(flows, key=str)],
    }  # fmt: skip


def _addr_key(s: str) -> tuple:
    """Sort key: IPv4 addresses in numeric order, then IPv6."""
    try:
        a = ipaddress.ip_address(s)
        return (a.version, int(a))
    except ValueError:
        return (9, 0)


# ------------------------------------------------------------------------------------------- reading
class SafeSession:
    """A boto3 session whose ``client()`` may be called from many threads at once (boto3's own is not safe
    for that); everything else is the session's own."""

    def __init__(self, sess):
        self._sess = sess._sess if isinstance(sess, SafeSession) else sess
        self._lock = threading.Lock()

    def client(self, *a, **kw):
        with self._lock:
            return self._sess.client(*a, **kw)

    def __getattr__(self, name):
        return getattr(self._sess, name)


def each_region(fn, regions: Sequence[str], workers: int = REGION_WORKERS) -> list:
    """``fn(region)`` for every region, up to ``workers`` at once (each region has its own API limits);
    the results in the regions' order."""
    regions = list(regions)
    if len(regions) <= 1 or workers <= 1:
        return [fn(r) for r in regions]
    with ThreadPoolExecutor(max_workers=min(workers, len(regions))) as pool:
        return list(pool.map(fn, regions))


def plan_read(sess, doc: dict, regions: Sequence[str], days: int, now: float, say=LOG.info) -> list[tuple]:
    """Take each region's snapshot and rule history into ``doc`` (the regions at once) and return the
    slices still to read."""
    safe = SafeSession(sess)

    def fetch(region):
        say(f"reading security groups, interfaces and flow logs in {region}")
        try:
            snap = snapshot(safe, region)
        except (ClientError, BotoCoreError) as exc:  # one region out of reach must not stop the others
            return None, describe_error(exc)[:300]
        try:
            hist = rule_history(safe, region, utcnow())
        except (ClientError, BotoCoreError) as exc:  # the report says history is unknown
            hist = {"events": [], "whole_since": now, "read": False, "error": describe_error(exc)[:300]}
            LOG.warning("%s: rule changes not read from CloudTrail: %s", region, hist["error"])
        return snap, hist

    got = dict(zip(regions, each_region(fetch, regions)))
    tasks = []
    for region in regions:
        entry = doc["regions"].setdefault(region, {})
        snap, hist = got[region]
        if snap is None:
            entry["error"] = hist
            LOG.warning("%s not read: %s", region, entry["error"])
            continue
        entry["snapshot"], entry["taken"], entry["history"] = snap, now, hist
        entry.pop("error", None)
        qsets = query_sets(entry["snapshot"])
        entry["query_sets"] = qsets
        if not qsets:
            LOG.warning("%s: no VPC flow log in CloudWatch Logs with source, target, port, action and interface", region)
            continue
        if doc.get("egress"):  # slices read before outbound was asked for are read again, with it
            doc["chunks"] = [c for c in doc["chunks"] if c["r"] != region or "egr" in c]
        drop_stale_tails(doc, region, now)
        have = [(c["s"], c["e"]) for c in doc["chunks"] if c["r"] == region and c["st"] in ("ok", "cut")
                and not c.get("tail") and not coarse_cut(c)]  # fmt: skip
        vpcs = _vpc_ranges(entry["snapshot"])
        span = None if _whole(entry) else entry.get("slice")  # how short slices had to be to fit the row limit
        tasks += [(region, a, b, qsets, vpcs) for s, e in plan(now, days, have) for a, b in _pieces(s, e, span)]
    return tasks


def cut_tasks(doc: dict, first_only: bool = False) -> list[tuple]:
    """Read tasks for the hours an earlier read kept cut at the row limit (``coarse_cut``), in pieces of each
    region's learned slice length. ``first_only``: one hour per region not yet split, to learn that length."""
    tasks = []
    for region, entry in (doc.get("regions") or {}).items():
        qsets = entry.get("query_sets")
        if not qsets:
            continue
        if _whole(entry):
            continue
        vpcs = _vpc_ranges(entry.get("snapshot") or {})
        cut = sorted((c["s"], c["e"]) for c in doc["chunks"] if c["r"] == region and coarse_cut(c))
        if first_only:
            cut = cut[-1:] if cut and not entry.get("slice") else []
        tasks += [(region, a, b, qsets, vpcs) for s, e in cut for a, b in _pieces(s, e, entry.get("slice"))]
    return tasks


def coarse_cut(c: dict) -> bool:
    """A slice that hit the row limit while it could still have been split (read before slices went below an
    hour): read again, split finer, and replaced."""
    return c["st"] == "cut" and c["e"] - c["s"] > MIN_SPLIT and not c.get("top")


def _whole(entry: dict) -> bool:
    """A region so busy that even a minute of its flow log overflows the row limit: it is read in whole slices
    (the busiest rows of each), since splitting only multiplies the queries and the bytes billed (a minute-long
    query scans about 4 times the bytes per hour of an hour-long one)."""
    if entry.get("slice") and entry["slice"] <= MIN_SPLIT:  # learned before this was known
        entry.pop("slice")
        entry["whole"] = 1
    return bool(entry.get("whole"))


def _pieces(s: int, e: int, span) -> list[tuple[int, int]]:
    """[s, e) in pieces of ``span`` seconds (whole, when there is no span or it is longer)."""
    if not span or e - s <= span * 1.5:
        return [(s, e)]
    span = max(int(span), MIN_SPLIT // 2)
    return [(a, min(a + span, e)) for a in range(s, e, span)]


def drop_stale_tails(doc: dict, region: str, now: float) -> None:
    """Tail slices run past the last full hour. Once the hourly read reaches into them they would be counted
    twice, so all of the region's tail slices go and the tail is read again from the new last full hour."""
    end = read_end(now)
    tails = [c for c in doc["chunks"] if c["r"] == region and c.get("tail")]
    if any(c["s"] < end for c in tails):
        doc["chunks"] = [c for c in doc["chunks"] if not (c["r"] == region and c.get("tail"))]


def plan_tail(doc: dict, regions: Sequence[str], now: float) -> list[tuple]:
    """The slices from the last full hour (or the last tail read) up to TAIL_LAG ago, one per region."""
    tasks = []
    stop = _floor(now - TAIL_LAG, 60)
    for region in regions:
        entry = doc["regions"].get(region) or {}
        if not entry.get("query_sets") or entry.get("error"):
            continue
        drop_stale_tails(doc, region, now)
        start = max([read_end(now)] + [c["e"] for c in doc["chunks"] if c["r"] == region and c.get("tail")])
        if stop - start >= 60:
            tasks.append((region, start, stop, entry["query_sets"], _vpc_ranges(entry["snapshot"]), True))
    return tasks


def run_read(sess, doc: dict, tasks: list[tuple], days: int, now: float, cancelled=lambda: False, progress=None) -> dict:
    """Read the slices into ``doc`` (saved every dozen slices and at the end). A task with a sixth element
    True is a tail slice: its chunks are marked so the hourly read replaces them."""
    lock = threading.Lock()
    clients: dict = {}
    state = {"done": 0, "bytes": 0, "secs": 0, "queries": 0}
    hint: dict = {"_whole": {r for r, x in (doc.get("regions") or {}).items() if _whole(x)}}  # region: shortest span seen to overflow

    def tick(nbytes, secs):
        with lock:
            state["bytes"] += nbytes
            state["secs"] += secs
            state["queries"] += 1
            if progress:
                progress(state["done"], len(tasks), state["bytes"], state["secs"])

    def one(task):
        region, s, e, qsets, vpcs, *rest = task
        tail = bool(rest and rest[0])
        if cancelled():
            return
        with lock:
            logs = clients.get(region) or clients.setdefault(
                region, sess.client("logs", region_name=region, config=BOTO_CONFIG)
            )
        try:
            got = read_chunk(logs, region, s, e, qsets, vpcs, cancelled, bool(doc.get("egress")), tick, hint)
        except (ClientError, BotoCoreError) as exc:  # one slice out of reach must not stop the account's read
            got = [{"r": region, "s": s, "e": e, "st": "failed", "b": 0, "rows": [], "pub": [], "pc": False,
                    "err": describe_error(exc)[:300]}]  # fmt: skip
        with lock:
            if any(c["st"] != "failed" for c in got):  # replaces an earlier read of these hours that hit the row limit
                doc["chunks"] = [c for c in doc["chunks"]
                                 if not (c["r"] == region and coarse_cut(c) and c["s"] < e and c["e"] > s)]  # fmt: skip
            if region in hint["_whole"] and region in doc["regions"]:
                doc["regions"][region]["whole"] = 1
                doc["regions"][region].pop("slice", None)
            elif len(got) > 1 and region in doc["regions"]:  # split to stay under the row limit: start there next time
                span = min(c["e"] - c["s"] for c in got)
                entry = doc["regions"][region]
                entry["slice"] = min(entry.get("slice") or span, span)
        for chunk in got:
            if tail:
                chunk["tail"] = True
            with lock:
                doc["chunks"].append(chunk)
                if chunk["st"] == "failed":  # a failed slice is not ticked: its bytes count here
                    state["bytes"] += chunk["b"]
        if cancelled() and sum(c["e"] - c["s"] for c in got) < e - s:  # stopped part way: not counted as read
            return
        with lock:
            state["done"] += 1
            done = state["done"]
            if done % 12 == 0:
                save(doc)
            if progress:
                progress(done, len(tasks), state["bytes"], state["secs"])
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
def _covered(chunks: list, bins: list, step: int, end: int) -> list:
    """The share of each bin (0 to 1) that flow logs were read for, in any region: 0 is a bin with no data."""
    ivs: list = []
    for s, e in sorted((c["s"], c["e"]) for c in chunks):
        if ivs and s <= ivs[-1][1]:
            ivs[-1][1] = max(ivs[-1][1], e)
        else:
            ivs.append([s, e])
    out = []
    for b in bins:
        lo, hi = b, min(b + step, end)
        if hi <= lo:
            out.append(1.0)
            continue
        got = sum(max(0, min(hi, e) - max(lo, s)) for s, e in ivs)
        out.append(round(min(1.0, got / (hi - lo)), 2))
    return out


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
    # every window is built, read or not: one longer than the read shows its unread part as having no data
    ranges = {k: build(doc, k, onprem, internal, names) for k in RANGES}
    fits = [rep.pop("fit", None) for rep in ranges.values()]  # the rules are read over the whole read: keep one
    regions = [r for r, x in doc["regions"].items() if x.get("query_sets")]
    return {
        "schema": "sg-tightener.review/v1",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "account": doc["account"],
        "name": doc.get("name", ""),
        "mode": doc.get("mode", "live"),
        "first": first,
        "end": end,
        "default": ([k for k in keys if k != "1y"] or keys)[-1],
        "accounts": {a["account"]: a.get("name", "") for a in siblings(doc)},  # a year is a bar a week: offered, not opened on
        "ranges": ranges,
        "fit": fits[-1] or {"rules": [], "labels": {}, "cap": FIT_CAP},
        "reach": reach_model(doc),
        "hosts": hosts_model(doc),
        "names": len(names or []),
        "source_types": [{"key": k, "name": n, "kind": kind, "note": sg_ipintel.GROUP_NOTE.get(k, "")}
                         for k, (n, kind) in SOURCE_TYPES.items()],
        "port_classes": [{"key": k, "name": n, "note": note, "risky": k in RISKY_CLASSES}
                         for k, (n, note) in PORT_CLASSES.items()],
        "port_services": {_port_label(p, n): [c, s] for (p, n), (c, s) in PORT_SERVICES.items()},
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
    if getattr(args, "egress", False) and not doc.get("egress"):
        doc["egress"] = True
        LOG.info("outbound connections are read from now on (a third query per slice, about half as much again); "
                 "slices read before without them are read again")
    now = time.time()
    tasks = plan_read(sess, doc, regions, args.days, now)
    save(doc)
    if not tasks:
        LOG.info("nothing to read: the last %d days are already read in %s", args.days, ", ".join(regions))
        return 0
    est = estimate(doc, account, regions, now)
    hours = sum(t[2] - t[1] for t in tasks) / HOUR
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
    doc = sg_review_demo.build_doc(sg_review_demo.ACCOUNT, now, 180)  # half the year window: shows what no data looks like
    write_page(page_data(doc, "", "", now, parse_names(sg_review_demo.NAMES)), args.out)  # the other account: siblings
    LOG.info("wrote %s (a made-up account: no AWS call was made)", args.out)
    return 0


def cmd_reach(args) -> int:
    account = _pick_account(args.account)
    doc = load(account)
    if not doc:
        raise SystemExit(f"nothing read for {account}: run `sg_review.py read` first")
    got = reach(reach_model(doc), args.address)
    if args.json:
        print(json.dumps(got, indent=2))
        return 0
    s = got["summary"]
    print(f"{got['address']} can reach {s['groups']} security group(s) on {s['interfaces']} interface(s); "
          f"{s['risky']} on risky ports, {s['open_to_all']} only because the rule is open to every IP address")
    if got["groups_in"]:
        print(f"  its own interface is in {', '.join(got['groups_in'])}")
    for x in got["rows"]:
        kinds = sorted({a[1] or "interface" for a in x["assets"]})
        print(f"  {'!' if x['risky'] else ' '} {x['gname'] or x['group']:<22} {x['ports']:<14} {x['region']:<12} "
              f"via {x['via']:<20} {len(x['assets'])} interface(s): {', '.join(kinds)[:60]}")
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


def cmd_fold_replies(args) -> int:
    """Every saved read, reply traffic folded (load does it) and saved, one account at a time."""
    total = 0
    for account in sorted(stamps()):
        doc = sg_store.review_load(account, doc_schema=SCHEMA)
        if not doc or doc.get("replies_folded"):
            continue
        before = sum(len(c.get("rows") or []) for c in doc["chunks"])
        n = fold_replies(doc)
        save(doc)
        total += n
        print(f"{account}: {before:,} rows, {n:,} folded away", flush=True)
        del doc
    print(f"done: {total:,} rows folded away")
    return 0


def cmd_forget(args) -> int:
    account = _pick_account(args.account)
    LOG.info("deleted what was read for %s" if forget(account) else "nothing was read for %s", account)
    return 0


# ------------------------------------------------------------------------------------ watch and alert
WATCH_REPEAT = DAY  # an item still open is posted again after a day, not every hour
SEV_ICON = {"critical": ":red_circle:", "high": ":large_orange_circle:", "medium": ":large_yellow_circle:"}


def _sev_at_least(sev: str, floor: str) -> bool:
    return SEV_RANK[sev] <= SEV_RANK[floor]


def attention_id(it: dict) -> str:
    """What makes one "Needs attention" item the same item from one watch to the next."""
    ev = it.get("event") or {}
    return "|".join(str(p) for p in (it["key"], it.get("target") or "", it.get("name") or "", it.get("group") or "",
                                     ev.get("t", "")))  # fmt: skip


def _watch_path(account: str) -> Path:
    if not _ACCT_RE.fullmatch(account or ""):
        raise KeyError(account)
    return _dir() / f"{account}.watch.json"


def load_watch(account: str) -> dict:
    try:
        got = json.loads(sg_store.File(_watch_path(account)).read_text())
        return got if isinstance(got.get("sent"), dict) else {"sent": {}}
    except (OSError, ValueError, AttributeError):
        return {"sent": {}}


def save_watch(account: str, state: dict) -> None:
    sg_store.File(_watch_path(account)).write_text(json.dumps(state, indent=1))


def fresh_items(items: list[dict], state: dict, now: float, floor: str = "medium",
                repeat: float = WATCH_REPEAT) -> list[dict]:  # fmt: skip
    """The items at or above ``floor`` not posted in the last ``repeat`` seconds; ``state`` records them as posted.
    Items no longer open are dropped from ``state``, so one that comes back is posted at once."""
    sent = state.setdefault("sent", {})
    open_ids = set()
    out = []
    for it in items:
        if not _sev_at_least(it["sev"], floor):
            continue
        k = attention_id(it)
        open_ids.add(k)
        if k not in sent or now - sent[k] >= repeat:
            out.append(it)
            sent[k] = now
    for k in [k for k in sent if k not in open_ids]:
        del sent[k]
    return out


def alert_text(account: str, name: str, items: list[dict], markdown: bool = True) -> str:
    """The message: one paragraph per item, worst first."""
    who = f"{name} ({account})" if name else account
    head = f"sg_review: {len(items)} item{'s' if len(items) != 1 else ''} need{'s' if len(items) == 1 else ''} attention in {who}"
    out = [f"*{head}*" if markdown else head, ""]
    for it in items:
        srcs = ", ".join(it["srcs"][:5]) + (f" and {len(it['srcs']) - 5} more" if len(it["srcs"]) > 5 else "")
        title = f"{it['sev'].upper()} · {it['label']}: {it['title']}" + (f" ({it['target']})" if it.get("target") else "")
        out.append(f"{SEV_ICON.get(it['sev'], '')} *{title}*" if markdown else title)
        out.append(it["reason"])
        out.append(f"Do: {it['action']}")
        if it["srcs"]:
            fresh = f" · {it['new']} new (never seen before)" if it.get("new") else ""
            out.append(f"Sources: {srcs} · {it['flows']:,} flows{fresh}")
        if it.get("cli"):
            out += [f"Fix: {line}" for line in it["cli"].splitlines()]
        if it.get("restore"):
            r = it["restore"]
            out.append("Restore: " + db_exec(f"aws ec2 authorize-security-group-ingress --region {r['region']} --group-id "
                                             f"{r['group']} --ip-permissions '{json.dumps(r['perms'], separators=(',', ':'))}'",
                                             "sg_review: put back a revoked rule that is still needed"))  # fmt: skip
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def post_slack(url: str, text: str, timeout: float = 15) -> None:
    import urllib.request

    if not url.startswith("https://"):
        raise ValueError("the Slack webhook must be an https:// URL")
    req = urllib.request.Request(url, data=json.dumps({"text": text}).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})  # fmt: skip
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp.read()


def send_email(host: str, port: int, sender: str, to: list[str], subject: str, text: str, user: str = "",
               password: str = "", starttls: bool = True) -> None:  # fmt: skip
    import smtplib
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, sender, ", ".join(to)
    msg.set_content(text)
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        if starttls:
            smtp.starttls()
        if user:
            smtp.login(user, password)
        smtp.send_message(msg)


def _read_cost(doc: dict, account: str, regions: list[str], tasks: list[tuple], now: float) -> float | None:
    est = estimate(doc, account, regions, now)
    hours = sum(t[2] - t[1] for t in tasks) / HOUR
    return est["rate"] * hours * HOUR / 1e9 * INSIGHTS_PER_GB if est["rate"] is not None else None


def _report_opts(args) -> tuple[str, str, list]:
    return getattr(args, "onprem", ""), getattr(args, "internal", ""), load_names(getattr(args, "names", None))


ALERTS = ("refused", "all")


THREAT_ALERTS = frozenset({"Known malicious let in", "Outbound to a known malicious IP address"})


def alert_items(items: list[dict], mode: str = "refused") -> list[dict]:
    """What watch posts: rejected traffic, and always a known malicious address let in or called out to (a
    compromise in progress cannot wait for --alerts all); with "all", every Needs attention item."""
    if mode == "all":
        return list(items)
    return [it for it in items if it.get("kind") == "refused" or it.get("label") in THREAT_ALERTS]


def watch_once(sess, args, now: float | None = None) -> dict:
    """Read what is new in the last day, up to five minutes ago, build the last 24 hours and post the items not
    posted yet: by default only rejected traffic (--alerts refused); --alerts all adds exposure, drift and the rest."""
    now = now or time.time()
    regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    account = with_backoff(lambda: sess.client("sts", config=BOTO_CONFIG).get_caller_identity())["Account"]
    doc = load(account) or new_doc(account, args.name or "")
    if args.name:
        doc["name"] = args.name
    tasks = plan_read(sess, doc, regions, 1, now, say=LOG.debug)
    if getattr(args, "tail", True):
        tasks += plan_tail(doc, regions, now)
    save(doc)
    out = {"account": account, "read": 0, "bytes": 0, "items": 0, "posted": 0, "skipped": ""}
    if tasks:
        cost = _read_cost(doc, account, regions, tasks, now)
        if cost is not None and cost > args.max_cost:
            out["skipped"] = f"the read would cost {_cost(cost)}, over --max-cost US${args.max_cost:.2f}"
            LOG.warning("not read: %s", out["skipped"])
        else:
            st = run_read(sess, doc, tasks, 1, now)
            out["read"], out["bytes"] = st["done"], st["bytes"]
    if not any(c["st"] in ("ok", "cut") for c in doc["chunks"]):
        LOG.warning("nothing read yet for %s: no flow log in CloudWatch Logs in %s?", account, ", ".join(regions))
        return out
    onprem, internal, names = _report_opts(args)
    rep = build(doc, "24h", onprem, internal, names)
    items = alert_items(rep.get("attention", []), getattr(args, "alerts", "refused"))
    out["items"] = len(items)
    state = load_watch(account)
    new = fresh_items(items, state, now, args.min_severity, args.repeat * HOUR)
    if new:
        text = alert_text(account, doc.get("name", ""), new, markdown=True)
        sent = False
        slack = args.slack or os.environ.get("SG_REVIEW_SLACK_WEBHOOK", "")
        if slack:
            post_slack(slack, text)
            sent = True
        if args.email_to:
            plain = alert_text(account, doc.get("name", ""), new, markdown=False)
            send_email(args.smtp_host or os.environ.get("SG_REVIEW_SMTP_HOST", "localhost"), args.smtp_port,
                       args.email_from or os.environ.get("SG_REVIEW_EMAIL_FROM", "sg-review@localhost"),
                       [a.strip() for a in args.email_to.split(",") if a.strip()],
                       plain.splitlines()[0], plain, os.environ.get("SG_REVIEW_SMTP_USER", ""),
                       os.environ.get("SG_REVIEW_SMTP_PASSWORD", ""), not args.smtp_plain)  # fmt: skip
            sent = True
        if not sent:
            print(text, end="")
        out["posted"] = len(new)
    save_watch(account, state)
    if getattr(args, "securityhub", False):
        res = push_hub(sess, account, hub_findings(account, rep), regions)
        out["hub"] = res
        LOG.info("Security Hub: %d sent, %d archived, %d refused", res["sent"], res["archived"], res["failed"])
    LOG.info("%s: %d slice(s) read (%s), %d item(s) need attention, %d new posted", account, out["read"],
             _gb(out["bytes"]), out["items"], out["posted"])  # fmt: skip
    return out


def _org_watch_accounts(sess, args) -> list[dict]:
    accounts = org_accounts(sess, getattr(args, "ou_id", None))
    if getattr(args, "accounts", None):
        keep = {a.strip() for a in args.accounts.split(",")}
        accounts = [a for a in accounts if a["Id"] in keep]
    if not accounts:
        raise SystemExit("no active account found")
    return accounts


def watch_org_once(sess, args, accounts: list[dict], now: float | None = None) -> list[dict]:
    """One watch in every account (a role assumed in each, fresh each time, as the credentials last an hour);
    one account out of reach is logged and the rest still run."""
    import copy

    out = []
    for a in accounts:
        try:
            s = _assume(sess, a["Id"], args.role_name, args.external_id)
            one = copy.copy(args)
            one.name = a.get("Name", "") or args.name
            out.append(watch_once(s, one, now))
        except (ClientError, BotoCoreError) as exc:
            LOG.warning("%s (%s) not watched: %s", a["Id"], a.get("Name", ""), describe_error(exc))
            out.append({"account": a["Id"], "error": describe_error(exc)[:300]})
    return out


def cmd_watch(args) -> int:
    if args.min_severity not in ATTENTION:
        raise SystemExit(f"--min-severity must be one of {', '.join(ATTENTION)}")
    if getattr(args, "alerts", "refused") not in ALERTS:
        raise SystemExit(f"--alerts must be one of {', '.join(ALERTS)}")
    if not args.offline:
        sg_ipintel.refresh()
    sess = _session(args.profile)
    across = getattr(args, "ou_id", None) or getattr(args, "org", False)
    accounts = _org_watch_accounts(sess, args) if across else []
    if across:
        LOG.info("watching %d account(s) for rejected traffic", len(accounts))
    while True:
        try:
            if across:
                watch_org_once(sess, args, accounts)
            else:
                watch_once(sess, args)
        except (ClientError, BotoCoreError, OSError, ValueError) as exc:  # a loop must survive one bad hour
            if not args.loop:
                raise
            LOG.error("this watch failed, trying again next time: %s",
                      describe_error(exc) if isinstance(exc, (ClientError, BotoCoreError)) else exc)  # fmt: skip
        if not args.loop:
            return 0
        time.sleep(args.every * 60)
        if not args.offline:
            sg_ipintel.refresh()


# --------------------------------------------------------------------------------------- Security Hub
def hub_findings(account: str, rep: dict, now: str | None = None) -> list[dict]:
    """Everything worth tracking in Security Hub from one report: the "Needs attention" items, and every
    PrivateLink, exposure and hygiene finding down to low (not the info ones)."""
    out, seen = [], set()
    for it in [*rep.get("attention", []), *rep.get("drift", []), *rep.get("privatelink", []), *rep.get("posture", [])]:
        if it["sev"] == "info":
            continue
        k = f"{it.get('kind', '')}|{attention_id(it)}"
        if k in seen:
            continue
        seen.add(k)
        out.append(sg_securityhub.from_review_item(account, it, k, now))
    return out


def _hub_path(account: str) -> Path:
    if not _ACCT_RE.fullmatch(account or ""):
        raise KeyError(account)
    return _dir() / f"{account}.securityhub.json"


def push_hub(sess, account: str, findings: list[dict], regions: Sequence[str] = ()) -> dict:
    """Send `findings` for `account`, archiving the ones sent before that are gone; per region, as Security Hub
    is regional. The state is kept in <account>.securityhub.json."""
    try:
        state = json.loads(sg_store.File(_hub_path(account)).read_text())
    except (OSError, ValueError):
        state = {}
    now = sg_securityhub._now()
    grouped = sg_securityhub.by_region(findings)
    before = {scope.split("/", 1)[1] for scope in (state.get("securityhub") or {}) if scope.startswith(account + "/")}
    total = {"sent": 0, "failed": 0, "archived": 0, "errors": []}
    for region in sorted(set(grouped) | before | set(regions)):
        todo = sg_securityhub.plan(grouped.get(region, []), state, f"{account}/{region}", now)
        if not todo:
            continue
        res = sg_securityhub.send(sess, region, todo)
        total["archived"] += sum(1 for f in todo if f["RecordState"] == "ARCHIVED")
        for k in ("sent", "failed", "errors"):
            total[k] += res[k]
    sg_store.File(_hub_path(account)).write_text(json.dumps(state, indent=1))
    if total["failed"]:
        LOG.warning("Security Hub refused %d finding(s): %s", total["failed"], "; ".join(total["errors"][:3]))
    return total


def cmd_securityhub(args) -> int:
    account = _pick_account(args.account)
    doc = load(account)
    if not doc or not doc["chunks"]:
        raise SystemExit(f"nothing read for {account}: run `sg_review.py read` first")
    if not args.offline:
        sg_ipintel.refresh()
    onprem, internal, names = _report_opts(args)
    rep = build(doc, args.range, onprem, internal, names)
    findings = hub_findings(account, rep)
    if args.out:
        Path(args.out).write_text(json.dumps(findings, indent=1) + "\n")
        LOG.info("wrote %d finding(s) in ASFF to %s (nothing sent)", len(findings), args.out)
        return 0
    res = push_hub(_session(args.profile), account, findings, list(doc["regions"]))
    LOG.info("Security Hub: %d finding(s) sent, %d archived (no longer open), %d refused", res["sent"],
             res["archived"], res["failed"])  # fmt: skip
    return 1 if res["failed"] else 0


# ----------------------------------------------------------------------------------------- org roll-up
def _assume(sess, account: str, role: str, external_id: str = ""):
    import boto3

    kw = {"RoleArn": f"arn:aws:iam::{account}:role/{role}", "RoleSessionName": "sg-review"}
    if external_id:
        kw["ExternalId"] = external_id
    c = sess.client("sts", config=BOTO_CONFIG).assume_role(**kw)["Credentials"]
    return boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                         aws_session_token=c["SessionToken"])  # fmt: skip


def org_accounts(sess, ou_id: str | None) -> list[dict]:
    """The active accounts in the OU and every OU under it, or in the whole organisation."""
    org = sess.client("organizations", config=BOTO_CONFIG)
    out = []
    if not ou_id:
        for page in org.get_paginator("list_accounts").paginate():
            out += page.get("Accounts", [])
    else:
        queue = [ou_id]
        while queue:
            cur = queue.pop()
            for page in org.get_paginator("list_accounts_for_parent").paginate(ParentId=cur):
                out += page.get("Accounts", [])
            for page in org.get_paginator("list_organizational_units_for_parent").paginate(ParentId=cur):
                queue += [o["Id"] for o in page.get("OrganizationalUnits", [])]
    return sorted((a for a in out if a.get("Status") == "ACTIVE"), key=lambda a: a.get("Name", ""))


SPEND_DAYS = 30  # "spend a month" is the last 30 days, so a new account is not judged on a part month


def account_spend(ce, days: int = SPEND_DAYS) -> dict[str, float]:
    """US$ spent by each account Cost Explorer can see over the last ``days`` (credits and refunds left out).
    From the management account this is every account in the organisation; from any other only its own.
    Cost Explorer charges US$0.01 a page."""
    end = datetime.now(timezone.utc).date()
    kw: dict = {"TimePeriod": {"Start": (end - timedelta(days=days)).isoformat(), "End": end.isoformat()},
                "Granularity": "MONTHLY", "Metrics": ["UnblendedCost"],
                "GroupBy": [{"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"}],
                "Filter": {"Not": {"Dimensions": {"Key": "RECORD_TYPE", "Values": ["Credit", "Refund"]}}}}  # fmt: skip
    out: dict[str, float] = {}
    while True:
        r = ce.get_cost_and_usage(**kw)
        for period in r.get("ResultsByTime") or []:
            for g in period.get("Groups") or []:
                a = g["Keys"][0]
                out[a] = out.get(a, 0.0) + float(g["Metrics"]["UnblendedCost"]["Amount"])
        if not r.get("NextPageToken"):
            return {a: round(v, 2) for a, v in out.items()}
        kw["NextPageToken"] = r["NextPageToken"]


OWNER_TAGS = ("owner", "accountowner", "businessowner", "ownername", "owneremail", "technicalowner", "productowner",
              "teamowner", "contact", "team")  # tag keys read as the account's owner, first found wins (case, - and _ ignored)


def owner_of(tags: list[dict]) -> str:
    """The account's owner from its Organizations tags, or "" when it has none."""
    norm = {k: v for t in tags or [] if (k := str(t.get("Key", "")).lower().replace("-", "").replace("_", "").replace(" ", ""))
            and str(t.get("Value", "")).strip() for v in [str(t["Value"]).strip()]}  # fmt: skip
    return next((norm[k] for k in OWNER_TAGS if k in norm), "")


def org_tree(org) -> dict:
    """The organisation as a tree from an Organizations client: each OU with its own active accounts and
    the OUs under it, and the root at the top. The console's OU picker draws it."""

    def pages(op, key, **kw):
        out = []
        for page in org.get_paginator(op).paginate(**kw):
            out += page.get(key, [])
        return out

    def node(pid: str, name: str) -> dict:
        accts = [{"account": a["Id"], "name": a.get("Name", "")} for a in pages("list_accounts_for_parent", "Accounts", ParentId=pid)
                 if a.get("Status", "ACTIVE") == "ACTIVE"]  # fmt: skip
        kids = [node(o["Id"], o.get("Name", o["Id"])) for o in pages("list_organizational_units_for_parent",
                                                                      "OrganizationalUnits", ParentId=pid)]  # fmt: skip
        return {"id": pid, "name": name, "accounts": sorted(accts, key=lambda a: a["name"].lower()),
                "children": sorted(kids, key=lambda k: k["name"].lower())}  # fmt: skip

    roots = org.list_roots().get("Roots", [])
    if not roots:
        raise RuntimeError("the organisation has no root")
    return node(roots[0]["Id"], roots[0].get("Name") or "Root")


ORG_REFUSED = 200  # refused sources per account in the roll-up (the account's own page has them all)


def refused_rows(account: str, name: str, rep: dict, limit: int = ORG_REFUSED) -> list[dict]:
    """One account's refused sources, flat, for the OU-wide view: who was turned away, where, and the verdict."""
    out = []
    for r in (rep.get("refused") or [])[:limit]:
        t = (r.get("targets") or [{}])[0]
        v = r.get("verdict") or {}
        pc = t.get("pc") or {}
        out.append({"account": account, "account_name": name, "src": r["src"], "name": r.get("name", ""),
                    "cat": r.get("cat", ""), "type": r.get("group", ""), "flows": r.get("flows", 0),
                    "first": r.get("first"), "last": r.get("last"), "ports": r.get("ports", 0),
                    "dsts": r.get("dsts", 0), "sev": v.get("sev", "info"), "verdict": v.get("label", ""),
                    "reason": v.get("reason", ""), "region": t.get("region", ""), "eni": t.get("eni", ""),
                    "kind": t.get("kind", ""), "dst": t.get("dst", ""), "proto": t.get("proto", ""),
                    "port": t.get("port"), "port_class": pc.get("name", ""), "risky": bool(pc.get("risky")),
                    "groups": t.get("groups", []), "first_ever": r.get("first_ever"),
                    "seen_before": bool(r.get("seen_before")), "new": bool(r.get("new")),
                    "v6": bool(r.get("v6")), "internal": r.get("cat") in ("internal", "datacentre"),
                    "scan": bool(r.get("sweep")), "threat": r.get("group") == "threat",
                    "tor": r.get("group") == "anon",
                    # everything the Fix dialog shows: who the source is, every place it tried, and why it was refused
                    "provider": r.get("provider", ""), "what": r.get("what", ""), "range": r.get("range", ""),
                    "service": r.get("service", ""), "src_vpc": r.get("vpc", ""), "by": t.get("by", ""),
                    "title": v.get("title", ""), "action": v.get("action", ""), "wanted": bool(v.get("wanted")),
                    "key": v.get("key", ""), "event": v.get("event"), "restore": v.get("restore"),
                    "moved_from": v.get("moved_from", ""), "periods": len(r.get("bins") or []),
                    "targets": [{"eni": x.get("eni", ""), "dst": x.get("dst", ""), "proto": x.get("proto", ""),
                                 "port": x.get("port"), "flows": x.get("flows", 0), "kind": x.get("kind", ""),
                                 "groups": x.get("groups", []), "region": x.get("region", ""), "vpc": x.get("vpc", ""),
                                 "subnet": x.get("subnet", ""), "desc": x.get("desc", ""), "public": x.get("public", ""),
                                 "port_class": (x.get("pc") or {}).get("name", ""), "risky": bool((x.get("pc") or {}).get("risky")),
                                 "by": x.get("by", "")} for x in r.get("targets") or []]})  # fmt: skip
    return out


HIGH_RISK_TYPES = ("scanner", "anon", "threat")
OPEN_SOURCES = ("0.0.0.0/0", "::/0")


def _high_risk(r: dict) -> bool:
    """Scanning ports (many ports or many IP addresses), a known scanner, a threat list, a Tor or VPN exit."""
    return bool(r.get("sweep")) or r.get("group") in HIGH_RISK_TYPES


# Over-exposure per asset, RAG: never-seen addresses that can reach one network interface through its groups.
RAG_GREEN_MAX = 256  # a /24 or less of addresses nobody used
RAG_AMBER_MAX = 65536  # up to a /16; more, or open to the internet on a risky port, is red


def asset_rag(over: int, open_risky: bool = False) -> str:
    if open_risky or over > RAG_AMBER_MAX:
        return "red"
    return "amber" if over > RAG_GREEN_MAX else "green"


def _asset_rows(asset_enis, asset_over, enis, groups, snaps, rules, logged_ids) -> list[dict]:
    """One row per interface with groups: what it is, its over-exposure now and per period, internet-open rules."""
    open_by_group: dict[str, list] = {}
    for r in rules:
        if r.get("source") in OPEN_SOURCES:
            open_by_group.setdefault(r["group"], []).append(r)
    out = []
    for e in asset_enis:
        x = enis[e]
        inst = ((snaps.get(x["region"]) or {}).get("instances") or {}).get(x.get("instance") or "", {})
        opens = [r for gid in x["groups"] for r in open_by_group.get(gid, [])]
        risky = sorted({f'{r["ports"]} {(r.get("pc") or {}).get("svc", "")}'.strip() for r in opens if (r.get("pc") or {}).get("risky")})
        series = asset_over[e]
        out.append({
            "eni": e, "region": x["region"], "kind": x.get("kind", ""), "name": inst.get("name") or x.get("desc", ""),
            "instance": x.get("instance", ""), "public": bool(x.get("public")),
            "groups": [groups[g]["name"] if g in groups else g for g in x["groups"]],
            "over": series[-1] if series else 0, "series": series,
            "open": len(opens), "open_risky": risky,
            "logged": all(g in logged_ids for g in x["groups"] if g in groups),
        })
    return out


SEEN_PUBLIC = 3000  # public sources kept per account in the estate's address book (by flows); private ones all
SEEN_PORTS = 8  # ports kept per source (by flows); how many there were is counted


def sightings(doc: dict) -> dict:
    """The account's part of the estate's address book: every source its flow logs hold (the whole read, not one
    range), with flows let in, refused and answered (its replies to the account's own connections), when first and
    last seen, in which regions, and the ports it asked for; and every address of the account's own interfaces with
    what is behind it. IP addresses are reused, so first and last seen date each sighting.
    Each source: [flows let in, refused, replies, first, last, ports refused, addresses tried, regions,
    [[proto, port, let in, refused]] busiest first, ports let in]."""
    by: dict[str, list] = {}  # src -> [in, refused, replies, first, last, {(proto, port): [in, refused]}, regions, dsts, ports, dsts counted]

    def one(src, c):
        x = by.get(src)
        if x is None:
            x = by[src] = [0, 0, 0, c["s"], c["e"], {}, set(), set(), 0, 0]
        x[3], x[4] = min(x[3], c["s"]), max(x[4], c["e"])
        x[6].add(c["r"])
        return x

    for c in doc.get("chunks") or []:
        if c.get("st") not in ("ok", "cut"):
            continue
        for src, dst, _eni, proto, dport, action, flows in c.get("rows") or []:
            if not src:
                continue
            x = one(src, c)
            if dport >= EPHEMERAL and action == "ACCEPT":
                x[2] += flows
                continue
            i = 0 if action == "ACCEPT" else 1
            x[i] += flows
            p = x[5].setdefault((str(proto), dport), [0, 0])
            p[i] += flows
            x[7].add(dst)
        for src, flows, ports, dsts, dst, _eni, port, proto in c.get("pub") or []:
            if not src:
                continue
            x = one(src, c)
            x[1] += flows
            p = x[5].setdefault((str(proto), port), [0, 0])
            p[1] += flows
            x[7].add(dst)
            x[8] = max(x[8], ports)
            x[9] = max(x[9], dsts)  # counted when the read folded them, not named
    private = [s for s in by if private_ip(s)]
    public = sorted((s for s in by if not private_ip(s)), key=lambda s: -(by[s][0] + by[s][1] + by[s][2]))[:SEEN_PUBLIC]
    seen = {}
    for s in private + public:
        x = by[s]
        ports = sorted(x[5].items(), key=lambda kv: -(kv[1][0] + kv[1][1]))[:SEEN_PORTS]
        refused_ports = max(x[8], sum(1 for v in x[5].values() if v[1]))
        seen[s] = [x[0], x[1], x[2], x[3], x[4], refused_ports, max(x[9], len(x[7])), sorted(x[6]),
                   [[pr, pt, a, b] for (pr, pt), (a, b) in ports], sum(1 for v in x[5].values() if v[0])]  # fmt: skip
    hosts = hosts_model(doc)
    ips: dict[str, list] = {}
    for ip, eid in hosts["by_ip"].items():
        ips.setdefault(eid, []).append(ip)
    own = {eid: [*e, ips.get(eid, [])] for eid, e in hosts["enis"].items() if ips.get(eid)}
    return {"seen": seen, "own": own, "name": doc.get("name", "")}


def private_ip(ip: str) -> bool:
    """RFC 1918, carrier-grade NAT (100.64.0.0/10, what EKS pods often use) and IPv6 unique local: addresses inside
    someone's own networks. Not ipaddress's is_private, which counts the documentation ranges too."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version == 6:
        return a in _ULA
    n = int(a)
    return any(lo <= n <= hi for lo, hi in PRIVATE)


_ULA = ipaddress.ip_network("fc00::/7")


def report_row(kind: str, account: str, name: str, range_key: str):
    """One account's row for a console report ("macro" or "refused"), or None if none of its flow logs were read.
    A top-level function so the console can build many in parallel processes. "flow" is whether its flow
    logs were read and over how many days, for every account."""
    doc = load(account, rows=kind not in ("estimate", "flow"))  # those two need no traffic: a fraction of the memory
    if kind == "estimate":  # what reading back each READ_DAYS would cost, from the bytes per second earlier reads scanned
        if not doc:
            return None
        e = estimate(doc, account)
        return {"rate": e["rate"], "spent": e["spent"], "regions": e["regions"],
                "cost": {str(x["days"]): x["cost"] for x in e["ranges"]},
                "bytes": {str(x["days"]): x["bytes"] for x in e["ranges"]}}
    if kind == "seen":
        return sightings(doc) if doc else None
    if kind == "flow":
        import sg_remediate

        _, days = sg_remediate.window(doc, 3650) if doc else ({}, 0.0)
        return {"status": sg_remediate.flow_status(doc), "days": days}
    if not doc or not any(c["st"] in ("ok", "cut") for c in doc["chunks"]):
        return None
    if kind == "macro":
        rep = build(doc, range_key, names=load_names(), assets=True)
        return macro_row(account, doc.get("name") or name, rep)
    rep = build(doc, range_key)
    name = doc.get("name", "")
    cov = rep.get("covered") or [1.0]
    return {"rows": refused_rows(account, name, rep, limit=1000),
            "account": {"account": account, "name": name, "refused": rep["summary"]["refused"],
                        "attention": rep["summary"]["attention"], "end": rep.get("end"),
                        "first": _evidence(doc)[0],
                        "covered": round(sum(cov) / len(cov), 2), "bins": rep.get("bins") or [],
                        "by_type": ((rep.get("series") or {}).get("by_group") or {}).get("refused") or {}}}  # fmt: skip


def permitted_ips(rules: list) -> int:
    """IPv4 addresses the rules let in today, rule by rule."""
    return sum(int(r.get("allowed") or 0) for r in rules)


def needed_ips(rules: list) -> int:
    """IPv4 addresses the rules would let in once tightened, as Remediate works it out: a narrowed rule keeps its
    suggestion, an unused one goes, and the rest stay as they are."""
    n = 0
    for r in rules:
        if r.get("status") == "unused":
            continue
        if r.get("status") == "tighten" and r.get("suggest_size") is not None:
            n += int(r["suggest_size"])
        else:
            n += int(r.get("allowed") or 0)
    return n


def macro_row(account: str, name: str, rep: dict, mode: str = "") -> dict:
    """One account's numbers for the all-accounts risk overview: over-provisioning by owner, exposure, probing."""
    s = rep.get("summary") or {}
    se = rep.get("series") or {}
    rules = rep.get("rules") or []
    refused, active = rep.get("refused") or [], rep.get("active") or []
    v4 = [r for r in rules if ":" not in str(r.get("source", ""))]
    open_rules = [r for r in rules if r.get("source") in OPEN_SOURCES]
    open_risky = [r for r in open_rules if (r.get("pc") or {}).get("risky")]
    posture = rep.get("posture") or []
    hi_ref = [r for r in refused if _high_risk(r)]
    hi_act = [r for r in active if r.get("group") in HIGH_RISK_TYPES]  # active rows carry no sweep: the type is what counts
    bins = rep.get("bins") or []
    hi_series = [0] * len(bins)
    for r in hi_ref:
        for b in r.get("bins") or []:
            if 0 <= b < len(bins):
                hi_series[b] += 1
    classes: dict[str, int] = {}
    for r in open_rules:
        k = (r.get("pc") or {}).get("name") or "Other"
        classes[k] = classes.get(k, 0) + 1
    cov = rep.get("covered") or [1.0]
    top = sorted((r for r in v4 if r.get("status") in ("tighten", "unused") and r.get("never")),
                 key=lambda r: (-r["never"] * max(1, r.get("enis", 0)), -r["never"]))[:8]
    assets = [a for a in rep.get("assets") or [] if a["logged"]]
    for a in assets:
        a["rag"] = asset_rag(a["over"], bool(a["open_risky"]))
        a["start"] = a["series"][0] if a["series"] else 0
    rag_series = {k: [0] * len(bins) for k in ("red", "amber", "green")}
    for a in assets:
        for i, n in enumerate(a["series"][: len(bins)]):
            rag_series[asset_rag(n, bool(a["open_risky"]))][i] += 1
    rag = {k: sum(1 for a in assets if a["rag"] == k) for k in ("red", "amber", "green")}
    rag_start = {k: v[0] if v else 0 for k, v in rag_series.items()}
    overs = sorted(a["over"] for a in assets)
    worst = sorted(assets, key=lambda a: ({"red": 0, "amber": 1, "green": 2}[a["rag"]], -a["over"]))
    over_series_tot = [sum(v[i] for v in (se.get("over") or {}).values()) for i in range(len(bins))]
    return {
        "account": account, "name": name, "mode": mode, "end": rep.get("end"), "step": rep.get("step"),
        "permitted": permitted_ips(v4), "needed": needed_ips(v4),
        "bins": bins, "covered": round(sum(cov) / len(cov), 2), "history_days": s.get("history_days", 0),
        "over_now": s.get("over_now", 0), "over_by_cat": s.get("over_by_cat", {}),
        "over_by_type": {k: (v[-1] if v else 0) for k, v in (se.get("over_by_group") or {}).items()},
        "over_series": {k: list(v) for k, v in (se.get("over") or {}).items()},
        "over_type_series": {k: list(v) for k, v in (se.get("over_by_group") or {}).items()},
        "refused_series": {k: list(v) for k, v in (se.get("refused") or {}).items()},
        "high_series": hi_series,
        "rules": len(rules), "tighten": s.get("tighten", 0), "unused": s.get("unused", 0),
        "open": len(open_rules), "open_risky": len(open_risky),
        "open_risky_list": [{"group": r.get("gname") or r.get("group"), "ports": r.get("ports"), "source": r.get("source"),
                             "service": (r.get("pc") or {}).get("svc", ""), "region": r.get("region"),
                             "enis": r.get("enis", 0)} for r in open_risky[:10]],
        "open_classes": classes,
        "top_rules": [{"group": r.get("gname") or r.get("group"), "ports": r.get("ports"), "source": r.get("source"),
                       "never": r.get("never", 0), "status": r.get("status"), "region": r.get("region"),
                       "enis": r.get("enis", 0)} for r in top],
        "over_start": over_series_tot[0] if over_series_tot else 0, "over_total_series": over_series_tot,
        "assets_total": len(assets), "assets_unlogged": len(rep.get("assets") or []) - len(assets),
        "asset_rag": rag, "asset_rag_start": rag_start, "asset_rag_series": rag_series,
        "asset_over_avg": round(sum(overs) / len(overs)) if overs else 0,
        "asset_over_median": overs[len(overs) // 2] if overs else 0,
        "rag": "red" if rag["red"] else "amber" if rag["amber"] else "green",
        "assets": [{k: a[k] for k in ("eni", "region", "kind", "name", "instance", "public", "groups", "over", "start",
                                      "open", "open_risky", "rag")} for a in worst[:200]],
        "refused": s.get("refused", 0), "high_refused": len(hi_ref), "high_active": len(hi_act),
        "high_active_list": [{"src": r["src"], "name": r.get("name", ""), "type": r.get("group", ""),
                              "ports": sorted({f"{PROTO_NAME.get(str(t.get('proto')), t.get('proto'))} {t.get('port')}"
                                               for t in (r.get("targets") or [])})[:4],
                              "flows": r.get("flows", 0), "last": r.get("last")} for r in hi_act[:10]],
        "external_refused": sum(1 for r in refused if r.get("cat") == "internet" and not _high_risk(r)),
        "internal_refused": s.get("refused_internal", 0),
        "attention": s.get("attention", {}), "posture": s.get("posture", {}),
        "egress_bad": sum(1 for p in posture if p.get("area") == "egress" and p.get("sev") in ("critical", "high")),
        "exposure": sum(1 for p in posture if p.get("area") == "exposure" and p.get("sev") in ("critical", "high")),
        "not_logged": s.get("not_logged", 0), "new_refused": s.get("new_refused", 0),
        "attention_scope": _attention_scope(rep.get("attention") or []),
        "ext_now": sum((s.get("over_by_cat") or {}).get(k, 0) for k in EXTERNAL_CATS),
        "ext_by_cat": {k: (s.get("over_by_cat") or {}).get(k, 0) for k in EXTERNAL_CATS},
        "ext_rules": _external_rules(rules),
    }


SCOPE_OF_CAT = {"internet": "external", "saas": "saas", "internal": "internal", "datacentre": "internal", "aws": "internal"}


def _external_rules(rules: list, n: int = 5) -> list[dict]:
    """The rules that let the most of the public internet in: open to everyone on a risky port first, then open
    to everyone, then by never-seen public IP addresses times the assets the rule reaches."""
    def weight(r):
        is_open = r.get("source") in OPEN_SOURCES
        risky = bool((r.get("pc") or {}).get("risky"))
        return (not (is_open and risky), not is_open, -(r.get("never_ext") or 0) * max(1, r.get("enis", 0)))

    pick = [r for r in rules if r.get("source") in OPEN_SOURCES or r.get("never_ext")]
    return [{"group": r.get("gname") or r.get("group"), "gid": r.get("group"), "region": r.get("region"),
             "ports": r.get("ports"), "source": r.get("source"), "desc": r.get("desc", ""),
             "open": r.get("source") in OPEN_SOURCES, "risky": bool((r.get("pc") or {}).get("risky")),
             "service": (r.get("pc") or {}).get("svc", ""), "never_ext": r.get("never_ext") or 0,
             "never_ext_by": r.get("never_ext_by") or {}, "allowed": r.get("allowed", 0), "here": r.get("here", 0),
             "enis": r.get("enis", 0), "status": r.get("status"), "suggest": (r.get("suggest") or [])[:6],
             "last_used": r.get("last_used"),
             "seen_from": [{"src": t.get("src"), "name": t.get("name", ""), "cat": t.get("cat", "")}
                           for t in (r.get("top") or [])[:3]]}
            for r in sorted(pick, key=weight)[:n]]  # fmt: skip


def _attention_scope(items: list) -> dict:
    """Needs-attention counts by where the source sits: external (internet), SaaS and partners, or internal."""
    out = {k: {sev: 0 for sev in SEVERITIES} for k in ("external", "saas", "internal")}
    for it in items:
        scope = SCOPE_OF_CAT.get(it.get("cat", ""))
        if scope and it.get("sev") in out[scope]:
            out[scope][it["sev"]] += 1
    return out


def org_row(account: str, name: str, rep: dict | None, status: str, page: str = "", error: str = "") -> dict:
    """One account in the roll-up: its verdict counts and its "Needs attention" items."""
    rep = rep or {}
    att = rep.get("attention", [])
    return {"account": account, "name": name, "status": status, "error": error, "page": page,
            "attention": (rep.get("summary") or {}).get("attention", {}),
            "verdicts": (rep.get("summary") or {}).get("verdicts", {}),
            "refused": (rep.get("summary") or {}).get("refused", 0),
            "items": [{k: it.get(k) for k in ("sev", "label", "title", "target", "reason", "action", "flows", "srcs")}
                      for it in att],
            "refused_rows": refused_rows(account, name, rep) if rep else []}  # fmt: skip


def org_summary(rows: list[dict]) -> dict:
    tot = {s: 0 for s in ATTENTION}
    for r in rows:
        for s in ATTENTION:
            tot[s] += r["attention"].get(s, 0)

    def worst(r):
        return tuple(-r["attention"].get(s, 0) for s in ATTENTION)

    refused = sorted((x for r in rows for x in r.get("refused_rows") or []),
                     key=lambda x: (SEV_RANK.get(x["sev"], 9), -x["flows"]))  # fmt: skip
    return {"schema": "sg-tightener.review-org/v1",
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "accounts": len(rows), "failed": sum(1 for r in rows if r["status"] != "ok"), "attention": tot,
            "refused_total": sum(r.get("refused", 0) for r in rows), "refused": refused,
            "rows": sorted(rows, key=lambda r: (r["status"] != "ok", worst(r), r["name"]))}  # fmt: skip


def org_page(summary: dict, range_key: str) -> str:
    """A small self-contained page: one row per account, worst first, each linking to its own page."""
    e = html.escape
    sev_col = {"critical": "var(--crit)", "high": "var(--high)", "medium": "var(--med)"}
    rows = []
    for r in summary["rows"]:
        counts = " ".join(f'<span class="pill" style="--p:{sev_col[s]}">{r["attention"][s]} {s}</span>'
                          for s in ATTENTION if r["attention"].get(s)) or '<span class="muted">nothing</span>'  # fmt: skip
        items = "".join(f'<li><span class="pill" style="--p:{sev_col.get(it["sev"], "var(--muted)")}">{e(it["label"])}</span> '
                        f'{e(it["title"])}{" · " + e(it["target"]) if it.get("target") else ""}'
                        f'<div class="muted small">{e(it["reason"])}</div></li>' for it in r["items"][:5])  # fmt: skip
        more = f'<li class="muted">and {len(r["items"]) - 5} more on its page</li>' if len(r["items"]) > 5 else ""
        name = e(r["name"] or r["account"])
        link = f'<a href="{e(r["page"])}">{name}</a>' if r["page"] else name
        status = "" if r["status"] == "ok" else f'<div class="small warn">{e(r["status"])}: {e(r["error"])}</div>'
        rows.append(f'<tr><td>{link}<div class="muted small"><code>{e(r["account"])}</code></div>{status}</td>'
                    f'<td>{counts}</td><td><ul>{items}{more}</ul></td></tr>')  # fmt: skip
    t = summary["attention"]
    head = " ".join(f'<span class="pill" style="--p:{sev_col[s]}">{t[s]} {s}</span>' for s in ATTENTION)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Group Review, all accounts</title>
<style>
:root {{ --bg: #f7f6f2; --surface: #fff; --ink: #0b0b0b; --muted: #7a7873; --grid: #e1e0d9;
  --crit: #d03b3b; --high: #e0673a; --med: #b7791f; color-scheme: light; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg: #141413; --surface: #1d1d1b; --ink: #f0efec; --muted: #898781;
  --grid: #2c2c2a; --crit: #e05555; --high: #ec835a; --med: #e3a93c; color-scheme: dark; }} }}
body {{ margin: 0; background: var(--bg); color: var(--ink); font: 14px/1.5 system-ui, -apple-system, Segoe UI, sans-serif; }}
main {{ max-width: 1200px; margin: 0 auto; padding: 24px 16px; }}
table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 10px; overflow: hidden; }}
th, td {{ text-align: left; vertical-align: top; padding: 10px 12px; border-bottom: 1px solid var(--grid); }}
ul {{ margin: 0; padding-left: 18px; }} li {{ margin-bottom: 6px; }}
.muted {{ color: var(--muted); }} .small {{ font-size: 12.5px; }} .warn {{ color: var(--high); }}
.pill {{ display: inline-block; font-size: 11px; font-weight: 650; padding: 1px 7px; border-radius: 999px; white-space: nowrap;
  border: 1px solid color-mix(in srgb, var(--p) 45%, transparent); background: color-mix(in srgb, var(--p) 14%, var(--surface));
  color: color-mix(in srgb, var(--p) 75%, var(--ink)); }}
a {{ color: inherit; font-weight: 600; }}
.tools {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 8px 0 12px; }}
input[type=search], select {{ font: inherit; padding: 6px 10px; border: 1px solid var(--grid); border-radius: 8px;
  background: var(--surface); color: var(--ink); min-width: 0; }}
input[type=search] {{ flex: 1 1 260px; }}
.scroll {{ overflow-x: auto; }} code {{ font-size: 12.5px; }} h2 {{ margin-top: 32px; }}
@media (max-width: 700px) {{ td:nth-child(2), th:nth-child(2) {{ display: none; }} }}
</style></head><body><main>
<h1>Security Group Review, all accounts</h1>
<p class="muted">{summary["accounts"]} accounts, the last {e(range_key)}, worst first{f', {summary["failed"]} not read' if summary["failed"] else ''}.
Needs attention across them: {head}. Each account's page has the evidence, the verdict on every source and the commands.</p>
<table><thead><tr><th>Account</th><th>Needs attention</th><th>Worst items</th></tr></thead><tbody>
{"".join(rows)}
</tbody></table>
<h2 id="refused">All rejected traffic</h2>
<p class="muted">{summary.get("refused_total", 0):,} refused sources across the accounts read; the {len(summary.get("refused") or []):,} busiest
(up to {ORG_REFUSED} per account) are below, worst verdict first. Filter by any text: account, source, owner, port, verdict.</p>
<div class="tools"><input id="q" type="search" placeholder="Filter: account, source, owner, port, verdict…" aria-label="Filter rejected traffic">
<select id="sev" aria-label="Severity"><option value="">Every severity</option><option>critical</option><option>high</option>
<option>medium</option><option>low</option><option>info</option></select>
<label class="small"><input id="risky" type="checkbox"> risky ports only</label>
<label class="small"><input id="fresh" type="checkbox"> new addresses only</label>
<label class="small"><input id="v6" type="checkbox"> IPv6 only</label> <span id="n" class="muted small"></span></div>
<div class="scroll"><table id="rt"><thead><tr><th>Severity</th><th>Account</th><th>Source</th><th>Refused on</th><th>Flows</th><th>Last seen</th><th>Verdict</th></tr></thead><tbody></tbody></table></div>
<script id="rdata" type="application/json">{_script_json(summary.get("refused") or [])}</script>
<script>
(() => {{
  const rows = JSON.parse(document.getElementById("rdata").textContent);
  const esc = (t) => String(t ?? "").replace(/[&<>"']/g, (c) => ({{"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}})[c]);
  const col = {{critical: "var(--crit)", high: "var(--high)", medium: "var(--med)"}};
  const when = (t) => t ? new Date(t * 1000).toISOString().slice(0, 16).replace("T", " ") : "";
  const proto = {{"6": "tcp", "17": "udp", "1": "icmp"}};
  const tb = document.querySelector("#rt tbody");
  const draw = () => {{
    const q = document.getElementById("q").value.toLowerCase().trim();
    const sev = document.getElementById("sev").value;
    const risky = document.getElementById("risky").checked;
    const fresh = document.getElementById("fresh").checked;
    const v6 = document.getElementById("v6").checked;
    const shown = rows.filter((r) => (!sev || r.sev === sev) && (!risky || r.risky) && (!fresh || r.new) && (!v6 || r.v6) && (!q ||
      [r.account, r.account_name, r.src, r.name, r.type, r.port, r.port_class, r.verdict, r.reason, r.kind, r.region, r.eni, r.dst]
        .join(" ").toLowerCase().includes(q)));
    tb.innerHTML = shown.slice(0, 2000).map((r) => `<tr><td><span class="pill" style="--p:${{col[r.sev] || "var(--muted)"}}">${{esc(r.sev)}}</span></td>
      <td>${{esc(r.account_name || r.account)}}<div class="muted small"><code>${{esc(r.account)}}</code></div></td>
      <td><code>${{esc(r.src)}}</code>${{r.new ? ' <span class="pill" style="--p:var(--high)">new</span>' : ""}}${{r.v6 ? ' <span class="pill">IPv6</span>' : ""}}
        <div class="muted small">${{r.internal ? "internal" : "external"}} · ${{esc(r.name)}}${{r.type ? " · " + esc(r.type) : ""}}${{r.scan ? " · scanning" : ""}}${{r.threat ? " · known malicious" : r.tor ? " · Tor exit" : ""}}</div>
        ${{r.first_ever ? `<div class="muted small">${{r.new ? "first seen" : "seen since"}} ${{when(r.first_ever).slice(0, 10)}}</div>` : ""}}</td>
      <td>${{esc(proto[r.proto] || r.proto)}} ${{esc(r.port)}}${{r.risky ? " ⚠" : ""}} <span class="muted small">${{esc(r.port_class)}}</span>
        <div class="muted small">${{esc(r.kind)}} ${{esc(r.dst)}} · ${{esc(r.region)}}${{r.ports > 1 ? ` · ${{r.ports}} ports` : ""}}</div></td>
      <td>${{Number(r.flows).toLocaleString()}}</td><td class="small">${{when(r.last)}}</td>
      <td>${{esc(r.verdict)}}<div class="muted small">${{esc(r.reason)}}</div></td></tr>`).join("");
    document.getElementById("n").textContent = `${{shown.length.toLocaleString()}} of ${{rows.length.toLocaleString()}}`;
  }};
  for (const id of ["q", "sev", "risky", "fresh", "v6"]) document.getElementById(id).addEventListener("input", draw);
  draw();
}})();
</script>
<p class="muted small">Written {e(summary["generated_at"])} by sg-tightener sg_review.py org.</p>
</main></body></html>
"""


def cmd_org(args) -> int:
    if args.days not in READ_DAYS:
        raise SystemExit(f"--days must be one of {', '.join(map(str, READ_DAYS))}")
    regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    sess = _session(args.profile)
    accounts = org_accounts(sess, args.ou_id)
    if args.accounts:
        keep = {a.strip() for a in args.accounts.split(",")}
        accounts = [a for a in accounts if a["Id"] in keep]
    if not accounts:
        raise SystemExit("no active account found")
    LOG.info("%d account(s): taking each one's security groups and rule history first (Describe calls, free)", len(accounts))
    now = time.time()
    plans, failed = [], []
    for a in accounts:
        try:
            s = _assume(sess, a["Id"], args.role_name, args.external_id)
            doc = load(a["Id"]) or new_doc(a["Id"], a.get("Name", ""))
            doc["name"] = a.get("Name", "") or doc.get("name", "")
            tasks = plan_read(s, doc, regions, args.days, now, say=LOG.debug)
            save(doc)
            plans.append((a, s, doc, tasks, _read_cost(doc, a["Id"], regions, tasks, now) if tasks else 0.0))
        except (ClientError, BotoCoreError) as exc:  # one account out of reach must not stop the others
            failed.append(org_row(a["Id"], a.get("Name", ""), None, "not read", error=describe_error(exc)[:300]))
            LOG.warning("%s (%s) not read: %s", a["Id"], a.get("Name", ""), failed[-1]["error"])
    known = [c for *_, c in plans if c is not None]
    unknown = sum(1 for *_, c in plans if c is None)
    slices = sum(len(t) for _, _, _, t, _ in plans)
    LOG.info("%d slice(s) to read in %d account(s): %s%s", slices, len(plans), _cost(sum(known)) if known else "",
             f" plus {unknown} account(s) not measured yet" if unknown else "")  # fmt: skip
    if slices and not args.yes and not _confirm("Read the flow logs of these accounts?"):
        LOG.info("not read")
        return 1
    stop = threading.Event()
    previous = signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        for a, s, doc, tasks, _ in plans:
            if tasks and not stop.is_set():
                LOG.info("reading %s (%s)", a["Id"], a.get("Name", ""))
                run_read(s, doc, tasks, args.days, now, stop.is_set)
    finally:
        signal.signal(signal.SIGINT, previous)
    if not args.offline:
        sg_ipintel.refresh()
    onprem, internal, names = _report_opts(args)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = list(failed)
    for a, s, doc, _, _ in plans:
        if not any(c["st"] in ("ok", "cut") for c in doc["chunks"]):
            rows.append(org_row(a["Id"], doc.get("name", ""), None, "no flow logs", error="no flow log read in "
                                + ", ".join(regions)))  # fmt: skip
            continue
        page = f"sg-review-{a['Id']}.html"
        data = page_data(doc, onprem, internal, names=names)
        write_page(data, str(out_dir / page))
        key = args.range if args.range in data["ranges"] else data["default"]
        rows.append(org_row(a["Id"], doc.get("name", ""), data["ranges"][key], "ok", page))
        if getattr(args, "securityhub", False):
            try:  # each account's findings go to its own Security Hub, sent with the role assumed in it
                res = push_hub(s, a["Id"], hub_findings(a["Id"], data["ranges"][key]), regions)
                LOG.info("%s: Security Hub %d sent, %d archived, %d refused", a["Id"], res["sent"], res["archived"],
                         res["failed"])  # fmt: skip
            except (ClientError, BotoCoreError) as exc:
                LOG.warning("%s: not sent to Security Hub: %s", a["Id"], describe_error(exc))
    summary = org_summary(rows)
    (out_dir / "org.json").write_text(json.dumps(summary, indent=1))
    (out_dir / "index.html").write_text(org_page(summary, args.range))
    t = summary["attention"]
    LOG.info("wrote %s: %d account(s), %d critical, %d high, %d medium", out_dir / "index.html", summary["accounts"],
             t["critical"], t["high"], t["medium"])  # fmt: skip
    return 130 if stop.is_set() else 2 if summary["failed"] else 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sg_review.py", description=__doc__.splitlines()[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter)  # fmt: skip
    p.add_argument("--data-dir", default=str(sg_ipintel.DATA_DIR),
                   help="where reads and IP address lists are kept (default ~/.sg-tightener)")  # fmt: skip
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("read", help="read an account's flow logs (live, read-only, cost confirmed first)")
    r.add_argument("--regions", required=True, help="comma-separated regions")
    r.add_argument("--days", type=int, default=1, help="read back this far: 1, 7, 30, 90, 180 or 365 (default 1)")
    r.add_argument("--profile", help="AWS profile (default: the usual credential chain)")
    r.add_argument("--name", help="a name for the account in the report (default: its alias)")
    r.add_argument("--egress", action="store_true", help="also read outbound connections, so the report can fit "
                   "outbound rules and flag connections to Tor, scanners or threat-list IP addresses (about half as much again per read; "
                   "stays on for this account)")
    r.add_argument("--yes", action="store_true", help="skip the typed confirmation")
    r.set_defaults(fn=cmd_read)
    o = sub.add_parser("report", help="write the self-contained HTML page")
    o.add_argument("--account", help="the account read (default: the only one)")
    o.add_argument("--onprem", default="", help='data centre ranges to name, e.g. "10.200.0.0/16 Johannesburg DC"')
    o.add_argument("--internal", default="", help='your other accounts\' ranges, e.g. "10.40.0.0/16 Payments prod"')
    o.add_argument("--names", help="names file (YAML or JSON) naming partners and other networks by range or AS "
                   "number (default ~/.sg-tightener/names.yaml if it exists; `sg_review.py names` writes an example)")
    o.add_argument("--offline", action="store_true", help="do not refresh the public IP address lists")
    o.add_argument("--out", help="output file (default sg-review-<account>.html)")
    o.set_defaults(fn=cmd_report)
    a = sub.add_parser("approved", help="write sg-tightener's approved.json for one region")
    a.add_argument("--region", required=True)
    a.add_argument("--account")
    a.add_argument("--out", default="approved.json")
    a.set_defaults(fn=cmd_approved)
    d = sub.add_parser("demo", help="write the report for a made-up account")
    d.add_argument("--out", default="sg-review-demo.html")
    d.add_argument("--offline", action="store_true", help="do not refresh the public IP address lists")
    d.set_defaults(fn=cmd_demo)
    rc = sub.add_parser("reach", help="blast radius: every security group, port and interface one IP address can reach")
    rc.add_argument("address", help="an IPv4 or IPv6 address, such as a data centre laptop or a build server")
    rc.add_argument("--account")
    rc.add_argument("--json", action="store_true", help="print JSON")
    rc.set_defaults(fn=cmd_reach)
    n = sub.add_parser("names", help="check the names file, or write an example one if there is none")
    n.add_argument("--out", help="the names file (default ~/.sg-tightener/names.yaml)")
    n.set_defaults(fn=cmd_names)
    w = sub.add_parser("watch", help="real-time alerts on rejected traffic: read up to five minutes ago and post "
                       "what needs attention to Slack or email (run with --loop: every 5 minutes)")
    g = sub.add_parser("org", help="read every account in an OU (assuming a role in each) and write a roll-up of what "
                       "needs attention in each")
    for q in (w, g):
        q.add_argument("--regions", required=True, help="comma-separated regions")
        q.add_argument("--profile", help="AWS profile (default: the usual credential chain)")
        q.add_argument("--onprem", default="", help="data centre ranges to name, as for report")
        q.add_argument("--internal", default="", help="your other accounts' ranges, as for report")
        q.add_argument("--names", help="names file, as for report")
        q.add_argument("--offline", action="store_true", help="do not refresh the public IP address lists")
        q.add_argument("--securityhub", action="store_true", help="also send the findings to AWS Security Hub "
                       "(ASFF; findings no longer open are archived)")
    w.add_argument("--name", help="a name for the account in the alerts (default: as read before)")
    w.add_argument("--slack", help="Slack incoming-webhook URL (or SG_REVIEW_SLACK_WEBHOOK)")
    w.add_argument("--email-to", help="comma-separated IP addresses to email (SMTP; see --smtp-host)")
    w.add_argument("--email-from", help="sender IP address (or SG_REVIEW_EMAIL_FROM)")
    w.add_argument("--smtp-host", help="SMTP server (or SG_REVIEW_SMTP_HOST; default localhost); login from "
                   "SG_REVIEW_SMTP_USER and SG_REVIEW_SMTP_PASSWORD")
    w.add_argument("--smtp-port", type=int, default=587)
    w.add_argument("--smtp-plain", action="store_true", help="do not use STARTTLS (a local relay)")
    w.add_argument("--min-severity", default="high", help="post items at or above: critical, high or medium (default high)")
    w.add_argument("--repeat", type=float, default=24, help="post an item still open again after this many hours (default 24)")
    w.add_argument("--max-cost", type=float, default=0.50, help="skip a read estimated above this many US$ (default 0.50)")
    w.add_argument("--loop", action="store_true", help="keep running, once every --every minutes")
    w.add_argument("--every", type=float, default=5, help="minutes between watches with --loop (default 5)")
    w.add_argument("--alerts", default="refused", help="what to post: refused (rejected traffic, and known malicious IP addresses "
                   "let in or called out to; the default) or all (adds exposure, rules opened wide, hygiene, PrivateLink)")
    w.add_argument("--ou-id", help="watch every active account in this OU and the OUs under it (a role assumed in each)")
    w.add_argument("--org", action="store_true", help="watch every active account in the organisation")
    w.add_argument("--accounts", help="only these comma-separated account ids (with --ou-id or --org)")
    w.add_argument("--role-name", default="OrganizationAccountAccessRole", help="role to assume in each account")
    w.add_argument("--external-id", default="", help="external id for the role, if it needs one")
    w.add_argument("--no-tail", dest="tail", action="store_false", help="read only to the last full hour (alerts "
                   "up to 75 minutes late, about half the cost)")
    w.set_defaults(fn=cmd_watch)
    g.add_argument("--role-name", default="OrganizationAccountAccessRole", help="role to assume in each account")
    g.add_argument("--external-id", default="", help="external id for the role, if it needs one")
    g.add_argument("--ou-id", help="read the accounts in this OU and the OUs under it (default: the whole organisation)")
    g.add_argument("--accounts", help="only these comma-separated account ids")
    g.add_argument("--days", type=int, default=1, help="read back this far: 1, 7, 30, 90, 180 or 365 (default 1)")
    g.add_argument("--range", default="1w", help="the range the roll-up counts: 24h, 1w, 1m, 3m, 6m or 1y (default 1w, or "
                   "the longest read when shorter)")
    g.add_argument("--out-dir", default="sg-review-org", help="where the roll-up and the account pages go")
    g.add_argument("--yes", action="store_true", help="skip the typed confirmation")
    g.set_defaults(fn=cmd_org)
    f = sub.add_parser("forget", help="delete what was read for an account")
    f.add_argument("--account")
    f.set_defaults(fn=cmd_forget)
    fr = sub.add_parser("fold-replies", help="fold reply traffic in reads saved before 5.24.0, and save them")
    fr.set_defaults(fn=cmd_fold_replies)
    h = sub.add_parser("securityhub", help="send an account's findings to AWS Security Hub (ASFF), archiving the "
                       "ones no longer open")
    h.add_argument("--account", help="the account read (default: the only one)")
    h.add_argument("--range", default="1w", help="the range the findings come from: 24h, 1w, 1m, 3m, 6m or 1y (default 1w)")
    h.add_argument("--profile", help="AWS profile to send with (default: the usual credential chain)")
    h.add_argument("--onprem", default="", help="data centre ranges to name, as for report")
    h.add_argument("--internal", default="", help="your other accounts' ranges, as for report")
    h.add_argument("--names", help="names file, as for report")
    h.add_argument("--offline", action="store_true", help="do not refresh the public IP address lists")
    h.add_argument("--out", help="write the findings (ASFF JSON) to this file instead of sending them")
    h.set_defaults(fn=cmd_securityhub)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = _build_parser().parse_args(argv)
    sg_ipintel.set_data_dir(args.data_dir)
    try:
        return args.fn(args)
    except (ClientError, BotoCoreError) as exc:
        LOG.error("%s", sg_tightener.login_hint(exc, getattr(args, "profile", None)) or describe_error(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
