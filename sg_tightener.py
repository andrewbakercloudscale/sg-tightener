#!/usr/bin/env python3
"""sg_tightener.py — Evidence-based security group CIDR tightening.

Replaces broad RFC 1918 ingress rules on AWS security groups with the
tightest covering CIDR blocks empirically observed in VPC flow logs.

Modes:
  analyse  Read flow logs (CloudWatch Logs or S3) and emit an
           approved JSON file: the observed source IPs and, for
           each, the destination address and port it reached.
           Before reading, the flow logs
           feeding the destination are checked with
           ec2:DescribeFlowLogs: the parse layout is derived from
           the configured log format, and a warning is raised when
           the format lacks pkt-srcaddr — without it, traffic that
           arrives through a transit gateway or NAT gateway is
           recorded under the intermediate interface's IP (the next
           hop), not the true source.
  plan     Read the approved file, the current SG inventory and the
           network interfaces, and emit a plan.json describing rules
           to revoke and rules to authorise. Each group keeps only
           the sources that reached an interface carrying it. Plans are signed with a state hash so
           apply refuses to run against a stale snapshot.
  apply    Execute a plan. Halts immediately on any single-group
           failure and prints the revert command.
  revert   Restore the exact pre-apply state from the manifest
           written by the most recent apply.

This module also exposes a pure-Python CIDR collapse function
(``collapse_ips_to_cidrs``) used by the test suite. It is part of
the CloudToRepo project: https://cloudtorepo.com

Usage:
  sg_tightener.py analyse  --region <r> [--days 90] [--out approved.json]
                           [--log-group <name> | --s3-bucket <b> --s3-prefix <p>]
  sg_tightener.py plan     --region <r> --approved approved.json
                           [--max-rules 60] [--tolerance 0.30]
                           [--prefix-threshold 24] [--out plan.json]
  sg_tightener.py apply    --plan plan.json [--region <r>] [--yes]
  sg_tightener.py revert   --manifest manifest-<ts>.json [--yes]
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import gzip
import hashlib
import ipaddress
import json
import logging
import os
import re
import sys
import time
from typing import Callable, Iterable, Iterator, Sequence

try:
    import boto3
    import botocore
    from botocore.config import Config as BotoConfig
except ImportError:
    boto3 = None
    botocore = None
    BotoConfig = None

LOG = logging.getLogger("sg_tightener")

RFC1918_BLOCKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

DEFAULT_PREFIX_THRESHOLD = 24
DEFAULT_TOLERANCE = 0.30
DEFAULT_MAX_RULES = 60
DEFAULT_DAYS = 90

# approved.json: v1 holds source IPs only; v2 adds ``flows``, the destination
# (address, port, protocol) each source reached. plan reads either.
APPROVED_SCHEMA_V1 = "sg-tightener.approved/v1"
APPROVED_SCHEMA_V2 = "sg-tightener.approved/v2"

# CloudWatch Logs Insights returns at most this many rows per query. A query
# that returns exactly this many has been cut off; see run_insights_query.
INSIGHTS_ROW_LIMIT = 10000


# --------------------------------------------------------------------------- #
# CIDR collapsing
# --------------------------------------------------------------------------- #

def _is_strict_rfc1918(net: ipaddress.IPv4Network) -> bool:
    return any(net.subnet_of(b) for b in RFC1918_BLOCKS)


def _normalise_ips(ips: Iterable[str]) -> list[ipaddress.IPv4Address]:
    out: list[ipaddress.IPv4Address] = []
    seen: set[ipaddress.IPv4Address] = set()
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip.strip())
        except (ValueError, AttributeError):
            continue
        if not isinstance(addr, ipaddress.IPv4Address):
            continue
        if addr not in seen:
            seen.add(addr)
            out.append(addr)
    return out


def _widest_block_for(
    addr: ipaddress.IPv4Address,
    observed: set[ipaddress.IPv4Address],
    tolerance: float,
) -> ipaddress.IPv4Network:
    """Widest containing CIDR where (block_size - observed_in_block)/block_size <= tolerance.

    Always returns at least the /32 host route, and never widens past the
    RFC 1918 block the address belongs to.
    """
    home_block = next((b for b in RFC1918_BLOCKS if addr in b), None)
    if home_block is None:
        return ipaddress.ip_network(f"{addr}/32")
    best = ipaddress.ip_network(f"{addr}/32")
    for prefix in range(31, home_block.prefixlen - 1, -1):
        candidate = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
        if not candidate.subnet_of(home_block):
            break
        size = candidate.num_addresses
        in_block = sum(1 for o in observed if o in candidate)
        gap = (size - in_block) / size
        if gap <= tolerance:
            best = candidate
        else:
            break
    return best


def _force_fit(
    nets: list[ipaddress.IPv4Network],
    max_rules: int,
) -> list[ipaddress.IPv4Network]:
    """Merge the closest pairs of CIDR blocks until count <= max_rules.

    Operates per-RFC-1918 home block — merges never cross a boundary
    (e.g. a 10/8 block is never merged with a 172.16/12 block).
    """
    if len(nets) <= max_rules:
        return nets

    def home(net: ipaddress.IPv4Network) -> int:
        for i, b in enumerate(RFC1918_BLOCKS):
            if net.subnet_of(b):
                return i
        return -1

    groups: dict[int, list[ipaddress.IPv4Network]] = {}
    for n in nets:
        groups.setdefault(home(n), []).append(n)

    while sum(len(g) for g in groups.values()) > max_rules:
        biggest_key = max(groups, key=lambda k: len(groups[k]))
        if len(groups[biggest_key]) <= 1:
            break
        items = sorted(groups[biggest_key], key=lambda n: int(n.network_address))
        best_pair: tuple[int, int] | None = None
        best_cost = None
        for i in range(len(items) - 1):
            a, b = items[i], items[i + 1]
            super_net = _smallest_covering(a, b)
            if super_net is None:
                continue
            cost = super_net.num_addresses - (a.num_addresses + b.num_addresses)
            if best_cost is None or cost < best_cost:
                best_cost = cost
                best_pair = (i, i + 1)
        if best_pair is None:
            break
        i, j = best_pair
        merged = _smallest_covering(items[i], items[j])
        new_items = items[:i] + [merged] + items[j + 1:]
        groups[biggest_key] = new_items

    return [n for g in groups.values() for n in g]


def _smallest_covering(
    a: ipaddress.IPv4Network,
    b: ipaddress.IPv4Network,
) -> ipaddress.IPv4Network | None:
    home = next((blk for blk in RFC1918_BLOCKS if a.subnet_of(blk) and b.subnet_of(blk)), None)
    if home is None:
        return None
    lo = min(int(a.network_address), int(b.network_address))
    hi = max(int(a.broadcast_address), int(b.broadcast_address))
    for prefix in range(32, home.prefixlen - 1, -1):
        size = 1 << (32 - prefix)
        base = (lo // size) * size
        if base + size - 1 >= hi:
            candidate = ipaddress.ip_network((base, prefix))
            if candidate.subnet_of(home):
                return candidate
    return home


def collapse_ips_to_cidrs(
    ips: Sequence[str],
    max_rules: int = DEFAULT_MAX_RULES,
    tolerance: float = DEFAULT_TOLERANCE,
) -> list[str]:
    """Collapse observed IPs into a CIDR list <= max_rules in size.

    Layer 1: widen each IP to the widest block respecting ``tolerance``.
    Layer 2: deduplicate, widen tolerance in 5% steps if still over budget.
    Layer 3: force-fit merge nearest pairs while respecting RFC 1918 home block.

    Returns sorted ``"a.b.c.d/p"`` strings.
    """
    addrs = _normalise_ips(ips)
    if not addrs:
        return []
    observed = set(addrs)

    def _collapse_at(t: float) -> list[ipaddress.IPv4Network]:
        blocks: set[ipaddress.IPv4Network] = set()
        for a in addrs:
            blocks.add(_widest_block_for(a, observed, t))
        # ipaddress.collapse_addresses merges contiguous & adjacent nets.
        return list(ipaddress.collapse_addresses(blocks))

    t = max(0.0, min(1.0, tolerance))
    nets = _collapse_at(t)
    while len(nets) > max_rules and t < 0.95:
        t = round(min(0.95, t + 0.05), 2)
        LOG.warning("widening tolerance to %.2f to fit %d rule budget", t, max_rules)
        nets = _collapse_at(t)

    if len(nets) > max_rules:
        LOG.warning(
            "tolerance widening exhausted; force-fitting %d blocks into %d rules — "
            "request a quota increase from AWS Support to keep precision",
            len(nets), max_rules,
        )
        nets = _force_fit(nets, max_rules)

    nets_sorted = sorted(nets, key=lambda n: (int(n.network_address), n.prefixlen))
    return [str(n) for n in nets_sorted]


# --------------------------------------------------------------------------- #
# Eligibility
# --------------------------------------------------------------------------- #

def rule_is_eligible(
    cidr: str | None,
    prefix_threshold: int = DEFAULT_PREFIX_THRESHOLD,
) -> bool:
    """A rule is in-scope iff it is a strict RFC 1918 subset and shorter
    than the configured prefix threshold. Anything else — including
    0.0.0.0/0, overlapping non-private ranges, security-group references,
    IPv6, and already-tight CIDRs — is left untouched."""
    if not cidr:
        return False
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    if not isinstance(net, ipaddress.IPv4Network):
        return False
    if not _is_strict_rfc1918(net):
        return False
    return net.prefixlen < prefix_threshold


# --------------------------------------------------------------------------- #
# Port range merging
# --------------------------------------------------------------------------- #

def merge_port_ranges(
    ranges: Iterable[tuple[int, int]],
) -> list[tuple[int, int]]:
    """Merge adjacent or overlapping (from, to) ranges into smallest spanning ranges."""
    items = sorted((min(a, b), max(a, b)) for a, b in ranges)
    if not items:
        return []
    merged: list[tuple[int, int]] = [items[0]]
    for lo, hi in items[1:]:
        last_lo, last_hi = merged[-1]
        if lo <= last_hi + 1:
            merged[-1] = (last_lo, max(last_hi, hi))
        else:
            merged.append((lo, hi))
    return merged


# --------------------------------------------------------------------------- #
# Plan signing
# --------------------------------------------------------------------------- #

def state_hash(payload: object) -> str:
    blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


# --------------------------------------------------------------------------- #
# AWS helpers (only used by analyse/plan/apply/revert main entry points)
# --------------------------------------------------------------------------- #

def _require_boto3() -> None:
    if boto3 is None:
        sys.stderr.write(
            "boto3 is required. Activate the venv created by ./install.sh\n"
        )
        sys.exit(2)


def _client(service: str, region: str | None = None):
    _require_boto3()
    cfg = BotoConfig(retries={"max_attempts": 10, "mode": "adaptive"})
    return boto3.client(service, region_name=region, config=cfg)


def _list_security_groups(region: str) -> list[dict]:
    ec2 = _client("ec2", region)
    out: list[dict] = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        out.extend(page.get("SecurityGroups", []))
    return out


# --------------------------------------------------------------------------- #
# Flow-log configuration preflight
# --------------------------------------------------------------------------- #
# VPC flow logs only record the TRUE origin of traffic that reaches an
# interface through an intermediate hop — a transit gateway attachment ENI,
# a NAT gateway ENI, an EKS pod behind a node ENI — in the version-3
# ``pkt-srcaddr`` field. The DEFAULT log format stops at version 2: for such
# flows its ``srcaddr`` contains the private IP of the INTERMEDIATE interface
# (the next hop), not the client. An approved list built from default-format
# logs in a transit-gateway estate therefore contains TGW/NAT infrastructure
# addresses and misses the real client CIDRs. These checks verify the flow
# logs feeding the analysis before any list is written.

DEFAULT_LOG_FORMAT_FIELDS = [
    "version", "account-id", "interface-id", "srcaddr", "dstaddr",
    "srcport", "dstport", "protocol", "packets", "bytes",
    "start", "end", "action", "log-status",
]

# Custom format we recommend when warning: original addresses, direction,
# and everything the default format already provided.
RECOMMENDED_LOG_FORMAT = (
    "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} "
    "${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} "
    "${action} ${log-status} ${pkt-srcaddr} ${pkt-dstaddr} ${flow-direction}"
)


def parse_log_format(log_format: str) -> list[str]:
    """Ordered field names from a flow-log format string (``${field} ...``)."""
    return re.findall(r"\$\{([a-z0-9-]+)\}", log_format or "")


@dataclasses.dataclass
class FlowLogCheck:
    fields: list[str]        # ordered fields the parsers should use
    warnings: list[str]
    errors: list[str]        # fatal: the analysis output would be garbage
    verified: bool           # True when a matching flow-log config was found


def check_flow_log_config(
    flow_logs: list[dict],
    accepted_only: bool = True,
    traffic: str | None = None,
) -> FlowLogCheck:
    """Evaluates the describe_flow_logs entries that feed the analysis
    destination and returns the parse field order plus warnings/errors.

    ``traffic`` is what the caller needs: "ACCEPT", "REJECT" or "ALL". It
    defaults from ``accepted_only``. For "ALL" (the viewer export) a flow log
    that captures only one side is a warning, not an error: half the picture
    is still worth showing, as long as the reader is told.
    """
    if traffic is None:
        traffic = "ACCEPT" if accepted_only else "REJECT"
    warnings: list[str] = []
    errors: list[str] = []

    if not flow_logs:
        return FlowLogCheck(
            fields=list(DEFAULT_LOG_FORMAT_FIELDS),
            warnings=[
                "no flow log delivering to this destination was found in this "
                "account/region, so the log format cannot be verified (the logs "
                "may be delivered from another account). Analysis will assume "
                "the DEFAULT format — if these logs use a custom format the "
                "parsed columns WILL be wrong. Note the default format has no "
                "pkt-srcaddr field: traffic arriving through a transit gateway "
                "or NAT gateway is recorded with the intermediate interface's "
                "IP (the next hop), not the true source."
            ],
            errors=[],
            verified=False,
        )

    for fl in flow_logs:
        flid = fl.get("FlowLogId", "?")
        status = fl.get("FlowLogStatus", "")
        if status != "ACTIVE":
            warnings.append(f"flow log {flid} status is {status or 'unknown'}, not ACTIVE — its data may be stale or absent")
        if fl.get("DeliverLogsErrorMessage"):
            warnings.append(f"flow log {flid} reports a delivery error: {fl['DeliverLogsErrorMessage']}")
        ttype = fl.get("TrafficType", "")
        if traffic == "ACCEPT" and ttype == "REJECT":
            errors.append(f"flow log {flid} captures REJECT traffic only — an accepted-traffic analysis would observe nothing")
        if traffic == "REJECT" and ttype == "ACCEPT":
            errors.append(f"flow log {flid} captures ACCEPT traffic only — a rejected-traffic analysis would observe nothing")
        if traffic == "ALL" and ttype in ("ACCEPT", "REJECT"):
            warnings.append(f"flow log {flid} captures {ttype} traffic only — the other side will be missing from the picture")

    formats = {fl.get("LogFormat") or "" for fl in flow_logs}
    if len(formats) > 1:
        errors.append(
            "the flow logs feeding this destination use DIFFERENT log formats; "
            "records in one destination cannot be parsed positionally when the "
            "column order varies per record. Align the formats or split the "
            "destinations."
        )
        return FlowLogCheck(list(DEFAULT_LOG_FORMAT_FIELDS), warnings, errors, verified=True)

    fields = parse_log_format(next(iter(formats)))
    if not fields:
        fields = list(DEFAULT_LOG_FORMAT_FIELDS)

    if "action" not in fields:
        errors.append("log format has no ${action} field — accepted traffic cannot be distinguished from rejected traffic")
    if "srcaddr" not in fields and "pkt-srcaddr" not in fields:
        errors.append("log format has neither ${srcaddr} nor ${pkt-srcaddr} — there is no source address to analyse")

    if "pkt-srcaddr" not in fields:
        warnings.append(
            "log format has no ${pkt-srcaddr} (v3) field. For traffic that "
            "reaches an interface through an intermediate hop — a transit "
            "gateway attachment ENI or a NAT gateway ENI — ${srcaddr} records "
            "the intermediate interface's private IP (the NEXT HOP), not the "
            "original client. Approved lists built from these logs can contain "
            "TGW/NAT infrastructure addresses and miss the real client CIDRs. "
            "Flow logs cannot be edited in place: create a replacement flow "
            f"log with a custom format such as: {RECOMMENDED_LOG_FORMAT}"
        )
    if "flow-direction" not in fields:
        warnings.append(
            "log format has no ${flow-direction} (v5) field — ingress and "
            "egress records cannot be separated, so the destinations of "
            "OUTBOUND connections also appear as observed sources and inflate "
            "the approved list."
        )

    return FlowLogCheck(fields, warnings, errors, verified=True)


def _describe_matching_flow_logs(region: str, log_group: str | None, s3_bucket: str | None):
    """Fetches flow-log configs that deliver to the analysis destination.
    Returns None when the API call itself fails (missing ec2:DescribeFlowLogs
    permission, endpoint issues) so the caller can degrade to a warning."""
    try:
        ec2 = _client("ec2", region)
        all_logs: list[dict] = []
        paginator = ec2.get_paginator("describe_flow_logs")
        for page in paginator.paginate():
            all_logs.extend(page.get("FlowLogs", []))
    except Exception as exc:  # noqa: BLE001 — any API failure degrades to "unverified"
        LOG.warning("could not verify flow-log configuration (ec2:DescribeFlowLogs failed: %s)", exc)
        return None

    matched = []
    for fl in all_logs:
        dest_type = fl.get("LogDestinationType", "cloud-watch-logs")
        if log_group and dest_type == "cloud-watch-logs" and fl.get("LogGroupName") == log_group:
            matched.append(fl)
        elif s3_bucket and dest_type == "s3":
            # LogDestination is arn:aws:s3:::bucket or arn:aws:s3:::bucket/prefix
            dest = fl.get("LogDestination", "")
            bucket = dest.split(":::", 1)[-1].split("/", 1)[0]
            if bucket == s3_bucket:
                matched.append(fl)
    return matched


# --------------------------------------------------------------------------- #
# Analyse
# --------------------------------------------------------------------------- #

@dataclasses.dataclass
class AnalyseConfig:
    region: str
    days: int
    log_group: str | None
    s3_bucket: str | None
    s3_prefix: str | None
    out_path: str
    accepted_only: bool = True
    # When set, the window is this many hours and ``days`` is ignored.
    hours: int | None = None
    traffic: str | None = None  # "ACCEPT" | "REJECT" | "ALL"; default from accepted_only

    def window(self, now: dt.datetime | None = None) -> tuple[dt.datetime, dt.datetime]:
        end = now or dt.datetime.now(dt.timezone.utc)
        span = dt.timedelta(hours=self.hours) if self.hours else dt.timedelta(days=self.days)
        return end - span, end


def build_cloudwatch_query(fields: list[str], accepted_only: bool = True) -> tuple[str, str]:
    """Builds the Logs Insights query for the given log format and returns
    (query, result_field_name).

    CloudWatch auto-discovers named fields (srcAddr, action, ...) ONLY for
    default-format VPC flow logs. Custom-format records must be split
    positionally out of @message, otherwise the query silently returns
    nothing — so the query is derived from the actual configured format."""
    wanted_action = "ACCEPT" if accepted_only else "REJECT"
    if fields == DEFAULT_LOG_FORMAT_FIELDS:
        query = (
            "fields srcAddr, action | "
            f"filter action = \"{wanted_action}\" | "
            "stats count() by srcAddr | "
            f"limit {INSIGHTS_ROW_LIMIT}"
        )
        return query, "srcAddr"

    idx = {f: i for i, f in enumerate(fields)}
    pattern = " ".join("*" for _ in fields)
    aliases = ", ".join(f"f{i}" for i in range(len(fields)))
    src = f"f{idx['pkt-srcaddr']}" if "pkt-srcaddr" in idx else f"f{idx['srcaddr']}"
    query = (
        f"fields @message | parse @message \"{pattern}\" as {aliases} | "
        f"filter f{idx['action']} = \"{wanted_action}\" | "
    )
    if "flow-direction" in idx:
        query += f"filter f{idx['flow-direction']} = \"ingress\" | "
    query += f"stats count() by {src} | limit {INSIGHTS_ROW_LIMIT}"
    return query, src


# Field names Logs Insights discovers on its own for DEFAULT-format flow logs.
_DISCOVERED_FIELD = {
    "version": "version", "account-id": "accountId", "interface-id": "interfaceId",
    "srcaddr": "srcAddr", "dstaddr": "dstAddr", "srcport": "srcPort",
    "dstport": "dstPort", "protocol": "protocol", "packets": "packets",
    "bytes": "bytes", "start": "start", "end": "end", "action": "action",
    "log-status": "logStatus",
}

# Logical record keys (as flow_records names them) -> flow-log fields, best first.
_LOGICAL_FIELDS = {
    "src": ("pkt-srcaddr", "srcaddr"),
    "dst": ("pkt-dstaddr", "dstaddr"),
    "srcport": ("srcport",),
    "dstport": ("dstport",),
    "protocol": ("protocol",),
    "action": ("action",),
    "packets": ("packets",),
    "bytes": ("bytes",),
    "interface": ("interface-id",),
}


def build_flow_stats_query(
    fields: list[str],
    *,
    by: Sequence[str],
    action: str | None = None,
    ingress_only: bool = True,
    bin_seconds: int | None = None,
) -> tuple[str, dict[str, str]]:
    """Logs Insights ``stats`` query over flow-log records, grouped by
    logical keys (``src``, ``dst``, ``dstport``, ``protocol``, ``action`` ...).

    Returns (query, columns) where ``columns`` maps each logical key, plus
    ``records``, ``packets``, ``bytes`` and ``bucket`` (when binned), to the
    name the result rows carry. Like build_cloudwatch_query, the query reads
    discovered field names for the default format and splits @message
    positionally for any custom one, and prefers pkt-srcaddr/pkt-dstaddr.
    """
    default = list(fields) == DEFAULT_LOG_FORMAT_FIELDS
    idx = {f: i for i, f in enumerate(fields)}

    def ref(logical: str) -> str:
        for name in _LOGICAL_FIELDS[logical]:
            if name in idx:
                return _DISCOVERED_FIELD[name] if default else f"f{idx[name]}"
        raise ValueError(f"flow-log format has no field for {logical!r}")

    if default:
        query = "fields @timestamp"
    else:
        pattern = " ".join("*" for _ in fields)
        aliases = ", ".join(f"f{i}" for i in range(len(fields)))
        query = f"fields @message | parse @message \"{pattern}\" as {aliases}"
    if action:
        query += f" | filter {ref('action')} = \"{action}\""
    if ingress_only and "flow-direction" in idx and not default:
        query += f" | filter f{idx['flow-direction']} = \"ingress\""

    columns = {key: ref(key) for key in by}
    group = [columns[key] for key in by]
    stats = ["count(*) as records"]
    columns["records"] = "records"
    for metric in ("packets", "bytes"):
        if any(n in idx for n in _LOGICAL_FIELDS[metric]):
            stats.append(f"sum({ref(metric)}) as {metric}_sum")
            columns[metric] = f"{metric}_sum"
    if bin_seconds:
        group.append(f"bin({int(bin_seconds)}s)")
        columns["bucket"] = f"bin({int(bin_seconds)}s)"
    query += f" | stats {', '.join(stats)} by {', '.join(group)} | limit {INSIGHTS_ROW_LIMIT}"
    return query, columns


def run_insights_query(
    logs,
    log_group: str,
    query: str,
    start: dt.datetime,
    end: dt.datetime,
    *,
    limit: int | None = None,
    min_window: dt.timedelta = dt.timedelta(minutes=1),
    poll_seconds: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict[str, str]]:
    """Run a Logs Insights query over [start, end] and return every row.

    Insights stops at ``limit`` rows without saying so. Returning that
    partial answer is how an approved list silently loses sources and the
    plan then revokes their access. So a result that reaches the limit is
    thrown away and the window is split in half, recursively, until every
    part fits. The caller merges the parts: every query used here is a
    ``stats ... by`` whose rows can be combined across windows.

    Raises RuntimeError when the query fails, or when a window of
    ``min_window`` still reaches the limit (refuse rather than truncate).
    Rows are returned as {field: value} dicts.
    """
    limit = INSIGHTS_ROW_LIMIT if limit is None else limit
    resp = logs.start_query(
        logGroupName=log_group,
        startTime=int(start.timestamp()),
        endTime=int(end.timestamp()),
        queryString=query,
    )
    qid = resp["queryId"]
    while True:
        result = logs.get_query_results(queryId=qid)
        status = result.get("status")
        if status in ("Complete", "Failed", "Cancelled", "Timeout"):
            break
        sleep(poll_seconds)
    if status != "Complete":
        raise RuntimeError(
            f"Logs Insights query on {log_group} ended with status {status} "
            f"for {start.isoformat()} to {end.isoformat()} — refusing to "
            "continue with a partial view"
        )
    rows = result.get("results", [])
    if len(rows) < limit:
        return [{c["field"]: c.get("value", "") for c in row} for row in rows]

    if end - start <= min_window:
        raise RuntimeError(
            f"Logs Insights returned {len(rows)} rows (its limit) even for the "
            f"{int((end - start).total_seconds())}s window starting "
            f"{start.isoformat()}; the answer would be truncated. Narrow the "
            "query (fewer interfaces, a smaller --days) rather than act on it."
        )
    mid = start + (end - start) / 2
    # Insights takes whole seconds; keep the halves from overlapping.
    mid = mid.replace(microsecond=0)
    LOG.info(
        "Logs Insights hit its %d-row limit for %s to %s; splitting the window",
        limit, start.isoformat(), end.isoformat(),
    )
    first = run_insights_query(logs, log_group, query, start, mid, limit=limit,
                               min_window=min_window, poll_seconds=poll_seconds, sleep=sleep)
    second = run_insights_query(logs, log_group, query, mid + dt.timedelta(seconds=1), end,
                                limit=limit, min_window=min_window,
                                poll_seconds=poll_seconds, sleep=sleep)
    return first + second


def _analyse_from_cloudwatch(cfg: AnalyseConfig, fields: list[str]) -> list[str]:
    logs = _client("logs", cfg.region)
    start, end = cfg.window()
    query, src_field = build_cloudwatch_query(fields, cfg.accepted_only)
    rows = run_insights_query(logs, cfg.log_group, query, start, end)
    # '-' is the flow-log placeholder for "not applicable" (e.g. pkt-srcaddr
    # on records where it could not be computed) — never a real source.
    return sorted({
        row[src_field]
        for row in rows
        if row.get(src_field) and row[src_field] != "-"
    })


# The logical keys a flow in approved.json carries: who (src) reached what
# (dst, dstport) over which protocol. src, dst and dstport are required for
# per-group planning; protocol is used when the format has it.
_FLOW_KEYS = ("src", "dst", "dstport", "protocol")


def flow_keys_for(fields: list[str]) -> tuple[str, ...] | None:
    """The flow keys ``fields`` can supply, or None when the format has no
    destination address or port (then only source IPs can be recorded and
    ``plan`` falls back to per-rule evidence)."""
    keys = tuple(k for k in _FLOW_KEYS if any(n in fields for n in _LOGICAL_FIELDS[k]))
    if not {"src", "dst", "dstport"} <= set(keys):
        return None
    return keys


def _flow_entry(src: str | None, dst: str | None, dstport, protocol: str | None) -> dict | None:
    """One approved.json flow, or None when there is no usable source.
    '-' (flow-log "not applicable") becomes None for dst and protocol."""
    if not src or src == "-":
        return None
    port = dstport if isinstance(dstport, int) or dstport is None else _int_or_none(dstport)
    return {
        "src": src,
        "dst": dst if dst and dst != "-" else None,
        "dstport": port,
        "protocol": protocol if protocol and protocol != "-" else None,
    }


def _sorted_flows(flows: Iterable[dict]) -> list[dict]:
    unique = {(f["src"], f["dst"], f["dstport"], f["protocol"]): f for f in flows}
    return [unique[k] for k in sorted(
        unique, key=lambda k: (k[0], k[1] or "", -1 if k[2] is None else k[2], k[3] or ""))]


def _analyse_flows_from_cloudwatch(cfg: AnalyseConfig, fields: list[str]) -> list[dict] | None:
    """Accepted ingress flows as (src, dst, dstport, protocol), or None when
    the log format records no destination (the caller falls back to IPs)."""
    keys = flow_keys_for(fields)
    if keys is None:
        return None
    logs = _client("logs", cfg.region)
    start, end = cfg.window()
    query, columns = build_flow_stats_query(
        fields, by=keys, action="ACCEPT" if cfg.accepted_only else "REJECT", ingress_only=True)
    rows = run_insights_query(logs, cfg.log_group, query, start, end)
    flows = []
    for row in rows:
        entry = _flow_entry(*(row.get(columns[k]) if k in columns else None for k in _FLOW_KEYS))
        if entry:
            flows.append(entry)
    return _sorted_flows(flows)


def _int_or_none(value: str | None) -> int | None:
    try:
        return int(value) if value not in (None, "-") else None
    except ValueError:
        return None


def flow_records(lines: Iterable[str], fields: list[str]) -> Iterator[dict]:
    """Parse space-separated flow-log records laid out per ``fields``.

    Yields one dict per record with: src, dst, srcport, dstport, protocol
    (IANA number as a string), action, packets, bytes, start, end,
    direction (None when the format has no flow-direction) and interface.

    ``src``/``dst`` prefer pkt-srcaddr/pkt-dstaddr (the ORIGINAL addresses)
    over srcaddr/dstaddr, which for traffic through a transit gateway or NAT
    gateway interface hold the intermediate hop's address. A "-" packet
    address falls back to the interface address. Header rows, short lines,
    and records with no action or no source (NODATA/SKIPDATA) are skipped.
    """
    idx = {f: i for i, f in enumerate(fields)}
    action_i = idx.get("action")
    if action_i is None or ("srcaddr" not in idx and "pkt-srcaddr" not in idx):
        return
    n = len(fields)

    def pick(parts: list[str], *names: str) -> str | None:
        for name in names:
            i = idx.get(name)
            if i is not None and parts[i] != "-":
                return parts[i]
        return None

    for line in lines:
        parts = line.split()
        if len(parts) < n:
            continue
        action = parts[action_i]
        # Also skips each file's header row: its 'action' column holds the
        # literal field name.
        if action not in ("ACCEPT", "REJECT"):
            continue
        src = pick(parts, "pkt-srcaddr", "srcaddr")
        if src is None:
            continue
        yield {
            "src": src,
            "dst": pick(parts, "pkt-dstaddr", "dstaddr"),
            "srcport": _int_or_none(pick(parts, "srcport")),
            "dstport": _int_or_none(pick(parts, "dstport")),
            "protocol": pick(parts, "protocol"),
            "action": action,
            "packets": _int_or_none(pick(parts, "packets")) or 0,
            "bytes": _int_or_none(pick(parts, "bytes")) or 0,
            "start": _int_or_none(pick(parts, "start")),
            "end": _int_or_none(pick(parts, "end")),
            "direction": pick(parts, "flow-direction"),
            "interface": pick(parts, "interface-id"),
        }


def ips_from_flow_log_lines(lines: Iterable[str], fields: list[str], accepted_only: bool = True) -> set[str]:
    """Extracts observed source addresses from space-separated flow-log
    records laid out per ``fields``. Prefers pkt-srcaddr (the ORIGINAL
    source) over srcaddr, which for traffic through a transit gateway or
    NAT gateway interface contains the intermediate hop's address."""
    wanted_action = "ACCEPT" if accepted_only else "REJECT"
    return {
        r["src"]
        for r in flow_records(lines, fields)
        if r["action"] == wanted_action and r["direction"] != "egress"
    }


def iter_s3_flow_log_lines(
    s3,
    bucket: str,
    prefix: str | None,
    start: dt.datetime,
    end: dt.datetime,
) -> Iterator[tuple[dict, list[str]]]:
    """Yield (object summary, lines) for every flow-log object in the window.

    Objects are selected by LastModified. ``.gz`` objects are decompressed.
    An object that cannot be read is logged and skipped; if more than 10% of
    the objects in the window fail, RuntimeError is raised after the last
    one, so nobody acts on a partial view.
    """
    prefix = (prefix or "").rstrip("/")
    total = 0
    failed = 0
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            if obj["LastModified"] < start or obj["LastModified"] > end:
                continue
            total += 1
            try:
                body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
                if obj["Key"].endswith(".gz"):
                    body = gzip.decompress(body)
                lines = body.decode("utf-8", errors="ignore").splitlines()
            except Exception as exc:  # noqa: BLE001 — broad on purpose, see docstring
                failed += 1
                LOG.warning("failed to read s3://%s/%s: %s", bucket, obj["Key"], exc)
                continue
            yield obj, lines
    if total and failed / total > 0.10:
        raise RuntimeError(
            f"S3 flow-log read failure ratio {failed}/{total} exceeds 10% — refusing "
            "to act on a partial view. Check IAM and bucket policies."
        )


def _analyse_from_s3(cfg: AnalyseConfig, fields: list[str]) -> list[str]:
    if not cfg.s3_bucket:
        return []
    s3 = _client("s3", cfg.region)
    start, end = cfg.window()
    ips: set[str] = set()
    for _obj, lines in iter_s3_flow_log_lines(s3, cfg.s3_bucket, cfg.s3_prefix, start, end):
        ips |= ips_from_flow_log_lines(lines, fields, cfg.accepted_only)
    return sorted(ips)


def _analyse_flows_from_s3(cfg: AnalyseConfig, fields: list[str]) -> list[dict] | None:
    """S3 counterpart of _analyse_flows_from_cloudwatch."""
    if flow_keys_for(fields) is None:
        return None
    if not cfg.s3_bucket:
        return []
    s3 = _client("s3", cfg.region)
    start, end = cfg.window()
    wanted_action = "ACCEPT" if cfg.accepted_only else "REJECT"
    flows = []
    for _obj, lines in iter_s3_flow_log_lines(s3, cfg.s3_bucket, cfg.s3_prefix, start, end):
        for r in flow_records(lines, fields):
            if r["action"] != wanted_action or r["direction"] == "egress":
                continue
            entry = _flow_entry(r["src"], r["dst"], r["dstport"], r["protocol"])
            if entry:
                flows.append(entry)
    return _sorted_flows(flows)


def preflight_flow_logs(cfg: AnalyseConfig) -> FlowLogCheck:
    """Verify the flow logs feeding cfg's destination and return the check.

    Logs every warning, and raises RuntimeError on a configuration that
    cannot answer the question (REJECT-only capture, no action or source
    field, mixed formats). Shared by ``analyse`` and ``sg_diagnose`` so both
    parse records with the configured log format rather than assuming one.
    """
    matched = _describe_matching_flow_logs(cfg.region, cfg.log_group, cfg.s3_bucket)
    if matched is None:
        check = FlowLogCheck(
            fields=list(DEFAULT_LOG_FORMAT_FIELDS),
            warnings=[
                "flow-log configuration could not be verified (add "
                "ec2:DescribeFlowLogs to the analysis role to enable this "
                "check) — assuming the DEFAULT log format. If these logs use "
                "a custom format the parsed columns WILL be wrong, and the "
                "default format records only the next-hop address (not the "
                "true source) for traffic through a transit gateway or NAT "
                "gateway."
            ],
            errors=[],
            verified=False,
        )
    else:
        check = check_flow_log_config(matched, cfg.accepted_only, traffic=cfg.traffic)

    for warning in check.warnings:
        LOG.warning("flow-log config: %s", warning)
    if check.errors:
        for error in check.errors:
            LOG.error("flow-log config: %s", error)
        raise RuntimeError(
            "flow-log configuration cannot support this analysis: "
            + "; ".join(check.errors)
        )
    return check


def run_analyse(cfg: AnalyseConfig) -> dict:
    if not cfg.log_group and not cfg.s3_bucket:
        raise ValueError("either --log-group or --s3-bucket is required")

    # Preflight: verify the flow logs feeding this destination can actually
    # answer "who talks to these instances" before writing any approved list.
    check = preflight_flow_logs(cfg)

    # Record which destination (address and port) each source reached, so
    # plan can give each group only the sources that reached its interfaces.
    if cfg.log_group:
        flows = _analyse_flows_from_cloudwatch(cfg, check.fields)
    else:
        flows = _analyse_flows_from_s3(cfg, check.fields)
    if flows is None:
        LOG.warning(
            "log format has no destination address or port, so approved.json "
            "will hold source IPs only and plan will grant every observed source "
            "inside a rule to every group carrying that rule (per rule, not per "
            "group). Add ${dstaddr} and ${dstport} (or ${pkt-dstaddr}) to the "
            "flow-log format for per-group plans."
        )
        if cfg.log_group:
            ips = _analyse_from_cloudwatch(cfg, check.fields)
        else:
            ips = _analyse_from_s3(cfg, check.fields)
    else:
        ips = sorted({f["src"] for f in flows})

    if not ips:
        raise RuntimeError(
            "no source IPs observed — refusing to write an empty approved list. "
            "Verify that flow logs are enabled and the analysis window contains traffic."
        )

    payload = {
        "schema": APPROVED_SCHEMA_V2 if flows is not None else APPROVED_SCHEMA_V1,
        "region": cfg.region,
        "days": cfg.days,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": "cloudwatch" if cfg.log_group else "s3",
        "flow_log_check": {
            "verified": check.verified,
            "fields": check.fields,
            "warnings": check.warnings,
        },
        "ips": sorted(set(ips)),
    }
    if flows is not None:
        payload["flows"] = flows
    with open(cfg.out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    LOG.info("wrote %d observed IPs (%d flows) to %s", len(payload["ips"]),
             len(payload.get("flows", [])), cfg.out_path)
    return payload


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #

def _eligible_rules(sg: dict, prefix_threshold: int) -> list[dict]:
    out = []
    for perm in sg.get("IpPermissions", []):
        proto = perm.get("IpProtocol")
        from_p = perm.get("FromPort")
        to_p = perm.get("ToPort")
        for ip in perm.get("IpRanges", []):
            if rule_is_eligible(ip.get("CidrIp"), prefix_threshold):
                out.append({
                    "cidr": ip["CidrIp"],
                    "protocol": proto,
                    "from_port": from_p,
                    "to_port": to_p,
                    "description": ip.get("Description"),
                })
    return out


def _all_rule_count(sg: dict) -> int:
    n = 0
    for perm in sg.get("IpPermissions", []):
        n += len(perm.get("IpRanges", []))
        n += len(perm.get("Ipv6Ranges", []))
        n += len(perm.get("UserIdGroupPairs", []))
        n += len(perm.get("PrefixListIds", []))
    return n


def _allocate_budget(needs: list[int], budget: int) -> list[int]:
    """Split ``budget`` rule slots across units that each need ``needs[i]``.

    Every unit with evidence gets at least one slot. When the total need fits,
    each unit gets what it needs; otherwise the slots above the first are
    shared in proportion to each unit's extra need (largest remainder).
    """
    alloc = [1 if n > 0 else 0 for n in needs]
    spare = budget - sum(alloc)
    if spare <= 0:
        return alloc
    extra = [max(0, n - a) for n, a in zip(needs, alloc)]
    total_extra = sum(extra)
    if total_extra <= spare:
        return [a + e for a, e in zip(alloc, extra)]
    shares = [e * spare / total_extra for e in extra]
    floors = [int(x) for x in shares]
    leftover = spare - sum(floors)
    order = sorted(range(len(needs)), key=lambda i: shares[i] - floors[i], reverse=True)
    for i in order[:leftover]:
        floors[i] += 1
    return [a + f for a, f in zip(alloc, floors)]


def _replacements_within(
    original: ipaddress.IPv4Network,
    ips: list[str],
    max_rules: int,
    tolerance: float,
) -> list[ipaddress.IPv4Network]:
    """Collapse ``ips`` (all inside ``original``) without ever leaving it.

    collapse_ips_to_cidrs may widen up to the RFC 1918 home block; any block
    that grew past the original rule is clipped back to the original, so a
    replacement can only ever narrow a rule.
    """
    nets = [ipaddress.ip_network(c) for c in collapse_ips_to_cidrs(
        ips, max_rules=max_rules, tolerance=tolerance)]
    clipped = [original if not n.subnet_of(original) else n for n in nets]
    return list(ipaddress.collapse_addresses(clipped))


# Security-group protocol names -> the IANA numbers flow logs record.
_PROTOCOL_NUMBERS = {"tcp": "6", "udp": "17", "icmp": "1", "icmpv6": "58"}


def flow_matches_rule(flow: dict, protocol, from_port, to_port) -> bool:
    """Whether a rule (protocol, port range) would have admitted ``flow``.

    Protocol "-1" admits everything. Otherwise the flow's protocol must be
    the rule's, and for TCP and UDP its destination port must be inside the
    rule's range (for ICMP the rule's "ports" are type and code, which flow
    logs do not record, so only the protocol is compared). A flow with no
    protocol or no port recorded (an old or hand-edited approved.json) is
    not ruled out on that count.
    """
    proto = str(protocol).lower()
    if proto == "-1":
        return True
    wanted = _PROTOCOL_NUMBERS.get(proto, proto)
    if flow.get("protocol") is not None and str(flow["protocol"]) != wanted:
        return False
    port = flow.get("dstport")
    if wanted in ("6", "17") and port is not None and from_port is not None and to_port is not None:
        return int(from_port) <= int(port) <= int(to_port)
    return True


def interface_groups_by_ip(
    interfaces: list[dict],
) -> tuple[dict[str, set[str]], list[tuple[ipaddress.IPv4Network, set[str]]]]:
    """Map each interface's private IPv4 addresses to the groups it carries.

    ``interfaces`` is DescribeNetworkInterfaces output. Returns
    ({ip: {group ids}}, [(delegated /28 prefix, {group ids})]), the second
    for interfaces using prefix delegation (EKS prefix mode), whose pod
    addresses never appear in PrivateIpAddresses.
    """
    by_ip: dict[str, set[str]] = {}
    prefixes: list[tuple[ipaddress.IPv4Network, set[str]]] = []
    for eni in interfaces:
        gids = {g["GroupId"] for g in eni.get("Groups", []) if g.get("GroupId")}
        if not gids:
            continue
        ips = {eni.get("PrivateIpAddress")}
        ips |= {pa.get("PrivateIpAddress") for pa in eni.get("PrivateIpAddresses", [])}
        for ip in ips - {None}:
            by_ip.setdefault(ip, set()).update(gids)
        for pfx in eni.get("Ipv4Prefixes", []):
            try:
                prefixes.append((ipaddress.ip_network(pfx["Ipv4Prefix"]), gids))
            except (KeyError, ValueError):
                continue
    return by_ip, prefixes


def _groups_for_destination(dst: str | None, by_ip, prefixes) -> set[str] | None:
    """Group ids on the interface that owns ``dst``, or None if no known
    interface does."""
    if not dst:
        return None
    if dst in by_ip:
        return by_ip[dst]
    try:
        addr = ipaddress.ip_address(dst)
    except ValueError:
        return None
    found = set()
    for net, gids in prefixes:
        if addr in net:
            found |= gids
    return found or None


def _attribute_flows(
    approved_ips: list[str],
    flows: list[dict] | None,
    interfaces: list[dict] | None,
) -> tuple[dict[str, list[dict]], list[dict], dict]:
    """Split the evidence into flows per group and flows for every group.

    Returns (by_group, everywhere, report). A flow whose destination is an
    interface we know goes to that interface's groups only. Everything else
    goes to ``everywhere`` and is treated as before per-group evidence
    existed, i.e. it counts for every group whose rule admits it:

    * no ``flows`` at all (an approved/v1 file): every source;
    * a flow whose destination matches no interface in the region (the
      interface was deleted or replaced, as Fargate tasks and autoscaled
      instances are, or the address is in another account);
    * an address in ``ips`` that no flow mentions (added by hand or by
      sg_diagnose).

    Unattributed evidence keeps access rather than cutting it: without it,
    a service whose interfaces were replaced during the window would lose
    every source that only reached the old ones. ``report`` lists it.
    """
    if flows is None:
        return {}, [{"src": ip} for ip in approved_ips], {"attribution": "per-rule"}

    by_ip, prefixes = interface_groups_by_ip(interfaces or [])
    by_group: dict[str, list[dict]] = {}
    everywhere: list[dict] = []
    unknown_dst: set[str] = set()
    for f in flows:
        gids = _groups_for_destination(f.get("dst"), by_ip, prefixes)
        if gids is None:
            everywhere.append(f)
            unknown_dst.add(f.get("dst") or "-")
            continue
        for gid in gids:
            by_group.setdefault(gid, []).append(f)

    in_flows = {f["src"] for f in flows}
    extra = sorted(set(approved_ips) - in_flows)
    everywhere.extend({"src": ip} for ip in extra)
    report = {
        "attribution": "per-group",
        "unattributed_destinations": sorted(unknown_dst),
        "sources_without_flows": extra,
    }
    return by_group, everywhere, report


def build_plan(
    sgs: list[dict],
    approved_ips: list[str],
    *,
    flows: list[dict] | None = None,
    interfaces: list[dict] | None = None,
    max_rules: int = DEFAULT_MAX_RULES,
    tolerance: float = DEFAULT_TOLERANCE,
    prefix_threshold: int = DEFAULT_PREFIX_THRESHOLD,
    region: str | None = None,
) -> dict:
    """Plan replacements for every eligible rule, scoped to that rule.

    Each eligible rule is rebuilt only from the observed RFC 1918 addresses
    that fall inside its own CIDR, and the result never extends past that
    CIDR. A replacement can therefore narrow a rule but never grant a
    source the rule did not already allow, and public addresses in the
    approved list can never reach a private rule. A rule with no observed
    traffic is revoked with no replacement and listed under
    ``removed_without_evidence`` so the reviewer sees it.

    With ``flows`` (approved/v2) and ``interfaces`` (DescribeNetworkInterfaces
    output), a group's rule is rebuilt only from sources that reached an
    interface carrying that group, on a protocol and port the rule admits;
    see _attribute_flows for evidence that cannot be tied to an interface.
    Without ``flows`` every source inside a rule counts for every group
    carrying it (per rule, not per group).
    """
    by_group, everywhere, attribution = _attribute_flows(
        [str(a) for a in _normalise_ips(approved_ips)], flows, interfaces)

    private_cache: dict[str, ipaddress.IPv4Address | None] = {}

    def _private(ip: str) -> ipaddress.IPv4Address | None:
        if ip not in private_cache:
            addrs = _normalise_ips([ip])
            private_cache[ip] = addrs[0] if addrs and any(addrs[0] in b for b in RFC1918_BLOCKS) else None
        return private_cache[ip]

    plan_groups = []
    for sg in sgs:
        eligible = _eligible_rules(sg, prefix_threshold)
        if not eligible:
            continue
        revokes_per_proto_port: dict[tuple, list[dict]] = {}
        for r in eligible:
            key = (r["protocol"], r["from_port"], r["to_port"])
            revokes_per_proto_port.setdefault(key, []).append(r)

        # Per-group budget = max_rules - (rules NOT being touched).
        existing_total = _all_rule_count(sg)
        untouched = existing_total - len(eligible)
        budget = max(1, max_rules - untouched)

        # One unit per eligible rule: the observed private sources inside it
        # that reached this group (or cannot be tied to any interface) on a
        # protocol and port the rule admits.
        evidence = by_group.get(sg["GroupId"], []) + everywhere
        units = []
        for key, rules in revokes_per_proto_port.items():
            matching = [f for f in evidence if flow_matches_rule(f, *key)]
            for r in rules:
                net = ipaddress.ip_network(r["cidr"], strict=False)
                inside = sorted({a for a in (_private(f["src"]) for f in matching)
                                 if a is not None and a in net})
                units.append((key, net, [str(a) for a in inside]))

        needs = [
            len(_replacements_within(net, ips, max_rules=10**9, tolerance=tolerance))
            if ips else 0
            for _key, net, ips in units
        ]
        allocation = _allocate_budget(needs, budget)

        authorised_by_key: dict[tuple, list[ipaddress.IPv4Network]] = {}
        removed: list[dict] = []
        for (key, net, ips), slots in zip(units, allocation):
            if not ips:
                removed.append({
                    "cidr": str(net),
                    "protocol": key[0],
                    "from_port": key[1],
                    "to_port": key[2],
                })
                continue
            authorised_by_key.setdefault(key, []).extend(
                _replacements_within(net, ips, max_rules=slots, tolerance=tolerance)
            )

        authorise_perms: list[dict] = []
        for (proto, from_p, to_p), nets in authorised_by_key.items():
            merged = sorted(
                ipaddress.collapse_addresses(nets),
                key=lambda n: (int(n.network_address), n.prefixlen),
            )
            authorise_perms.append({
                "IpProtocol": proto,
                "FromPort": from_p,
                "ToPort": to_p,
                "IpRanges": [
                    {"CidrIp": str(c), "Description": "sg-tightener evidence-based"}
                    for c in merged
                ],
            })

        if removed:
            LOG.warning(
                "%s: %d eligible rule(s) saw no traffic and will be revoked with "
                "no replacement — check removed_without_evidence in the plan",
                sg["GroupId"], len(removed),
            )

        # If multiple eligible rules share a CIDR set but differ on ports,
        # the operator can ask to merge. We surface that here.
        port_merge_flagged = False
        port_ranges_by_proto: dict[str, list[tuple[int, int]]] = {}
        for k in revokes_per_proto_port:
            proto, fp, tp = k
            if fp is None or tp is None:
                continue
            port_ranges_by_proto.setdefault(str(proto), []).append((int(fp), int(tp)))
        for proto, ranges in port_ranges_by_proto.items():
            merged_ranges = merge_port_ranges(ranges)
            if len(merged_ranges) < len(ranges):
                port_merge_flagged = True

        revoke_perms = []
        restore_perms = []
        for (proto, from_p, to_p), rules in revokes_per_proto_port.items():
            revoke_perms.append({
                "IpProtocol": proto,
                "FromPort": from_p,
                "ToPort": to_p,
                "IpRanges": [{"CidrIp": r["cidr"]} for r in rules],
            })
            # What revert puts back: the same rules with their descriptions,
            # so a round trip leaves the group exactly as it was.
            restore_perms.append({
                "IpProtocol": proto,
                "FromPort": from_p,
                "ToPort": to_p,
                "IpRanges": [
                    {"CidrIp": r["cidr"], **({"Description": r["description"]} if r.get("description") else {})}
                    for r in rules
                ],
            })

        plan_groups.append({
            "group_id": sg["GroupId"],
            "group_name": sg.get("GroupName"),
            "vpc_id": sg.get("VpcId"),
            "revoke": revoke_perms,
            "restore": restore_perms,
            "authorise": authorise_perms,
            "removed_without_evidence": removed,
            "port_merge_flagged": port_merge_flagged,
            "budget": budget,
            "current_rule_count": existing_total,
        })

    snapshot = [{
        "group_id": sg["GroupId"],
        "rules": sg.get("IpPermissions", []),
    } for sg in sgs]

    plan = {
        "schema": "sg-tightener.plan/v1",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "region": region,
        "max_rules": max_rules,
        "tolerance": tolerance,
        "prefix_threshold": prefix_threshold,
        "groups": plan_groups,
        "snapshot_hash": state_hash(snapshot),
        **attribution,
    }
    return plan


def _list_network_interfaces(region: str) -> list[dict]:
    ec2 = _client("ec2", region)
    out: list[dict] = []
    for page in ec2.get_paginator("describe_network_interfaces").paginate():
        out.extend(page.get("NetworkInterfaces", []))
    return out


def plan_from_approved(approved: dict, region: str, **kw) -> dict:
    """Build a plan from a loaded approved.json against ``region``'s groups.

    An approved/v2 file (with ``flows``) is planned per group, which also
    reads the region's network interfaces. A v1 file has no destinations and
    is planned per rule, with a warning.
    """
    sgs = _list_security_groups(region)
    flows = approved.get("flows")
    if flows is None:
        LOG.warning(
            "approved.json has no destination data (%s): every observed source "
            "inside a rule is granted to every group carrying that rule (per "
            "rule, not per group). Re-run analyse with this version for a "
            "per-group plan.", approved.get("schema", "no schema"),
        )
        return build_plan(sgs, approved["ips"], region=region, **kw)
    plan = build_plan(sgs, approved["ips"], flows=flows,
                      interfaces=_list_network_interfaces(region), region=region, **kw)
    if plan["unattributed_destinations"]:
        LOG.warning(
            "%d destination(s) in approved.json match no network interface in "
            "%s; sources that reached only them are kept on every group whose "
            "rule admits them (per rule). See unattributed_destinations in the plan.",
            len(plan["unattributed_destinations"]), region,
        )
    if plan["sources_without_flows"]:
        LOG.warning(
            "%d address(es) in approved.json ips have no flow (added by hand or by "
            "sg_diagnose); they are kept on every group whose rule admits them.",
            len(plan["sources_without_flows"]),
        )
    return plan


# --------------------------------------------------------------------------- #
# Apply / revert
# --------------------------------------------------------------------------- #

def _current_snapshot_hash(region: str) -> str:
    sgs = _list_security_groups(region)
    snapshot = [{"group_id": sg["GroupId"], "rules": sg.get("IpPermissions", [])} for sg in sgs]
    return state_hash(snapshot)


def resolve_apply_region(plan: dict, cli_region: str | None, env: dict | None = None) -> str:
    """The region a plan is applied in.

    A plan records the region it was built from, and that is the only region
    whose snapshot hash it can match, so it wins. ``--region`` that disagrees
    is refused rather than silently ignored. Plans written before the region
    was recorded fall back to ``--region``, then AWS_REGION /
    AWS_DEFAULT_REGION.
    """
    env = os.environ if env is None else env
    planned = plan.get("region")
    if planned:
        if cli_region and cli_region != planned:
            raise SystemExit(
                f"plan was built in {planned} but --region is {cli_region}; "
                "a plan only applies in the region it was built from"
            )
        return planned
    region = cli_region or env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION")
    if not region:
        raise SystemExit(
            "this plan does not record its region (it predates that field); "
            "pass --region or re-run plan"
        )
    LOG.warning("plan does not record its region; applying in %s", region)
    return region


def _write_json(path: str, payload: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def apply_plan(plan: dict, region: str, *, manifest_path: str) -> None:
    """Apply ``plan`` group by group, recording each call that succeeded.

    The manifest is rewritten after every successful AWS call, so it always
    describes exactly what was changed: if a revoke fails nothing is
    recorded for that group, and if the authorise after a successful revoke
    fails only the revoke is. ``revert`` then undoes that and nothing more,
    even if the process is killed part way.
    """
    current = _current_snapshot_hash(region)
    if current != plan["snapshot_hash"]:
        raise RuntimeError(
            "plan is stale — security group state changed since it was generated. "
            "Re-run plan and review again."
        )

    ec2 = _client("ec2", region)
    manifest = {
        "schema": "sg-tightener.manifest/v1",
        "applied_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "region": region,
        "complete": False,
        "groups": [],
    }
    aws_errors: tuple = (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError)
    for grp in plan["groups"]:
        gid = grp["group_id"]
        manifest_grp: dict = {"group_id": gid, "revoked": [], "authorised": []}
        try:
            if grp["revoke"]:
                ec2.revoke_security_group_ingress(GroupId=gid, IpPermissions=grp["revoke"])
                # Record the rules as they were, descriptions included.
                manifest_grp["revoked"] = grp.get("restore") or grp["revoke"]
                if manifest_grp not in manifest["groups"]:
                    manifest["groups"].append(manifest_grp)
                _write_json(manifest_path, manifest)
            if grp["authorise"]:
                ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=grp["authorise"])
                manifest_grp["authorised"] = grp["authorise"]
                if manifest_grp not in manifest["groups"]:
                    manifest["groups"].append(manifest_grp)
                _write_json(manifest_path, manifest)
        except aws_errors as exc:
            _write_json(manifest_path, manifest)
            raise SystemExit(
                f"apply HALTED on {gid}: {exc}\n"
                f"Partial manifest written to {manifest_path}\n"
                f"Revert: sg_tightener.py revert --manifest {manifest_path}"
            )

    manifest["complete"] = True
    _write_json(manifest_path, manifest)
    LOG.info("apply complete; manifest written to %s", manifest_path)


def revert_from_manifest(manifest_path: str) -> None:
    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    ec2 = _client("ec2", manifest["region"])
    aws_errors = (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError)
    failures = 0
    for grp in reversed(manifest["groups"]):
        gid = grp["group_id"]
        if grp.get("authorised"):
            try:
                ec2.revoke_security_group_ingress(GroupId=gid, IpPermissions=grp["authorised"])
            except aws_errors as exc:
                failures += 1
                LOG.warning("revert: could not revoke the tightened rules on %s: %s", gid, exc)
        if grp.get("revoked"):
            try:
                ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=grp["revoked"])
            except aws_errors as exc:
                failures += 1
                LOG.warning("revert: could not re-authorise original rules on %s: %s", gid, exc)
    if failures:
        raise SystemExit(f"revert finished with {failures} failed call(s); see the warnings above")
    LOG.info("revert complete")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sg_tightener.py", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="mode", required=True)

    a = sub.add_parser("analyse", help="read flow logs and write approved IP list")
    a.add_argument("--region", required=True)
    a.add_argument("--days", type=int, default=DEFAULT_DAYS)
    a.add_argument("--log-group", help="CloudWatch Logs group containing VPC flow logs")
    a.add_argument("--s3-bucket", help="S3 bucket containing VPC flow logs")
    a.add_argument("--s3-prefix", help="S3 prefix under --s3-bucket")
    a.add_argument("--out", default="approved.json")

    pl = sub.add_parser("plan", help="emit a plan.json")
    pl.add_argument("--region", required=True)
    pl.add_argument("--approved", required=True)
    pl.add_argument("--max-rules", type=int, default=DEFAULT_MAX_RULES)
    pl.add_argument("--tolerance", type=float, default=DEFAULT_TOLERANCE)
    pl.add_argument("--prefix-threshold", type=int, default=DEFAULT_PREFIX_THRESHOLD)
    pl.add_argument("--out", default="plan.json")

    ap = sub.add_parser("apply", help="execute a plan")
    ap.add_argument("--plan", required=True)
    ap.add_argument("--region", help="only for plans that predate the recorded region; must match it otherwise")
    ap.add_argument("--yes", action="store_true")

    rv = sub.add_parser("revert", help="restore pre-apply state from a manifest")
    rv.add_argument("--manifest", required=True)
    rv.add_argument("--yes", action="store_true")

    return p


def _confirm(action: str) -> None:
    answer = input(f"Type 'yes' to {action}: ").strip().lower()
    if answer != "yes":
        sys.exit("aborted")


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = _build_parser().parse_args(argv)

    if args.mode == "analyse":
        cfg = AnalyseConfig(
            region=args.region,
            days=args.days,
            log_group=args.log_group,
            s3_bucket=args.s3_bucket,
            s3_prefix=args.s3_prefix,
            out_path=args.out,
        )
        run_analyse(cfg)
        return 0

    if args.mode == "plan":
        with open(args.approved, "r", encoding="utf-8") as fh:
            approved = json.load(fh)
        plan = plan_from_approved(
            approved,
            args.region,
            max_rules=args.max_rules,
            tolerance=args.tolerance,
            prefix_threshold=args.prefix_threshold,
        )
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(plan, fh, indent=2)
        LOG.info(
            "wrote plan covering %d groups to %s",
            len(plan["groups"]), args.out,
        )
        return 0

    if args.mode == "apply":
        with open(args.plan, "r", encoding="utf-8") as fh:
            plan = json.load(fh)
        region = resolve_apply_region(plan, args.region)
        if not args.yes:
            _confirm(f"apply this plan in {region}")
        ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        manifest_path = f"manifest-{ts}.json"
        apply_plan(plan, region, manifest_path=manifest_path)
        return 0

    if args.mode == "revert":
        if not args.yes:
            _confirm("revert from manifest")
        revert_from_manifest(args.manifest)
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
