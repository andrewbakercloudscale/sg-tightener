#!/usr/bin/env python3
"""sg_extend.py — flow-log-driven break-glass ingress extender.

Break-glass tool for live incidents. Reads VPC flow logs over a recent
window (default: the last 24 hours), finds the source IPs whose traffic was
REJECTED, and adds ingress rules to the operator-named security groups so
that the blocked traffic is unblocked immediately — without waiting for the
standard analyse/plan/apply loop.

Design guarantees:
  * Strictly additive. It only ever calls AuthorizeSecurityGroupIngress and
    never revokes anything. The worst-case outcome of a wrong invocation is
    a broader permission set, never an outage.
  * Rule-budget aware. The discovered source IPs are grouped into the
    smallest CIDR blocks allowed by ``--tolerance`` — the fraction of unused
    (never-observed) addresses tolerated inside a grouping block. A tolerance
    of 0.5 lets a CIDR be used to cover a set of IPs even when half of that
    block's addresses were never seen. Grouping is done per protocol/port, so
    a rule only ever opens the port that was actually rejected. Raise the
    tolerance to fit more sources into fewer rules under the per-group limit.
  * Private by default. Only RFC 1918 source IPs are added; internet REJECT
    noise is ignored unless ``--include-public`` is given.

Every invocation writes a timestamped manifest recording exactly what was
added so the next tightening cycle can fold the changes back into the
evidence base. Part of the CloudToRepo project: https://cloudtorepo.com

Usage:
  sg_extend.py --region us-east-1
               --groups sg-aaaa,sg-bbbb
               (--log-group <name> | --s3-bucket <b> [--s3-prefix <p>])
               [--hours 24]
               [--tolerance 0.5]         # fraction of unused IPs allowed per CIDR
               [--ports 443,5432]        # restrict to these dst ports/ranges
               [--include-public]        # also add non-RFC1918 sources
               [--description "DR failover 2026-05-28"]
               [--max-rules 60]
               [--yes]
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Sequence

try:
    import boto3
    import botocore
except ImportError:
    boto3 = None
    botocore = None

from sg_tightener import (
    add_profile_arg,
    caller_arn,
    friendly_login_errors,
    sign,
    use_profile,
    DEFAULT_LOG_FORMAT_FIELDS,
    DEFAULT_TOLERANCE,
    RFC1918_BLOCKS,
    AnalyseConfig,
    _client,
    build_flow_stats_query,
    collapse_ips_to_cidrs,
    flow_records,
    InterfaceIndex,
    describe_groups,
    iter_s3_flow_log_lines,
    preflight_flow_logs,
    run_insights_query,
)

LOG = logging.getLogger("sg_extend")

GROUP_ID_RE = re.compile(r"^sg-[0-9a-f]{8,17}$")
PORT_SPEC_RE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")

# VPC flow logs record the IANA protocol number. We only build ingress
# rules for the port-bearing protocols that account for essentially all
# application traffic; anything else (ICMP, ESP, ...) is skipped with a
# warning because a port-scoped break-glass rule would be meaningless.
PROTO_NUM_TO_NAME = {"6": "tcp", "17": "udp"}

# AWS publishes its public IP ranges as a single JSON file refreshed
# weekly-ish. When --include-public is on we use this to summarise any
# observed public source IP into the AWS service's published prefix
# (e.g. a Lambda Hyperplane ENI's egress IP collapses into the EC2
# range for that region) rather than enumerating /32 host routes that
# will break the moment AWS rotates the IP.
AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
AWS_IP_RANGES_CACHE = os.path.join(
    os.path.expanduser("~"), ".cache", "sg-tightener", "aws-ip-ranges.json"
)
AWS_IP_RANGES_TTL_SECONDS = 7 * 24 * 3600  # 7 days — AWS refreshes weekly

# Services we never want to collapse into. AMAZON is the catch-all
# parent class covering essentially everything AWS — using it as a
# trust source defeats the point of evidence-based tightening.
AWS_SERVICE_BLOCKLIST = {"AMAZON"}


# --------------------------------------------------------------------------- #
# AWS IP ranges
# --------------------------------------------------------------------------- #

def load_aws_ip_ranges(
    *,
    cache_path: str | None = None,
    ttl_seconds: int | None = None,
    fetch: bool = True,
) -> list[dict]:
    """Return the parsed list of AWS IPv4 prefix entries.

    Uses a local cache (``~/.cache/sg-tightener/aws-ip-ranges.json``) that
    is refreshed once per ``ttl_seconds`` (default 7 days). Passing
    ``fetch=False`` skips the network call entirely — useful for tests
    and air-gapped environments where the cache is pre-seeded.

    The returned list is the raw ``prefixes`` array from ip-ranges.json;
    each entry has ``ip_prefix``, ``region``, ``service``, and
    ``network_border_group`` keys.
    """
    path = cache_path or AWS_IP_RANGES_CACHE
    ttl = AWS_IP_RANGES_TTL_SECONDS if ttl_seconds is None else ttl_seconds

    stale = True
    if os.path.exists(path):
        age = time.time() - os.path.getmtime(path)
        stale = age > ttl

    if stale and fetch:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with urllib.request.urlopen(AWS_IP_RANGES_URL, timeout=15) as resp:
                body = resp.read()
            with open(path, "wb") as fh:
                fh.write(body)
        except (urllib.error.URLError, OSError) as exc:
            LOG.warning("failed to refresh AWS IP ranges: %s — falling back to cache", exc)
            if not os.path.exists(path):
                return []

    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        LOG.warning("failed to read AWS IP ranges cache: %s", exc)
        return []
    return data.get("prefixes", [])


def classify_aws_service(
    ip: str, ranges: list[dict]
) -> tuple[str, str, str] | None:
    """Return (service, region, ip_prefix) for the most specific non-AMAZON
    prefix containing ``ip``, or None if no match.

    Falls back to the AMAZON entry only if no service-specific entry
    matches — and even then, AMAZON is rejected because it's too broad
    to be useful as a trust source. This means an IP that exists only
    under AMAZON returns None and is treated as a regular public IP.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None
    if not isinstance(addr, ipaddress.IPv4Address):
        return None

    best: tuple[int, dict] | None = None
    for entry in ranges:
        prefix = entry.get("ip_prefix")
        service = entry.get("service")
        if not prefix or not service or service in AWS_SERVICE_BLOCKLIST:
            continue
        try:
            net = ipaddress.ip_network(prefix)
        except ValueError:
            continue
        if addr not in net:
            continue
        if best is None or net.prefixlen > best[0]:
            best = (net.prefixlen, entry)

    if not best:
        return None
    entry = best[1]
    return entry["service"], entry.get("region", ""), entry["ip_prefix"]


def split_aws_service_flows(
    flows: set[tuple[str, str, int]],
    ranges: list[dict],
) -> tuple[set[tuple[str, str, int]], dict[tuple[str, str, int], tuple[str, str]]]:
    """Partition flows into (regular_flows, aws_service_summaries).

    Regular flows retain their original ``(src, proto, port)`` shape and
    are passed through the standard ``filter_flows`` / ``build_perms``
    pipeline. AWS-service summaries collapse every observed source IP
    that falls inside a published AWS service prefix into a single
    ``(service_prefix_cidr, service_label, proto, port)`` summary entry
    so a Lambda Hyperplane ENI cluster becomes one rule, not 50.
    """
    regular: set[tuple[str, str, int]] = set()
    summaries: dict[tuple[str, str, int], tuple[str, str]] = {}
    for src, proto, port in flows:
        cls = classify_aws_service(src, ranges)
        if cls is None:
            regular.add((src, proto, port))
            continue
        service, region, ip_prefix = cls
        # Key the summary by the prefix CIDR so multiple observed IPs
        # collapse into one entry per (service prefix, proto, port).
        summary_key = (ip_prefix, proto, port)
        summaries[summary_key] = (service, region)
    return regular, summaries


def build_aws_service_perms(
    summaries: dict[tuple[str, str, int], tuple[str, str]],
    description_prefix: str,
) -> list[dict]:
    """Render AWS-service summaries as IpPermissions.

    One permission entry per (proto, port); within it, one IpRange per
    distinct AWS service prefix observed. The description carries the
    AWS service / region label so the rule's origin is visible at audit
    time without cross-referencing a manifest.
    """
    by_pp: dict[tuple[str, int], list[tuple[str, str, str]]] = {}
    for (prefix, proto, port), (service, region) in summaries.items():
        by_pp.setdefault((proto, port), []).append((prefix, service, region))
    perms: list[dict] = []
    for (proto, port), entries in sorted(by_pp.items()):
        # Dedupe identical prefix entries while preserving stable order.
        seen: set[str] = set()
        ip_ranges: list[dict] = []
        for prefix, service, region in sorted(entries):
            if prefix in seen:
                continue
            seen.add(prefix)
            label = f"{description_prefix} ({service} {region})".strip()
            ip_ranges.append({"CidrIp": prefix, "Description": label})
        perms.append({
            "IpProtocol": proto,
            "FromPort": port,
            "ToPort": port,
            "IpRanges": ip_ranges,
        })
    return perms


# --------------------------------------------------------------------------- #
# Input validation (kept stable — imported by the regression suite)
# --------------------------------------------------------------------------- #

def parse_cidr(value: str) -> str:
    """Validate a CIDR. Must include a prefix length. Returns canonical form."""
    if "/" not in value:
        raise ValueError(f"CIDR must include prefix length: {value!r}")
    net = ipaddress.ip_network(value.strip(), strict=False)
    return str(net)


def parse_port_spec(value: str) -> tuple[int, int]:
    """Parse '443' or '8000-8100' into (from_port, to_port). Raises on garbage."""
    m = PORT_SPEC_RE.match(value.strip())
    if not m:
        raise ValueError(f"invalid port spec: {value!r}")
    lo = int(m.group(1))
    hi = int(m.group(2)) if m.group(2) else lo
    if not (0 <= lo <= 65535 and 0 <= hi <= 65535):
        raise ValueError(f"port out of range: {value!r}")
    if hi < lo:
        raise ValueError(f"port range hi < lo: {value!r}")
    return lo, hi


def parse_group_id(value: str) -> str:
    if not GROUP_ID_RE.match(value.strip()):
        raise ValueError(f"not a security-group id: {value!r}")
    return value.strip()


# --------------------------------------------------------------------------- #
# Pure flow-shaping helpers (testable without AWS)
# --------------------------------------------------------------------------- #

def proto_name(num: str | None) -> str | None:
    """Map an IANA protocol number (as a string) to an EC2 IpProtocol.

    Returns None for protocols we do not build port-scoped rules for.
    """
    if num is None:
        return None
    return PROTO_NUM_TO_NAME.get(str(num).strip())


def _port_allowed(port: int, specs: list[tuple[int, int]] | None) -> bool:
    if specs is None:
        return True
    return any(lo <= port <= hi for lo, hi in specs)


def filter_flows(
    flows: set[tuple[str, str, int]],
    *,
    include_public: bool,
    port_specs: list[tuple[int, int]] | None,
) -> set[tuple[str, str, int]]:
    """Keep only valid IPv4 flows that pass the privacy and port filters."""
    out: set[tuple[str, str, int]] = set()
    for src, proto, port in flows:
        try:
            addr = ipaddress.ip_address(src)
        except ValueError:
            continue
        if not isinstance(addr, ipaddress.IPv4Address):
            continue
        if not include_public and not any(addr in b for b in RFC1918_BLOCKS):
            continue  # ignore internet REJECT noise unless asked
        if not _port_allowed(port, port_specs):
            continue
        out.add((src, proto, port))
    return out


def build_perms(
    flows: set[tuple[str, str, int]],
    description: str,
    *,
    tolerance: float,
    max_rules: int,
) -> list[dict]:
    """Collapse flows into IpPermissions, grouping source IPs into CIDRs.

    Sources are grouped per (protocol, port) and collapsed with
    ``collapse_ips_to_cidrs`` so a CIDR block may be used whenever the
    fraction of never-observed addresses inside it is <= ``tolerance``.
    """
    by_pp: dict[tuple[str, int], list[str]] = {}
    for src, proto, port in flows:
        by_pp.setdefault((proto, port), []).append(src)
    perms: list[dict] = []
    for (proto, port), ips in sorted(by_pp.items()):
        cidrs = collapse_ips_to_cidrs(ips, max_rules=max_rules, tolerance=tolerance)
        perms.append({
            "IpProtocol": proto,
            "FromPort": port,
            "ToPort": port,
            "IpRanges": [
                {"CidrIp": c, "Description": description} for c in cidrs
            ],
        })
    return perms


def perm_rule_count(perms: list[dict]) -> int:
    return sum(len(p.get("IpRanges", [])) for p in perms)


def _rule_count(sg: dict) -> int:
    n = 0
    for perm in sg.get("IpPermissions", []):
        n += len(perm.get("IpRanges", []))
        n += len(perm.get("Ipv6Ranges", []))
        n += len(perm.get("UserIdGroupPairs", []))
        n += len(perm.get("PrefixListIds", []))
    return n


def _existing_nets_for(
    sg: dict, proto: str, port: int
) -> list[ipaddress.IPv4Network]:
    """IPv4 networks already permitted on this group for proto/port.

    A rule with protocol "-1" (all) or a port range spanning ``port`` counts.
    """
    nets: list[ipaddress.IPv4Network] = []
    for perm in sg.get("IpPermissions", []):
        if perm.get("IpProtocol") not in (proto, "-1"):
            continue
        fp, tp = perm.get("FromPort"), perm.get("ToPort")
        if fp is not None and tp is not None and not (fp <= port <= tp):
            continue
        for ip in perm.get("IpRanges", []):
            try:
                nets.append(ipaddress.ip_network(ip["CidrIp"], strict=False))
            except (KeyError, ValueError):
                continue
    return nets


def partition_flows_by_group(
    flows: set[tuple[str, str, int]],
    dst_map: dict[tuple[str, str, int], set[str]],
    dst_to_groups: dict[str, set[str]],
) -> dict[str, set[tuple[str, str, int]]]:
    """Split flows by which security group's ENIs received them.

    Returns ``dict[group_id, set[flow_tuple]]``. A flow is attributed to
    every SG attached to every destination ENI that observed it — AWS
    evaluates ingress permissively across attached SGs, so we record
    every candidate and let the rule-budget logic decide which actually
    gets the rule.
    """
    out: dict[str, set[tuple[str, str, int]]] = {}
    for flow in flows:
        dsts = dst_map.get(flow, set())
        seen_groups: set[str] = set()
        for d in dsts:
            seen_groups.update(dst_to_groups.get(d, set()))
        for gid in seen_groups:
            out.setdefault(gid, set()).add(flow)
    return out


def filter_existing(perms: list[dict], sg: dict) -> list[dict]:
    """Drop candidate CIDRs already covered by an existing rule on the same
    protocol/port, so the budget is honest and we avoid duplicate errors."""
    out: list[dict] = []
    for perm in perms:
        existing = _existing_nets_for(sg, perm["IpProtocol"], perm["FromPort"])
        keep = []
        for ip in perm.get("IpRanges", []):
            try:
                cand = ipaddress.ip_network(ip["CidrIp"], strict=False)
            except ValueError:
                continue
            if any(cand.subnet_of(e) for e in existing):
                continue  # already permitted
            keep.append(ip)
        if keep:
            out.append({**perm, "IpRanges": keep})
    return out


# --------------------------------------------------------------------------- #
# ENI / SG discovery (AWS)
# --------------------------------------------------------------------------- #

def resolve_destination_groups(
    interfaces: list[dict],
    destinations: Sequence[tuple[str, str | None]],
) -> dict[tuple[str, str | None], set[str]]:
    """Map each (destination IP, logging interface id) to the SG ids on the
    interface that received it (see sg_tightener.InterfaceIndex).

    AWS evaluates ingress permissively across every SG attached to an ENI,
    so all attached SGs are candidates for the rule. A record logged by the
    sending side is ignored; an address several VPCs use, with no interface
    id to tell them apart, is refused rather than opened in every VPC.
    Destinations that resolve to nothing (another account, deleted
    interfaces) are left out.
    """
    index = InterfaceIndex(interfaces)
    out: dict[tuple[str, str | None], set[str]] = {}
    for dst, iface in set(destinations):
        eni, status = index.resolve(dst, iface)
        if status == "ambiguous":
            vpcs = {o.get("VpcId") for o in index.owners(dst)}
            LOG.warning("%s belongs to interfaces in %d VPCs and the flow log records no "
                        "interface-id; skipped rather than opened in all of them (pass "
                        "--groups, or add ${interface-id} to the log format)", dst, len(vpcs))
            continue
        gids = index.groups(eni)
        if gids:
            out[(dst, iface)] = gids
    return out


def _list_interfaces(ec2_client) -> list[dict]:
    out: list[dict] = []
    for page in ec2_client.get_paginator("describe_network_interfaces").paginate():
        out.extend(page.get("NetworkInterfaces", []))
    return out


# --------------------------------------------------------------------------- #
# Flow-log readers (AWS)
# --------------------------------------------------------------------------- #

def _add_flow(flows, dst_map, src, dst, proto_num, dstport, iface=None) -> None:
    proto = proto_name(proto_num)
    if proto is None or not src or src == "-":
        return
    try:
        port = int(dstport)
    except (TypeError, ValueError):
        return
    key = (src.strip(), proto, port)
    flows.add(key)
    if dst and dst != "-":
        dst_map.setdefault(key, set()).add(
            (dst.strip(), iface.strip() if iface and iface != "-" else None))


def read_rejected_flows_cloudwatch(
    region: str, log_group: str, hours: int,
    fields: list[str] | None = None,
) -> tuple[set[tuple[str, str, int]], dict[tuple[str, str, int], set[str]]]:
    """Query CloudWatch Logs Insights for REJECTed flows in the window.

    Returns ``(flows, dst_map)`` — the standard 3-tuple flow set used by
    every downstream pure helper, plus a mapping from each flow tuple to
    the (destination IP, logging interface id or None) pairs that observed it. The destination
    information is what makes ENI-based group discovery possible.

    ``fields`` is the configured log format (from preflight_flow_logs); the
    query follows it, so custom formats and pkt-srcaddr are honoured. A
    result that reaches the Insights row limit is split by time rather than
    truncated (run_insights_query).
    """
    fields = list(fields or DEFAULT_LOG_FORMAT_FIELDS)
    logs = _client("logs", region)
    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(hours=hours)
    by = ("src", "dst", "dstport", "protocol") + (("interface",) if "interface-id" in fields else ())
    query, cols = build_flow_stats_query(fields, by=by, action="REJECT")
    rows = run_insights_query(logs, log_group, query, start, end)

    flows: set[tuple[str, str, int]] = set()
    dst_map: dict[tuple[str, str, int], set[str]] = {}
    for row in rows:
        _add_flow(flows, dst_map, row.get(cols["src"], ""), row.get(cols["dst"]),
                  row.get(cols["protocol"]), row.get(cols["dstport"]),
                  row.get(cols["interface"]) if "interface" in cols else None)
    return flows, dst_map


def read_rejected_flows_s3(
    region: str, bucket: str, prefix: str | None, hours: int,
    fields: list[str] | None = None,
) -> tuple[set[tuple[str, str, int]], dict[tuple[str, str, int], set[str]]]:
    """Parse VPC flow-log objects in S3 for REJECTed ingress flows.

    Returns ``(flows, dst_map)`` matching the CloudWatch reader; see that
    function's docstring for the contract. Records are parsed with the
    configured log format (``fields``), not assumed to be the default one.
    """
    fields = list(fields or DEFAULT_LOG_FORMAT_FIELDS)
    s3 = _client("s3", region)
    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(hours=hours)
    flows: set[tuple[str, str, int]] = set()
    dst_map: dict[tuple[str, str, int], set[str]] = {}
    for _obj, lines in iter_s3_flow_log_lines(s3, bucket, prefix, start, end):
        for rec in flow_records(lines, fields):
            if rec["action"] != "REJECT" or rec["direction"] == "egress":
                continue
            _add_flow(flows, dst_map, rec["src"], rec["dst"], rec["protocol"], rec["dstport"],
                      rec["interface"])
    return flows, dst_map


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _merge_perms(*lists: list[dict]) -> list[dict]:
    """Combine per-source permission lists, grouping by (proto, FromPort, ToPort)."""
    bucket: dict[tuple, list[dict]] = {}
    for lst in lists:
        for perm in lst:
            key = (perm["IpProtocol"], perm["FromPort"], perm["ToPort"])
            bucket.setdefault(key, []).extend(perm.get("IpRanges", []))
    merged: list[dict] = []
    for (proto, fp, tp), ranges in sorted(bucket.items(), key=lambda kv: (kv[0][0], kv[0][1] or 0)):
        seen: set[str] = set()
        deduped: list[dict] = []
        for r in ranges:
            cidr = r.get("CidrIp")
            if not cidr or cidr in seen:
                continue
            seen.add(cidr)
            deduped.append(r)
        if deduped:
            merged.append({
                "IpProtocol": proto, "FromPort": fp, "ToPort": tp,
                "IpRanges": deduped,
            })
    return merged


def _apply_to_group(
    ec2_client, gid: str, sg: dict | None, perms: list[dict],
    *, max_rules: int,
) -> dict:
    """Authorise ``perms`` on ``gid`` with budget + already-present checks.

    Returns a manifest entry describing the outcome — no exceptions
    propagate; the caller decides how to react.
    """
    if sg is None:
        return {"group_id": gid, "status": "NOT_FOUND"}
    perms = filter_existing(perms, sg)
    if not perms:
        return {"group_id": gid, "status": "ALREADY_PRESENT"}
    would_add = perm_rule_count(perms)
    existing = _rule_count(sg)
    if existing + would_add > max_rules:
        return {
            "group_id": gid, "status": "SKIPPED_BUDGET",
            "existing_rules": existing, "would_add": would_add,
            "max_rules": max_rules,
        }
    aws_errors = (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError)
    try:
        ec2_client.authorize_security_group_ingress(GroupId=gid, IpPermissions=perms)
        return {
            "group_id": gid, "status": "ADDED",
            "added_rules": would_add, "rules": perms,
        }
    except aws_errors as exc:
        err = str(exc)
        if "InvalidPermission.Duplicate" not in err:
            return {"group_id": gid, "status": "ERROR", "error": err}
    # The call is all or nothing: one duplicate means NOTHING was added.
    # Add the rules one by one and skip only the ones that already exist.
    added: list[dict] = []
    duplicates: list[dict] = []
    for perm in perms:
        for r in perm.get("IpRanges", []):
            one = {**perm, "IpRanges": [r]}
            try:
                ec2_client.authorize_security_group_ingress(GroupId=gid, IpPermissions=[one])
                added.append(one)
            except aws_errors as exc:
                if "InvalidPermission.Duplicate" in str(exc):
                    duplicates.append(one)
                    continue
                return {"group_id": gid, "status": "ERROR", "error": str(exc),
                        "added_rules": len(added), "rules": added}
    return {"group_id": gid, "status": "ADDED" if added else "ALREADY_PRESENT",
            "added_rules": len(added), "rules": added, "already_present": duplicates}


@friendly_login_errors
def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    p = argparse.ArgumentParser(prog="sg_extend.py")
    p.add_argument("--region", required=True)
    p.add_argument("--groups", help="comma-separated SG ids to add to (omit to "
                                    "auto-discover from REJECT destination ENIs)")
    p.add_argument("--log-group", help="CloudWatch Logs group containing VPC flow logs")
    p.add_argument("--s3-bucket", help="S3 bucket containing VPC flow logs")
    p.add_argument("--s3-prefix", help="S3 prefix under --s3-bucket")
    p.add_argument("--hours", type=int, default=24, help="flow-log window (default 24)")
    p.add_argument("--tolerance", type=float, default=DEFAULT_TOLERANCE,
                   help="fraction (0.0-1.0) of unused IPs allowed inside a "
                        "grouping CIDR; higher packs more sources into fewer "
                        f"rules (default {DEFAULT_TOLERANCE})")
    p.add_argument("--ports", help="restrict to these dst ports/ranges, e.g. 443,5432")
    p.add_argument("--include-public", action="store_true",
                   help="also add non-RFC1918 (public) source IPs")
    p.add_argument("--no-aws-summarise", action="store_true",
                   help="when --include-public is on, treat AWS-service "
                        "source IPs as individual /32s instead of summarising "
                        "into the AWS published service prefix")
    p.add_argument("--max-groups", type=int, default=20,
                   help="auto-discover mode: refuse to act on more than this "
                        "many groups in one run (default 20)")
    p.add_argument("--description", default="sg-extend break-glass")
    p.add_argument("--max-rules", type=int, default=60)
    p.add_argument("--yes", action="store_true", help="bypass the 'extend' prompt")
    add_profile_arg(p)
    args = p.parse_args(argv)
    use_profile(args.profile)

    if not args.log_group and not args.s3_bucket:
        p.error("either --log-group or --s3-bucket is required")
    if args.hours < 1:
        p.error("--hours must be >= 1")
    if not 0.0 <= args.tolerance <= 1.0:
        p.error("--tolerance must be between 0.0 and 1.0")

    try:
        explicit_groups = (
            [parse_group_id(g) for g in args.groups.split(",") if g.strip()]
            if args.groups else []
        )
        port_specs = (
            [parse_port_spec(x) for x in args.ports.split(",") if x.strip()]
            if args.ports else None
        )
    except ValueError as exc:
        sys.exit(f"input error: {exc}")

    # --- discover rejected traffic --------------------------------------- #
    # Verify the flow logs first and parse with their real format: a custom
    # format read as the default one puts the wrong columns in every rule.
    try:
        check = preflight_flow_logs(AnalyseConfig(
            region=args.region, days=1, hours=args.hours,
            log_group=args.log_group, s3_bucket=args.s3_bucket,
            s3_prefix=args.s3_prefix, out_path="", accepted_only=False,
        ))
    except RuntimeError as exc:
        sys.exit(str(exc))
    if args.log_group:
        flows, dst_map = read_rejected_flows_cloudwatch(
            args.region, args.log_group, args.hours, check.fields
        )
    else:
        flows, dst_map = read_rejected_flows_s3(
            args.region, args.s3_bucket, args.s3_prefix, args.hours, check.fields
        )
    flows = filter_flows(
        flows, include_public=args.include_public, port_specs=port_specs
    )

    scope = "" if args.include_public else "private "
    if not flows:
        LOG.info(
            "no rejected %ssources found in the last %dh — nothing to do",
            scope, args.hours,
        )
        return 0

    # --- AWS service summarisation -------------------------------------- #
    aws_summaries: dict[tuple[str, str, int], tuple[str, str]] = {}
    # Which original (src, proto, port) flows each summary stands for, so a
    # summary only goes to the groups those flows actually reached.
    aws_origins: dict[tuple[str, str, int], set[tuple[str, str, int]]] = {}
    if args.include_public and not args.no_aws_summarise:
        ranges = load_aws_ip_ranges()
        if ranges:
            regular_flows, aws_summaries = split_aws_service_flows(flows, ranges)
            for flow in flows - regular_flows:
                cls = classify_aws_service(flow[0], ranges)
                if cls:
                    aws_origins.setdefault((cls[2], flow[1], flow[2]), set()).add(flow)
            if aws_summaries:
                LOG.info(
                    "summarised %d public source IP(s) into %d AWS service prefix(es)",
                    len(flows) - len(regular_flows), len(aws_summaries),
                )
            flows = regular_flows
        else:
            LOG.warning(
                "no AWS IP ranges available (network or cache miss) — "
                "public IPs will be added as individual /32 rules",
            )

    LOG.warning(
        "found %d rejected %sflow(s) over the last %dh:",
        len(flows) + len(aws_summaries), scope, args.hours,
    )
    for src, proto, port in sorted(flows):
        print(f"  {src}/32  {proto}/{port}")
    for (prefix, proto, port), (service, region) in sorted(aws_summaries.items()):
        print(f"  {prefix:<18}  {proto}/{port}  (AWS {service} {region})")

    # --- group discovery ------------------------------------------------ #
    ec2 = _client("ec2", args.region)
    auto_mode = not explicit_groups
    all_flows = flows | {f for origs in aws_origins.values() for f in origs}

    if auto_mode:
        destinations = {d for flow in all_flows for d in dst_map.get(flow, set())}
        LOG.info("resolving %d destination(s) to their interfaces", len(destinations))
        dst_to_groups = resolve_destination_groups(_list_interfaces(ec2), list(destinations))
        discovered_groups = {gid for gids in dst_to_groups.values() for gid in gids}
        if not discovered_groups:
            sys.exit(
                "could not derive any security groups from REJECT destinations — "
                "specify --groups explicitly, or verify the destination ENIs still "
                "exist in this region."
            )
        if len(discovered_groups) > args.max_groups:
            sys.exit(
                f"refusing to act: discovered {len(discovered_groups)} groups, "
                f"exceeds --max-groups {args.max_groups}. Tighten --ports / "
                f"--hours or pass --groups explicitly."
            )
        groups = sorted(discovered_groups)
        LOG.warning("auto-discovered %d destination security group(s): %s",
                    len(groups), ", ".join(groups))
        # Every group only gets rules for the flows whose destinations sat
        # on that group's interfaces, AWS-service summaries included.
        reached = partition_flows_by_group(all_flows, dst_map, dst_to_groups)
        flows_per_group = {gid: fl & flows for gid, fl in reached.items()}
        aws_per_group = {
            gid: {k: v for k, v in aws_summaries.items() if aws_origins.get(k, set()) & fl}
            for gid, fl in reached.items()
        }
    else:
        groups = explicit_groups
        flows_per_group = {gid: flows for gid in groups}
        aws_per_group = {gid: aws_summaries for gid in groups}

    # Look the groups up before asking, so a typo or a group in another
    # account is reported now, not after the operator has said yes.
    sg_by_id = describe_groups(ec2, groups)
    missing = [g for g in groups if g not in sg_by_id]
    if missing:
        LOG.warning("not found in %s (typo, deleted, or owned by another account): %s",
                    args.region, ", ".join(missing))
        if not set(groups) - set(missing):
            sys.exit("none of the security groups exist — nothing to do")

    if not args.yes:
        try:
            answer = input(
                "Type 'extend' to add these to the security groups: "
            ).strip().lower()
        except EOFError:
            answer = ""
        if answer != "extend":
            sys.exit("aborted")

    manifest = {
        "schema": "sg-extend.manifest/v1",
        "applied_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "region": args.region,
        "description": args.description,
        "source": "cloudwatch" if args.log_group else "s3",
        "window_hours": args.hours,
        "tolerance": args.tolerance,
        "include_public": args.include_public,
        "aws_summarise": args.include_public and not args.no_aws_summarise,
        "mode": "auto" if auto_mode else "explicit",
        "discovered_flows": [
            {"cidr": f"{s}/32", "protocol": pr, "port": po}
            for s, pr, po in sorted(flows)
        ],
        "aws_service_summaries": [
            {"cidr": prefix, "protocol": proto, "port": port,
             "service": service, "region": region}
            for (prefix, proto, port), (service, region) in sorted(aws_summaries.items())
        ],
        "complete": False,
        "groups": [],
    }
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    manifest_path = f"sg_extend-manifest-{ts}.json"

    by = caller_arn()

    def write_manifest() -> None:
        sign(manifest, by)
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)

    for gid in groups:
        sg = sg_by_id.get(gid)
        group_flows = flows_per_group.get(gid, set())

        regular_perms = build_perms(
            group_flows, args.description,
            tolerance=args.tolerance, max_rules=args.max_rules,
        ) if group_flows else []
        aws_perms = build_aws_service_perms(aws_per_group.get(gid, {}), args.description)
        merged_perms = _merge_perms(regular_perms, aws_perms)
        if not merged_perms:
            manifest["groups"].append({
                "group_id": gid, "status": "NO_FLOWS_FOR_GROUP",
            })
            LOG.info("%s has no attributable flows in this run", gid)
            continue

        result = _apply_to_group(
            ec2, gid, sg, merged_perms, max_rules=args.max_rules,
        )
        manifest["groups"].append(result)
        # Written after every group: the manifest is the record of what was
        # opened, and must survive a crash part way through.
        write_manifest()
        status = result["status"]
        if status == "ADDED":
            LOG.info("added %d rule(s) to %s%s", result["added_rules"], gid,
                     f" ({len(result['already_present'])} already present)"
                     if result.get("already_present") else "")
        elif status == "SKIPPED_BUDGET":
            LOG.warning(
                "%s skipped: %d existing + %d new > %d max — raise --tolerance to "
                "pack into fewer rules, run sg_compact to reclaim budget, or raise "
                "the SG quota",
                gid, result["existing_rules"], result["would_add"], args.max_rules,
            )
        elif status == "ALREADY_PRESENT":
            LOG.info("%s already covers every discovered source — nothing to add", gid)
        elif status == "NOT_FOUND":
            LOG.warning("%s not found — skipped", gid)
        elif status == "ERROR":
            LOG.error("authorize failed on %s: %s", gid, result.get("error", ""))

    manifest["complete"] = True
    write_manifest()
    LOG.info("manifest written to %s", manifest_path)
    errors = [g["group_id"] for g in manifest["groups"] if g["status"] == "ERROR"]
    return 1 if errors else 0

if __name__ == "__main__":
    sys.exit(main())
