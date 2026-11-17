#!/usr/bin/env python3
"""sg_viz.py — see what is connected to what, what is blocked, and when.

Read-only. Builds one JSON file describing a region's traffic over a time
window (who talked to which interface, on which port, accepted or
rejected, per time bucket), the interfaces and security groups involved,
and which rule allowed each connection. A local web viewer draws it as a
timeline, a connection map and a table. Load a plan.json on top and every
observed connection the plan would cut off is highlighted before anyone
runs ``apply``.

Modes:
  export   Read flow logs (CloudWatch Logs or S3), network interfaces and
           security groups and write viz-data.json. Only Describe*, Logs
           Insights and S3 Get/List calls are made.
  overlay  Add a plan's impact to an existing viz-data.json.
  serve    Run the viewer on http://127.0.0.1 (loopback only). It opens
           exported files, the built-in sample, or runs an export with
           your local AWS credentials. Nothing is sent anywhere else.

Usage:
  sg_viz.py export  --region <r> [--days 7 | --hours 24] [--bucket 3600]
                    (--log-group <name> | --s3-bucket <b> [--s3-prefix <p>])
                    [--plan plan.json] [--out viz-data.json]
  sg_viz.py overlay --data viz-data.json --plan plan.json [--out <file>]
  sg_viz.py serve   [--port 8765] [--data viz-data.json] [--open]
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import logging
import sys
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterable, Sequence

import sg_tightener
from sg_tightener import (
    AnalyseConfig,
    build_flow_stats_query,
    flow_records,
    iter_s3_flow_log_lines,
    preflight_flow_logs,
    run_insights_query,
)

LOG = logging.getLogger("sg_viz")

SCHEMA = "sg-tightener.viz/v1"
VIEWER_DIR = Path(__file__).resolve().parent / "viewer"
PROTO_NAMES = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}
PROTO_NUMBERS = {v: k for k, v in PROTO_NAMES.items()}
MAX_BODY = 64 * 1024 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "[::1]"}
DEFAULT_PORT = 8765


# --------------------------------------------------------------------------- #
# Time buckets
# --------------------------------------------------------------------------- #

def default_bucket_seconds(start: dt.datetime, end: dt.datetime) -> int:
    """Hourly up to a week, six-hourly up to a month, daily beyond."""
    span = end - start
    if span <= dt.timedelta(days=7):
        return 3600
    if span <= dt.timedelta(days=31):
        return 6 * 3600
    return 86400


def _bucket_of(ts: int, bucket_seconds: int) -> int:
    return ts // bucket_seconds * bucket_seconds


def _iso(ts: int | float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_insights_time(value: str) -> int:
    """'2026-11-16 09:00:00.000' (Insights, UTC) -> epoch seconds."""
    value = value.strip().replace("T", " ").rstrip("Z")
    parsed = dt.datetime.strptime(value[:19], "%Y-%m-%d %H:%M:%S")
    return int(parsed.replace(tzinfo=dt.timezone.utc).timestamp())


def _int(value) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


# --------------------------------------------------------------------------- #
# Flow aggregation
# --------------------------------------------------------------------------- #

def aggregate_records(
    records: Iterable[dict],
    bucket_seconds: int,
    *,
    default_ts: int | None = None,
) -> list[dict]:
    """Sum flow_records() output by (src, dst, port, proto, action, bucket).

    Egress records are dropped when the format says which they are. A
    record without a ``start`` time is placed at ``default_ts`` (the S3
    object's delivery time) or skipped when there is none.
    """
    acc: dict[tuple, dict] = {}
    for r in records:
        if r.get("direction") == "egress":
            continue
        ts = r.get("start") or default_ts
        if ts is None or not r.get("dst"):
            continue
        key = (r["src"], r["dst"], r.get("dstport"), r.get("protocol") or "", r["action"],
               _bucket_of(int(ts), bucket_seconds))
        row = acc.setdefault(key, {"records": 0, "packets": 0, "bytes": 0})
        row["records"] += 1
        row["packets"] += r.get("packets") or 0
        row["bytes"] += r.get("bytes") or 0
    return _flows_from_acc(acc)


def flows_from_insights_rows(rows: Iterable[dict], columns: dict[str, str]) -> list[dict]:
    """Normalise Logs Insights ``stats ... by bin()`` rows into flows.

    Rows for the same key are summed: a window split to stay under the
    Insights row limit can return the same bucket from both halves.
    """
    acc: dict[tuple, dict] = {}
    for row in rows:
        src = row.get(columns["src"], "")
        dst = row.get(columns["dst"], "")
        if not src or src == "-" or not dst or dst == "-":
            continue
        port = row.get(columns["dstport"])
        key = (src, dst, _int(port) if port not in (None, "", "-") else None,
               row.get(columns["protocol"], ""), row.get(columns["action"], ""),
               _parse_insights_time(row[columns["bucket"]]))
        acc_row = acc.setdefault(key, {"records": 0, "packets": 0, "bytes": 0})
        acc_row["records"] += _int(row.get(columns["records"]))
        acc_row["packets"] += _int(row.get(columns.get("packets", ""), 0))
        acc_row["bytes"] += _int(row.get(columns.get("bytes", ""), 0))
    return _flows_from_acc(acc)


def _flows_from_acc(acc: dict[tuple, dict]) -> list[dict]:
    out = []
    for (src, dst, port, proto, action, bucket), v in acc.items():
        out.append({"src": src, "dst": dst, "port": port, "proto": PROTO_NAMES.get(proto, proto),
                    "action": action, "bucket": bucket, **v})
    out.sort(key=lambda f: (f["bucket"], f["src"], f["dst"], f["port"] or 0, f["action"]))
    return out


# --------------------------------------------------------------------------- #
# Interfaces and rule coverage
# --------------------------------------------------------------------------- #

def interface_entry_from_dict(d: dict) -> dict:
    """Normalise a flowgen.Interface-like dict."""
    return {
        "eni": d["eni"], "ips": [d["ip"]], "groups": list(d.get("groups", [])),
        "description": d.get("description", ""), "vpc_id": d.get("vpc_id"),
        "subnet_id": d.get("subnet"), "type": d.get("interface_type", "interface"),
        "instance_id": d.get("instance_id"),
    }


def interfaces_from_enis(enis: Iterable[dict]) -> list[dict]:
    """Normalise DescribeNetworkInterfaces entries."""
    out = []
    for eni in enis:
        ips = [p["PrivateIpAddress"] for p in eni.get("PrivateIpAddresses", []) if p.get("PrivateIpAddress")]
        if not ips and eni.get("PrivateIpAddress"):
            ips = [eni["PrivateIpAddress"]]
        out.append({
            "eni": eni["NetworkInterfaceId"],
            "ips": ips,
            "groups": [g["GroupId"] for g in eni.get("Groups", []) if g.get("GroupId")],
            "description": eni.get("Description", ""),
            "vpc_id": eni.get("VpcId"),
            "subnet_id": eni.get("SubnetId"),
            "type": eni.get("InterfaceType", "interface"),
            "instance_id": (eni.get("Attachment") or {}).get("InstanceId"),
        })
    return out


def _proto_matches(rule_proto: str | None, flow_proto: str) -> bool:
    if rule_proto in (None, "-1", "all"):
        return True
    rule = PROTO_NAMES.get(str(rule_proto), str(rule_proto)).lower()
    return rule == flow_proto.lower()


def _port_matches(perm: dict, port: int | None, proto: str) -> bool:
    if perm.get("IpProtocol") in ("-1", "all", None):
        return True
    fp, tp = perm.get("FromPort"), perm.get("ToPort")
    if proto in ("icmp", "icmpv6") or fp in (None, -1):
        return True
    if port is None:
        return False
    return fp <= port <= (tp if tp is not None else fp)


def _describe_rule(gid: str, perm: dict, source: str) -> str:
    proto = perm.get("IpProtocol")
    if proto in ("-1", None):
        what = "all traffic"
    else:
        name = PROTO_NAMES.get(str(proto), str(proto))
        fp, tp = perm.get("FromPort"), perm.get("ToPort")
        what = f"{name} {fp}" if fp == tp else f"{name} {fp}-{tp}"
    return f"{gid}: {what} from {source}"


def rules_covering(
    perms_by_group: dict[str, list[dict]],
    dst_groups: Sequence[str],
    src: str,
    port: int | None,
    proto: str,
    ip_groups: dict[str, set[str]],
) -> list[str]:
    """Every ingress rule on ``dst_groups`` that admits src -> port/proto.

    CIDR rules match by address; a security-group reference matches when
    the source address belongs to an interface in the referenced group.
    Prefix-list rules cannot be resolved here and are reported as possible.
    """
    try:
        addr = ipaddress.ip_address(src)
    except ValueError:
        return []
    found = []
    for gid in dst_groups:
        for perm in perms_by_group.get(gid, []):
            if not _proto_matches(perm.get("IpProtocol"), proto) or not _port_matches(perm, port, proto):
                continue
            ranges = perm.get("IpRanges", []) if addr.version == 4 else perm.get("Ipv6Ranges", [])
            key = "CidrIp" if addr.version == 4 else "CidrIpv6"
            for r in ranges:
                try:
                    if addr in ipaddress.ip_network(r[key], strict=False):
                        found.append(_describe_rule(gid, perm, r[key]))
                except (KeyError, ValueError):
                    continue
            for pair in perm.get("UserIdGroupPairs", []):
                if pair.get("GroupId") in ip_groups.get(src, set()):
                    found.append(_describe_rule(gid, perm, pair["GroupId"]))
            for pl in perm.get("PrefixListIds", []):
                found.append(_describe_rule(gid, perm, f"{pl.get('PrefixListId')} (prefix list, not resolved)"))
    return found


# --------------------------------------------------------------------------- #
# The data file
# --------------------------------------------------------------------------- #

def _rank(conn: dict) -> tuple:
    return (-(conn["accepted"]["packets"] + conn["rejected"]["packets"]), conn["src"], conn["dst"])


def build_viz_data(
    *,
    region: str,
    start: dt.datetime,
    end: dt.datetime,
    bucket_seconds: int,
    flows: list[dict],
    interfaces: list[dict],
    groups: list[dict],
    flow_log_check: dict,
    source: str,
) -> dict:
    """Assemble viz-data.json from aggregated flows and the inventory.

    ``connections`` holds one entry per (src, dst, port, proto) with totals
    and the rules that allow it; ``flows`` holds the per-bucket counts as
    compact rows [connection, bucket index, "A"|"R", records, packets, bytes].
    """
    first_bucket = _bucket_of(int(start.timestamp()), bucket_seconds)
    n_buckets = max(1, (int(end.timestamp()) - first_bucket + bucket_seconds - 1) // bucket_seconds)

    ip_to_iface = {ip: i for i in interfaces for ip in i["ips"]}
    ip_groups = {ip: set(i["groups"]) for i in interfaces for ip in i["ips"]}
    perms_by_group = {g["GroupId"]: g.get("IpPermissions", []) for g in groups}

    conns: dict[tuple, dict] = {}
    rows: list[list] = []
    for f in flows:
        key = (f["src"], f["dst"], f["port"], f["proto"])
        conn = conns.get(key)
        if conn is None:
            iface = ip_to_iface.get(f["dst"])
            conn = conns[key] = {
                "src": f["src"], "dst": f["dst"], "port": f["port"], "proto": f["proto"],
                "eni": iface["eni"] if iface else None,
                "groups": list(iface["groups"]) if iface else [],
                "first_seen": f["bucket"], "last_seen": f["bucket"],
                "accepted": {"records": 0, "packets": 0, "bytes": 0},
                "rejected": {"records": 0, "packets": 0, "bytes": 0},
            }
        side = conn["accepted" if f["action"] == "ACCEPT" else "rejected"]
        for k in ("records", "packets", "bytes"):
            side[k] += f[k]
        conn["first_seen"] = min(conn["first_seen"], f["bucket"])
        conn["last_seen"] = max(conn["last_seen"], f["bucket"])

    ordered = sorted(conns.values(), key=_rank)
    index = {(c["src"], c["dst"], c["port"], c["proto"]): i for i, c in enumerate(ordered)}
    for i, c in enumerate(ordered):
        c["id"] = i
        c["allowed_by"] = rules_covering(perms_by_group, c["groups"], c["src"], c["port"], c["proto"], ip_groups)
        c["status"] = ("mixed" if c["accepted"]["records"] and c["rejected"]["records"]
                       else "accepted" if c["accepted"]["records"] else "rejected")
        c["first_seen"] = _iso(c["first_seen"])
        c["last_seen"] = _iso(c["last_seen"] + bucket_seconds)
        c["plan_impact"] = None

    for f in flows:
        b = (f["bucket"] - first_bucket) // bucket_seconds
        if not 0 <= b < n_buckets:
            continue
        rows.append([index[(f["src"], f["dst"], f["port"], f["proto"])], b,
                     "A" if f["action"] == "ACCEPT" else "R", f["records"], f["packets"], f["bytes"]])
    rows.sort()

    used_groups = {g for c in ordered for g in c["groups"]}
    used_enis = {c["eni"] for c in ordered if c["eni"]}
    return {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "region": region,
        "source": source,
        "window": {
            "start": _iso(start.timestamp()),
            "end": _iso(end.timestamp()),
            "first_bucket": _iso(first_bucket),
            "bucket_seconds": bucket_seconds,
            "buckets": n_buckets,
        },
        "flow_log_check": flow_log_check,
        "interfaces": [i for i in interfaces if i["eni"] in used_enis],
        "groups": [
            {"group_id": g["GroupId"], "name": g.get("GroupName", ""), "vpc_id": g.get("VpcId"),
             "rules": g.get("IpPermissions", [])}
            for g in groups if g["GroupId"] in used_groups
        ],
        "connections": ordered,
        "flow_columns": ["connection", "bucket", "action", "records", "packets", "bytes"],
        "flows": rows,
        "plan": None,
    }


# --------------------------------------------------------------------------- #
# Plan overlay
# --------------------------------------------------------------------------- #

def _ranges_key(perm: dict) -> tuple:
    return (str(perm.get("IpProtocol")), perm.get("FromPort"), perm.get("ToPort"))


def rules_after_plan(rules: list[dict], plan_group: dict) -> list[dict]:
    """A group's ingress rules once the plan's revokes and authorises apply."""
    revoked = {(_ranges_key(p), r["CidrIp"]) for p in plan_group.get("revoke", []) for r in p.get("IpRanges", [])}
    out = []
    for perm in rules:
        kept = [r for r in perm.get("IpRanges", []) if (_ranges_key(perm), r.get("CidrIp")) not in revoked]
        out.append({**perm, "IpRanges": kept})
    out.extend(plan_group.get("authorise", []))
    return out


def apply_plan_overlay(data: dict, plan: dict, plan_name: str = "plan.json") -> dict:
    """Mark every observed accepted connection the plan would stop.

    For each connection to an interface with a group in the plan, coverage
    is evaluated across ALL the interface's groups (AWS allows a packet if
    any attached group does), before and after the plan:

      blocked  allowed now, not allowed after the plan
      kept     allowed now and after, and a plan group is involved

    Returns a new dict; the input is not modified.
    """
    out = json.loads(json.dumps(data))
    plan_groups = {g["group_id"]: g for g in plan.get("groups", [])}
    perms_now = {g["group_id"]: g["rules"] for g in out["groups"]}
    perms_after = {
        gid: rules_after_plan(rules, plan_groups[gid]) if gid in plan_groups else rules
        for gid, rules in perms_now.items()
    }
    ip_groups = {ip: set(i["groups"]) for i in out["interfaces"] for ip in i["ips"]}

    blocked = kept = 0
    for c in out["connections"]:
        c["plan_impact"] = None
        if not c["accepted"]["records"] or not any(g in plan_groups for g in c["groups"]):
            continue
        now = rules_covering(perms_now, c["groups"], c["src"], c["port"], c["proto"], ip_groups)
        after = rules_covering(perms_after, c["groups"], c["src"], c["port"], c["proto"], ip_groups)
        if now and not after:
            c["plan_impact"] = "blocked"
            blocked += 1
        elif after:
            c["plan_impact"] = "kept"
            c["allowed_after_plan"] = after
            kept += 1

    warnings = []
    if plan.get("region") and plan["region"] != out.get("region"):
        warnings.append(f"the plan was built in {plan['region']} but this data is from {out.get('region')}")
    missing = sorted(set(plan_groups) - set(perms_now))
    if missing:
        warnings.append(f"{len(missing)} plan group(s) saw no traffic in this window: {', '.join(missing)}")

    out["plan"] = {
        "name": plan_name,
        "generated_at": plan.get("generated_at"),
        "region": plan.get("region"),
        "blocked_connections": blocked,
        "kept_connections": kept,
        "warnings": warnings,
        "groups": [
            {
                "group_id": g["group_id"],
                "group_name": g.get("group_name"),
                "revoke": [f"{p['IpProtocol']} {p.get('FromPort')}-{p.get('ToPort')} {r['CidrIp']}"
                           for p in g.get("revoke", []) for r in p.get("IpRanges", [])],
                "authorise": [f"{p['IpProtocol']} {p.get('FromPort')}-{p.get('ToPort')} {r['CidrIp']}"
                              for p in g.get("authorise", []) for r in p.get("IpRanges", [])],
                "removed_without_evidence": g.get("removed_without_evidence", []),
            }
            for g in plan.get("groups", [])
        ],
    }
    return out


# --------------------------------------------------------------------------- #
# Export from AWS (read only)
# --------------------------------------------------------------------------- #

def _all_network_interfaces(ec2) -> list[dict]:
    out = []
    for page in ec2.get_paginator("describe_network_interfaces").paginate():
        out.extend(page.get("NetworkInterfaces", []))
    return out


def _groups_by_id(ec2, group_ids: Sequence[str]) -> list[dict]:
    out = []
    ids = sorted(set(group_ids))
    for i in range(0, len(ids), 200):
        resp = ec2.describe_security_groups(GroupIds=ids[i:i + 200])
        out.extend(resp.get("SecurityGroups", []))
    return out


def export(
    *,
    region: str,
    start: dt.datetime,
    end: dt.datetime,
    bucket_seconds: int | None = None,
    log_group: str | None = None,
    s3_bucket: str | None = None,
    s3_prefix: str | None = None,
) -> dict:
    """Read flow logs and inventory for ``region`` and build viz-data."""
    if not log_group and not s3_bucket:
        raise ValueError("either a log group or an S3 bucket is required")
    bucket_seconds = bucket_seconds or default_bucket_seconds(start, end)
    hours = max(1, int((end - start).total_seconds() // 3600))
    cfg = AnalyseConfig(region=region, days=max(1, hours // 24), hours=hours, log_group=log_group,
                        s3_bucket=s3_bucket, s3_prefix=s3_prefix, out_path="", traffic="ALL")
    check = preflight_flow_logs(cfg)

    if log_group:
        query, columns = build_flow_stats_query(
            check.fields, by=("src", "dst", "dstport", "protocol", "action"), bin_seconds=bucket_seconds)
        rows = run_insights_query(sg_tightener._client("logs", region), log_group, query, start, end)
        flows = flows_from_insights_rows(rows, columns)
    else:
        s3 = sg_tightener._client("s3", region)
        flows = []
        for obj, lines in iter_s3_flow_log_lines(s3, s3_bucket, s3_prefix, start, end):
            flows.extend(aggregate_records(flow_records(lines, check.fields), bucket_seconds,
                                           default_ts=int(obj["LastModified"].timestamp())))
        flows = _merge_flows(flows)
    flows = [f for f in flows if start.timestamp() - bucket_seconds < f["bucket"] <= end.timestamp()]

    ec2 = sg_tightener._client("ec2", region)
    interfaces = interfaces_from_enis(_all_network_interfaces(ec2))
    dst_ips = {f["dst"] for f in flows}
    interfaces = [i for i in interfaces if dst_ips.intersection(i["ips"])]
    group_ids = {g for i in interfaces for g in i["groups"]}
    groups = _groups_by_id(ec2, sorted(group_ids)) if group_ids else []

    data = build_viz_data(
        region=region, start=start, end=end, bucket_seconds=bucket_seconds, flows=flows,
        interfaces=interfaces, groups=groups,
        flow_log_check={"verified": check.verified, "fields": check.fields, "warnings": check.warnings},
        source=f"cloudwatch:{log_group}" if log_group else f"s3:{s3_bucket}/{s3_prefix or ''}",
    )
    LOG.info("%d connections, %d flow rows, %d interfaces, %d groups",
             len(data["connections"]), len(data["flows"]), len(data["interfaces"]), len(data["groups"]))
    return data


def _merge_flows(flows: list[dict]) -> list[dict]:
    acc: dict[tuple, dict] = {}
    for f in flows:
        key = (f["src"], f["dst"], f["port"], PROTO_NUMBERS.get(f["proto"], f["proto"]), f["action"], f["bucket"])
        row = acc.setdefault(key, {"records": 0, "packets": 0, "bytes": 0})
        for k in row:
            row[k] += f[k]
    return _flows_from_acc(acc)


# --------------------------------------------------------------------------- #
# Local web server
# --------------------------------------------------------------------------- #

class VizServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int, data: dict | None = None):
        super().__init__(("127.0.0.1", port), VizHandler)
        self.data = data
        self.export_lock = threading.Lock()


class VizHandler(BaseHTTPRequestHandler):
    """Serves the viewer and a small JSON API to this machine only.

    The server holds your AWS credentials, so a web page open in the same
    browser must not be able to drive it:
      * it listens on 127.0.0.1 only;
      * a Host header that is not a loopback name is refused (DNS rebinding);
      * POSTs need ``X-SG-Viz: 1`` and a JSON body, which a foreign page
        cannot send without a CORS preflight that is never granted;
      * an Origin header, when present, must be this server's own.
    """

    server: VizServer
    server_version = "sg_viz"
    sys_version = ""

    def log_message(self, fmt, *args):  # quieter than the default
        LOG.debug("%s - %s", self.address_string(), fmt % args)

    # -- guards ------------------------------------------------------------ #

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").strip().lower()
        name = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
        return name in LOOPBACK_HOSTS

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        port = self.server.server_address[1]
        return origin in {f"http://127.0.0.1:{port}", f"http://localhost:{port}", f"http://[::1]:{port}"}

    def _send(self, status: int, body: bytes, ctype: str, *, cache: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        )
        if not cache:
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json")

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    # -- routes ------------------------------------------------------------ #

    def do_GET(self):  # noqa: N802
        if not self._host_ok():
            return self._error(HTTPStatus.MISDIRECTED_REQUEST, "this server only answers to 127.0.0.1")
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            return self._file(VIEWER_DIR / "index.html", "text/html; charset=utf-8")
        if path == "/sample-data.json":
            return self._file(VIEWER_DIR / "sample-data.json", "application/json")
        if path == "/api/health":
            return self._json(200, {"server": "sg_viz", "schema": SCHEMA,
                                    "aws": sg_tightener.boto3 is not None,
                                    "data": self.server.data is not None})
        if path == "/api/data":
            if self.server.data is None:
                return self._error(404, "no data file was given to serve")
            return self._json(200, self.server.data)
        if path == "/api/profiles":
            return self._json(200, {"profiles": _profiles()})
        return self._error(404, "not found")

    do_HEAD = do_GET

    def do_POST(self):  # noqa: N802
        if not self._host_ok():
            return self._error(HTTPStatus.MISDIRECTED_REQUEST, "this server only answers to 127.0.0.1")
        if self.headers.get("X-SG-Viz") != "1" or not self._origin_ok():
            return self._error(403, "cross-site request refused")
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            return self._error(415, "send application/json")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if not 0 < length <= MAX_BODY:
            return self._error(413, "request body missing or too large")
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            return self._error(400, "body is not JSON")
        if not isinstance(body, dict):
            return self._error(400, "body must be a JSON object")

        path = self.path.split("?", 1)[0]
        if path == "/api/overlay":
            return self._overlay(body)
        if path == "/api/export":
            return self._export(body)
        return self._error(404, "not found")

    def _file(self, path: Path, ctype: str) -> None:
        try:
            body = path.read_bytes()
        except OSError:
            return self._error(404, f"{path.name} is missing")
        self._send(200, body, ctype)

    def _overlay(self, body: dict) -> None:
        data, plan = body.get("data"), body.get("plan")
        if not isinstance(data, dict) or data.get("schema") != SCHEMA:
            return self._error(400, f"data is not a {SCHEMA} file")
        if not isinstance(plan, dict) or not str(plan.get("schema", "")).startswith("sg-tightener.plan/"):
            return self._error(400, "plan is not an sg-tightener plan.json")
        name = str(body.get("plan_name") or "plan.json")[:200]
        try:
            return self._json(200, apply_plan_overlay(data, plan, name))
        except (KeyError, TypeError, ValueError) as exc:
            return self._error(400, f"could not overlay this plan: {exc}")

    def _export(self, body: dict) -> None:
        try:
            req = parse_export_request(body)
        except ValueError as exc:
            return self._error(400, str(exc))
        if sg_tightener.boto3 is None:
            return self._error(500, "boto3 is not installed in this Python")
        if not self.server.export_lock.acquire(blocking=False):
            return self._error(409, "an export is already running")
        try:
            if req.pop("profile"):
                sg_tightener.boto3.setup_default_session(profile_name=body["profile"])
            else:
                sg_tightener.boto3.setup_default_session()
            data = export(**req)
        except Exception as exc:  # noqa: BLE001 — every failure goes back to the page
            LOG.warning("export failed: %s", exc)
            return self._error(502, f"{type(exc).__name__}: {exc}")
        finally:
            self.server.export_lock.release()
        self.server.data = data
        return self._json(200, data)


def _profiles() -> list[str]:
    if sg_tightener.boto3 is None:
        return []
    try:
        return sorted(sg_tightener.boto3.session.Session().available_profiles)
    except Exception:  # noqa: BLE001 — a broken config file just means no list
        return []


def parse_export_request(body: dict) -> dict:
    """Validate the viewer's export form. Raises ValueError with a message for the page."""
    import re

    region = str(body.get("region") or "")
    if not re.fullmatch(r"[a-z]{2}(-[a-z]+)+-\d", region):
        raise ValueError("region looks wrong (e.g. eu-west-1)")
    profile = body.get("profile") or None
    if profile is not None and (not isinstance(profile, str) or not re.fullmatch(r"[\w+=,.@/-]{1,128}", profile)):
        raise ValueError("profile name looks wrong")
    try:
        hours = int(body.get("hours") or 24)
    except (TypeError, ValueError):
        raise ValueError("hours must be a whole number")
    if not 1 <= hours <= 24 * 90:
        raise ValueError("hours must be between 1 and 2160 (90 days)")
    bucket = body.get("bucket_seconds")
    if bucket not in (None, "", 0):
        try:
            bucket = int(bucket)
        except (TypeError, ValueError):
            raise ValueError("bucket must be a number of seconds")
        if bucket < 60 or bucket % 60:
            raise ValueError("bucket must be a whole number of minutes")
    else:
        bucket = None
    log_group = (body.get("log_group") or "").strip() or None
    s3_bucket = (body.get("s3_bucket") or "").strip() or None
    if bool(log_group) == bool(s3_bucket):
        raise ValueError("give either a log group or an S3 bucket")
    if log_group and not re.fullmatch(r"[\w./#-]{1,512}", log_group):
        raise ValueError("log group name looks wrong")
    if s3_bucket and not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", s3_bucket):
        raise ValueError("S3 bucket name looks wrong")
    end = dt.datetime.now(dt.timezone.utc).replace(second=0, microsecond=0)
    return {
        "profile": profile,
        "region": region,
        "start": end - dt.timedelta(hours=hours),
        "end": end,
        "bucket_seconds": bucket,
        "log_group": log_group,
        "s3_bucket": s3_bucket,
        "s3_prefix": (body.get("s3_prefix") or "").strip() or None,
    }


def serve(port: int, data: dict | None = None, open_browser: bool = False) -> None:
    server = VizServer(port, data)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"sg_viz viewer on {url}  (loopback only; Ctrl-C to stop)", flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _write_json(path: str, payload: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, separators=(",", ":"))


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sg_viz.py", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="mode", required=True)

    e = sub.add_parser("export", help="read flow logs and inventory, write viz-data.json")
    e.add_argument("--region", required=True)
    window = e.add_mutually_exclusive_group()
    window.add_argument("--days", type=int)
    window.add_argument("--hours", type=int)
    e.add_argument("--bucket", type=int, help="seconds per time bucket (default: by window length)")
    e.add_argument("--log-group")
    e.add_argument("--s3-bucket")
    e.add_argument("--s3-prefix")
    e.add_argument("--plan", help="also overlay this plan.json")
    e.add_argument("--out", default="viz-data.json")

    o = sub.add_parser("overlay", help="add a plan's impact to a viz-data.json")
    o.add_argument("--data", required=True)
    o.add_argument("--plan", required=True)
    o.add_argument("--out", help="default: overwrite --data")

    s = sub.add_parser("serve", help="run the viewer on 127.0.0.1")
    s.add_argument("--port", type=int, default=DEFAULT_PORT)
    s.add_argument("--data", help="viz-data.json to show on open")
    s.add_argument("--open", action="store_true", help="open the browser")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    p = _build_parser()
    args = p.parse_args(argv)

    if args.mode == "export":
        if not args.log_group and not args.s3_bucket:
            p.error("either --log-group or --s3-bucket is required")
        span = dt.timedelta(hours=args.hours) if args.hours else dt.timedelta(days=args.days or 7)
        if span <= dt.timedelta(0):
            p.error("the window must be positive")
        if args.bucket is not None and (args.bucket < 60 or args.bucket % 60):
            p.error("--bucket must be a whole number of minutes, in seconds")
        end = dt.datetime.now(dt.timezone.utc).replace(second=0, microsecond=0)
        data = export(region=args.region, start=end - span, end=end, bucket_seconds=args.bucket,
                      log_group=args.log_group, s3_bucket=args.s3_bucket, s3_prefix=args.s3_prefix)
        if args.plan:
            data = apply_plan_overlay(data, _load_json(args.plan), Path(args.plan).name)
        _write_json(args.out, data)
        LOG.info("wrote %s; view it with: python sg_viz.py serve --data %s --open", args.out, args.out)
        return 0

    if args.mode == "overlay":
        data = apply_plan_overlay(_load_json(args.data), _load_json(args.plan), Path(args.plan).name)
        _write_json(args.out or args.data, data)
        plan = data["plan"]
        LOG.info("%d observed connection(s) would be blocked by %s", plan["blocked_connections"], args.plan)
        for w in plan["warnings"]:
            LOG.warning("%s", w)
        return 0

    if args.mode == "serve":
        serve(args.port, _load_json(args.data) if args.data else None, args.open)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
