"""Synthetic VPC flow-log generator for tests and the viewer demo.

Describes a small estate (interfaces, security groups, the clients that talk
to them and when) and turns it into flow-log records, formatted lines in any
log format, S3 objects and Logs Insights answers. Everything is deterministic
for a given seed, and nothing touches AWS.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import gzip
import random
import re
from typing import Iterable, Sequence

from sg_tightener import DEFAULT_LOG_FORMAT_FIELDS, RECOMMENDED_LOG_FORMAT, parse_log_format

RECOMMENDED_FIELDS = parse_log_format(RECOMMENDED_LOG_FORMAT)
ACCOUNT = "123456789012"
UTC = dt.timezone.utc


@dataclasses.dataclass
class Interface:
    eni: str
    ip: str
    groups: list[str]
    description: str = ""
    subnet: str = "subnet-0a1b2c3d4e5f60001"
    vpc_id: str = "vpc-0a1b2c3d4e5f60001"
    interface_type: str = "interface"
    instance_id: str | None = None


@dataclasses.dataclass
class Talker:
    """Traffic from ``sources`` to the interface at ``dst`` on ``port``.

    ``hours`` limits activity to those hours of the day (UTC), ``days`` to
    day offsets from the window start (None = every day), ``every`` is the
    chance a given active hour has traffic at all.
    """
    sources: list[str]
    dst: str
    port: int
    action: str = "ACCEPT"
    proto: str = "6"
    hours: range = range(24)
    days: Sequence[int] | None = None
    every: float = 1.0
    packets: tuple[int, int] = (10, 400)
    via: str | None = None  # next-hop address (TGW/NAT ENI) seen as srcaddr


@dataclasses.dataclass
class Topology:
    region: str
    interfaces: list[Interface]
    groups: list[dict]          # DescribeSecurityGroups shape
    talkers: list[Talker]


def generate_records(topo: Topology, start: dt.datetime, end: dt.datetime, seed: int = 7) -> list[dict]:
    """One aggregated record per (talker, source, hour) with traffic.

    Records use the keys ``flow_records`` yields, plus ``srcaddr`` (the
    next hop when the talker goes through one) for formatting.
    """
    rng = random.Random(seed)
    by_ip = {i.ip: i for i in topo.interfaces}
    out: list[dict] = []
    hour = start.replace(minute=0, second=0, microsecond=0)
    if hour < start:
        hour += dt.timedelta(hours=1)
    while hour < end:
        day = (hour - start).days
        for t in topo.talkers:
            if hour.hour not in t.hours:
                continue
            if t.days is not None and day not in t.days:
                continue
            for src in t.sources:
                if rng.random() > t.every:
                    continue
                packets = rng.randint(*t.packets)
                ts = int(hour.timestamp()) + rng.randint(0, 3000)
                out.append({
                    "src": src,
                    "srcaddr": t.via or src,
                    "dst": t.dst,
                    "srcport": rng.randint(32768, 60999),
                    "dstport": t.port,
                    "protocol": t.proto,
                    "action": t.action,
                    "packets": packets,
                    "bytes": packets * rng.randint(60, 1400),
                    "start": ts,
                    "end": ts + 60,
                    "direction": "ingress",
                    "interface": by_ip[t.dst].eni if t.dst in by_ip else "eni-0000000000000000",
                })
        hour += dt.timedelta(hours=1)
    return out


def format_line(rec: dict, fields: Sequence[str]) -> str:
    values = {
        "version": "5", "account-id": ACCOUNT, "interface-id": rec["interface"],
        "srcaddr": rec.get("srcaddr", rec["src"]), "dstaddr": rec["dst"],
        "pkt-srcaddr": rec["src"], "pkt-dstaddr": rec["dst"],
        "srcport": str(rec["srcport"]), "dstport": str(rec["dstport"]),
        "protocol": rec["protocol"], "packets": str(rec["packets"]),
        "bytes": str(rec["bytes"]), "start": str(rec["start"]), "end": str(rec["end"]),
        "action": rec["action"], "log-status": "OK",
        "flow-direction": rec.get("direction", "ingress"),
    }
    return " ".join(values.get(f, "-") for f in fields)


def format_lines(records: Iterable[dict], fields: Sequence[str], header: bool = True) -> list[str]:
    lines = [" ".join(fields)] if header else []
    lines.extend(format_line(r, fields) for r in records)
    return lines


def put_s3_objects(s3, bucket: str, records: list[dict], fields: Sequence[str],
                   prefix: str = "AWSLogs", per_object: int = 500, gz: bool = True) -> list[str]:
    """Write records to S3 the way flow-log delivery does (header + lines, .gz)."""
    keys = []
    for n, i in enumerate(range(0, max(len(records), 1), per_object)):
        body = "\n".join(format_lines(records[i:i + per_object], fields)).encode()
        key = f"{prefix}/{ACCOUNT}/vpcflowlogs/part-{n:05d}.log"
        if gz:
            body, key = gzip.compress(body), key + ".gz"
        s3.put_object(Bucket=bucket, Key=key, Body=body)
        keys.append(key)
    return keys


# --------------------------------------------------------------------------- #
# Logs Insights emulator
# --------------------------------------------------------------------------- #

_DISCOVERED = {
    "version": "version", "account-id": "accountId", "interface-id": "interfaceId",
    "srcaddr": "srcAddr", "dstaddr": "dstAddr", "srcport": "srcPort", "dstport": "dstPort",
    "protocol": "protocol", "packets": "packets", "bytes": "bytes", "start": "start",
    "end": "end", "action": "action", "log-status": "logStatus",
}


class FakeLogs:
    """Just enough of Logs Insights for the queries this project builds.

    Understands ``parse @message "* * ..." as f0, f1, ...``, ``filter X = "V"``,
    ``stats count()/count(*)/sum(x) [as name] by a, b, bin(Ns)`` and
    ``limit N`` — and, like the real service, stops at the limit without
    saying so. Records are formatted with ``fields`` and timestamped with
    their ``start``.
    """

    def __init__(self, records: list[dict], fields: Sequence[str]):
        self.events = [(r["start"], format_line(r, fields)) for r in records]
        self.fields = list(fields)
        self.queries: list[tuple[str, int, int]] = []
        self._results: dict[str, list] = {}

    def start_query(self, logGroupName, startTime, endTime, queryString):  # noqa: N803 — boto names
        self.queries.append((queryString, startTime, endTime))
        qid = f"q{len(self.queries)}"
        self._results[qid] = self._run(queryString, startTime, endTime)
        return {"queryId": qid}

    def get_query_results(self, queryId):  # noqa: N803
        return {"status": "Complete", "results": self._results.pop(queryId)}

    def _run(self, query: str, start: int, end: int) -> list:
        stages = [s.strip() for s in query.split("|")]
        rows = []
        for ts, line in self.events:
            if not start <= ts <= end:
                continue
            parts = line.split()
            row = {"@timestamp": ts}
            if self.fields == DEFAULT_LOG_FORMAT_FIELDS:
                row.update({_DISCOVERED[f]: parts[i] for i, f in enumerate(self.fields)})
            rows.append((row, parts))
        limit = 10000
        out = []
        for stage in stages:
            if stage.startswith("parse @message"):
                for row, parts in rows:
                    row.update({f"f{i}": p for i, p in enumerate(parts)})
            elif stage.startswith("filter "):
                m = re.match(r'filter (\S+) = "([^"]*)"', stage)
                rows = [(r, p) for r, p in rows if r.get(m.group(1)) == m.group(2)]
            elif stage.startswith("stats "):
                out = self._stats(stage, [r for r, _ in rows])
            elif stage.startswith("limit "):
                limit = int(stage.split()[1])
        return out[:limit]

    @staticmethod
    def _stats(stage: str, rows: list[dict]) -> list:
        aggs_part, by_part = stage[len("stats "):].split(" by ")
        by = [b.strip() for b in by_part.split(",")]
        aggs = []
        for a in aggs_part.split(","):
            m = re.match(r"\s*(count|sum)\(([^)]*)\)(?:\s+as\s+(\S+))?", a)
            aggs.append((m.group(1), m.group(2), m.group(3) or f"{m.group(1)}({m.group(2)})"))
        groups: dict[tuple, list[dict]] = {}
        for r in rows:
            key = []
            for b in by:
                bm = re.match(r"bin\((\d+)s\)", b)
                if bm:
                    size = int(bm.group(1))
                    t = r["@timestamp"] // size * size
                    key.append(dt.datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%d %H:%M:%S.000"))
                else:
                    key.append(r.get(b, ""))
            groups.setdefault(tuple(key), []).append(r)
        out = []
        for key, members in groups.items():
            cells = [{"field": b, "value": v} for b, v in zip(by, key)]
            for fn, arg, name in aggs:
                val = len(members) if fn == "count" else sum(int(m.get(arg, 0) or 0) for m in members)
                cells.append({"field": name, "value": str(val)})
            out.append(cells)
        return out


# --------------------------------------------------------------------------- #
# The demo estate
# --------------------------------------------------------------------------- #

def _sg(gid: str, name: str, *perms: dict, desc: str = "") -> dict:
    return {"GroupId": gid, "GroupName": name, "Description": desc or name,
            "VpcId": "vpc-0a1b2c3d4e5f60001", "OwnerId": ACCOUNT, "IpPermissions": list(perms)}


def _perm(port: int, *cidrs: str, proto: str = "tcp", to_port: int | None = None) -> dict:
    return {"IpProtocol": proto, "FromPort": port, "ToPort": to_port or port,
            "IpRanges": [{"CidrIp": c, "Description": "legacy broad rule"} for c in cidrs],
            "Ipv6Ranges": [], "UserIdGroupPairs": [], "PrefixListIds": []}


def sample_topology() -> Topology:
    """A small payments estate with broad legacy rules and a mix of traffic."""
    office = [f"10.20.33.{i}" for i in (11, 12, 14, 20, 41, 77)]
    partner = ["172.16.5.10", "172.16.5.11"]
    interfaces = [
        Interface("eni-0db00000000000001", "10.4.1.20", ["sg-0db0000000000001"], "payments-db primary",
                  instance_id="i-0db0000000000001"),
        Interface("eni-0db00000000000002", "10.4.1.21", ["sg-0db0000000000001"], "payments-db replica",
                  instance_id="i-0db0000000000002"),
        Interface("eni-0a900000000000001", "10.4.2.10", ["sg-0a90000000000001", "sg-0a90000000000002"],
                  "payments-api a", instance_id="i-0a90000000000001"),
        Interface("eni-0a900000000000002", "10.4.2.11", ["sg-0a90000000000001", "sg-0a90000000000002"],
                  "payments-api b", instance_id="i-0a90000000000002"),
        Interface("eni-0ca00000000000001", "10.4.3.30", ["sg-0ca0000000000001"], "ElastiCache payments-cache",
                  interface_type="interface"),
        Interface("eni-0b500000000000001", "10.4.0.5", ["sg-0b50000000000001"], "bastion",
                  instance_id="i-0b50000000000001"),
    ]
    groups = [
        _sg("sg-0db0000000000001", "payments-db", _perm(5432, "10.0.0.0/8")),
        _sg("sg-0a90000000000001", "payments-api", _perm(443, "10.0.0.0/8", "172.16.0.0/12")),
        _sg("sg-0a90000000000002", "payments-api-metrics", _perm(9100, "10.4.0.0/16")),
        _sg("sg-0ca0000000000001", "payments-cache", _perm(6379, "10.4.0.0/16")),
        _sg("sg-0b50000000000001", "bastion", _perm(22, "10.0.0.0/8")),
    ]
    talkers = [
        # API servers use the database around the clock.
        Talker(["10.4.2.10", "10.4.2.11"], "10.4.1.20", 5432, packets=(200, 2000)),
        Talker(["10.4.1.20"], "10.4.1.21", 5432, packets=(500, 900)),  # replication
        Talker(["10.4.2.10", "10.4.2.11"], "10.4.3.30", 6379, packets=(100, 1500)),
        # Office users reach the API in working hours, through the transit gateway.
        Talker(office, "10.4.2.10", 443, hours=range(7, 18), every=0.7, via="10.4.250.9"),
        Talker(office, "10.4.2.11", 443, hours=range(7, 18), every=0.7, via="10.4.250.9"),
        # The partner calls in a few times a day.
        Talker(partner, "10.4.2.10", 443, hours=range(9, 15), every=0.4),
        # Prometheus scrapes metrics.
        Talker(["10.4.9.50"], "10.4.2.10", 9100, packets=(5, 20)),
        Talker(["10.4.9.50"], "10.4.2.11", 9100, packets=(5, 20)),
        # Quarter-end batch job: ran on day 9 only, at night.
        Talker(["10.9.7.3"], "10.4.1.20", 5432, hours=range(1, 4), days=[9], packets=(3000, 9000)),
        # An engineer on the bastion.
        Talker(["10.20.33.41"], "10.4.0.5", 22, hours=range(10, 12), days=[3, 4, 17, 25]),
        # Rejected: a scanner probing MySQL, a misconfigured client, internet noise.
        Talker([f"10.66.1.{i}" for i in range(2, 30, 3)], "10.4.1.20", 3306, action="REJECT",
               days=[21, 22], packets=(1, 3)),
        Talker(["10.4.5.7"], "10.4.3.30", 6380, action="REJECT", every=0.5, packets=(2, 6)),
        Talker(["203.0.113.50", "198.51.100.7"], "10.4.0.5", 22, action="REJECT", every=0.3, packets=(1, 4)),
    ]
    return Topology("eu-west-1", interfaces, groups, talkers)


def sample_window() -> tuple[dt.datetime, dt.datetime]:
    end = dt.datetime(2026, 11, 16, 0, 0, tzinfo=UTC)
    return end - dt.timedelta(days=30), end


def build_sample() -> dict:
    """Demo viz-data: 30 days of traffic, with a plan overlay.

    The plan comes from an approved list built over the last 14 days only,
    so the quarter-end batch job (day 9 of 30) is not in it: the overlay
    shows exactly the traffic that plan would cut off.
    """
    import sg_tightener
    import sg_viz

    topo = sample_topology()
    start, end = sample_window()
    records = generate_records(topo, start, end)
    data = sg_viz.build_viz_data(
        region=topo.region,
        start=start,
        end=end,
        bucket_seconds=3600,
        flows=sg_viz.aggregate_records(records, 3600),
        interfaces=[sg_viz.interface_entry_from_dict(dataclasses.asdict(i)) for i in topo.interfaces],
        groups=topo.groups,
        flow_log_check={"verified": True, "fields": RECOMMENDED_FIELDS, "warnings": []},
        source="synthetic sample",
    )
    recent = end - dt.timedelta(days=14)
    approved = sorted({r["src"] for r in records
                       if r["action"] == "ACCEPT" and r["start"] >= recent.timestamp()})
    plan = sg_tightener.build_plan(topo.groups, approved, region=topo.region)
    plan["generated_at"] = end.isoformat()
    return sg_viz.apply_plan_overlay(data, plan, plan_name="sample plan (14-day approved list)")


__all__ = [
    "FakeLogs", "Interface", "Talker", "Topology", "RECOMMENDED_FIELDS",
    "generate_records", "format_line", "format_lines", "put_s3_objects",
    "sample_topology", "sample_window", "build_sample",
]
