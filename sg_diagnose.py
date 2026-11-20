#!/usr/bin/env python3
"""sg_diagnose.py — surface legitimate sources rejected after tightening.

After a tightening apply, run this to find private sources whose
connections were REJECTED over a recent window BY THE SECURITY GROUPS ON
THE INTERFACE THEY TRIED TO REACH. Each rejected flow is checked against
the groups on its own destination interface, on its own protocol and port
(the way AWS evaluates it), not against every rule in the region. With
--manifest, flows that a rule revoked by that apply would have admitted
are marked as caused by the tightening.

It never changes AWS. For each finding it prints the sg_extend command
that restores access now, and it can record the flows in approved.json so
the next plan keeps them. Adding to approved.json alone cannot restore
access: plan only narrows the broad rules that still exist, and apply has
already removed them.

Usage:
  sg_diagnose.py --region <r> [--hours 24] [--approved approved.json]
                 [--manifest manifest-<ts>.json]
                 [--log-group <name> | --s3-bucket <b> --s3-prefix <p>]

Exit code 0 means no rejected sources were found (or they were recorded).
Exit code 1 means rejected sources were found and not recorded.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import logging
import sys
from typing import Sequence

from sg_tightener import (
    APPROVED_SCHEMA_V2,
    RFC1918_BLOCKS,
    AnalyseConfig,
    InterfaceIndex,
    _analyse_flows_from_cloudwatch,
    _analyse_flows_from_s3,
    _list_network_interfaces,
    _list_security_groups,
    _sorted_flows,
    preflight_flow_logs,
)
from sg_viz import PROTO_NAMES, rules_covering

LOG = logging.getLogger("sg_diagnose")


def _private(ip: str | None) -> bool:
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        return False
    return isinstance(addr, ipaddress.IPv4Address) and any(addr in b for b in RFC1918_BLOCKS)


def diagnose(
    flows: list[dict],
    sgs: list[dict],
    interfaces: list[dict],
    manifest: dict | None = None,
) -> dict:
    """Classify rejected flows against the groups on their destination.

    Returns {"blocked": [...], "allowed_by_groups": n, "unresolved": [...],
    "ignored": n}. Each ``blocked`` entry is a flow the destination's groups
    do not admit now, with the destination interface, its groups, and
    ``caused_by`` (the revoked rules from ``manifest`` that would have
    admitted it). ``allowed_by_groups`` counts rejects the groups do admit
    (refused by a network ACL, or return traffic); ``unresolved`` lists
    destinations no single interface owns (deleted, another account, or an
    address several VPCs use).
    """
    index = InterfaceIndex(interfaces)
    perms = {sg["GroupId"]: sg.get("IpPermissions", []) for sg in sgs}
    revoked: dict[str, list[dict]] = {}
    for grp in (manifest or {}).get("groups", []):
        revoked.setdefault(grp["group_id"], []).extend(grp.get("revoked", []))

    blocked: list[dict] = []
    unresolved: set[str] = set()
    allowed = ignored = 0
    for f in flows:
        if not _private(f.get("src")):
            ignored += 1
            continue
        eni, status = index.resolve(f.get("dst"), f.get("interface"))
        if status == "not-owner":
            ignored += 1  # the sender's copy of the connection
            continue
        groups = sorted(index.groups(eni))
        if status != "ok" or not groups:
            unresolved.add(f.get("dst") or "-")
            continue
        proto = PROTO_NAMES.get(str(f.get("protocol")), str(f.get("protocol") or ""))
        src_eni, _ = index.resolve(f["src"], prefer_vpc=eni.get("VpcId"))
        src_groups = {f["src"]: index.groups(src_eni)}
        if rules_covering(perms, groups, f["src"], f.get("dstport"), proto, src_groups):
            allowed += 1
            continue
        caused_by = rules_covering(revoked, groups, f["src"], f.get("dstport"), proto, src_groups)
        blocked.append({**f, "eni": eni.get("NetworkInterfaceId"), "groups": groups,
                        "proto": proto, "caused_by": caused_by})
    blocked.sort(key=lambda b: (not b["caused_by"], b["src"], b["dst"], b.get("dstport") or 0))
    return {"blocked": blocked, "allowed_by_groups": allowed,
            "unresolved": sorted(unresolved), "ignored": ignored}


def extend_commands(blocked: list[dict], region: str, hours: int, source_args: list[str]) -> list[str]:
    """One sg_extend command per set of groups, limited to the blocked ports."""
    by_groups: dict[tuple[str, ...], set[int]] = {}
    for b in blocked:
        ports = by_groups.setdefault(tuple(b["groups"]), set())
        if b.get("dstport") is not None:
            ports.add(int(b["dstport"]))
    out = []
    for groups, ports in sorted(by_groups.items()):
        cmd = ["python", "sg_extend.py", "--region", region, "--groups", ",".join(groups),
               "--hours", str(hours), *source_args]
        if ports:
            cmd += ["--ports", ",".join(str(p) for p in sorted(ports))]
        out.append(" ".join(cmd))
    return out


def record_in_approved(path: str, blocked: list[dict]) -> dict:
    """Add the blocked flows (and their sources) to approved.json."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            approved = json.load(fh)
    except FileNotFoundError:
        approved = {"schema": APPROVED_SCHEMA_V2, "ips": [], "flows": []}
    entries = [{"src": b["src"], "dst": b.get("dst"), "dstport": b.get("dstport"),
                "protocol": b.get("protocol"), "interface": b.get("interface")} for b in blocked]
    if "flows" in approved:
        approved["flows"] = _sorted_flows(approved["flows"] + entries)
    approved["ips"] = sorted(set(approved.get("ips", [])) | {b["src"] for b in blocked})
    approved["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(approved, fh, indent=2)
    return approved


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    p = argparse.ArgumentParser(prog="sg_diagnose.py")
    p.add_argument("--region", required=True)
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--approved", default="approved.json")
    p.add_argument("--manifest", help="manifest written by the apply to check against: rejected "
                                      "flows its revoked rules would have admitted are marked")
    p.add_argument("--log-group")
    p.add_argument("--s3-bucket")
    p.add_argument("--s3-prefix")
    p.add_argument("--apply", action="store_true",
                   help="kept for compatibility: only prints the commands to run")
    args = p.parse_args(argv)

    if not args.log_group and not args.s3_bucket:
        p.error("either --log-group or --s3-bucket is required")
    if args.hours < 1:
        p.error("--hours must be >= 1")

    cfg = AnalyseConfig(
        region=args.region,
        days=max(1, -(-args.hours // 24)),
        hours=args.hours,  # the window; days is informational only
        log_group=args.log_group,
        s3_bucket=args.s3_bucket,
        s3_prefix=args.s3_prefix,
        out_path=args.approved,
        accepted_only=False,  # we want REJECTs
    )
    check = preflight_flow_logs(cfg)
    reader = _analyse_flows_from_cloudwatch if args.log_group else _analyse_flows_from_s3
    flows = reader(cfg, check.fields)
    if flows is None:
        sys.exit("the flow-log format has no destination address or port, so a rejected flow "
                 "cannot be tied to the group that refused it. Add ${dstaddr} and ${dstport}.")
    LOG.info("observed %d rejected flow(s)", len(flows))

    manifest = None
    if args.manifest:
        with open(args.manifest, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)

    result = diagnose(flows, _list_security_groups(args.region),
                      _list_network_interfaces(args.region), manifest)
    if result["allowed_by_groups"]:
        LOG.info("%d rejected flow(s) are admitted by their destination's groups (refused by a "
                 "network ACL, or return traffic): not a security-group problem",
                 result["allowed_by_groups"])
    if result["unresolved"]:
        LOG.warning("%d destination(s) could not be tied to one interface (deleted, another "
                    "account, or used in several VPCs): %s", len(result["unresolved"]),
                    ", ".join(result["unresolved"][:20]))

    blocked = result["blocked"]
    if not blocked:
        LOG.info("no private sources are being rejected by security groups — nothing to do")
        return 0

    caused = sum(1 for b in blocked if b["caused_by"])
    LOG.warning("%d private flow(s) rejected by their destination's security groups%s:",
                len(blocked), f", {caused} caused by the tightening in {args.manifest}" if manifest else "")
    for b in blocked:
        mark = "  CAUSED BY TIGHTENING (was: " + "; ".join(b["caused_by"]) + ")" if b["caused_by"] else ""
        print(f"  {b['src']} -> {b['dst']} {b['proto']}/{b.get('dstport')} "
              f"on {b['eni']} [{', '.join(b['groups'])}]{mark}")

    source_args = (["--log-group", args.log_group] if args.log_group
                   else ["--s3-bucket", args.s3_bucket] + (["--s3-prefix", args.s3_prefix] if args.s3_prefix else []))
    print("\nTo restore access now (adds rules only), review and run:")
    for cmd in extend_commands(blocked, args.region, args.hours, source_args):
        print(f"  {cmd}")
    if manifest and caused:
        print(f"Or undo the whole apply: python sg_tightener.py revert --manifest {args.manifest}")

    try:
        answer = input(f"Record these {len(blocked)} flow(s) in {args.approved} so the next plan "
                       "keeps them? [y/N] ")
    except EOFError:
        answer = ""
    if answer.strip().lower() != "y":
        return 1
    approved = record_in_approved(args.approved, blocked)
    LOG.info("%s now holds %d source(s); this does not change AWS — run the commands above "
             "to restore access now", args.approved, len(approved["ips"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
