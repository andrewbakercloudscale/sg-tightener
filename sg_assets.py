#!/usr/bin/env python3
"""sg_assets.py: security groups per asset (a network interface, or the instance it belongs to).

A security group is shared: changing its rules changes every asset that carries it. To tighten one asset
on its own, sg-tightener gives it a group of its own, ``sgt-<eni>``, holding only what flow logs show that
asset received (the rules of every group it carries, merged, with the wide private ranges narrowed to the
sources seen), then swaps the asset onto it. Nothing else changes; swapping back undoes it.

Assets that are replaced rather than kept (auto scaling instances, EKS and ECS interfaces, interfaces AWS
manages for load balancers, Lambda and endpoints) are refused: a new instance would come up with the old
groups. Tighten those groups instead (``sg_tightener plan`` and a change request), which every instance,
present and future, inherits; or change the launch template.

The database records which groups each asset carries, and every change to that, in the audit trail.
The CLI is ``sg_db.py assets | asset-plan | asset-propose | asset-apply | asset-revert | asset-log``.
"""

from __future__ import annotations

import datetime as dt
import json
import logging

import sg_db
import sg_tightener

LOG = logging.getLogger("sg_assets")
PLAN_SCHEMA = "sg-tightener.asset-plan/v1"
TAG = "sg-tightener:asset"


class AssetError(sg_db.Refused):
    pass


# ------------------------------------------------------------------------------------------ read
def describe_assets(ec2) -> list[dict]:
    """Every network interface with what it is, what it is attached to and its groups."""
    enis = []
    for page in ec2.get_paginator("describe_network_interfaces").paginate():
        enis += page.get("NetworkInterfaces", [])
    instances = sorted({(e.get("Attachment") or {}).get("InstanceId") for e in enis} - {None, ""})
    asg: dict[str, str] = {}
    for i in range(0, len(instances), 100):
        try:
            for res in ec2.describe_instances(InstanceIds=instances[i:i + 100]).get("Reservations", []):
                for inst in res.get("Instances", []):
                    tags = {t["Key"]: t["Value"] for t in inst.get("Tags") or []}
                    asg[inst["InstanceId"]] = (tags.get("aws:autoscaling:groupName")
                                               or ("eks:" + tags["eks:cluster-name"] if tags.get("eks:cluster-name") else ""))  # fmt: skip
        except Exception as exc:  # noqa: BLE001 - without it no asset is known to be auto scaled: say so
            LOG.warning("could not read the instances (auto scaling membership unknown): %s", exc)
    return [asset_of(e, asg) for e in enis]


def asset_of(e: dict, asg: dict) -> dict:
    inst = (e.get("Attachment") or {}).get("InstanceId") or ""
    ips = [a["PrivateIpAddress"] for a in e.get("PrivateIpAddresses") or [] if a.get("PrivateIpAddress")]
    if e.get("PrivateIpAddress") and e["PrivateIpAddress"] not in ips:
        ips.insert(0, e["PrivateIpAddress"])
    ips += [a["Ipv6Address"] for a in e.get("Ipv6Addresses") or [] if a.get("Ipv6Address")]
    return {"eni": e["NetworkInterfaceId"], "instance": inst, "asg": asg.get(inst, ""),
            "kind": "requester-managed" if e.get("RequesterManaged") else (e.get("InterfaceType") or "interface"),
            "vpc_id": e.get("VpcId") or "", "ips": ips, "description": e.get("Description") or "",
            "groups": sorted(g["GroupId"] for g in e.get("Groups") or [])}  # fmt: skip


def why_not_alone(a: dict) -> str:
    """Why this asset cannot have a group of its own ("" when it can)."""
    d = a.get("description", "")
    if a.get("asg", "").startswith("eks:") or d.startswith("aws-K8S") or "eks" in a.get("kind", ""):
        return "it is an EKS node or pod interface: replaced nodes come up with the node group's groups"
    if a.get("asg"):
        return (f"it is in auto scaling group {a['asg']}: a new instance comes up with the launch template's groups. "
                f"Tighten those groups (every instance inherits it), or change the launch template")  # fmt: skip
    if a.get("kind") != "interface":
        return f"AWS manages this interface ({a.get('kind')}{': ' + d if d else ''})"
    if d.startswith("arn:aws:ecs") or "ecs" in d.lower():
        return "it is an ECS task interface: tasks are replaced with the service's groups"
    return ""


def observe_assets(store: sg_db.Store, account: str, region: str, assets: list[dict], actor: str,
                   origin: str = "external") -> list[dict]:  # fmt: skip
    """Record each asset's groups; a change of groups on a known asset is an audit entry of its own, and
    assets that came and went (auto scaling) one entry together. Call inside a transaction."""
    known = {a["eni"]: a for a in list_assets(store, account, region)}
    now = sg_db._now()
    changed = []
    seen = set()
    for a in assets:
        seen.add(a["eni"])
        old = known.get(a["eni"])
        if old is not None and old["groups"] != a["groups"]:
            detail = {"eni": a["eni"], "instance": a["instance"], "asg": a["asg"], "before": old["groups"],
                      "after": a["groups"]}  # fmt: skip
            store.audit(actor, origin, "asset-groups-changed", account, region, ",".join(a["groups"]), detail,
                        "the asset's groups changed outside this tool" if origin == "external" else "")  # fmt: skip
            changed.append(detail)
        store.db.execute("INSERT INTO assets (account, region, eni, instance, asg, kind, vpc_id, ips, groups, description, "
                         "observed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (account, region, eni) DO UPDATE "
                         "SET instance = excluded.instance, asg = excluded.asg, kind = excluded.kind, vpc_id = "
                         "excluded.vpc_id, ips = excluded.ips, groups = excluded.groups, description = "
                         "excluded.description, observed_at = excluded.observed_at",
                         (account, region, a["eni"], a["instance"], a["asg"], a["kind"], a["vpc_id"], json.dumps(a["ips"]),
                          json.dumps(a["groups"]), a["description"], now))  # fmt: skip
    gone = sorted(set(known) - seen)
    for eni in gone:
        store.db.execute("DELETE FROM assets WHERE account = ? AND region = ? AND eni = ?", (account, region, eni))
    added = sorted(seen - set(known))
    if added or gone:
        first = not known
        store.audit(actor, "import" if first else origin, "assets-imported" if first else "assets-came-and-went",
                    account, region, "",
                    {"added": [{"eni": a["eni"], "instance": a["instance"], "asg": a["asg"], "groups": a["groups"]}
                               for a in assets if a["eni"] in added][:500],
                     "added_count": len(added),
                     "removed": [{"eni": e, "instance": known[e]["instance"], "groups": known[e]["groups"]} for e in gone][:500],
                     "removed_count": len(gone)},
                    "first read of the assets" if first else "interfaces created or deleted (auto scaling, replacements)")  # fmt: skip
    return changed


def list_assets(store: sg_db.Store, account: str, region: str) -> list[dict]:
    cols = ("eni", "instance", "asg", "kind", "vpc_id", "ips", "groups", "description", "observed_at")
    return [{**dict(zip(cols, r)), "ips": json.loads(r[5]), "groups": json.loads(r[6])} for r in store.db.execute(
        f"SELECT {', '.join(cols)} FROM assets WHERE account = ? AND region = ? ORDER BY instance, eni", (account, region))]


def read_assets(store: sg_db.Store, ec2, account: str, region: str, actor: str) -> list[dict]:
    """Read every asset from AWS and record it (and any change of groups). Returns the assets."""
    assets = describe_assets(ec2)
    with store:
        observe_assets(store, account, region, assets, actor)
    return assets


def asset_history(store: sg_db.Store, eni: str = "", instance: str = "") -> list[dict]:
    """Every audit entry about this interface (or every interface of this instance), oldest first."""
    needle = eni or instance
    if not needle:
        return []
    cols = ("seq", "at", "actor", "origin", "action", "account", "region", "group_id", "detail", "reason", "ticket")
    out = []
    for row in store.db.execute(f"SELECT {', '.join(cols)} FROM audit WHERE (action LIKE 'asset%' OR action LIKE "
                                f"'request-%') AND detail LIKE ? ORDER BY seq", (f"%{needle}%",)):  # fmt: skip
        e = {**dict(zip(cols, row)), "detail": json.loads(row[8])}
        d = e["detail"]
        many = d.get("added", []) + d.get("removed", []) if e["action"].startswith("assets-") else []
        key = "eni" if eni else "instance"
        if d.get(key) == needle or any(isinstance(x, dict) and x.get(key) == needle for x in many):
            out.append(e)
    return out


# ------------------------------------------------------------------------------------------ plan
def _merged_rules(groups: dict[str, dict], account: str, direction: str) -> dict:
    key = "IpPermissions" if direction == sg_db.IN else "IpPermissionsEgress"
    out: dict = {}
    for g in groups.values():
        for r, d in sg_db.rules_from_permissions(g.get(key) or [], direction, account).items():
            out.setdefault(r, d)
    return out


def plan_asset(ec2, account: str, region: str, approved: dict, eni: str = "", instance: str = "",
               max_rules: int = sg_tightener.DEFAULT_MAX_RULES, by: str = "") -> list[dict]:  # fmt: skip
    """One plan per interface of the asset: the group it should have on its own, from its own flows."""
    assets = [a for a in describe_assets(ec2) if (eni and a["eni"] == eni) or (instance and a["instance"] == instance)]
    if not assets:
        raise AssetError(f"no network interface {eni or 'for instance ' + instance} in {account} {region}")
    raw = {e["NetworkInterfaceId"]: e for e in ec2.describe_network_interfaces(
        NetworkInterfaceIds=[a["eni"] for a in assets])["NetworkInterfaces"]}  # fmt: skip
    flows_all = approved.get("flows")
    if flows_all is None:
        raise AssetError("approved.json has no flows (approved/v1): re-run sg_tightener analyse for per-interface evidence")
    in_any_flow = {f["src"] for f in flows_all}
    plans = []
    for a in assets:
        why = why_not_alone(a)
        if why:
            raise AssetError(f"{a['eni']} cannot have a group of its own: {why}")
        groups = sg_tightener.describe_groups(ec2, a["groups"])
        ingress = _merged_rules(groups, account, sg_db.IN)
        egress = _merged_rules(groups, account, sg_db.OUT)
        synthetic = {"GroupId": f"asset:{a['eni']}", "GroupName": f"sgt-{a['eni']}", "VpcId": a["vpc_id"],
                     "IpPermissions": [sg_db.to_permission(r, d) for r, d in sorted(ingress.items())]}  # fmt: skip
        iface = {**raw[a["eni"]], "Groups": [{"GroupId": synthetic["GroupId"]}]}
        ips = set(a["ips"])
        mine = [f for f in flows_all if f.get("interface") == a["eni"] or (not f.get("interface") and f.get("dst") in ips)]
        hand = sorted(set(approved.get("ips") or []) - in_any_flow)  # added by hand: kept wherever a rule admits them
        plan = sg_tightener.build_plan([synthetic], sorted({f["src"] for f in mine}) + hand, flows=mine,
                                       interfaces=[iface], max_rules=max_rules, region=region)  # fmt: skip
        final = dict(ingress)
        removed, added = {}, {}
        for pg in plan["groups"]:
            for r in sg_db.rules_from_permissions(pg["revoke"], sg_db.IN, account):
                if r in final:
                    removed[r] = final.pop(r)
            for r, d in sg_db.rules_from_permissions(pg["authorise"], sg_db.IN, account).items():
                if r not in final:
                    final[r] = d
                    added[r] = d
        if len(final) + len(egress) > max_rules * 2:
            LOG.warning("%s: %d inbound and %d outbound rules: over the usual quota; review before proposing",
                        a["eni"], len(final), len(egress))  # fmt: skip
        doc = {"schema": PLAN_SCHEMA, "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "account": account,
               "region": region, "eni": a["eni"], "instance": a["instance"], "vpc_id": a["vpc_id"], "ips": a["ips"],
               "from_groups": a["groups"], "group_name": f"sgt-{a['eni']}",
               "ingress": [sg_db._rule_json(r, d) for r, d in sorted(final.items())],
               "egress": [sg_db._rule_json(r, d) for r, d in sorted(egress.items())],
               "narrowed": {"removed": [sg_db._rule_json(r, d) for r, d in sorted(removed.items())],
                            "added": [sg_db._rule_json(r, d) for r, d in sorted(added.items())]},
               "evidence": {"flows": len(mine), "sources": len({f["src"] for f in mine}), "hand_added": len(hand)}}  # fmt: skip
        plans.append(sg_tightener.sign(doc, by))
    return plans


def plan_text(p: dict) -> list[str]:
    head = (f"{p['eni']}{' (' + p['instance'] + ')' if p['instance'] else ''}: a group of its own, {p['group_name']}, "
            f"in place of {', '.join(p['from_groups'])}; {p['evidence']['flows']} flow(s) from "
            f"{p['evidence']['sources']} source(s)")  # fmt: skip
    out = [head]
    for r in p["narrowed"]["removed"]:
        out.append("  - " + sg_db.rule_text(sg_db._rule_tuple(r), r.get("description", "")))
    for r in p["narrowed"]["added"]:
        out.append("  + " + sg_db.rule_text(sg_db._rule_tuple(r), r.get("description", "")))
    kept = len(p["ingress"]) - len(p["narrowed"]["added"])
    out.append(f"  {kept} inbound rule(s) kept as they are, {len(p['egress'])} outbound")
    return out


# ------------------------------------------------------------------------------------------ requests
def propose(store: sg_db.Store, plan: dict, actor: str, reason: str, ticket: str = "") -> int:
    """An asset plan as a change request. Call inside a transaction."""
    if plan.get("schema") != PLAN_SCHEMA:
        raise AssetError("not an asset plan (sg_db.py asset-plan writes one)")
    sg_tightener.check_integrity(plan, "asset plan", "", allow_modified=False)
    if not reason.strip():
        raise AssetError("a reason is required: it goes in the audit trail")
    for c in store.requests("pending", plan["account"], plan["region"]) + store.requests("approved", plan["account"], plan["region"]):
        if c.get("kind") == "asset" and c["changes"].get("eni") == plan["eni"]:
            raise AssetError(f"request #{c['id']} for {plan['eni']} is already {c['status']}")
    body = {k: plan[k] for k in ("eni", "instance", "vpc_id", "from_groups", "group_name", "ingress", "egress",
                                 "narrowed", "evidence", "generated_at")}  # fmt: skip
    body["kind"] = "asset"
    cur = store.db.execute("INSERT INTO requests (at, account, region, proposer, reason, ticket, changes, status) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')",
                           (sg_db._now(), plan["account"], plan["region"], actor, reason, ticket,
                            json.dumps(body, sort_keys=True)))  # fmt: skip
    rid = cur.lastrowid
    store.audit(actor, "tool", "asset-request-proposed", plan["account"], plan["region"], ",".join(plan["from_groups"]),
                {"request": rid, "eni": plan["eni"], "instance": plan["instance"], "from_groups": plan["from_groups"],
                 "inbound": len(plan["ingress"]), "outbound": len(plan["egress"]), **plan["narrowed"]}, reason, ticket)  # fmt: skip
    if not store.approvals():
        store._approve(rid, actor, "approvals are off")
    return rid


def _perms(rules: list[dict]) -> list[dict]:
    return [sg_db.to_permission(sg_db._rule_tuple(r), r.get("description", "")) for r in rules]


def apply(store: sg_db.Store, ec2, account: str, rid: int, actor: str) -> dict:
    """Carry out an approved asset request: create the group, give it the rules, swap the interface onto it."""
    r = store._request(rid)
    if r.get("kind") != "asset":
        raise AssetError(f"request #{rid} is not an asset request: sg_db.py apply applies rule changes")
    if r["status"] != "approved":
        raise AssetError(f"request #{rid} is {r['status']}: it must be approved by a second person first")
    region, plan = r["region"], r["changes"]
    store.require_enforce(account, "change an asset's security groups")
    ext = sg_db.ensure_current(store, ec2, account, region, actor)
    if ext:
        raise AssetError(f"{len(ext)} group(s) were changed in AWS outside this tool; review them with "
                         f"sg_db.py reconcile --regions {region} first")  # fmt: skip
    now = {a["eni"]: a for a in describe_assets(ec2)}
    a = now.get(plan["eni"])
    if a is None:
        raise AssetError(f"{plan['eni']} no longer exists")
    if a["groups"] != sorted(plan["from_groups"]):
        raise AssetError(f"{plan['eni']} now carries {', '.join(a['groups'])}, not {', '.join(plan['from_groups'])} "
                         f"as when it was planned: plan it again")  # fmt: skip
    why = why_not_alone(a)
    if why:
        raise AssetError(f"{a['eni']} cannot have a group of its own: {why}")
    perms = sg_db.check_permissions(ec2, a["groups"][:1], [a])
    with store:
        store.record_permissions(account, region, actor, perms)
    bad = sg_db._permission_problems(perms)
    if bad:
        raise AssetError("nothing was changed: this identity cannot do every step (checked with DryRun):\n  " + "\n  ".join(bad))

    name = f"{plan['group_name']}-{dt.datetime.now(dt.timezone.utc):%Y%m%d%H%M}"
    gid = ec2.create_security_group(
        GroupName=name, VpcId=a["vpc_id"],
        Description=f"sg-tightener: {a['eni']} only, from {', '.join(a['groups'])} (request {rid})"[:255],
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [
            {"Key": TAG, "Value": a["eni"]}, {"Key": "sg-tightener:request", "Value": str(rid)},
            {"Key": "Name", "Value": name}]}])["GroupId"]  # fmt: skip
    failed = []
    default_out = {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    want_out = _perms(plan["egress"])
    if not any(p.get("IpProtocol") == "-1" and {"CidrIp": "0.0.0.0/0"} in [{"CidrIp": x["CidrIp"]} for x in p.get("IpRanges", [])]
               for p in want_out):  # fmt: skip
        try:
            ec2.revoke_security_group_egress(GroupId=gid, IpPermissions=[default_out])
        except Exception as exc:  # noqa: BLE001
            failed.append(f"revoke default outbound: {exc}")
    for direction, perms_ in (("ingress", _perms(plan["ingress"])), ("egress", want_out)):
        call = ec2.authorize_security_group_ingress if direction == "ingress" else ec2.authorize_security_group_egress
        for p in perms_:
            try:
                call(GroupId=gid, IpPermissions=[p])
            except Exception as exc:  # noqa: BLE001 - recorded; a duplicate (the default outbound) is harmless
                if "Duplicate" not in str(exc):
                    failed.append(f"{direction} {p}: {exc}")
    live = sg_db.read_live(ec2, account, [gid]).get(gid)
    with store:
        store.synced(account, region, gid, live, actor, "apply", "asset-group-created", f"request #{rid}: {r['reason']}",
                     r["ticket"], desired_too=True)  # fmt: skip
    if failed:
        with store:
            store.audit(actor, "apply", "asset-swap-skipped", account, region, gid,
                        {"request": rid, "eni": a["eni"], "failed": failed}, "a rule could not be added: not swapped")  # fmt: skip
        return {"group": gid, "swapped": False, "failed": failed}
    ec2.modify_network_interface_attribute(NetworkInterfaceId=a["eni"], Groups=[gid])
    after = {**a, "groups": [gid]}
    with store:
        observe_assets(store, account, region, [after] + [x for e, x in now.items() if e != a["eni"]], actor, "apply")
        # observe_assets recorded the swap as "asset-groups-changed" with origin apply; name the request too
        store.audit(actor, "apply", "asset-swapped", account, region, gid,
                    {"request": rid, "eni": a["eni"], "instance": a["instance"], "before": a["groups"], "after": [gid]},
                    f"request #{rid}: {r['reason']}", r["ticket"])  # fmt: skip
        store.db.execute("UPDATE requests SET status = 'applied', applied_at = ? WHERE id = ?", (sg_db._now(), rid))
    return {"group": gid, "swapped": True, "failed": [], "before": a["groups"]}


def revert(store: sg_db.Store, ec2, account: str, region: str, eni: str, actor: str, reason: str) -> dict:
    """Put the interface back on the groups it had before the last swap. Allowed in any mode (an undo)."""
    if not reason.strip():
        raise AssetError("a reason is required: it goes in the audit trail")
    swaps = [e for e in asset_history(store, eni=eni) if e["action"] == "asset-swapped"]
    if not swaps:
        raise AssetError(f"sg-tightener never swapped {eni}'s groups")
    before = swaps[-1]["detail"]["before"]
    now = {a["eni"]: a for a in describe_assets(ec2)}
    a = now.get(eni)
    if a is None:
        raise AssetError(f"{eni} no longer exists")
    ec2.modify_network_interface_attribute(NetworkInterfaceId=eni, Groups=before)
    with store:
        observe_assets(store, account, region, [{**a, "groups": sorted(before)}] + [x for e, x in now.items() if e != eni],
                       actor, "revert")  # fmt: skip
        store.audit(actor, "revert", "asset-reverted", account, region, ",".join(before),
                    {"eni": eni, "instance": a["instance"], "before": a["groups"], "after": sorted(before)}, reason)
    return {"eni": eni, "groups": sorted(before), "was": a["groups"]}
