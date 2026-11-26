#!/usr/bin/env python3
"""Remediate an account: from a look back of its VPC flow logs (three months by default), what every security
group's inbound rules should become, which groups can then be merged, and one set of change requests for all
of it.

For each inbound rule the flow logs decide: narrow the sources to those seen (with headroom), narrow a port range
to the ports used, remove a rule nothing used, or leave it (in use across the range, open to everyone, or not
enough evidence). Then groups in the same VPC with the same outbound rules whose tightened inbound rules are the
same, or would be with one more port and no new source, are merged: their interfaces move onto one of them.

The person proposing does the analysis and unticks anything sensitive; the person approving only approves.
"""

from __future__ import annotations

import ipaddress
import json

import sg_assets
import sg_db
import sg_review

DAY = 86400
DEFAULT_DAYS = 90
LOOKBACKS = (30, 90, 180, 365)
ACTIONABLE = ("tighten", "remove", "ports")
MERGE_EXTRA_PORTS = 1  # a merge may give a group at most this many more ports (from sources it already lets in)
MERGE_EXTRA_ADDRESSES = 256  # and at most this many more IPv4 addresses on the ports it has


class RemediateError(Exception):
    pass


# ------------------------------------------------------------------------------------------- one rule
def port_ranges(rule: dict, used: list) -> list | None:
    """The ports a rule needs, as ranges, from the (protocol, port) seen through it: None when it cannot be
    narrowed (all protocols, one port already, nothing seen, or too many gaps to be worth it)."""
    proto, lo, hi = str(rule["proto"]), int(rule["from"]), int(rule["to"])
    if proto not in ("6", "17") or hi <= lo:
        return None
    eph = sg_review.EPHEMERAL
    # Records folded into EPHEMERAL itself are replies to connections the interface opened. Security groups are
    # stateful, so replies need no inbound rule: they are left out, and a rule is narrowed to the real ports seen.
    ports = sorted({int(p) for pr, p in used if str(pr) == proto and lo <= int(p) <= hi and int(p) != eph})
    if not ports:
        return None
    out: list = []
    for p in ports:
        a, b = p, p
        if out and a <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    if len(out) > 8 or sum(b - a + 1 for a, b in out) >= hi - lo + 1:
        return None
    return out


def _cidr_size(cidr: str) -> int:
    try:
        return ipaddress.ip_network(cidr, strict=False).num_addresses
    except ValueError:
        return 0


def _internal(source: str, total: int) -> int:
    """How many of a source's IPv4 addresses are internal (RFC 1918 and 100.64/10). Another security group is
    internal; a prefix list or anything else that is not an address range counts as external."""
    if source.startswith("sg-"):
        return total
    try:
        net = ipaddress.ip_network(source, strict=False)
    except ValueError:
        return 0
    if net.version != 4:
        return 0
    n = 0
    for c in sg_review.PRIVATE_V4:
        p = ipaddress.ip_network(c)
        if net.overlaps(p):
            n += min(net.num_addresses, p.num_addresses)
    return min(n, total)


def plan_rule(r: dict) -> dict:
    """One rule of the review's table: the old rule, the new rules (None to leave it, [] to remove it) and what
    goes."""
    span = 1 if str(r["proto"]) in ("-1", "1") else int(r["to"]) - int(r["from"]) + 1
    status = r.get("status", "")
    cidrs = list(r.get("suggest") or [])
    ranges = port_ranges(r, r.get("ports_used") or []) if status in ("tighten", "used") else None
    if status == "unused":
        action, new = "remove", []
    elif status == "tighten" and cidrs:
        action = "tighten"
        new = [{"proto": str(r["proto"]), "from": a, "to": b, "source": c}
               for c in cidrs for a, b in (ranges or [[int(r["from"]), int(r["to"])]])]  # fmt: skip
    elif status == "used" and ranges:
        action = "ports"
        new = [{"proto": str(r["proto"]), "from": a, "to": b, "source": r["source"]} for a, b in ranges]
    else:
        action = "keep" if status == "used" else "open" if status == "open" else "wait"
        new = None
    allowed = int(r.get("allowed") or 0)
    new_addr = 0 if new == [] else int(r.get("suggest_size") or allowed) if action == "tighten" else allowed
    new_ports = 0 if new == [] else sum(b - a + 1 for a, b in ranges) if ranges else span
    internal = _internal(r["source"], allowed)
    if new is None:
        new_internal = internal
    elif new == []:
        new_internal = 0
    elif action == "tighten":
        new_internal = min(new_addr, sum(_internal(c, _cidr_size(c)) for c in dict.fromkeys(cidrs)))
    else:
        new_internal = internal
    return {"key": f"{r['region']}|{r['group']}|{r['proto']}|{r['from']}|{r['to']}|{r['source']}",
            "region": r["region"], "group": r["group"], "gname": r.get("gname", ""), "proto": str(r["proto"]),
            "from": int(r["from"]), "to": int(r["to"]), "ports": r.get("ports", ""), "source": r["source"],
            "v6": ":" in r["source"], "desc": r.get("desc", ""), "status": status, "note": r.get("note", ""),
            "action": action, "new": new, "addresses": allowed,
            "new_addresses": allowed if new is None else new_addr,
            "internal": internal, "new_internal": new_internal,
            "cut_addresses": 0 if new is None else max(0, allowed - new_addr),
            "port_count": span, "new_ports": span if new is None else new_ports,
            "cut": bool(r.get("cut")), "seen": int(r.get("here") or 0), "last_used": r.get("last_used"), "days": r.get("days"),
            "flows": r.get("flows"),
            "mix": dict(r.get("mix") or {}), "top": [t.get("src") for t in (r.get("top") or [])][:5],
            "external": r.get("ext"), "urgent": urgent(r, action)}  # fmt: skip


def urgent(r: dict, action: str) -> bool:
    """Critical: a rule open to the whole internet (0.0.0.0/0 or ::/0) through which no internet address was seen
    in the flow logs read. Everything it lets in from outside is exposure nothing uses, so narrowing or removing
    it comes first. Also on evidence cut at the row limit (the busiest connections were read): acting on what was
    seen is the user's call, and Rejected traffic opens a rule again if something outside was missed."""
    return r.get("source") in ("0.0.0.0/0", "::/0") and action in ("tighten", "ports", "remove") and r.get("ext") == 0


def _tup(direction: str, proto, frm, to, source: str) -> tuple:
    p = sg_db._proto(str(proto))
    return (direction, p, -1, -1, source) if p == "-1" else (direction, p, int(frm), int(to), source)


# ------------------------------------------------------------------------------------------- the account
def flow_status(doc: dict | None) -> str:
    """read: flow logs read; not-read: flow logs exist in CloudWatch Logs but none read; no-flow-logs: none of
    the account's regions sends VPC flow logs to CloudWatch Logs (turn them on); unknown: never looked."""
    if not doc:
        return "unknown"
    if any(c.get("st") in ("ok", "cut") for c in doc.get("chunks") or []):
        return "read"
    looked = [x for x in (doc.get("regions") or {}).values() if x.get("snapshot")]
    if looked and not any(x.get("query_sets") for x in looked):
        return "no-flow-logs"
    return "not-read" if looked else "unknown"


def stored(doc: dict) -> tuple[float, float] | None:
    """The first and last moment of flow logs read, or None."""
    ok = [c for c in doc.get("chunks") or [] if c.get("st") in ("ok", "cut")]
    return (min(c["s"] for c in ok), max(c["e"] for c in ok)) if ok else None


def bounds(doc: dict, days: int, start: float | None = None, end: float | None = None) -> tuple[float, float]:
    """The evidence window: ``start`` to ``end`` when given, else the last ``days`` days of what was read."""
    have = stored(doc)
    if end is None:
        end = have[1] if have else 0.0
    if start is None:
        start = end - days * DAY
    return float(start), float(end)


def window(doc: dict, days: int, start: float | None = None, end: float | None = None) -> tuple[dict, float]:
    """The read cut to the evidence window, and how many days of flow logs that holds. A slice is kept only when
    it lies wholly inside the window, so a day left out (an attack, say) gives no evidence at all."""
    if not stored(doc):
        return {**doc, "chunks": []}, 0.0
    start, end = bounds(doc, days, start, end)
    kept = [c for c in doc["chunks"] if c["s"] >= start and c["e"] <= end]
    ok = [c for c in kept if c.get("st") in ("ok", "cut")]
    if not ok:
        return {**doc, "chunks": kept}, 0.0
    return {**doc, "chunks": kept}, round((max(c["e"] for c in ok) - min(c["s"] for c in ok)) / DAY, 1)


def plan(doc: dict, days: int, groups: dict, assets: dict, start: float | None = None,
         end: float | None = None) -> dict:
    """The remediation of one account. ``groups`` is {region: {gid: {name, vpc, description, in, out}}} with
    ``in`` and ``out`` {rule tuple: description} from the console's database, and ``assets`` {region: [asset]}."""
    start, end = bounds(doc, days, start, end)
    days = max(1, round((end - start) / DAY)) if stored(doc) else days
    w, have = window(doc, days, start, end)
    rows = [plan_rule(r) for r in (sg_review.build(w, "24h", "", "", sg_review.load_names()).get("rules") or [])] if w["chunks"] else []
    by_group: dict = {}
    for r in rows:
        by_group.setdefault((r["region"], r["group"]), []).append(r)
    out = []
    for region in sorted(groups):
        on: dict = {}
        for a in assets.get(region) or []:
            for g in a.get("groups") or []:
                on.setdefault(g, []).append(a)
        for gid, g in sorted(groups[region].items()):
            rs = by_group.get((region, gid), [])
            if not on.get(gid) and not rs:
                continue  # on no interface: protects nothing, left out
            acts = [r for r in rs if r["action"] in ACTIONABLE]
            mix: dict = {}
            for r in rs:
                for k, n in r["mix"].items():
                    mix[k] = mix.get(k, 0) + n
            v4 = [r for r in rs if not r["v6"] and r["action"] != "open"]
            out.append({"id": gid, "region": region, "name": g.get("name", ""), "vpc": g.get("vpc", ""),
                        "description": g.get("description", ""), "enis": len(on.get(gid, [])),
                        "movable": bool(on.get(gid)) and all(not sg_assets.why_not_alone(a) for a in on[gid]),
                        "rules_in": len(g.get("in") or {}), "rules_out": len(g.get("out") or {}),
                        "rules": rs, "changes": len(acts), "urgent": sum(1 for r in acts if r.get("urgent")),
                        "addresses": sum(r["addresses"] for r in v4), "new_addresses": sum(r["new_addresses"] for r in v4),
                        "internal": sum(r["internal"] for r in v4), "new_internal": sum(r["new_internal"] for r in v4),
                        "addresses6": sum(r["addresses"] for r in rs if r["v6"]),
                        "new_addresses6": sum(r["new_addresses"] for r in rs if r["v6"]),
                        "ports": sum(r["port_count"] for r in rs), "new_ports": sum(r["new_ports"] for r in rs),
                        "actions": {k: sum(1 for r in rs if r["action"] == k) for k in
                                    ("tighten", "ports", "remove", "keep", "open", "wait")},
                        "open": sum(1 for r in rs if r["action"] == "open"), "mix": mix})  # fmt: skip
    out.sort(key=lambda g: (-(g["addresses"] - g["new_addresses"]), -g["changes"], g["name"]))
    merges = find_merges(out, groups)
    have_range = stored(doc)
    return {"days": days, "have_days": have, "status": flow_status(doc), "groups": out, "merges": merges,
            "from": start, "to": end, "stored_from": have_range[0] if have_range else None,
            "stored_to": have_range[1] if have_range else None,
            "totals": totals(out, merges, groups), "categories": [{"key": k, "name": sg_review.CAT_NAME[k]} for k in sg_review.CATS]}  # fmt: skip


def after(g: dict, groups: dict) -> set:
    """A group's inbound rules once its plan is applied."""
    have = set((groups[g["region"]][g["id"]].get("in") or {}).keys())
    for r in g["rules"]:
        if r["action"] in ACTIONABLE:
            have.discard(_tup("in", r["proto"], r["from"], r["to"], r["source"]))
            have |= {_tup("in", n["proto"], n["from"], n["to"], n["source"]) for n in r["new"]}
    return have


def find_merges(plan_groups: list[dict], groups: dict, chosen: set | None = None) -> list[dict]:
    """Groups that can become one once tightened: same region, VPC and outbound rules, and every member keeps its
    near enough the same: see _fits. Only groups whose every interface can be moved
    (not auto scaling, EKS, ECS or AWS-managed) are merged."""
    buckets: dict = {}
    for g in plan_groups:
        if not g["movable"] or (chosen is not None and g["id"] not in chosen):
            continue
        outb = frozenset((groups[g["region"]][g["id"]].get("out") or {}).keys())
        buckets.setdefault((g["region"], g["vpc"], outb), []).append((g, after(g, groups)))
    merges = []
    for (region, vpc, _), items in buckets.items():
        items.sort(key=lambda x: (-x[0]["enis"], x[0]["name"]))
        clusters: list = []
        for g, rules in items:
            if not rules:
                continue
            for cl in clusters:
                union = cl["union"] | rules
                if all(_fits(m_rules, union) for _, m_rules in cl["members"] + [(g, rules)]):
                    cl["members"].append((g, rules))
                    cl["union"] = union
                    break
            else:
                clusters.append({"members": [(g, rules)], "union": set(rules)})
        for cl in clusters:
            if len(cl["members"]) < 2:
                continue
            target = cl["members"][0][0]
            merges.append({"id": "+".join(sorted(m["id"] for m, _ in cl["members"])), "region": region, "vpc": vpc,
                           "target": target["id"], "target_name": target["name"],
                           "members": [{"id": m["id"], "name": m["name"], "enis": m["enis"],
                                        "extra": [sg_db._rule_json(t, "") for t in sorted(cl["union"] - r)],
                                        **_gain(r, cl["union"])}
                                       for m, r in cl["members"]],
                           "enis": sum(m["enis"] for m, _ in cl["members"]), "rules": len(cl["union"]),
                           "union": [sg_db._rule_json(t, "") for t in sorted(cl["union"])]})  # fmt: skip
    return merges


OPEN = ("0.0.0.0/0", "::/0")


def _private(net) -> bool:
    """Inside the private ranges the product uses. Not ipaddress's is_private, which also counts documentation
    and reserved ranges (203.0.113.0/24, 2001:db8::/32) that are public as far as a security group goes."""
    pool = sg_review.PRIVATE_V4 if net.version == 4 else sg_review.PRIVATE_V6
    return any(net.subnet_of(ipaddress.ip_network(c)) for c in pool)


def _fits(own: set, union: set) -> bool:
    """Whether a member can take on the merged rules. Nearly identical is enough: on the ports it already has it may
    gain a few more private addresses (MERGE_EXTRA_ADDRESSES in all, an IPv6 /64 each at most; never a public one), and it may gain at most
    MERGE_EXTRA_PORTS new ports, from sources it already lets in. Never from everyone, and never a new risky port
    (remote admin, databases and the like)."""
    extra = union - own
    if not extra:
        return True
    if any(t[4] in OPEN for t in extra):
        return False
    have_ports, sources = {t[:4] for t in own}, {t[4] for t in own}
    new_ports = {t[:4] for t in extra} - have_ports
    if len(new_ports) > MERGE_EXTRA_PORTS:
        return False
    if any(t[:4] in new_ports and (t[4] not in sources or sg_review.rule_port_class(_as_rule(t)).get("risky"))
           for t in extra):  # fmt: skip
        return False
    more = 0
    for t in extra:
        if t[:4] in new_ports:
            continue
        try:
            net = ipaddress.ip_network(t[4], strict=False)
        except ValueError:
            return False  # a group or prefix-list source: merged only when it is already there
        if not _private(net):
            return False  # a merge never lets a group in from a new public address
        if net.version == 6:
            if net.prefixlen < 64:
                return False
        else:
            more += net.num_addresses
    return more <= MERGE_EXTRA_ADDRESSES


def _gain(own: set, union: set) -> dict:
    """What a member takes on in a merge, in words a person can check: new ports, and how many more IP addresses."""
    extra = union - own
    have = {t[:4] for t in own}
    ports = sorted({t[:4] for t in extra} - have)
    v4 = sum(ipaddress.ip_network(t[4], strict=False).num_addresses for t in extra
             if t[:4] in have and _is_net(t[4]) and ":" not in t[4])  # fmt: skip
    return {"gain_ports": [{"proto": p[1], "from": p[2], "to": p[3]} for p in ports], "gain_addresses": v4,
            "gain_v6": sum(1 for t in extra if t[:4] in have and ":" in t[4])}


def _is_net(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False)
    except ValueError:
        return False
    return True


def _as_rule(t: tuple) -> dict:
    proto = {"tcp": "6", "udp": "17", "icmp": "1"}.get(t[1], t[1])
    return {"proto": proto, "from": 0 if t[2] == -1 else t[2], "to": 65535 if t[3] == -1 else t[3]}


def totals(plan_groups: list[dict], merges: list[dict], groups: dict) -> dict:
    mix: dict = {}
    for g in plan_groups:
        for k, n in g["mix"].items():
            mix[k] = mix.get(k, 0) + n
    merged_away = sum(len(m["members"]) - 1 for m in merges)
    in_merge = {(m["region"], x["id"]) for m in merges for x in m["members"]}
    rules_after = sum(len(after(g, groups)) + g["rules_out"] for g in plan_groups if (g["region"], g["id"]) not in in_merge)
    rules_after += sum(m["rules"] + next(g["rules_out"] for g in plan_groups if g["id"] == m["target"] and g["region"] == m["region"])
                       for m in merges)  # fmt: skip
    return {"groups": len(plan_groups), "groups_after": len(plan_groups) - merged_away,
            # every group in the account, those on no interface too (they protect nothing; left out of the plan)
            "groups_all": sum(len(v) for v in groups.values()),
            "groups_changed": sum(1 for g in plan_groups if g["changes"]),
            "rules": sum(g["rules_in"] + g["rules_out"] for g in plan_groups), "rules_after": rules_after,
            "changes": sum(g["changes"] for g in plan_groups),
            "urgent": sum(g["urgent"] for g in plan_groups),
            "addresses": sum(g["addresses"] for g in plan_groups), "new_addresses": sum(g["new_addresses"] for g in plan_groups),
            "addresses6": sum(g["addresses6"] for g in plan_groups), "new_addresses6": sum(g["new_addresses6"] for g in plan_groups),
            "ports": sum(g["ports"] for g in plan_groups), "new_ports": sum(g["new_ports"] for g in plan_groups),
            "interfaces": sum(g["enis"] for g in plan_groups), "mix": mix,
            "removed": sum(g["actions"]["remove"] for g in plan_groups), "open": sum(g["open"] for g in plan_groups),
            "wait": sum(g["actions"]["wait"] for g in plan_groups),
            "incomplete": sum(1 for g in plan_groups for r in g["rules"] if r.get("cut") and r["action"] in ACTIONABLE), "keep": sum(g["actions"]["keep"] for g in plan_groups),
            "narrowed": sum(g["actions"]["tighten"] + g["actions"]["ports"] for g in plan_groups)}  # fmt: skip


# ------------------------------------------------------------------------------------------- proposing
def propose(store: sg_db.Store, account: str, p: dict, groups: dict, assets: dict, chosen: list[str],
            merge_ids: list[str], actor: str, ticket: str = "") -> list[dict]:
    """The chosen groups' changes as one rule request per region, and each chosen merge as a request of its own
    (applied after the rules, it moves the members' interfaces onto the target). Returns the requests made."""
    keep = set(chosen)
    picked = [g for g in p["groups"] if g["id"] in keep and g["changes"]]
    merges = [m for m in find_merges(p["groups"], groups, keep) if m["id"] in set(merge_ids)]
    if not picked and not merges:
        raise RemediateError("nothing chosen to change")
    made = []
    days = p["have_days"] or p["days"]
    regions = sorted({g["region"] for g in picked} | {m["region"] for m in merges})
    for region in regions:
        changes = []
        for g in (x for x in picked if x["region"] == region):
            for r in g["rules"]:
                if r["action"] not in ACTIONABLE:
                    continue
                changes.append((g["id"], "remove", _tup("in", r["proto"], r["from"], r["to"], r["source"]), r["desc"]))
                changes += [(g["id"], "add", _tup("in", n["proto"], n["from"], n["to"], n["source"]), r["desc"]) for n in r["new"]]
        for m in (x for x in merges if x["region"] == region):
            have = after(next(g for g in p["groups"] if g["id"] == m["target"] and g["region"] == region), groups)
            changes += [(m["target"], "add", t, "merged") for t in
                        sorted(sg_db._rule_tuple(x) for x in m["union"]) if t not in have]  # fmt: skip
        n_rules = sum(1 for c in changes if c[1] == "remove")
        cut = sum(g["addresses"] - g["new_addresses"] for g in picked if g["region"] == region)
        if changes:
            reason = (f"Remediate {account} {region}: {len([g for g in picked if g['region'] == region])} group(s), "
                      f"{n_rules} rule(s) cut to what {days:g} days of VPC flow logs show in use "
                      f"({cut:,} fewer IPv4 addresses let in)")  # fmt: skip
            with store:
                rid = store.propose(account, region, actor, reason, ticket, changes)
            if rid:
                made.append({"id": rid, "kind": "rules", "region": region, "changes": len(changes)})
        for m in (x for x in merges if x["region"] == region):
            members = [x["id"] for x in m["members"] if x["id"] != m["target"]]
            enis = {a["eni"]: sorted(a["groups"]) for a in assets.get(region) or [] if set(a["groups"]) & set(members)}
            body = {"kind": "merge", "target": m["target"], "target_name": m["target_name"], "members": members,
                    "names": {x["id"]: x["name"] for x in m["members"]}, "enis": enis, "need": m["union"],
                    "vpc": m["vpc"]}  # fmt: skip
            reason = (f"Merge {len(members) + 1} groups into {m['target_name']} ({m['target']}) in {region}: "
                      f"after tightening they allow the same traffic; {len(enis)} interface(s) move")  # fmt: skip
            with store:
                mid = store.db.execute("INSERT INTO requests (at, account, region, proposer, reason, ticket, changes, status) "
                                       "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending') RETURNING id",
                                       (sg_db._now(), account, region, actor, reason, ticket,
                                        json.dumps(body, sort_keys=True))).fetchone()[0]  # fmt: skip
                store.audit(actor, "tool", "merge-request-proposed", account, region, ",".join([m["target"]] + members),
                            {"request": mid, "target": m["target"], "members": members, "enis": sorted(enis)}, reason, ticket)
                if not store.approvals():
                    store._approve(mid, actor, "approvals are off")
            made.append({"id": mid, "kind": "merge", "region": region, "enis": len(enis)})
    return made


# ------------------------------------------------------------------------------------------- applying a merge
def propose_block(store: sg_db.Store, account: str, region: str, src: str, subnets: list, actor: str,
                  reason: str = "", ticket: str = "", detail: dict | None = None) -> dict:
    """A change request to block one internet source at the network ACLs of the subnets it reached (a load
    balancer's): a deny for all traffic from it, ahead of the ACL's allows. Approved like any other request; on
    Apply each subnet's ACL gets the entry. Addresses inside your network are refused: find the host instead."""
    try:
        ip = ipaddress.ip_address(src)
    except ValueError:
        raise RemediateError(f"{src!r} is not an IP address")
    if not sg_review._is_public(str(ip)):
        raise RemediateError(f"{src} is inside your network (or reserved): find the host and why it misbehaves, do not block it")
    subnets = sorted({str(s) for s in subnets if str(s).startswith("subnet-")})
    if not subnets:
        raise RemediateError("no subnet to block it at: read the account's flow logs again")
    cidr = f"{ip}/{32 if ip.version == 4 else 128}"
    for r in store.requests(account=account, region=region):
        c = r["changes"]
        if r["kind"] == "block" and c.get("cidr") == cidr and r["status"] in ("pending", "approved"):
            raise RemediateError(f"request #{r['id']} already blocks {cidr} ({r['status']})")
    body = {"kind": "block", "cidr": cidr, "subnets": subnets, **{k: v for k, v in (detail or {}).items()
                                                                 if k in ("lbs", "vpc", "resets", "share", "name", "why")}}  # fmt: skip
    reason = reason.strip() or (f"Block {cidr} at the network ACL of {len(subnets)} subnet(s) in {region}: "
                                f"{(detail or {}).get('why') or 'connections reset'}")  # fmt: skip
    with store:
        rid = store.db.execute("INSERT INTO requests (at, account, region, proposer, reason, ticket, changes, status) "
                               "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending') RETURNING id",
                               (sg_db._now(), account, region, actor, reason, ticket, json.dumps(body, sort_keys=True))).fetchone()[0]  # fmt: skip
        store.audit(actor, "tool", "block-request-proposed", account, region, ",".join(subnets),
                    {"request": rid, **body}, reason, ticket)  # fmt: skip
        if not store.approvals():
            store._approve(rid, actor, "approvals are off")
    return {"id": rid, "kind": "block", "region": region, "cidr": cidr, "subnets": subnets,
            "status": store._request(rid)["status"]}  # fmt: skip


NACL_FIRST = 1  # deny entries go in at the lowest free rule number below the ACL's first inbound allow


def _free_rule_number(entries: list) -> int | None:
    """The lowest unused inbound rule number that sorts before every inbound allow (ACLs stop at the first
    match), or None when the allows start at 1 with no gap."""
    inbound = [e for e in entries if not e.get("Egress") and e.get("RuleNumber", 32767) < 32767]
    used = {e["RuleNumber"] for e in inbound}
    first_allow = min((e["RuleNumber"] for e in inbound if e.get("RuleAction") == "allow"), default=32767)
    return next((n for n in range(NACL_FIRST, first_allow) if n not in used), None)


def apply_block(store: sg_db.Store, ec2, account: str, rid: int, actor: str) -> dict:
    """Carry out an approved block: each subnet's network ACL gets an inbound deny for the source, numbered
    ahead of its allows. An ACL that already denies it is left alone; one shared by several subnets is changed
    once. The ACL entries can be deleted in AWS to undo it (each one is in the audit trail)."""
    r = store._request(rid)
    if r.get("kind") != "block":
        raise RemediateError(f"request #{rid} is not a block")
    if r["status"] != "approved":
        raise RemediateError(f"request #{rid} is {r['status']}: it must be approved by a second person first")
    region, b = r["region"], r["changes"]
    store.require_enforce(account, "block a source at the network ACL")
    acls = ec2.describe_network_acls(Filters=[{"Name": "association.subnet-id", "Values": b["subnets"]}]).get("NetworkAcls", [])
    if not acls:
        raise RemediateError(f"no network ACL found for {', '.join(b['subnets'])}: the subnets may be gone")
    v6 = ":" in b["cidr"]
    done, skipped = [], []
    for acl in acls:
        aid, entries = acl["NetworkAclId"], acl.get("Entries") or []
        if any(not e.get("Egress") and e.get("RuleAction") == "deny" and (e.get("Ipv6CidrBlock") if v6 else e.get("CidrBlock")) == b["cidr"]
               for e in entries):  # fmt: skip
            skipped.append(f"{aid}: already denies {b['cidr']}")
            continue
        n = _free_rule_number(entries)
        if n is None:
            skipped.append(f"{aid}: no free rule number ahead of its allows; renumber its entries first")
            continue
        ec2.create_network_acl_entry(NetworkAclId=aid, RuleNumber=n, Protocol="-1", RuleAction="deny", Egress=False,
                                     **({"Ipv6CidrBlock": b["cidr"]} if v6 else {"CidrBlock": b["cidr"]}))  # fmt: skip
        subs = sorted(a["SubnetId"] for a in acl.get("Associations") or [] if a.get("SubnetId") in b["subnets"])
        done.append({"acl": aid, "rule": n, "subnets": subs})
    with store:
        for d in done:
            store.audit(actor, "apply", "nacl-deny-added", account, region, d["acl"],
                        {"request": rid, "cidr": b["cidr"], "rule": d["rule"], "subnets": d["subnets"],
                         "undo": f"aws ec2 delete-network-acl-entry --network-acl-id {d['acl']} --rule-number {d['rule']} --ingress --region {region}"},
                        f"request #{rid}: {r['reason']}", r["ticket"])  # fmt: skip
        if done or not skipped or all("already denies" in s for s in skipped):
            store.db.execute("UPDATE requests SET status = 'applied', applied_at = ? WHERE id = ?", (sg_db._now(), rid))
    return {"cidr": b["cidr"], "added": done, "skipped": skipped}


def apply_merge(store: sg_db.Store, ec2, account: str, rid: int, actor: str) -> dict:
    """Carry out an approved merge: the target must already hold every rule the members need (apply the rule
    request first); then each member's interfaces carry the target instead. The emptied groups are left in place
    (on no interface, they protect nothing) for deleting later; each move can be undone from the interface's
    History."""
    r = store._request(rid)
    if r.get("kind") != "merge":
        raise RemediateError(f"request #{rid} is not a merge")
    if r["status"] != "approved":
        raise RemediateError(f"request #{rid} is {r['status']}: it must be approved by a second person first")
    region, m = r["region"], r["changes"]
    store.require_enforce(account, "merge security groups")
    ext = sg_db.ensure_current(store, ec2, account, region, actor)
    if ext:
        raise RemediateError(f"{len(ext)} group(s) were changed in AWS outside this tool: Refresh from AWS and review them first")
    have = store.rules(account, region, m["target"], "synced")
    missing = [x for x in m["need"] if sg_db._rule_tuple(x) not in have]
    if missing:
        raise RemediateError(f"{m['target_name']} does not hold {len(missing)} rule(s) the merged groups need yet: "
                             f"apply the rule changes for {region} first")  # fmt: skip
    now = {a["eni"]: a for a in sg_assets.describe_assets(ec2)}
    moved, skipped = [], []
    members = set(m["members"])
    for eni in sorted(m["enis"]):
        a = now.get(eni)
        if a is None:
            skipped.append(f"{eni}: no longer exists")
            continue
        if not set(a["groups"]) & members:
            continue
        why = sg_assets.why_not_alone(a)
        if why:
            skipped.append(f"{eni}: {why}")
            continue
        new = sorted({m["target"] if g in members else g for g in a["groups"]})
        ec2.modify_network_interface_attribute(NetworkInterfaceId=eni, Groups=new)
        moved.append((a, new))
    with store:
        sg_assets.observe_assets(store, account, region, [{**a, "groups": new} for a, new in moved]
                                 + [x for e, x in now.items() if e not in {a["eni"] for a, _ in moved}], actor, "apply")  # fmt: skip
        for a, new in moved:
            store.audit(actor, "apply", "asset-swapped", account, region, m["target"],
                        {"request": rid, "eni": a["eni"], "instance": a.get("instance", ""), "before": a["groups"], "after": new},
                        f"request #{rid}: {r['reason']}", r["ticket"])  # fmt: skip
        store.audit(actor, "apply", "groups-merged", account, region, ",".join([m["target"]] + m["members"]),
                    {"request": rid, "moved": [a["eni"] for a, _ in moved], "skipped": skipped}, r["reason"], r["ticket"])
        store.db.execute("UPDATE requests SET status = 'applied', applied_at = ? WHERE id = ?", (sg_db._now(), rid))
    return {"moved": len(moved), "skipped": skipped, "target": m["target"]}
