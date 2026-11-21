#!/usr/bin/env python3
"""sg_db.py: every security group and rule in a local database, with an audit trail.

The database (SQLite, ``~/.sg-tightener/sg.db``) is the source of truth for security groups. AWS is
where the rules are enforced; the database is where they are decided. Nothing else, Terraform
included, may create, change or delete a group or a rule.

Each group's rules are held twice:

* **desired**: what the rules should be. Changed only by this tool (``add``, ``remove``, ``exec``,
  ``adopt``) and by sg_tightener, sg_extend and sg_compact, each with who and why.
* **synced**: what AWS held the last time the tool read or changed it.

``apply`` pushes desired to AWS. ``reconcile`` reads AWS: anything that differs from synced was
changed outside the tool (console, CLI, Terraform). It is recorded in the audit trail as external,
reported, and left for a person to decide: ``apply`` puts AWS back to desired, ``adopt`` accepts the
change into desired. The audit trail is append-only (triggers refuse UPDATE and DELETE) and
hash-chained, so ``verify`` shows whether anyone edited or removed an entry.

Usage:
  sg_db.py import    --regions eu-west-1,us-east-1 [--profile P]
  sg_db.py reconcile --regions eu-west-1 [--slack URL] [--no-cloudtrail]
  sg_db.py show      --region eu-west-1 [--group sg-…]
  sg_db.py diff      --region eu-west-1
  sg_db.py add       --region R --group sg-… --proto tcp --port 443 --source 10.20.0.0/24 --reason "…" [--ticket CHG-1]
  sg_db.py remove    --region R --group sg-… (--proto tcp --port 22 --source 0.0.0.0/0 | --all) --reason "…"
  sg_db.py exec      --reason "…" -- aws ec2 revoke-security-group-ingress --region R --group-id sg-… --ip-permissions '…'
  sg_db.py apply     --region R [--group sg-…] [--yes]
  sg_db.py adopt     --region R [--group sg-…] --reason "…"
  sg_db.py create-group --region R --vpc vpc-… --name N --description D --reason "…"
  sg_db.py log       [--region R] [--group sg-…] [--since 7d] [--json]
  sg_db.py verify
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import hashlib
import json
import logging
import os
import re
import shlex
import sqlite3
import sys
from pathlib import Path
from typing import Iterable

import sg_tightener
from sg_tightener import add_profile_arg, friendly_login_errors, use_profile

LOG = logging.getLogger("sg_db")

DB_ENV = "SG_TIGHTENER_DB"
GENESIS = "0" * 64
IN, OUT = "in", "out"
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS regions (
  account TEXT NOT NULL, region TEXT NOT NULL, imported_at TEXT NOT NULL, synced_at TEXT NOT NULL,
  PRIMARY KEY (account, region));
CREATE TABLE IF NOT EXISTS groups (
  account TEXT NOT NULL, region TEXT NOT NULL, group_id TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '', vpc_id TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (account, region, group_id));
CREATE TABLE IF NOT EXISTS rules (
  account TEXT NOT NULL, region TEXT NOT NULL, group_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('desired', 'synced')),
  direction TEXT NOT NULL CHECK (direction IN ('in', 'out')),
  proto TEXT NOT NULL, from_port INTEGER NOT NULL, to_port INTEGER NOT NULL, source TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (account, region, group_id, state, direction, proto, from_port, to_port, source));
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL, origin TEXT NOT NULL,
  action TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, group_id TEXT NOT NULL,
  detail TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', ticket TEXT NOT NULL DEFAULT '',
  prev TEXT NOT NULL, hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_group ON audit (account, region, group_id);
CREATE TRIGGER IF NOT EXISTS audit_append_only_u BEFORE UPDATE ON audit
  BEGIN SELECT RAISE(ABORT, 'the audit trail is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_append_only_d BEFORE DELETE ON audit
  BEGIN SELECT RAISE(ABORT, 'the audit trail is append-only'); END;
"""

# A rule: (direction, proto, from_port, to_port, source). Source is an IPv4 or IPv6 range, a prefix
# list id, a group id in the same account, or "<account>/<group id>" for another account's group.
Rule = tuple


class Refused(RuntimeError):
    """The database will not do this as things stand (external changes, unapplied changes)."""


# ------------------------------------------------------------------------------------------ rules
def _proto(p) -> str:
    p = str(p if p is not None else "-1").lower()
    return {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6", "all": "-1"}.get(p, p)


def _ports(proto: str, lo, hi) -> tuple[int, int]:
    if proto == "-1":
        return -1, -1
    lo = -1 if lo is None else int(lo)
    hi = lo if hi is None else int(hi)
    return lo, hi


def rules_from_permissions(perms: Iterable[dict], direction: str, account: str = "") -> dict[Rule, str]:
    """{rule: description} for AWS IpPermissions (as describe_security_groups returns them, or as a
    command would send them)."""
    out: dict[Rule, str] = {}
    for p in perms or []:
        proto = _proto(p.get("IpProtocol"))
        lo, hi = _ports(proto, p.get("FromPort"), p.get("ToPort"))
        for r in p.get("IpRanges") or []:
            out[(direction, proto, lo, hi, r["CidrIp"])] = r.get("Description") or ""
        for r in p.get("Ipv6Ranges") or []:
            out[(direction, proto, lo, hi, r["CidrIpv6"])] = r.get("Description") or ""
        for r in p.get("PrefixListIds") or []:
            out[(direction, proto, lo, hi, r["PrefixListId"])] = r.get("Description") or ""
        for r in p.get("UserIdGroupPairs") or []:
            uid = r.get("UserId") or ""
            src = r["GroupId"] if not uid or uid == account else f"{uid}/{r['GroupId']}"
            out[(direction, proto, lo, hi, src)] = r.get("Description") or ""
    return out


def to_permission(rule: Rule, description: str = "") -> dict:
    """One rule as an IpPermissions entry."""
    _d, proto, lo, hi, src = rule
    p: dict = {"IpProtocol": proto}
    if proto != "-1":
        p["FromPort"], p["ToPort"] = int(lo), int(hi)
    extra = {"Description": description} if description else {}
    if src.startswith("pl-"):
        p["PrefixListIds"] = [{"PrefixListId": src, **extra}]
    elif "sg-" in src:
        uid, _, gid = src.rpartition("/")
        p["UserIdGroupPairs"] = [{"GroupId": gid, **({"UserId": uid} if uid else {}), **extra}]
    elif ":" in src:
        p["Ipv6Ranges"] = [{"CidrIpv6": src, **extra}]
    else:
        p["IpRanges"] = [{"CidrIp": src, **extra}]
    return p


def group_from_aws(g: dict, account: str) -> dict:
    rules = rules_from_permissions(g.get("IpPermissions"), IN, account)
    rules.update(rules_from_permissions(g.get("IpPermissionsEgress"), OUT, account))
    return {"name": g.get("GroupName") or "", "vpc": g.get("VpcId") or "", "description": g.get("Description") or "",
            "rules": rules}


def read_live(ec2, account: str, group_ids: Iterable[str] | None = None) -> dict[str, dict]:
    """{group id: group} as AWS holds it now."""
    ids = list(group_ids or [])
    out = {}
    if ids:
        try:
            groups = ec2.describe_security_groups(GroupIds=ids)["SecurityGroups"]
        except Exception as exc:
            if "NotFound" not in str(exc):
                raise
            if len(ids) == 1:
                return {}  # deleted
            groups = [g for i in ids for g in read_live_raw(ec2, i)]
    else:
        groups = [g for page in ec2.get_paginator("describe_security_groups").paginate()
                  for g in page.get("SecurityGroups", [])]  # fmt: skip
    for g in groups:
        out[g["GroupId"]] = group_from_aws(g, account)
    return out


def read_live_raw(ec2, gid: str) -> list[dict]:
    try:
        return ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"]
    except Exception as exc:
        if "NotFound" in str(exc):
            return []
        raise


def rule_text(rule: Rule, description: str = "") -> str:
    d, proto, lo, hi, src = rule
    ports = "all traffic" if proto == "-1" else f"{proto} {lo}" if lo == hi else f"{proto} {lo}-{hi}"
    arrow = "from" if d == IN else "to"
    return f"{'inbound' if d == IN else 'outbound'} {ports} {arrow} {src}" + (f" ({description})" if description else "")


def _rule_json(rule: Rule, description: str = "") -> dict:
    d, proto, lo, hi, src = rule
    return {"direction": d, "proto": proto, "from": lo, "to": hi, "source": src, "description": description}


# ------------------------------------------------------------------------------------------ store
def default_path() -> Path:
    env = os.environ.get(DB_ENV)
    return Path(env).expanduser() if env else Path.home() / ".sg-tightener" / "sg.db"


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def actor_name(arn: str = "") -> str:
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001
        user = "unknown"
    return f"{arn} ({user})" if arn else user


class Store:
    """The database. Every write goes through a transaction and leaves an audit entry."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        new = not self.path.exists()
        self.db = sqlite3.connect(str(self.path), isolation_level=None, timeout=30)
        if new:
            os.chmod(self.path, 0o600)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    # transactions: BEGIN IMMEDIATE so two writers queue rather than interleave
    def __enter__(self):
        self.db.execute("BEGIN IMMEDIATE")
        return self

    def __exit__(self, exc_type, *_):
        self.db.execute("ROLLBACK" if exc_type else "COMMIT")

    # ---------------------------------------------------------------- audit
    def audit(self, actor: str, origin: str, action: str, account: str, region: str, group_id: str,
              detail: dict, reason: str = "", ticket: str = "") -> None:  # fmt: skip
        row = self.db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row[0] if row else GENESIS
        entry = {"at": _now(), "actor": actor, "origin": origin, "action": action, "account": account,
                 "region": region, "group_id": group_id, "detail": json.dumps(detail, sort_keys=True),
                 "reason": reason, "ticket": ticket, "prev": prev}  # fmt: skip
        entry["hash"] = _hash(entry)
        self.db.execute("INSERT INTO audit (at, actor, origin, action, account, region, group_id, detail, reason, "
                        "ticket, prev, hash) VALUES (:at, :actor, :origin, :action, :account, :region, :group_id, "
                        ":detail, :reason, :ticket, :prev, :hash)", entry)  # fmt: skip

    def verify(self) -> tuple[bool, int, str]:
        """(intact, entries, what is wrong). Recomputes every hash and link."""
        prev, n = GENESIS, 0
        cols = ("seq", "at", "actor", "origin", "action", "account", "region", "group_id", "detail", "reason",
                "ticket", "prev", "hash")  # fmt: skip
        for row in self.db.execute(f"SELECT {', '.join(cols)} FROM audit ORDER BY seq"):
            e = dict(zip(cols, row))
            n += 1
            if e["prev"] != prev:
                return False, n, f"entry {e['seq']} does not follow the entry before it (one removed or reordered)"
            if _hash({k: v for k, v in e.items() if k not in ("seq", "hash")}) != e["hash"]:
                return False, n, f"entry {e['seq']} was changed after it was written"
            prev = e["hash"]
        return True, n, ""

    def log(self, account: str = "", region: str = "", group_id: str = "", since: str = "",
            limit: int = 500) -> list[dict]:  # fmt: skip
        q, args = "SELECT seq, at, actor, origin, action, account, region, group_id, detail, reason, ticket FROM audit", []
        where = []
        for col, v in (("account", account), ("region", region), ("group_id", group_id)):
            if v:
                where.append(f"{col} = ?")
                args.append(v)
        if since:
            where.append("at >= ?")
            args.append(since)
        if where:
            q += " WHERE " + " AND ".join(where)
        q += " ORDER BY seq DESC LIMIT ?"
        args.append(limit)
        cols = ("seq", "at", "actor", "origin", "action", "account", "region", "group_id", "detail", "reason", "ticket")
        return [{**dict(zip(cols, r)), "detail": json.loads(r[8])} for r in self.db.execute(q, args)][::-1]

    # ---------------------------------------------------------------- reads
    def imported(self, account: str, region: str) -> bool:
        return self.db.execute("SELECT 1 FROM regions WHERE account = ? AND region = ?",
                               (account, region)).fetchone() is not None  # fmt: skip

    def regions(self, account: str = "") -> list[tuple[str, str]]:
        q = "SELECT account, region FROM regions" + (" WHERE account = ?" if account else "") + " ORDER BY 1, 2"
        return list(self.db.execute(q, (account,) if account else ()))

    def groups(self, account: str, region: str) -> dict[str, dict]:
        out = {gid: {"name": n, "vpc": v, "description": d}
               for gid, n, v, d in self.db.execute("SELECT group_id, name, vpc_id, description FROM groups WHERE "
                                                   "account = ? AND region = ? ORDER BY group_id", (account, region))}  # fmt: skip
        return out

    def rules(self, account: str, region: str, group_id: str, state: str) -> dict[Rule, str]:
        return {(d, p, lo, hi, s): desc for d, p, lo, hi, s, desc in self.db.execute(
            "SELECT direction, proto, from_port, to_port, source, description FROM rules WHERE account = ? AND "
            "region = ? AND group_id = ? AND state = ?", (account, region, group_id, state))}

    def pending(self, account: str, region: str, group_id: str = "") -> list[tuple[str, str, Rule, str]]:
        """What apply would do: (group, "add" or "remove", rule, description), removals first."""
        out = []
        for gid in [group_id] if group_id else self.groups(account, region):
            want, have = self.rules(account, region, gid, "desired"), self.rules(account, region, gid, "synced")
            out += [(gid, "remove", r, have[r]) for r in sorted(set(have) - set(want))]
            out += [(gid, "add", r, want[r]) for r in sorted(set(want) - set(have))]
        out.sort(key=lambda x: (x[0], x[1] != "remove"))
        return out

    # ---------------------------------------------------------------- writes (inside `with store:`)
    def _put_group(self, account, region, gid, g) -> None:
        self.db.execute("INSERT INTO groups (account, region, group_id, name, vpc_id, description) VALUES "
                        "(?, ?, ?, ?, ?, ?) ON CONFLICT (account, region, group_id) DO UPDATE SET name = "
                        "excluded.name, vpc_id = excluded.vpc_id, description = excluded.description",
                        (account, region, gid, g.get("name", ""), g.get("vpc", ""), g.get("description", "")))  # fmt: skip

    def _set_rules(self, account, region, gid, state, rules: dict[Rule, str]) -> None:
        self.db.execute("DELETE FROM rules WHERE account = ? AND region = ? AND group_id = ? AND state = ?",
                        (account, region, gid, state))  # fmt: skip
        self.db.executemany("INSERT INTO rules (account, region, group_id, state, direction, proto, from_port, "
                            "to_port, source, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            [(account, region, gid, state, *r, desc) for r, desc in rules.items()])  # fmt: skip

    def _drop_group(self, account, region, gid) -> None:
        self.db.execute("DELETE FROM rules WHERE account = ? AND region = ? AND group_id = ?", (account, region, gid))
        self.db.execute("DELETE FROM groups WHERE account = ? AND region = ? AND group_id = ?", (account, region, gid))

    def _touch(self, account, region) -> None:
        self.db.execute("UPDATE regions SET synced_at = ? WHERE account = ? AND region = ?", (_now(), account, region))

    def import_region(self, account: str, region: str, live: dict[str, dict], actor: str, reason: str = "") -> int:
        """Take every group and rule AWS holds now as both desired and synced. Returns the rule count."""
        if self.imported(account, region):
            raise Refused(f"{account} {region} is already in the database; use reconcile")
        n = 0
        for gid, g in sorted(live.items()):
            self._put_group(account, region, gid, g)
            for state in ("desired", "synced"):
                self._set_rules(account, region, gid, state, g["rules"])
            self.audit(actor, "import", "group-imported", account, region, gid,
                       {"name": g["name"], "vpc": g["vpc"], "rules": [_rule_json(r, d) for r, d in sorted(g["rules"].items())]},
                       reason or "first import")  # fmt: skip
            n += len(g["rules"])
        self.db.execute("INSERT INTO regions (account, region, imported_at, synced_at) VALUES (?, ?, ?, ?)",
                        (account, region, _now(), _now()))  # fmt: skip
        return n

    def observe(self, account: str, region: str, live: dict[str, dict], actor: str, who=None,
                only: Iterable[str] | None = None) -> list[dict]:  # fmt: skip
        """Compare AWS (``live``) with synced; record each difference as an external change and take it as
        synced. Desired is not touched, so apply would put it back. A group created outside the tool is
        taken into desired as it is (the tool never deletes groups); one deleted outside is dropped.
        ``who(group_id)`` may name who changed it (CloudTrail). Returns the changes."""
        changes = []
        known = self.groups(account, region)
        scope = set(only) if only is not None else set(known) | set(live)
        for gid in sorted(scope):
            g = live.get(gid)
            by = (who(gid) if who else "") or ""
            note = {"changed_by": by} if by else {}
            if gid not in known and g is not None:
                self._put_group(account, region, gid, g)
                for state in ("desired", "synced"):
                    self._set_rules(account, region, gid, state, g["rules"])
                ch = {"group": gid, "change": "group created", "name": g["name"],
                      "rules": [_rule_json(r, d) for r, d in sorted(g["rules"].items())], **note}  # fmt: skip
                self.audit(actor, "external", "group-created", account, region, gid, ch,
                           "found in AWS, not made by this tool")
                changes.append(ch)
                continue
            if gid in known and g is None:
                ch = {"group": gid, "change": "group deleted", "name": known[gid]["name"], **note}
                self.audit(actor, "external", "group-deleted", account, region, gid, ch, "gone from AWS")
                self._drop_group(account, region, gid)
                changes.append(ch)
                continue
            if g is None:
                continue
            have = self.rules(account, region, gid, "synced")
            added = {r: d for r, d in g["rules"].items() if r not in have}
            removed = {r: d for r, d in have.items() if r not in g["rules"]}
            if not added and not removed:
                if (g["name"], g["vpc"]) != (known[gid]["name"], known[gid]["vpc"]):
                    self._put_group(account, region, gid, g)
                continue
            ch = {"group": gid, "change": "rules changed", "name": g["name"],
                  "added": [_rule_json(r, d) for r, d in sorted(added.items())],
                  "removed": [_rule_json(r, d) for r, d in sorted(removed.items())], **note}  # fmt: skip
            self.audit(actor, "external", "rules-changed", account, region, gid, ch,
                       "changed in AWS outside this tool")
            self._set_rules(account, region, gid, "synced", g["rules"])
            changes.append(ch)
        self._touch(account, region)
        return changes

    def desire(self, account: str, region: str, gid: str, actor: str, reason: str, ticket: str = "",
               add: dict[Rule, str] | None = None, remove: Iterable[Rule] = (), origin: str = "tool") -> dict:  # fmt: skip
        """Change desired: add and remove rules. Returns {"added": [...], "removed": [...]} of what changed."""
        if gid not in self.groups(account, region):
            raise Refused(f"{gid} is not in the database for {account} {region}")
        if not reason.strip():
            raise Refused("a reason is required: it goes in the audit trail")
        want = self.rules(account, region, gid, "desired")
        removed = [r for r in remove if r in want]
        for r in removed:
            del want[r]
        added = {r: d for r, d in (add or {}).items() if r not in want}
        want.update(added)
        if not added and not removed:
            return {"added": [], "removed": []}
        self._set_rules(account, region, gid, "desired", want)
        detail = {"added": [_rule_json(r, d) for r, d in sorted(added.items())],
                  "removed": [_rule_json(r) for r in sorted(removed)]}  # fmt: skip
        self.audit(actor, origin, "desired-changed", account, region, gid, detail, reason, ticket)
        return detail

    def adopt(self, account: str, region: str, actor: str, reason: str, gid: str = "") -> int:
        """Take what AWS holds (synced) as desired: accept external changes. Returns the groups changed."""
        if not reason.strip():
            raise Refused("a reason is required: it goes in the audit trail")
        n = 0
        for g in [gid] if gid else self.groups(account, region):
            want, have = self.rules(account, region, g, "desired"), self.rules(account, region, g, "synced")
            if want == have:
                continue
            self._set_rules(account, region, g, "desired", have)
            self.audit(actor, "tool", "adopted", account, region, g,
                       {"added": [_rule_json(r, d) for r, d in sorted(have.items()) if r not in want],
                        "removed": [_rule_json(r, d) for r, d in sorted(want.items()) if r not in have]}, reason)  # fmt: skip
            n += 1
        return n

    def synced(self, account: str, region: str, gid: str, live: dict | None, actor: str, origin: str,
               action: str, reason: str = "", ticket: str = "", desired_too: bool = False) -> dict:  # fmt: skip
        """After a change this tool (or sg_tightener, sg_extend, sg_compact) made: take AWS's group as synced,
        and with ``desired_too`` as desired as well. Records what AWS now holds that differs."""
        have = self.rules(account, region, gid, "synced")
        new = (live or {}).get("rules", {})
        detail = {"added": [_rule_json(r, d) for r, d in sorted(new.items()) if r not in have],
                  "removed": [_rule_json(r, d) for r, d in sorted(have.items()) if r not in new]}  # fmt: skip
        if live is None:
            self._drop_group(account, region, gid)
        else:
            self._put_group(account, region, gid, live)
            self._set_rules(account, region, gid, "synced", new)
            if desired_too:
                self._set_rules(account, region, gid, "desired", new)
        self.audit(actor, origin, action, account, region, gid, detail, reason, ticket)
        self._touch(account, region)
        return detail


def _hash(entry: dict) -> str:
    return hashlib.sha256(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ------------------------------------------------------------------------------------------ AWS side
def account_of(session=None) -> tuple[str, str]:
    """(account id, caller ARN)."""
    sts = (session or sg_tightener.boto3).client("sts")
    ident = sts.get_caller_identity()
    return ident["Account"], ident.get("Arn", "")


def ensure_current(store: Store, ec2, account: str, region: str, actor: str, who=None) -> list[dict]:
    """Import the region on first use; otherwise record any external change. Returns the external changes."""
    live = read_live(ec2, account)
    with store:
        if not store.imported(account, region):
            n = store.import_region(account, region, live, actor)
            LOG.info("imported %d group(s) and %d rule(s) in %s into %s", len(live), n, region, store.path)
            return []
        return store.observe(account, region, live, actor, who)


def push(store: Store, ec2, account: str, region: str, actor: str, gid: str = "", reason: str = "",
         ticket: str = "") -> dict:  # fmt: skip
    """Make AWS match desired. Refuses if AWS changed outside the tool since it was last read (reconcile
    first, so a person has seen it). Returns {"done": n, "failed": [...]}."""
    groups = [gid] if gid else sorted(store.groups(account, region))
    ext = None
    live = read_live(ec2, account, groups)
    with store:
        ext = store.observe(account, region, live, actor, only=groups)
    if ext:
        raise Refused(f"{len(ext)} group(s) were changed in AWS outside this tool; they are now in the audit "
                      f"trail. Review them with `sg_db.py reconcile --regions {region}`, then apply (to put them "
                      f"back) or adopt (to keep them).")  # fmt: skip
    out = {"done": 0, "failed": []}
    todo = store.pending(account, region, gid)
    by_group: dict[str, list] = {}
    for g, op, rule, desc in todo:
        by_group.setdefault(g, []).append((op, rule, desc))
    for g, ops in by_group.items():
        for op, rule, desc in ops:
            perm = to_permission(rule, "" if op == "remove" else desc)
            call = {("remove", IN): ec2.revoke_security_group_ingress, ("add", IN): ec2.authorize_security_group_ingress,
                    ("remove", OUT): ec2.revoke_security_group_egress, ("add", OUT): ec2.authorize_security_group_egress}[(op, rule[0])]  # fmt: skip
            try:
                call(GroupId=g, IpPermissions=[perm])
                out["done"] += 1
            except Exception as exc:  # noqa: BLE001 - recorded; the rest still run
                out["failed"].append(f"{g}: {op} {rule_text(rule)}: {exc}")
                LOG.error("%s: could not %s %s: %s", g, op, rule_text(rule), exc)
        live_g = read_live(ec2, account, [g]).get(g)
        with store:
            store.synced(account, region, g, live_g, actor, "apply", "applied", reason, ticket)
    return out


class TrackedEC2:
    """An EC2 client for sg_tightener, sg_extend and sg_compact: before the first change it imports the region
    (first use) or checks nothing changed outside the tool, and after each rule change it records what AWS now
    holds for that group, as desired and synced, in the audit trail."""

    WRITES = ("authorize_security_group_ingress", "revoke_security_group_ingress",
              "authorize_security_group_egress", "revoke_security_group_egress", "modify_security_group_rules")  # fmt: skip

    def __init__(self, ec2, region: str, tool: str, reason: str = "", store: Store | None = None,
                 account: str = "", arn: str = "", strict: bool = True):  # fmt: skip
        self._ec2, self._region, self._tool, self._reason = ec2, region, tool, reason
        self._store = store or Store()
        if not account:
            account, arn = account_of()
        self._account, self._actor = account, actor_name(arn)
        ext = ensure_current(self._store, ec2, account, region, self._actor)
        if ext and not strict:
            LOG.warning("%d security group(s) in %s were changed outside sg-tightener; recorded in the audit trail "
                        "(sg_db.py reconcile --regions %s). Going ahead: %s does not wait for that.",
                        len(ext), region, region, tool)  # fmt: skip
        elif ext:
            raise SystemExit(f"{len(ext)} security group(s) in {region} were changed outside sg-tightener and are now "
                             f"in the audit trail. Review: sg_db.py reconcile --regions {region}; then apply or adopt "
                             f"before running {tool}.")  # fmt: skip
        if strict and self._store.pending(account, region):
            raise SystemExit(f"the database has changes for {region} not yet applied (sg_db.py diff --region {region}). "
                             f"Apply them (sg_db.py apply) or put them back before running {tool}.")  # fmt: skip

    def __getattr__(self, name):
        attr = getattr(self._ec2, name)
        if name not in self.WRITES:
            return attr

        def write(**kw):
            res = attr(**kw)
            gid = kw.get("GroupId", "")
            live = read_live(self._ec2, self._account, [gid]).get(gid)
            with self._store:
                self._store.synced(self._account, self._region, gid, live, self._actor, self._tool,
                                   name.replace("_", "-"), self._reason, desired_too=True)  # fmt: skip
            return res

        return write


def track(ec2, region: str, tool: str, reason: str = "", strict: bool = True) -> TrackedEC2:
    """Wrap ``ec2`` so every rule change lands in the database. ``strict`` refuses to start while AWS has
    unreviewed external changes or the database has unapplied ones; revert and break-glass pass False."""
    return TrackedEC2(ec2, region, tool, reason, strict=strict)


# ------------------------------------------------------------------------------------------ exec
_SHORT_LIST = re.compile(r"(\w+)=\[(.*?)\](?=,\w+=|$)")


def parse_shorthand(text: str) -> list[dict]:
    """AWS CLI shorthand for one IpPermissions entry, as sg_review prints it:
    IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0},{CidrIp=…}]"""
    text = text.strip()
    if text.startswith(("[", "{")):
        v = json.loads(text)
        return v if isinstance(v, list) else [v]
    perm: dict = {}
    for key, body in _SHORT_LIST.findall(text):
        items = []
        for obj in re.findall(r"\{(.*?)\}", body):
            items.append(dict(kv.split("=", 1) for kv in obj.split(",") if "=" in kv))
        perm[key] = items
    scalars = _SHORT_LIST.sub("", text)
    for kv in scalars.split(","):
        if "=" in kv:
            k, v = kv.split("=", 1)
            perm[k] = int(v) if k in ("FromPort", "ToPort") else v
    return [perm]


def parse_command(argv: list[str]) -> dict:
    """An `aws ec2 authorize|revoke-security-group-ingress|egress` command line as
    {verb, direction, region, group, perms, rule_ids}."""
    a = [x for x in argv if x != "\\"]
    if a[:2] == ["aws", "ec2"]:
        a = a[2:]
    if not a:
        raise ValueError("no command given")
    m = re.fullmatch(r"(authorize|revoke)-security-group-(ingress|egress)", a[0])
    if not m:
        raise ValueError(f"only authorize/revoke-security-group-ingress/egress can be run through the database, not {a[0]}")
    opts: dict[str, list[str]] = {}
    key = None
    for tok in a[1:]:
        if tok.startswith("--"):
            key = tok[2:]
            opts.setdefault(key, [])
        elif key:
            opts[key].append(tok)
    one = {k: " ".join(v) for k, v in opts.items()}
    perms = []
    if "ip-permissions" in opts:
        for chunk in opts["ip-permissions"]:
            perms += parse_shorthand(chunk)
    elif "protocol" in one:
        port = one.get("port", "-1")
        lo, _, hi = port.partition("-") if not port.startswith("-") else ("-1", "", "-1")
        perm = {"IpProtocol": _proto(one["protocol"]), "FromPort": int(lo), "ToPort": int(hi or lo)}
        if "cidr" in one:
            perm["Ipv6Ranges" if ":" in one["cidr"] else "IpRanges"] = [
                {"CidrIpv6" if ":" in one["cidr"] else "CidrIp": one["cidr"]}]
        elif "source-group" in one:
            perm["UserIdGroupPairs"] = [{"GroupId": one["source-group"]}]
        perms.append(perm)
    ids = " ".join(opts.get("security-group-rule-ids", [])).split()
    if not perms and not ids:
        raise ValueError("the command names no rule (--ip-permissions, --protocol/--port/--cidr or --security-group-rule-ids)")
    if not one.get("group-id"):
        raise ValueError("the command has no --group-id")
    return {"verb": m.group(1), "direction": IN if m.group(2) == "ingress" else OUT, "region": one.get("region", ""),
            "group": one["group-id"], "perms": perms, "rule_ids": ids}


def rules_for_ids(ec2, gid: str, ids: list[str], account: str) -> list[Rule]:
    res = ec2.describe_security_group_rules(SecurityGroupRuleIds=ids)["SecurityGroupRules"]
    out = []
    for r in res:
        proto = _proto(r.get("IpProtocol"))
        lo, hi = _ports(proto, r.get("FromPort"), r.get("ToPort"))
        ref = r.get("ReferencedGroupInfo") or {}
        src = (r.get("CidrIpv4") or r.get("CidrIpv6") or r.get("PrefixListId")
               or (ref["GroupId"] if not ref.get("UserId") or ref.get("UserId") == account else f"{ref['UserId']}/{ref['GroupId']}"))  # fmt: skip
        out.append((OUT if r.get("IsEgress") else IN, proto, lo, hi, src))
    return out


# ------------------------------------------------------------------------------------------ CLI
def _session(profile):
    use_profile(profile)
    return sg_tightener.boto3.Session(profile_name=profile) if profile else sg_tightener.boto3.Session()


def _who_from_cloudtrail(sess, region: str):
    """who(group_id) from CloudTrail's last day of rule changes; empty when it cannot be read."""
    try:
        import sg_review

        events = sg_review.rule_history(sess, region, sg_review.utcnow(), days=1)["events"]
    except Exception as exc:  # noqa: BLE001 - attribution is a courtesy
        LOG.debug("CloudTrail not read: %s", exc)
        return lambda gid: ""
    last: dict[str, str] = {}
    for ev in events:
        last[ev["group"]] = f"{ev['who'] or 'unknown'} ({ev['name']} at {dt.datetime.fromtimestamp(ev['t'], dt.timezone.utc):%Y-%m-%d %H:%M} UTC" + (f" from {ev['ip']}" if ev.get("ip") else "") + ")"
    return lambda gid: last.get(gid, "")


def _change_lines(ch: dict) -> list[str]:
    head = f"{ch['group']} ({ch.get('name') or 'unnamed'}): {ch['change']}" + (f", by {ch['changed_by']}" if ch.get("changed_by") else "")
    lines = [head]
    for r in ch.get("added", []):
        lines.append("  + " + rule_text(_rule_tuple(r), r.get("description", "")))
    for r in ch.get("removed", []):
        lines.append("  - " + rule_text(_rule_tuple(r), r.get("description", "")))
    return lines


def _rule_tuple(r: dict) -> Rule:
    return (r["direction"], r["proto"], r["from"], r["to"], r["source"])


def _parse_port(text: str) -> tuple[int, int]:
    if text in ("all", "-1"):
        return -1, -1
    lo, _, hi = text.partition("-")
    return int(lo), int(hi or lo)


def _rule_from_args(args) -> Rule:
    proto = _proto(args.proto)
    lo, hi = (-1, -1) if proto == "-1" else _parse_port(args.port or "-1")
    return (args.direction, proto, lo, hi, args.source)


def cmd_import(args, store: Store) -> int:
    sess = _session(args.profile)
    account, arn = account_of(sess)
    actor = actor_name(arn)
    for region in _regions(args.regions):
        live = read_live(sess.client("ec2", region_name=region), account)
        with store:
            n = store.import_region(account, region, live, actor, args.reason or "first import")
        LOG.info("%s %s: %d group(s), %d rule(s) imported into %s", account, region, len(live), n, store.path)
    return 0


def cmd_reconcile(args, store: Store) -> int:
    sess = _session(args.profile)
    account, arn = account_of(sess)
    actor = actor_name(arn)
    found, lines = 0, []
    for region in _regions(args.regions):
        ec2 = sess.client("ec2", region_name=region)
        who = None if args.no_cloudtrail else _who_from_cloudtrail(sess, region)
        changes = ensure_current(store, ec2, account, region, actor, who)
        pend = store.pending(account, region)
        found += len(changes)
        if changes:
            lines.append(f"{account} {region}: {len(changes)} group(s) changed outside sg-tightener")
            for ch in changes:
                lines += _change_lines(ch)
        if pend:
            lines.append(f"{account} {region}: `sg_db.py apply --region {region}` would make {len(pend)} change(s) "
                         f"so AWS matches the database:")  # fmt: skip
            lines += [f"  {'revoke' if op == 'remove' else 'authorize'} {g}: {rule_text(r, d)}" for g, op, r, d in pend]
            lines.append(f"  or keep what AWS holds: sg_db.py adopt --region {region} [--group sg-…] --reason \"…\"")
    text = "\n".join(lines) if lines else "AWS matches the database."
    print(text)
    if found and args.slack:
        import sg_review

        sg_review.post_slack(args.slack, "*sg-tightener: security groups changed outside the tool*\n```" + text[:3500] + "```")
    return 1 if found or any(store.pending(account, r) for r in _regions(args.regions)) else 0


def cmd_show(args, store: Store) -> int:
    account = args.account or _only_account(store, args.region)
    for gid, g in store.groups(account, args.region).items():
        if args.group and gid != args.group:
            continue
        want, have = store.rules(account, args.region, gid, "desired"), store.rules(account, args.region, gid, "synced")
        print(f"{gid}  {g['name']}  ({g['vpc']})")
        for r in sorted(set(want) | set(have)):
            mark = " " if r in want and r in have else "+" if r in want else "-"
            print(f"  {mark} {rule_text(r, want.get(r) or have.get(r, ''))}")
    return 0


def cmd_diff(args, store: Store) -> int:
    account = args.account or _only_account(store, args.region)
    pend = store.pending(account, args.region, args.group or "")
    for g, op, r, d in pend:
        print(f"{'-' if op == 'remove' else '+'} {g}: {rule_text(r, d)}")
    if not pend:
        print("nothing to apply: AWS (as last read) matches the database")
    return 1 if pend else 0


def cmd_add_remove(args, store: Store, op: str) -> int:
    account = args.account or _only_account(store, args.region)
    actor = actor_name(sg_tightener.caller_arn())
    with store:
        if op == "remove" and args.all:
            rules = [r for r in store.rules(account, args.region, args.group, "desired") if r[0] == args.direction]
            d = store.desire(account, args.region, args.group, actor, args.reason, args.ticket, remove=rules)
        elif op == "remove":
            d = store.desire(account, args.region, args.group, actor, args.reason, args.ticket, remove=[_rule_from_args(args)])
        else:
            d = store.desire(account, args.region, args.group, actor, args.reason, args.ticket,
                             add={_rule_from_args(args): args.description or ""})  # fmt: skip
    n = len(d["added"]) + len(d["removed"])
    print(f"{n} change(s) recorded in the database; `sg_db.py apply --region {args.region}` makes them in AWS"
          if n else "nothing changed: the database already says that")  # fmt: skip
    return 0


def cmd_exec(args, store: Store) -> int:
    cmd = args.command
    if len(cmd) == 1:
        cmd = shlex.split(cmd[0])
    c = parse_command(cmd)
    region = c["region"] or args.region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if not region:
        raise SystemExit("the command has no --region and none is set")
    sess = _session(args.profile)
    account, arn = account_of(sess)
    actor = actor_name(arn)
    ec2 = sess.client("ec2", region_name=region)
    ext = ensure_current(store, ec2, account, region, actor)
    if ext:
        raise SystemExit(f"{len(ext)} group(s) were changed outside sg-tightener; review them with "
                         f"`sg_db.py reconcile --regions {region}` first")  # fmt: skip
    rules = rules_from_permissions(c["perms"], c["direction"], account)
    if c["rule_ids"]:
        rules.update({r: "" for r in rules_for_ids(ec2, c["group"], c["rule_ids"], account)})
    with store:
        if c["verb"] == "authorize":
            store.desire(account, region, c["group"], actor, args.reason, args.ticket, add=rules)
        else:
            store.desire(account, region, c["group"], actor, args.reason, args.ticket, remove=list(rules))
    if args.no_apply:
        print(f"recorded; `sg_db.py apply --region {region} --group {c['group']}` makes it in AWS")
        return 0
    res = push(store, ec2, account, region, actor, c["group"], args.reason, args.ticket)
    print(f"{res['done']} change(s) made in AWS and recorded" + (f"; {len(res['failed'])} failed" if res["failed"] else ""))
    return 1 if res["failed"] else 0


def cmd_apply(args, store: Store) -> int:
    sess = _session(args.profile)
    account, arn = account_of(sess)
    pend = store.pending(account, args.region, args.group or "")
    if not pend:
        print("nothing to apply")
        return 0
    for g, op, r, d in pend:
        print(f"{'revoke' if op == 'remove' else 'authorize'} {g}: {rule_text(r, d)}")
    if not args.yes:
        sg_tightener._confirm(f"make these {len(pend)} change(s) in {args.region}")
    try:
        res = push(store, sess.client("ec2", region_name=args.region), account, args.region, actor_name(arn),
                   args.group or "", args.reason or "sg_db.py apply", args.ticket)  # fmt: skip
    except Refused as exc:
        raise SystemExit(str(exc))
    print(f"{res['done']} change(s) made" + (f", {len(res['failed'])} failed" if res["failed"] else ""))
    return 1 if res["failed"] else 0


def cmd_adopt(args, store: Store) -> int:
    account = args.account or _only_account(store, args.region)
    with store:
        n = store.adopt(account, args.region, actor_name(sg_tightener.caller_arn()), args.reason, args.group or "")
    print(f"{n} group(s): what AWS holds is now what the database wants")
    return 0


def cmd_create_group(args, store: Store) -> int:
    if not args.reason.strip():
        raise SystemExit("--reason is required")
    sess = _session(args.profile)
    account, arn = account_of(sess)
    actor = actor_name(arn)
    ec2 = sess.client("ec2", region_name=args.region)
    ensure_current(store, ec2, account, args.region, actor)
    gid = ec2.create_security_group(GroupName=args.name, Description=args.description, VpcId=args.vpc)["GroupId"]
    live = read_live(ec2, account, [gid]).get(gid)
    with store:
        store.synced(account, args.region, gid, live, actor, "tool", "group-created", args.reason, args.ticket,
                     desired_too=True)  # fmt: skip
    print(gid)
    return 0


def cmd_log(args, store: Store) -> int:
    since = ""
    if args.since:
        m = re.fullmatch(r"(\d+)([hd])", args.since)
        if not m:
            raise SystemExit("--since is like 24h or 7d")
        delta = dt.timedelta(hours=int(m.group(1))) if m.group(2) == "h" else dt.timedelta(days=int(m.group(1)))
        since = (dt.datetime.now(dt.timezone.utc) - delta).replace(microsecond=0).isoformat()
    rows = store.log(args.account or "", args.region or "", args.group or "", since, args.limit)
    if args.json:
        print(json.dumps(rows, indent=1))
        return 0
    for e in rows:
        print(f"#{e['seq']} {e['at']} {e['origin']:<8} {e['action']:<16} {e['region']} {e['group_id']}  {e['actor']}"
              + (f"  [{e['ticket']}]" if e["ticket"] else "") + (f"  {e['reason']}" if e["reason"] else ""))  # fmt: skip
        for k in ("added", "removed"):
            for r in e["detail"].get(k, []):
                print(f"    {'+' if k == 'added' else '-'} {rule_text(_rule_tuple(r), r.get('description', ''))}")
        if e["detail"].get("changed_by"):
            print(f"    by {e['detail']['changed_by']}")
    return 0


def cmd_verify(args, store: Store) -> int:
    ok, n, why = store.verify()
    print(f"audit trail intact: {n} entries" if ok else f"AUDIT TRAIL BROKEN after {n} entries: {why}")
    return 0 if ok else 1


def _regions(text: str) -> list[str]:
    return [r.strip() for r in text.split(",") if r.strip()]


def _only_account(store: Store, region: str) -> str:
    accts = sorted({a for a, r in store.regions() if r == region})
    if len(accts) != 1:
        raise SystemExit(f"{'no account' if not accts else 'several accounts'} in the database for {region}: pass --account")
    return accts[0]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sg_db.py", description=__doc__.splitlines()[0])
    p.add_argument("--db", help=f"database file (default ${DB_ENV} or ~/.sg-tightener/sg.db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def reasoned(q, required=True):
        q.add_argument("--reason", required=required, help="why: kept in the audit trail")
        q.add_argument("--ticket", default="", help="change ticket, kept in the audit trail")

    def rule_args(q, required=True):
        q.add_argument("--direction", choices=(IN, OUT), default=IN)
        q.add_argument("--proto", required=required, help="tcp, udp, icmp, all or a protocol number")
        q.add_argument("--port", help="22, 8000-8100 or all")
        q.add_argument("--source", required=required, help="CIDR, pl-…, sg-… or ACCOUNT/sg-…")

    q = sub.add_parser("import", help="take every group and rule in these regions into the database")
    q.add_argument("--regions", required=True)
    q.add_argument("--reason", default="")
    add_profile_arg(q)
    q = sub.add_parser("reconcile", help="record and report changes made in AWS outside the tool")
    q.add_argument("--regions", required=True)
    q.add_argument("--slack", default=os.environ.get("SG_REVIEW_SLACK_WEBHOOK", ""), help="post external changes here")
    q.add_argument("--no-cloudtrail", action="store_true", help="do not look up who made each change")
    add_profile_arg(q)
    for name in ("show", "diff"):
        q = sub.add_parser(name, help="the rules the database holds" if name == "show" else "what apply would change")
        q.add_argument("--region", required=True)
        q.add_argument("--group")
        q.add_argument("--account")
    q = sub.add_parser("add", help="add a rule to the database (apply makes it in AWS)")
    q.add_argument("--region", required=True)
    q.add_argument("--group", required=True)
    q.add_argument("--account")
    q.add_argument("--description", default="")
    rule_args(q)
    reasoned(q)
    q = sub.add_parser("remove", help="remove a rule from the database (apply takes it out of AWS)")
    q.add_argument("--region", required=True)
    q.add_argument("--group", required=True)
    q.add_argument("--account")
    q.add_argument("--all", action="store_true", help="every rule in --direction")
    rule_args(q, required=False)
    reasoned(q)
    q = sub.add_parser("exec", help="run an aws ec2 authorize/revoke-security-group command through the database")
    q.add_argument("--region")
    q.add_argument("--no-apply", action="store_true", help="record it in the database only")
    reasoned(q)
    add_profile_arg(q)
    q.add_argument("command", nargs=argparse.REMAINDER, help="-- aws ec2 …  (or the whole command quoted)")
    q = sub.add_parser("apply", help="make AWS match the database")
    q.add_argument("--region", required=True)
    q.add_argument("--group")
    q.add_argument("--yes", action="store_true")
    reasoned(q, required=False)
    add_profile_arg(q)
    q = sub.add_parser("adopt", help="accept what AWS holds into the database")
    q.add_argument("--region", required=True)
    q.add_argument("--group")
    q.add_argument("--account")
    reasoned(q)
    q = sub.add_parser("create-group", help="create a security group, in AWS and the database")
    for a in ("--region", "--vpc", "--name", "--description"):
        q.add_argument(a, required=True)
    reasoned(q)
    add_profile_arg(q)
    q = sub.add_parser("log", help="the audit trail")
    q.add_argument("--region")
    q.add_argument("--group")
    q.add_argument("--account")
    q.add_argument("--since", help="24h, 7d, …")
    q.add_argument("--limit", type=int, default=500)
    q.add_argument("--json", action="store_true")
    sub.add_parser("verify", help="check the audit trail's hash chain")
    return p


@friendly_login_errors
def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = _build_parser().parse_args(argv)
    if getattr(args, "command", None) and args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if args.cmd == "remove" and not args.all and not (args.proto and args.source):
        raise SystemExit("remove needs --proto and --source (and --port), or --all")
    store = Store(args.db)
    try:
        handler = {"import": cmd_import, "reconcile": cmd_reconcile, "show": cmd_show, "diff": cmd_diff,
                   "exec": cmd_exec, "apply": cmd_apply, "adopt": cmd_adopt, "create-group": cmd_create_group,
                   "log": cmd_log, "verify": cmd_verify}.get(args.cmd)  # fmt: skip
        try:
            if args.cmd in ("add", "remove"):
                return cmd_add_remove(args, store, args.cmd)
            return handler(args, store)
        except Refused as exc:
            raise SystemExit(str(exc))
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main())
