#!/usr/bin/env python3
"""sg_db.py: every security group and rule in a local database, with an audit trail.

The database (SQLite, ``~/.sg-tightener/sg.db``) is the source of truth for security groups. AWS is
where the rules are enforced; the database is where they are decided. Nothing else, Terraform
included, may create, change or delete a group or a rule.

Each group's rules are held twice:

* **desired**: what the rules should be. Changed only by this tool (``add``, ``remove``, ``exec``,
  ``adopt``) and by sg_tightener, sg_extend and sg_compact, each with who and why.
* **synced**: what AWS held the last time the tool read or changed it.

Desired changes only by an approved **change request**: one person proposes (``add``, ``remove``,
``exec``, ``adopt``, ``propose --plan``) with a reason, and a different person approves it
(``approve``); two-person approval is on unless ``approvals off`` was set (audited).
``apply`` pushes desired to AWS. ``reconcile`` reads AWS: anything that differs from synced was
changed outside the tool (console, CLI, Terraform). It is recorded in the audit trail as external,
reported, and left for a person to decide: ``apply`` puts AWS back to desired, ``adopt`` accepts the
change into desired. The audit trail is append-only (triggers refuse UPDATE and DELETE) and
hash-chained, so ``verify`` shows whether anyone edited or removed an entry.

Usage:
  sg_db.py import    --regions eu-west-1,us-east-1 [--profile P] [--ou-id ou-… | --org] [--role-name R]
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
  sg_db.py requests  [--status pending]
  sg_db.py approve   ID [--note "…"]      (a different person from the one who proposed it)
  sg_db.py reject    ID --note "…"
  sg_db.py cancel    ID
  sg_db.py propose   --plan plan.json --reason "…"   (an sg_tightener or sg_compact plan)
  sg_db.py approvals on|off --reason "…"
  sg_db.py mode      [show | surveillance | enforce] (--account ID | --all) --reason "…"
  sg_db.py check     --regions R [--ou-id …] [--assets]        (DryRun: can this identity apply here?)
  sg_db.py assets    --region R [--account ID] [--json]        (every network interface and its groups)
  sg_db.py asset-plan  --region R (--eni eni-… | --instance i-…) --approved approved.json [--out F]
  sg_db.py asset-propose --plan asset-plan.json --reason "…"
  sg_db.py asset-apply ID          (an approved asset request: its own group, then the swap)
  sg_db.py asset-revert --region R --eni eni-… --reason "…"
  sg_db.py asset-log   (--eni eni-… | --instance i-…)
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
import time
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
CREATE TABLE IF NOT EXISTS accounts (account TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL,
  proposer TEXT NOT NULL, reason TEXT NOT NULL, ticket TEXT NOT NULL DEFAULT '', changes TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled', 'applied')),
  decided_by TEXT NOT NULL DEFAULT '', decided_at TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
  applied_at TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS requests_status ON requests (status, account, region);
CREATE TABLE IF NOT EXISTS modes (
  account TEXT PRIMARY KEY, mode TEXT NOT NULL CHECK (mode IN ('surveillance', 'enforce')),
  set_by TEXT NOT NULL, set_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS permissions (
  account TEXT NOT NULL, region TEXT NOT NULL, checked_at TEXT NOT NULL, actor TEXT NOT NULL,
  ok INTEGER NOT NULL, result TEXT NOT NULL, PRIMARY KEY (account, region));
CREATE TABLE IF NOT EXISTS assets (
  account TEXT NOT NULL, region TEXT NOT NULL, eni TEXT NOT NULL, instance TEXT NOT NULL DEFAULT '',
  asg TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT '', vpc_id TEXT NOT NULL DEFAULT '',
  ips TEXT NOT NULL DEFAULT '[]', groups TEXT NOT NULL DEFAULT '[]', description TEXT NOT NULL DEFAULT '',
  observed_at TEXT NOT NULL, PRIMARY KEY (account, region, eni));
CREATE TRIGGER IF NOT EXISTS audit_append_only_u BEFORE UPDATE ON audit
  BEGIN SELECT RAISE(ABORT, 'the audit trail is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_append_only_d BEFORE DELETE ON audit
  BEGIN SELECT RAISE(ABORT, 'the audit trail is append-only'); END;
"""

SURVEILLANCE, ENFORCE = "surveillance", "enforce"
ANY_ACCOUNT = "*"  # the default mode, for accounts without their own
# What applying needs, tried with DryRun before any change: (call, what it is for).
RULE_CALLS = ("authorize_security_group_ingress", "revoke_security_group_ingress",
              "authorize_security_group_egress", "revoke_security_group_egress")  # fmt: skip
ASSET_CALLS = ("create_security_group", "modify_network_interface_attribute", "create_tags")
PROBE_PERM = {"IpProtocol": "tcp", "FromPort": 9, "ToPort": 9,
              "IpRanges": [{"CidrIp": "192.0.2.9/32", "Description": "sg-tightener permission check"}]}  # fmt: skip

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
        for attempt in range(50):  # switching to WAL skips the busy timeout: several readers opening at once retry
            try:
                if self.db.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
                    self.db.execute("PRAGMA journal_mode=WAL")
                break
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc) or attempt == 49:
                    raise
                time.sleep(0.1)
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

    def adoption(self, account: str, region: str, gid: str = "") -> list[tuple[str, str, Rule, str]]:
        """The changes that would make desired what AWS holds (synced), as a change request's changes."""
        out = []
        for g in [gid] if gid else self.groups(account, region):
            want, have = self.rules(account, region, g, "desired"), self.rules(account, region, g, "synced")
            out += [(g, "add", r, d) for r, d in sorted(have.items()) if r not in want]
            out += [(g, "remove", r, d) for r, d in sorted(want.items()) if r not in have]
        return out

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

    # ---------------------------------------------------------------- accounts
    def name_account(self, account: str, name: str) -> None:
        if name:
            self.db.execute("INSERT INTO accounts (account, name) VALUES (?, ?) ON CONFLICT (account) DO UPDATE SET "
                            "name = excluded.name", (account, name))  # fmt: skip

    def account_names(self) -> dict[str, str]:
        return dict(self.db.execute("SELECT account, name FROM accounts"))

    # ---------------------------------------------------------------- modes
    def mode(self, account: str) -> str:
        """surveillance (the default: find and propose, never change AWS) or enforce (apply is allowed)."""
        for a in (account, ANY_ACCOUNT):
            row = self.db.execute("SELECT mode FROM modes WHERE account = ?", (a,)).fetchone()
            if row:
                return row[0]
        return SURVEILLANCE

    def modes(self) -> dict[str, str]:
        return dict(self.db.execute("SELECT account, mode FROM modes"))

    def set_mode(self, account: str, mode: str, actor: str, reason: str) -> None:
        """``account`` "*" sets the default for every account without its own mode."""
        if mode not in (SURVEILLANCE, ENFORCE):
            raise Refused("the mode is surveillance or enforce")
        if not reason.strip():
            raise Refused("a reason is required: it goes in the audit trail")
        before = self.mode(account)
        self.db.execute("INSERT INTO modes (account, mode, set_by, set_at) VALUES (?, ?, ?, ?) ON CONFLICT (account) "
                        "DO UPDATE SET mode = excluded.mode, set_by = excluded.set_by, set_at = excluded.set_at",
                        (account, mode, actor, _now()))  # fmt: skip
        self.audit(actor, "tool", f"mode-{mode}", "" if account == ANY_ACCOUNT else account, "", "",
                   {"mode": mode, "before": before, "scope": "default" if account == ANY_ACCOUNT else "account"}, reason)  # fmt: skip

    def require_enforce(self, account: str, what: str) -> None:
        if self.mode(account) != ENFORCE:
            raise Refused(f"{account} is in surveillance mode: sg-tightener reports what to change and records change "
                          f"requests, but does not {what}. When the organisation is ready: sg_db.py check --account "
                          f"{account} --regions R (permissions), then sg_db.py mode enforce --account {account} "
                          f"--reason \"…\".")  # fmt: skip

    def record_permissions(self, account: str, region: str, actor: str, result: dict) -> None:
        ok = all(not v["denied"] and not v["unknown"] for v in result.values())
        self.db.execute("INSERT INTO permissions (account, region, checked_at, actor, ok, result) VALUES (?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT (account, region) DO UPDATE SET checked_at = excluded.checked_at, actor = "
                        "excluded.actor, ok = excluded.ok, result = excluded.result",
                        (account, region, _now(), actor, int(ok), json.dumps(result, sort_keys=True)))  # fmt: skip
        self.audit(actor, "tool", "permissions-checked", account, region, "",
                   {"ok": ok, "denied": {k: v["denied"] for k, v in result.items() if v["denied"]},
                    "unknown": {k: v["unknown"] for k, v in result.items() if v["unknown"]}}, "permission check (DryRun)")  # fmt: skip

    def permissions(self, account: str = "", region: str = "") -> list[dict]:
        q, args = "SELECT account, region, checked_at, actor, ok, result FROM permissions", []
        if account:
            q, args = q + " WHERE account = ?" + (" AND region = ?" if region else ""), [account] + ([region] if region else [])
        cols = ("account", "region", "checked_at", "actor", "ok", "result")
        return [{**dict(zip(cols, r)), "ok": bool(r[4]), "result": json.loads(r[5])} for r in self.db.execute(q, args)]

    # ---------------------------------------------------------------- change requests
    def approvals(self) -> bool:
        row = self.db.execute("SELECT value FROM meta WHERE key = 'approvals'").fetchone()
        return (row[0] if row else "two-person") != "off"

    def set_approvals(self, on: bool, actor: str, reason: str) -> None:
        if not reason.strip():
            raise Refused("a reason is required: it goes in the audit trail")
        if self.approvals() == on:
            return
        self.db.execute("INSERT INTO meta (key, value) VALUES ('approvals', ?) ON CONFLICT (key) DO UPDATE SET "
                        "value = excluded.value", ("two-person" if on else "off",))  # fmt: skip
        self.audit(actor, "tool", "approvals-on" if on else "approvals-off", "", "", "",
                   {"approvals": "two-person" if on else "off"}, reason)  # fmt: skip

    def propose(self, account: str, region: str, actor: str, reason: str, ticket: str,
                changes: list[tuple[str, str, Rule, str]]) -> int | None:  # fmt: skip
        """A change request: (group, "add" or "remove", rule, description) each. With approvals off it is
        approved by the proposer at once. Returns the request id, or None when it changes nothing."""
        if not reason.strip():
            raise Refused("a reason is required: it goes in the audit trail")
        known = self.groups(account, region)
        for gid, op, _, _ in changes:
            if gid not in known:
                raise Refused(f"{gid} is not in the database for {account} {region}")
            if op not in ("add", "remove"):
                raise Refused(f"unknown change {op}")
        changes = [c for c in changes if self._would_change(account, region, c)]
        if not changes:
            return None
        body = json.dumps([{"group": g, "op": op, "rule": _rule_json(r, d)} for g, op, r, d in changes], sort_keys=True)
        cur = self.db.execute("INSERT INTO requests (at, account, region, proposer, reason, ticket, changes, status) "
                              "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')",
                              (_now(), account, region, actor, reason, ticket, body))  # fmt: skip
        rid = cur.lastrowid
        self.audit(actor, "tool", "request-proposed", account, region, _groups_of(changes),
                   {"request": rid, **_split(changes)}, reason, ticket)  # fmt: skip
        if not self.approvals():
            self._approve(rid, actor, "approvals are off")
        return rid

    def _would_change(self, account, region, c) -> bool:
        gid, op, rule, _ = c
        want = self.rules(account, region, gid, "desired")
        return (rule not in want) if op == "add" else (rule in want)

    def requests(self, status: str = "", account: str = "", region: str = "", rid: int | None = None) -> list[dict]:
        q, args, where = ("SELECT id, at, account, region, proposer, reason, ticket, changes, status, decided_by, "
                          "decided_at, note, applied_at FROM requests"), [], []  # fmt: skip
        for col, v in (("status", status), ("account", account), ("region", region), ("id", rid)):
            if v:
                where.append(f"{col} = ?")
                args.append(v)
        if where:
            q += " WHERE " + " AND ".join(where)
        cols = ("id", "at", "account", "region", "proposer", "reason", "ticket", "changes", "status", "decided_by",
                "decided_at", "note", "applied_at")  # fmt: skip
        out = [{**dict(zip(cols, r)), "changes": json.loads(r[7])} for r in self.db.execute(q + " ORDER BY id DESC", args)]
        for r in out:  # an asset request (sg_assets) holds one plan, not a list of rule changes
            r["kind"] = (r["changes"].get("kind") or "asset") if isinstance(r["changes"], dict) else "rules"
        return out

    def _request(self, rid: int) -> dict:
        got = self.requests(rid=rid)
        if not got:
            raise Refused(f"no change request #{rid}")
        return got[0]

    def decide(self, rid: int, actor: str, approve: bool, note: str = "") -> dict:
        """Approve (a different person from the proposer) or reject a pending request."""
        r = self._request(rid)
        if r["status"] != "pending":
            raise Refused(f"request #{rid} is {r['status']}, not pending")
        if approve and principal(actor) == principal(r["proposer"]):
            raise Refused(f"request #{rid} was proposed by {principal(actor)}: a different person must approve it")
        if not approve and not note.strip():
            raise Refused("say why it is rejected (--note): it goes in the audit trail")
        if approve:
            return self._approve(rid, actor, note)
        self.db.execute("UPDATE requests SET status = 'rejected', decided_by = ?, decided_at = ?, note = ? WHERE id = ?",
                        (actor, _now(), note, rid))  # fmt: skip
        self.audit(actor, "tool", "request-rejected", r["account"], r["region"], _groups_of_json(r["changes"]),
                   {"request": rid}, note, r["ticket"])  # fmt: skip
        return {"added": [], "removed": []}

    def _approve(self, rid: int, actor: str, note: str) -> dict:
        r = self._request(rid)
        self.db.execute("UPDATE requests SET status = 'approved', decided_by = ?, decided_at = ?, note = ? WHERE id = ?",
                        (actor, _now(), note, rid))  # fmt: skip
        self.audit(actor, "tool", "request-approved", r["account"], r["region"], _groups_of_json(r["changes"]),
                   {"request": rid, "proposer": r["proposer"], **({"eni": r["changes"]["eni"]} if r["kind"] == "asset" else {})},
                   note or "approved", r["ticket"])  # fmt: skip
        out = {"added": [], "removed": []}
        if r["kind"] != "rules":  # an asset or a merge: carried out on its own, not through desired
            return out
        by_group: dict[str, list] = {}
        for c in r["changes"]:
            by_group.setdefault(c["group"], []).append(c)
        for gid, cs in by_group.items():
            d = self.desire(r["account"], r["region"], gid, actor, f"request #{rid}: {r['reason']}", r["ticket"],
                            add={_rule_tuple(c["rule"]): c["rule"].get("description", "") for c in cs if c["op"] == "add"},
                            remove=[_rule_tuple(c["rule"]) for c in cs if c["op"] == "remove"], origin="approved")  # fmt: skip
            out["added"] += d["added"]
            out["removed"] += d["removed"]
        return out

    def cancel(self, rid: int, actor: str) -> None:
        r = self._request(rid)
        if r["status"] != "pending":
            raise Refused(f"request #{rid} is {r['status']}, not pending")
        if principal(actor) != principal(r["proposer"]):
            raise Refused(f"only {principal(r['proposer'])}, who proposed it, can cancel request #{rid}; reject it instead")
        self.db.execute("UPDATE requests SET status = 'cancelled', decided_by = ?, decided_at = ? WHERE id = ?",
                        (actor, _now(), rid))  # fmt: skip
        self.audit(actor, "tool", "request-cancelled", r["account"], r["region"], _groups_of_json(r["changes"]),
                   {"request": rid}, "cancelled by the proposer", r["ticket"])  # fmt: skip

    def settle(self, account: str, region: str) -> list[int]:
        """Mark approved requests whose every change AWS now holds as applied."""
        done = []
        for r in self.requests("approved", account, region):
            if r["kind"] != "rules":
                continue
            ok = True
            for c in r["changes"]:
                have = self.rules(account, region, c["group"], "synced")
                rule = _rule_tuple(c["rule"])
                if (c["op"] == "add") != (rule in have):
                    ok = False
                    break
            if ok:
                self.db.execute("UPDATE requests SET status = 'applied', applied_at = ? WHERE id = ?", (_now(), r["id"]))
                done.append(r["id"])
        return done

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


def principal(actor: str) -> str:
    """The AWS identity in an actor name ("arn (local user)"): who must differ between proposer and approver."""
    return actor.split(" (", 1)[0]


def _groups_of(changes) -> str:
    return ",".join(sorted({c[0] for c in changes}))


def _groups_of_json(changes) -> str:
    if isinstance(changes, dict):  # an asset request, or a merge of groups
        return ",".join(changes.get("from_groups") or changes.get("members") or [])
    return ",".join(sorted({c["group"] for c in changes}))


def _split(changes) -> dict:
    return {"added": [{"group": g, **_rule_json(r, d)} for g, op, r, d in changes if op == "add"],
            "removed": [{"group": g, **_rule_json(r, d)} for g, op, r, d in changes if op == "remove"]}  # fmt: skip


def plan_changes(plan: dict, account: str) -> list[tuple[str, str, Rule, str]]:
    """An sg_tightener or sg_compact plan as change-request changes: its revokes, then its authorisations."""
    if plan.get("schema") != "sg-tightener.plan/v1":
        raise Refused(f"not an sg-tightener plan (schema {plan.get('schema')!r})")
    out = []
    for g in plan.get("groups") or []:
        for r, d in rules_from_permissions(g.get("revoke") or [], IN, account).items():
            out.append((g["group_id"], "remove", r, d))
        for r, d in rules_from_permissions(g.get("authorise") or [], IN, account).items():
            out.append((g["group_id"], "add", r, d))
    return out


def _hash(entry: dict) -> str:
    return hashlib.sha256(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ------------------------------------------------------------------------------------------ AWS side
def account_of(session=None) -> tuple[str, str]:
    """(account id, caller ARN)."""
    sts = (session or sg_tightener.boto3).client("sts")
    ident = sts.get_caller_identity()
    return ident["Account"], ident.get("Arn", "")


def ensure_current(store: Store, ec2, account: str, region: str, actor: str, who=None, assets: bool = False) -> list[dict]:
    """Import the region on first use; otherwise record any external change. Returns the external changes.
    With ``assets`` also record every network interface's groups (and any change to them)."""
    live = read_live(ec2, account)
    found = describe = None
    if assets:
        import sg_assets

        describe = sg_assets.describe_assets(ec2)
    with store:
        if not store.imported(account, region):
            n = store.import_region(account, region, live, actor)
            LOG.info("imported %d group(s) and %d rule(s) in %s into %s", len(live), n, region, store.path)
            found = []
        else:
            found = store.observe(account, region, live, actor, who)
        if describe is not None:
            import sg_assets

            moved = sg_assets.observe_assets(store, account, region, describe, actor)
            found += [{"group": ",".join(m["after"]), "name": f"asset {m['eni']}" + (f" ({m['instance']})" if m["instance"] else ""),
                       "change": f"groups changed from {', '.join(m['before'])} to {', '.join(m['after'])}", "added": [],
                       "removed": []} for m in moved]  # fmt: skip
    return found


def _dry(call, **kw) -> str:
    """allowed, denied or unknown (with why), from one DryRun call."""
    try:
        call(DryRun=True, **kw)
        return "allowed"  # a client without DryRun support: it would have run, so it was allowed
    except Exception as exc:  # noqa: BLE001 - botocore ClientError or a test double
        code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if code == "DryRunOperation":
            return "allowed"
        if code in ("UnauthorizedOperation", "AccessDenied", "AccessDeniedException", "Client.UnauthorizedOperation"):
            return "denied"
        return f"unknown: {code or type(exc).__name__}: {str(exc)[:160]}"


def check_permissions(ec2, groups: Iterable[str], assets: Iterable[dict] = ()) -> dict:
    """Can this identity change these groups (and swap these assets' groups)? Every call is a DryRun, so
    service control policies, permission boundaries and tag or VPC conditions all count, and nothing changes.
    Returns {group or eni: {"allowed": [...], "denied": [...], "unknown": [...]}}."""
    out: dict[str, dict] = {}
    for gid in groups:
        res = {"allowed": [], "denied": [], "unknown": []}
        for name in RULE_CALLS:
            got = _dry(getattr(ec2, name), GroupId=gid, IpPermissions=[PROBE_PERM])
            res["allowed" if got == "allowed" else "denied" if got == "denied" else "unknown"].append(
                name if got in ("allowed", "denied") else f"{name} ({got[9:]})")
        out[gid] = res
    for a in assets:
        res = {"allowed": [], "denied": [], "unknown": []}
        calls = {"create_security_group": {"GroupName": "sg-tightener-permission-check", "Description": "check",
                                           "VpcId": a.get("vpc_id") or ""},
                 "modify_network_interface_attribute": {"NetworkInterfaceId": a["eni"], "Groups": a.get("groups") or []},
                 "create_tags": {"Resources": [a["eni"]], "Tags": [{"Key": "sg-tightener:check", "Value": "1"}]}}  # fmt: skip
        for name, kw in calls.items():
            got = _dry(getattr(ec2, name), **kw)
            res["allowed" if got == "allowed" else "denied" if got == "denied" else "unknown"].append(
                name if got in ("allowed", "denied") else f"{name} ({got[9:]})")
        out[a["eni"]] = res
    return out


def _permission_problems(result: dict) -> list[str]:
    return [f"{k}: " + ", ".join([f"not allowed {d}" for d in v["denied"]] + [f"could not check {u}" for u in v["unknown"]])
            for k, v in result.items() if v["denied"] or v["unknown"]]


def push(store: Store, ec2, account: str, region: str, actor: str, gid: str = "", reason: str = "",
         ticket: str = "") -> dict:  # fmt: skip
    """Make AWS match desired. Refuses if AWS changed outside the tool since it was last read (reconcile
    first, so a person has seen it). Refuses in surveillance mode, and before any change unless a DryRun
    shows every call needed is allowed. Returns {"done": n, "failed": [...]}."""
    store.require_enforce(account, "change security groups")
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
    if todo:
        perms = check_permissions(ec2, sorted({g for g, _, _, _ in todo}))
        with store:
            store.record_permissions(account, region, actor, perms)
        bad = _permission_problems(perms)
        if bad:
            raise Refused("nothing was changed: this identity cannot make every change (checked with DryRun):\n  "
                          + "\n  ".join(bad))
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
    with store:
        out["settled"] = store.settle(account, region)
    return out


class TrackedEC2:
    """An EC2 client for sg_tightener, sg_extend and sg_compact: before the first change it imports the region
    (first use) or checks nothing changed outside the tool, and after each rule change it records what AWS now
    holds for that group, as desired and synced, in the audit trail."""

    WRITES = ("authorize_security_group_ingress", "revoke_security_group_ingress",
              "authorize_security_group_egress", "revoke_security_group_egress", "modify_security_group_rules")  # fmt: skip

    def __init__(self, ec2, region: str, tool: str, reason: str = "", store: Store | None = None,
                 account: str = "", arn: str = "", strict: bool = True, undo: bool = False):  # fmt: skip
        self._ec2, self._region, self._tool, self._reason = ec2, region, tool, reason
        self._store = store or Store()
        if not account:
            account, arn = account_of()
        if not undo and self._store.mode(account) != ENFORCE:
            raise SystemExit(f"{account} is in surveillance mode: {tool} would change security groups. Use the plan "
                             f"as a report, or propose it (sg_db.py propose --plan …). When the organisation is ready: "
                             f"sg_db.py check --regions {region}; sg_db.py mode enforce --account {account} --reason \"…\".")  # fmt: skip
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
        if strict and self._store.approvals():
            raise SystemExit(f"two-person approval is on: propose this as a change request, then have someone else "
                             f"approve it and apply it: sg_db.py propose --plan PLAN.json --reason \"…\"; "
                             f"sg_db.py approve ID; sg_db.py apply --region {region}. ({tool} itself is for when "
                             f"approvals are off: sg_db.py approvals off --reason \"…\".)")  # fmt: skip
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
    unreviewed external changes or the database has unapplied ones; revert and break-glass pass False.
    Surveillance mode refuses every tool but a revert (undoing a change is always allowed)."""
    return TrackedEC2(ec2, region, tool, reason, strict=strict, undo="revert" in tool)


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
DEFAULT_ROLE = "OrganizationAccountAccessRole"


def _session(profile):
    use_profile(profile)
    return sg_tightener.boto3.Session(profile_name=profile) if profile else sg_tightener.boto3.Session()


class Targets:
    """The caller (who acts, for the audit trail) and a session per account: the caller's own, or a role
    assumed in each account of an OU or the organisation."""

    def __init__(self, args):
        self.base = _session(getattr(args, "profile", None))
        self.account, arn = account_of(self.base)
        self.actor = actor_name(arn)
        self.role = getattr(args, "role_name", None) or DEFAULT_ROLE
        self.external_id = getattr(args, "external_id", "") or ""
        self._sessions = {self.account: self.base}

    def session(self, account: str):
        if not account or account == self.account:
            return self.base
        if account not in self._sessions:
            import sg_review

            self._sessions[account] = sg_review._assume(self.base, account, self.role, self.external_id)
        return self._sessions[account]

    def accounts(self, args) -> list[tuple[str, str]]:
        """(account, name) for --ou-id / --org, narrowed by --accounts; else --account or the caller's own."""
        only = {a.strip() for a in (getattr(args, "accounts", "") or "").split(",") if a.strip()}
        if getattr(args, "ou_id", None) or getattr(args, "org", False):
            import sg_review

            found = [(a["Id"], a.get("Name", "")) for a in sg_review.org_accounts(self.base, getattr(args, "ou_id", None))]
            return [a for a in found if not only or a[0] in only]
        if only:
            return [(a, "") for a in sorted(only)]
        return [(getattr(args, "account", None) or self.account, "")]


def _for_each(args, store: Store, fn) -> tuple[list[str], int]:
    """Run fn(targets, account, session, region) for every account and region; one out of reach is reported
    and the rest still run. Returns (lines, failures)."""
    t = Targets(args)
    lines, failed = [], 0
    for account, name in t.accounts(args):
        try:
            sess = t.session(account)
        except Exception as exc:  # noqa: BLE001 - one account out of reach must not stop the others
            lines.append(f"{account} {name}: not reached ({exc})")
            failed += 1
            continue
        if name:
            with store:
                store.name_account(account, name)
        for region in _regions(args.regions):
            try:
                lines += fn(t, account, sess, region) or []
            except Refused:
                raise
            except Exception as exc:  # noqa: BLE001
                lines.append(f"{account} {region}: failed ({exc})")
                failed += 1
    return lines, failed


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
        last[ev["group"]] = (f"{ev['who'] or 'unknown'} ({ev['name']} at "
                             f"{dt.datetime.fromtimestamp(ev['t'], dt.timezone.utc):%Y-%m-%d %H:%M} UTC"
                             + (f" from {ev['ip']}" if ev.get("ip") else "") + ")")  # fmt: skip
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


def _caller_actor(args=None) -> str:
    sess = _session(getattr(args, "profile", None)) if args is not None else None
    return actor_name(account_of(sess)[1])


def _requested(store: Store, rid, region: str) -> str:
    if rid is None:
        return "nothing changed: the database already says that"
    r = store._request(rid)
    if r["status"] == "pending":
        return (f"change request #{rid} recorded, waiting for a second person: sg_db.py approve {rid}; "
                f"then sg_db.py apply --region {region}")  # fmt: skip
    return f"change request #{rid} approved (approvals are off); sg_db.py apply --region {region} makes it in AWS"


def cmd_import(args, store: Store) -> int:
    def one(t, account, sess, region):
        if store.imported(account, region):
            return [f"{account} {region}: already in the database (reconcile reads it again)"]
        import sg_assets

        ec2 = sess.client("ec2", region_name=region)
        live = read_live(ec2, account)
        assets = [] if args.no_assets else sg_assets.describe_assets(ec2)
        with store:
            n = store.import_region(account, region, live, t.actor, args.reason or "first import")
            if assets:
                sg_assets.observe_assets(store, account, region, assets, t.actor)
        return [f"{account} {region}: {len(live)} group(s), {n} rule(s)" + (f", {len(assets)} asset(s)" if assets else "")
                + " imported"]

    lines, failed = _for_each(args, store, one)
    print("\n".join(lines))
    return 2 if failed else 0


def cmd_reconcile(args, store: Store) -> int:
    found = {"ext": 0, "pend": 0}

    def one(t, account, sess, region):
        out = []
        ec2 = sess.client("ec2", region_name=region)
        who = None if args.no_cloudtrail else _who_from_cloudtrail(sess, region)
        changes = ensure_current(store, ec2, account, region, t.actor, who, assets=not args.no_assets)
        pend = store.pending(account, region)
        found["ext"] += len(changes)
        found["pend"] += len(pend)
        label = f"{account}{' (' + store.account_names().get(account, '') + ')' if store.account_names().get(account) else ''} {region}"
        if changes:
            out.append(f"{label}: {len(changes)} group(s) changed outside sg-tightener")
            for ch in changes:
                out += _change_lines(ch)
        if pend:
            out.append(f"{label}: `sg_db.py apply --account {account} --region {region}` would make {len(pend)} "
                       f"change(s) so AWS matches the database:")  # fmt: skip
            out += [f"  {'revoke' if op == 'remove' else 'authorize'} {g}: {rule_text(r, d)}" for g, op, r, d in pend]
            out.append(f"  or keep what AWS holds: sg_db.py adopt --account {account} --region {region} "
                       f"[--group sg-…] --reason \"…\" (a change request)")  # fmt: skip
        return out

    lines, failed = _for_each(args, store, one)
    waiting = store.requests("pending")
    if waiting:
        lines.append(f"{len(waiting)} change request(s) waiting for approval: sg_db.py requests --status pending")
    text = "\n".join(lines) if lines else "AWS matches the database."
    print(text)
    if found["ext"] and args.slack:
        import sg_review

        sg_review.post_slack(args.slack, "*sg-tightener: security groups changed outside the tool*\n```" + text[:3500] + "```")
    return 2 if failed else 1 if found["ext"] or found["pend"] else 0


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
    actor = _caller_actor(args)
    if op == "remove" and args.all:
        changes = [(args.group, "remove", r, d) for r, d in store.rules(account, args.region, args.group, "desired").items()
                   if r[0] == args.direction]  # fmt: skip
    elif op == "remove":
        changes = [(args.group, "remove", _rule_from_args(args), "")]
    else:
        changes = [(args.group, "add", _rule_from_args(args), args.description or "")]
    with store:
        rid = store.propose(account, args.region, actor, args.reason, args.ticket, changes)
    print(_requested(store, rid, args.region))
    return 0


def cmd_exec(args, store: Store) -> int:
    cmd = args.command
    if len(cmd) == 1:
        cmd = shlex.split(cmd[0])
    c = parse_command(cmd)
    region = c["region"] or args.region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if not region:
        raise SystemExit("the command has no --region and none is set")
    t = Targets(args)
    account = args.account or t.account
    sess = t.session(account)
    ec2 = sess.client("ec2", region_name=region)
    ext = ensure_current(store, ec2, account, region, t.actor)
    if ext:
        raise SystemExit(f"{len(ext)} group(s) were changed outside sg-tightener; review them with "
                         f"`sg_db.py reconcile --regions {region}` first")  # fmt: skip
    rules = rules_from_permissions(c["perms"], c["direction"], account)
    if c["rule_ids"]:
        rules.update({r: "" for r in rules_for_ids(ec2, c["group"], c["rule_ids"], account)})
    op = "add" if c["verb"] == "authorize" else "remove"
    with store:
        rid = store.propose(account, region, t.actor, args.reason, args.ticket,
                            [(c["group"], op, r, d) for r, d in rules.items()])  # fmt: skip
    if rid is None or store._request(rid)["status"] == "pending" or args.no_apply:
        print(_requested(store, rid, region))
        return 0
    if store.mode(account) != ENFORCE:
        print(_requested(store, rid, region) + f"\n{account} is in surveillance mode: recorded, not applied")
        return 0
    res = push(store, ec2, account, region, t.actor, c["group"], args.reason, args.ticket)
    print(f"{res['done']} change(s) made in AWS and recorded" + (f"; {len(res['failed'])} failed" if res["failed"] else ""))
    return 1 if res["failed"] else 0


def cmd_propose(args, store: Store) -> int:
    with open(args.plan, encoding="utf-8") as fh:
        plan = json.load(fh)
    region = plan.get("region") or args.region
    if not region:
        raise SystemExit("the plan names no region: pass --region")
    t = Targets(args)
    account = args.account or t.account
    ensure_current(store, t.session(account).client("ec2", region_name=region), account, region, t.actor)
    with store:
        rid = store.propose(account, region, t.actor, args.reason, args.ticket, plan_changes(plan, account))
    print(_requested(store, rid, region))
    return 0


def cmd_apply(args, store: Store) -> int:
    t = Targets(args)
    account = args.account or t.account
    pend = store.pending(account, args.region, args.group or "")
    if not pend:
        print("nothing to apply")
        return 0
    for g, op, r, d in pend:
        print(f"{'revoke' if op == 'remove' else 'authorize'} {g}: {rule_text(r, d)}")
    if not args.yes:
        sg_tightener._confirm(f"make these {len(pend)} change(s) in {account} {args.region}")
    try:
        res = push(store, t.session(account).client("ec2", region_name=args.region), account, args.region, t.actor,
                   args.group or "", args.reason or "sg_db.py apply", args.ticket)  # fmt: skip
    except Refused as exc:
        raise SystemExit(str(exc))
    print(f"{res['done']} change(s) made" + (f", {len(res['failed'])} failed" if res["failed"] else "")
          + (f"; request(s) applied: {', '.join('#' + str(i) for i in res['settled'])}" if res.get("settled") else ""))
    return 1 if res["failed"] else 0


def cmd_adopt(args, store: Store) -> int:
    account = args.account or _only_account(store, args.region)
    with store:
        rid = store.propose(account, args.region, _caller_actor(args), args.reason, args.ticket,
                            store.adoption(account, args.region, args.group or ""))  # fmt: skip
    print(_requested(store, rid, args.region) if rid is not None else "nothing to adopt: the database already wants what AWS holds")
    return 0


def cmd_requests(args, store: Store) -> int:
    rows = store.requests(args.status or "", args.account or "", args.region or "")
    if args.json:
        print(json.dumps(rows, indent=1))
        return 0
    for r in rows:
        print(f"#{r['id']} {r['status']:<9} {r['at']} {r['account']} {r['region']}  by {principal(r['proposer'])}"
              + (f"  [{r['ticket']}]" if r["ticket"] else "") + f"  {r['reason']}")  # fmt: skip
        if r["kind"] == "asset":
            import sg_assets

            print("    " + "\n    ".join(sg_assets.plan_text({**r["changes"], "account": r["account"]})))
        else:
            for c in r["changes"]:
                print(f"    {'+' if c['op'] == 'add' else '-'} {c['group']}: {rule_text(_rule_tuple(c['rule']), c['rule'].get('description', ''))}")
        if r["decided_by"]:
            print(f"    {r['status']} by {principal(r['decided_by'])} at {r['decided_at']}" + (f": {r['note']}" if r["note"] else ""))
    if not rows:
        print("no change requests" + (f" {args.status}" if args.status else ""))
    return 0


def cmd_decide(args, store: Store) -> int:
    actor = _caller_actor(args)
    with store:
        if args.cmd == "cancel":
            store.cancel(args.id, actor)
            print(f"change request #{args.id} cancelled")
            return 0
        store.decide(args.id, actor, args.cmd == "approve", args.note or "")
    r = store._request(args.id)
    nxt = (f"sg_db.py asset-apply {args.id}" if r["kind"] == "asset"
           else f"sg_db.py apply --account {r['account']} --region {r['region']}")  # fmt: skip
    print(f"change request #{args.id} {r['status']}" + (f"; {nxt} makes it in AWS" if r["status"] == "approved" else ""))
    return 0


def cmd_approvals(args, store: Store) -> int:
    with store:
        store.set_approvals(args.state == "on", _caller_actor(args), args.reason)
    print(f"two-person approval is {'on' if store.approvals() else 'off'}")
    return 0


def cmd_mode(args, store: Store) -> int:
    if args.state in (None, "show"):
        modes = store.modes()
        print(f"default: {modes.get(ANY_ACCOUNT, SURVEILLANCE)}")
        names = store.account_names()
        for account in sorted({a for a, _ in store.regions()} | (set(modes) - {ANY_ACCOUNT})):
            print(f"{account}{' (' + names[account] + ')' if names.get(account) else ''}: {store.mode(account)}"
                  + ("" if account in modes else " (default)"))  # fmt: skip
        return 0
    if not args.all and not args.account:
        raise SystemExit("pass --account ID, or --all for the default of every account without its own mode")
    account = ANY_ACCOUNT if args.all else args.account
    if args.state == ENFORCE and not args.all:
        checked = store.permissions(account)
        if not checked:
            raise SystemExit(f"check the permissions first: sg_db.py check --account {account} --regions R "
                             f"(it proves, with DryRun, that this identity can change {account}'s groups)")  # fmt: skip
        bad = [p["region"] for p in checked if not p["ok"]]
        if bad and not args.anyway:
            raise SystemExit(f"the last permission check failed in {', '.join(bad)}: fix the role, run sg_db.py check "
                             f"again, or pass --anyway")  # fmt: skip
    with store:
        store.set_mode(account, args.state, _caller_actor(args), args.reason)
    print(f"{'every account without its own mode' if args.all else account}: {args.state}")
    return 0


def cmd_check(args, store: Store) -> int:
    """DryRun every call apply needs, on every group in the database for these accounts and regions."""
    worst = {"bad": 0}

    def one(t, account, sess, region):
        ec2 = sess.client("ec2", region_name=region)
        ensure_current(store, ec2, account, region, t.actor)
        groups = sorted(store.groups(account, region))[: args.sample] if args.sample else sorted(store.groups(account, region))
        assets = []
        if args.assets:
            import sg_assets

            assets = [a for a in sg_assets.list_assets(store, account, region) if a["kind"] == "interface"][:1]
        res = check_permissions(ec2, groups, assets)
        with store:
            store.record_permissions(account, region, t.actor, res)
        bad = _permission_problems(res)
        worst["bad"] += bool(bad)
        head = f"{account} {region} ({store.mode(account)} mode): "
        if not res:
            return [head + "no security groups"]
        if not bad:
            return [head + f"can change all {len(groups)} group(s) checked" + (" and swap an asset's groups" if assets else "")]
        return [head + f"{len(bad)} of {len(res)} cannot be changed:"] + [f"  {b}" for b in bad[:20]]

    lines, failed = _for_each(args, store, one)
    print("\n".join(lines))
    return 2 if failed else 1 if worst["bad"] else 0


def cmd_assets(args, store: Store) -> int:
    import sg_assets

    t = Targets(args)
    account = args.account or t.account
    ec2 = t.session(account).client("ec2", region_name=args.region)
    ensure_current(store, ec2, account, args.region, t.actor, assets=True)
    rows = sg_assets.list_assets(store, account, args.region)
    if args.json:
        print(json.dumps([{**a, "alone": sg_assets.why_not_alone(a) or "yes"} for a in rows], indent=1))
        return 0
    names = {g: v["name"] for g, v in store.groups(account, args.region).items()}
    for a in rows:
        why = sg_assets.why_not_alone(a)
        print(f"{a['eni']}  {a['instance'] or '-':<20} {', '.join(a['ips'][:2]):<32} "
              + ", ".join(f"{g} ({names.get(g, '?')})" for g in a["groups"])
              + (f"\n    group of its own: no, {why}" if why else ""))  # fmt: skip
    return 0


def cmd_asset_plan(args, store: Store) -> int:
    import sg_assets

    if not (args.eni or args.instance):
        raise SystemExit("pass --eni eni-… or --instance i-…")
    with open(args.approved, encoding="utf-8") as fh:
        approved = json.load(fh)
    t = Targets(args)
    account = args.account or t.account
    ec2 = t.session(account).client("ec2", region_name=args.region)
    plans = sg_assets.plan_asset(ec2, account, args.region, approved, args.eni or "", args.instance or "",
                                 args.max_rules, by=t.actor)  # fmt: skip
    for p in plans:
        print("\n".join(sg_assets.plan_text(p)))
    out = plans[0] if len(plans) == 1 else {"schema": "sg-tightener.asset-plans/v1", "plans": plans}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print(f"written to {args.out}: review it, then sg_db.py asset-propose --plan {args.out} --reason \"…\" "
          f"(nothing in AWS has changed)")  # fmt: skip
    return 0


def cmd_asset_propose(args, store: Store) -> int:
    import sg_assets

    with open(args.plan, encoding="utf-8") as fh:
        doc = json.load(fh)
    plans = doc.get("plans") or [doc]
    actor = _caller_actor(args)
    for p in plans:
        with store:
            rid = sg_assets.propose(store, p, actor, args.reason, args.ticket)
        st = store._request(rid)["status"]
        print(f"change request #{rid} for {p['eni']}: {st}" + ("; a different person approves it: sg_db.py approve "
                                                              f"{rid}; then sg_db.py asset-apply {rid}" if st == "pending"
                                                              else f"; sg_db.py asset-apply {rid} makes it in AWS"))  # fmt: skip
    return 0


def cmd_asset_apply(args, store: Store) -> int:
    import sg_assets

    r = store._request(args.id)
    t = Targets(args)
    ec2 = t.session(r["account"]).client("ec2", region_name=r["region"])
    if not args.yes:
        print("\n".join(sg_assets.plan_text({**r["changes"], "account": r["account"]})))
        sg_tightener._confirm(f"create {r['changes']['group_name']} and move {r['changes']['eni']} onto it")
    res = sg_assets.apply(store, ec2, r["account"], args.id, t.actor)
    if res["swapped"]:
        print(f"{r['changes']['eni']} now carries {res['group']} only (was {', '.join(res['before'])}); "
              f"undo: sg_db.py asset-revert --region {r['region']} --eni {r['changes']['eni']} --reason \"…\"")  # fmt: skip
        return 0
    print(f"{res['group']} created but {r['changes']['eni']} NOT moved onto it: " + "; ".join(res["failed"]))
    return 1


def cmd_asset_revert(args, store: Store) -> int:
    import sg_assets

    t = Targets(args)
    account = args.account or t.account
    ec2 = t.session(account).client("ec2", region_name=args.region)
    res = sg_assets.revert(store, ec2, account, args.region, args.eni, t.actor, args.reason)
    print(f"{res['eni']} carries {', '.join(res['groups'])} again (was {', '.join(res['was'])})")
    return 0


def cmd_asset_log(args, store: Store) -> int:
    import sg_assets

    if not (args.eni or args.instance):
        raise SystemExit("pass --eni eni-… or --instance i-…")
    rows = sg_assets.asset_history(store, args.eni or "", args.instance or "")
    if args.json:
        print(json.dumps(rows, indent=1))
        return 0
    for e in rows:
        d = e["detail"]
        what = (f"{', '.join(d.get('before', []))} -> {', '.join(d.get('after', []))}" if "before" in d
                else "first seen" if e["action"] == "assets-imported" else e["action"])  # fmt: skip
        print(f"#{e['seq']} {e['at']} {e['origin']:<8} {e['action']:<22} {what}  {e['actor']}"
              + (f"  [{e['ticket']}]" if e["ticket"] else "") + (f"  {e['reason']}" if e["reason"] else ""))  # fmt: skip
    if not rows:
        print("nothing recorded for it (sg_db.py import or reconcile records every asset's groups)")
    return 0


def cmd_create_group(args, store: Store) -> int:
    if not args.reason.strip():
        raise SystemExit("--reason is required")
    t = Targets(args)
    account = args.account or t.account
    store.require_enforce(account, "create security groups")
    ec2 = t.session(account).client("ec2", region_name=args.region)
    ensure_current(store, ec2, account, args.region, t.actor)
    gid = ec2.create_security_group(GroupName=args.name, Description=args.description, VpcId=args.vpc)["GroupId"]
    live = read_live(ec2, account, [gid]).get(gid)
    with store:
        store.synced(account, args.region, gid, live, t.actor, "tool", "group-created", args.reason, args.ticket,
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
        print(f"#{e['seq']} {e['at']} {e['origin']:<8} {e['action']:<16} {e['account']} {e['region']} {e['group_id']}  "
              f"{e['actor']}" + (f"  [{e['ticket']}]" if e["ticket"] else "") + (f"  {e['reason']}" if e["reason"] else ""))  # fmt: skip
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

    def where(q, region_required=True):
        q.add_argument("--region", required=region_required)
        q.add_argument("--account", help="the account (default: the caller's, or the only one in the database)")

    def aws(q):
        add_profile_arg(q)
        q.add_argument("--role-name", default=DEFAULT_ROLE, help=f"role assumed in other accounts (default {DEFAULT_ROLE})")
        q.add_argument("--external-id", default="", help="external id for that role, if it needs one")

    def org(q):
        q.add_argument("--regions", required=True)
        q.add_argument("--ou-id", help="every active account in this OU and the OUs under it")
        q.add_argument("--org", action="store_true", help="every active account in the organisation")
        q.add_argument("--accounts", help="only these comma-separated account ids")
        aws(q)

    q = sub.add_parser("import", help="take every group and rule in these accounts and regions into the database")
    org(q)
    q.add_argument("--reason", default="")
    q.add_argument("--no-assets", action="store_true", help="do not record each network interface's groups")
    q = sub.add_parser("reconcile", help="record and report changes made in AWS outside the tool")
    org(q)
    q.add_argument("--no-assets", action="store_true", help="do not check each network interface's groups")
    q.add_argument("--slack", default=os.environ.get("SG_REVIEW_SLACK_WEBHOOK", ""), help="post external changes here")
    q.add_argument("--no-cloudtrail", action="store_true", help="do not look up who made each change")
    for name in ("show", "diff"):
        q = sub.add_parser(name, help="the rules the database holds" if name == "show" else "what apply would change")
        where(q)
        q.add_argument("--group")
    q = sub.add_parser("add", help="propose a rule (a change request; apply makes it in AWS once approved)")
    where(q)
    q.add_argument("--group", required=True)
    q.add_argument("--description", default="")
    rule_args(q)
    reasoned(q)
    add_profile_arg(q)
    q = sub.add_parser("remove", help="propose removing a rule (a change request)")
    where(q)
    q.add_argument("--group", required=True)
    q.add_argument("--all", action="store_true", help="every rule in --direction")
    rule_args(q, required=False)
    reasoned(q)
    add_profile_arg(q)
    q = sub.add_parser("exec", help="propose an aws ec2 authorize/revoke-security-group command (applied at once "
                       "only when approvals are off)")
    where(q, region_required=False)
    q.add_argument("--no-apply", action="store_true", help="record it in the database only")
    reasoned(q)
    aws(q)
    q.add_argument("command", nargs=argparse.REMAINDER, help="-- aws ec2 …  (or the whole command quoted)")
    q = sub.add_parser("propose", help="propose an sg_tightener or sg_compact plan as one change request")
    q.add_argument("--plan", required=True)
    where(q, region_required=False)
    reasoned(q)
    aws(q)
    q = sub.add_parser("requests", help="the change requests")
    q.add_argument("--status", choices=("pending", "approved", "rejected", "cancelled", "applied"))
    q.add_argument("--account")
    q.add_argument("--region")
    q.add_argument("--json", action="store_true")
    for name, hlp in (("approve", "approve a change request (not your own)"), ("reject", "reject a change request"),
                      ("cancel", "withdraw your own change request")):  # fmt: skip
        q = sub.add_parser(name, help=hlp)
        q.add_argument("id", type=int)
        q.add_argument("--note", default="", help="kept in the audit trail" + (" (required)" if name == "reject" else ""))
        add_profile_arg(q)
    q = sub.add_parser("approvals", help="turn two-person approval on or off (audited)")
    q.add_argument("state", choices=("on", "off"))
    q.add_argument("--reason", required=True)
    add_profile_arg(q)
    q = sub.add_parser("mode", help="surveillance (report only, the default) or enforce (apply allowed), per account")
    q.add_argument("state", nargs="?", choices=("show", SURVEILLANCE, ENFORCE))
    q.add_argument("--account")
    q.add_argument("--all", action="store_true", help="set the default for every account without its own mode")
    q.add_argument("--anyway", action="store_true", help="enforce although the last permission check failed")
    q.add_argument("--reason", default="")
    add_profile_arg(q)
    q = sub.add_parser("check", help="prove with DryRun that this identity can change the groups (nothing changes)")
    org(q)
    q.add_argument("--assets", action="store_true", help="also check creating a group and swapping an asset's groups")
    q.add_argument("--sample", type=int, default=0, help="check only this many groups per region (0: all)")
    q = sub.add_parser("assets", help="every network interface, what it is attached to, and its groups")
    where(q)
    q.add_argument("--json", action="store_true")
    aws(q)
    q = sub.add_parser("asset-plan", help="the group one asset should have on its own, from its own flows (changes nothing)")
    where(q)
    q.add_argument("--eni")
    q.add_argument("--instance")
    q.add_argument("--approved", required=True, help="approved.json from sg_tightener analyse (approved/v2, with flows)")
    q.add_argument("--max-rules", type=int, default=sg_tightener.DEFAULT_MAX_RULES)
    q.add_argument("--out", default="asset-plan.json")
    aws(q)
    q = sub.add_parser("asset-propose", help="propose an asset plan as a change request")
    q.add_argument("--plan", required=True)
    reasoned(q)
    add_profile_arg(q)
    q = sub.add_parser("asset-apply", help="carry out an approved asset request (enforce mode)")
    q.add_argument("id", type=int)
    q.add_argument("--yes", action="store_true")
    aws(q)
    q = sub.add_parser("asset-revert", help="put an asset back on the groups it had before sg-tightener moved it")
    where(q)
    q.add_argument("--eni", required=True)
    q.add_argument("--reason", required=True)
    aws(q)
    q = sub.add_parser("asset-log", help="every change to one asset's groups")
    q.add_argument("--eni")
    q.add_argument("--instance")
    q.add_argument("--json", action="store_true")
    q = sub.add_parser("apply", help="make AWS match the database")
    where(q)
    q.add_argument("--group")
    q.add_argument("--yes", action="store_true")
    reasoned(q, required=False)
    aws(q)
    q = sub.add_parser("adopt", help="propose accepting what AWS holds into the database (a change request)")
    where(q)
    q.add_argument("--group")
    reasoned(q)
    add_profile_arg(q)
    q = sub.add_parser("create-group", help="create a security group, in AWS and the database")
    where(q)
    for a in ("--vpc", "--name", "--description"):
        q.add_argument(a, required=True)
    reasoned(q)
    aws(q)
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
                   "log": cmd_log, "verify": cmd_verify, "propose": cmd_propose, "requests": cmd_requests,
                   "approve": cmd_decide, "reject": cmd_decide, "cancel": cmd_decide,
                   "approvals": cmd_approvals, "mode": cmd_mode, "check": cmd_check,
                   "assets": cmd_assets, "asset-plan": cmd_asset_plan, "asset-propose": cmd_asset_propose,
                   "asset-apply": cmd_asset_apply, "asset-revert": cmd_asset_revert, "asset-log": cmd_asset_log}.get(args.cmd)  # fmt: skip
        try:
            if args.cmd in ("add", "remove"):
                return cmd_add_remove(args, store, args.cmd)
            if args.cmd == "mode" and args.state in (SURVEILLANCE, ENFORCE) and not args.reason.strip():
                raise SystemExit("--reason is required to change the mode")
            return handler(args, store)
        except Refused as exc:
            raise SystemExit(str(exc))
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main())
