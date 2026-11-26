#!/usr/bin/env python3
"""sg_console.py: the security group console, a local web page for every account in the database.

One place to see every security group and rule (as the database wants them and as AWS holds them),
propose a change with a reason, approve or reject someone else's, apply approved changes, reconcile
with AWS, search the audit trail, and see every rejected flow across the accounts sg_review has read
(an OU, with ``sg_review.py org``).

It listens on 127.0.0.1 only and needs no sign-in of its own: open http://127.0.0.1:8765/. Other web
pages cannot use it: every change carries a key that only the console's own page holds (in a header,
with a JSON body), requests from other sites and other host names are refused, and nothing it returns
can be read by another site.
Who acts is the AWS identity the console runs as (``--profile``), exactly as with ``sg_db.py``: a
second person approves from their own console or ``sg_db.py approve``, with their own credentials.

Sign in from the page itself with AWS SSO (IAM Identity Center): no AWS CLI or profile is needed. Choose
the accounts and the role to use in each, then **Read** an account: its security groups go into the
database and its flow logs are read (the cost is shown first). **Always running** (or ``install``)
keeps the console running in the background and starts it at login, at the same bookmarkable address.

Usage:
  sg_console.py serve [--port 8765] [--profile P] [--role-name OrganizationAccountAccessRole] [--db DSN]
  sg_console.py install [--port 8765]     # always running: start at login, restart if it stops
  sg_console.py uninstall                 # stop running in the background
  sg_console.py open                      # open the console in the browser
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import os
import platform
import plistlib
import re
import secrets
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import sg_db
import sg_remediate
from sg_tightener import add_profile_arg, friendly_login_errors, use_profile

LOG = logging.getLogger("sg_console")
ASSET = Path(__file__).resolve().parent / "assets" / "sg_console.html"
MAX_BODY = 1 << 20
RANGES = ("24h", "1w", "1m", "3m", "6m", "1y")
MIN_SPEND = 100.0  # US$ in the last 30 days: reading an OU skips accounts spending less (0 reads every one)
AGES = {"estimate": 3600}  # reports that depend on the time as well as the read: rebuilt (in the background) this often
SETTLING = 600  # a read written to in the last ten minutes keeps its last report row (built in this window)
# Processes building report rows at once. Each holds one account's flow logs (often 1-3 GB): eight at once, two
# builds at a time, drove a 32 GB Mac into swap (load 90, 2026-11-25). Now at most a quarter of the cores, at most
# one per 6 GB of memory, one build at a time (REPORT_GATE), at low priority (nice) so the Mac stays usable.
def _mem_bytes() -> int:
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        return 8 << 30


def _mask_dsn(dsn: str) -> str:
    """A connection string with its password hidden."""
    return re.sub(r"(://[^:/@]+:)[^@]*@", r"\1•••@", re.sub(r"(password=)\S+", r"\1•••", dsn))


def _report_procs() -> int:
    return max(1, min(4, (os.cpu_count() or 2) // 4, _mem_bytes() // (6 << 30)))


REPORT_PROCS = int(os.environ.get("SG_REPORT_PROCS") or _report_procs())
REPORT_GATE = threading.BoundedSemaphore(1)  # one parallel report build at a time, whichever report asks
# A report kind whose rows changed shape since REPORT_CACHE_VERSION: only that kind is rebuilt (a single global bump
# rebuilt every report of every account at once). 9: own interfaces carry launch time, image and VPC.
KIND_VERSIONS = {"seen": 9, "macro": 11}  # macro 9: connection resets; 10: outbound rules by class


def _kind_version(kind: str) -> int:
    return KIND_VERSIONS.get(kind, REPORT_CACHE_VERSION)


SHOW_OLD = ("refused", "macro")  # reports whose rows from an earlier version are shown while being rebuilt
REPORT_CACHE_VERSION = 8  # 5: refused rows carry every target and the verdict; 6, 7: one service is not a scan; 8: the day before
# a page asking for a report some accounts have no row in yet gets the rows there are at once, and the rest are
# built in the background (it asks again); tests set SG_NO_WARM and get every row before the answer
REPORTS_WAIT = os.environ.get("SG_NO_WARM") == "1"
WARM = (("macro", "1m"), ("refused", "24h"), ("seen", "all"), ("macro", "1w"), ("macro", "3m"), ("macro", "24h"), ("macro", "6m"),
        ("macro", "1y"))  # built in the background, default views first, so a page opens from rows already built
WARM_EVERY = 600
# The console reads every chosen account's new flow logs by itself at these local times (on by default, once a day
# at 08:00; changed or turned off on the Overview). A time missed while asleep or signed out is caught up within
# SCHEDULE_CATCHUP; later than that it waits for the next one. Over max_cost (US$) it is priced and left for a yes.
SCHEDULE_DEFAULT = {"on": True, "times": ["08:00"], "max_cost": 25.0, "days": 7, "on_wake": True}  # days: how far back it fills hours never read
SCHEDULE_POLL = 60
SCHEDULE_CATCHUP = 6 * 3600
SCHEDULE_SOON = 2 * 3600  # a missed read is skipped when the next scheduled one is this close


def _slots(cfg: dict, t: float, day_offset: int = 0) -> list[tuple[float, str]]:
    """(epoch, "YYYY-MM-DD HH:MM") of each scheduled time on the local day ``day_offset`` days from ``t``."""
    lt = time.localtime(t + day_offset * 86400)
    out = []
    for hm in cfg.get("times") or []:
        h, m = (int(x) for x in hm.split(":"))
        at = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, h, m, 0, 0, 0, -1))
        out.append((at, time.strftime("%Y-%m-%d %H:%M", time.localtime(at))))
    return sorted(out)


def _due_slot(cfg: dict, t: float) -> str:
    """The latest scheduled time already passed (today or yesterday), else "". With "on_wake" (the default) a time
    missed while the Mac slept or was signed out runs once when it is back, unless the next time is under
    SCHEDULE_SOON away; without it, only within SCHEDULE_CATCHUP of the time."""
    past = [(at, s) for at, s in _slots(cfg, t, -1) + _slots(cfg, t) if at <= t]
    if not past:
        return ""
    at, s = past[-1]
    if cfg.get("on_wake", True):
        nxt = next((a for a, _ in _slots(cfg, t) + _slots(cfg, t, 1) if a > t), None)
        return s if nxt is None or nxt - t >= SCHEDULE_SOON or t - at < SCHEDULE_CATCHUP else ""
    return s if t < at + SCHEDULE_CATCHUP else ""


def _next_slot(cfg: dict, t: float) -> str:
    return next((s for at, s in _slots(cfg, t) + _slots(cfg, t, 1) if at > t), "")
DEFAULT_DAYS = 7  # a read's default look back: 30 days across an OU can cost hundreds of dollars in Logs Insights
FIRST_PASS = 86400  # an OU read does the last day of every account first, then goes further back
BATCH_WORKERS = 24  # accounts read at once when reading an OU: each runs its own Logs Insights queries (its own quota)
JOBS_SHOWN = 1000
LABEL = "com.sg-tightener.console"
UNIT = "sg-console.service"
PROTECTED = ("Desktop", "Documents", "Downloads", "Library/Mobile Documents")  # macOS keeps background programs out
RUNTIME = ("boto3", "pyyaml", "psycopg", "psycopg-binary")
PASS_ENV = ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy", "AWS_CA_BUNDLE",
            "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "SG_TIGHTENER_DB",
            "SG_TIGHTENER_PG_DSN", "SG_TIGHTENER_PG_SCHEMA")


RESUME_FOR = 3 * 86400  # a read interrupted longer ago than this is not carried on


_NET: dict = {"at": 0.0, "v": None, "hooks": []}  # hooks: called with (before, now) when metered changes
HOTSPOT_GATEWAY = "172.20.10."  # an iPhone Personal Hotspot always hands out this range


def _ifsummary(iface: str) -> str:
    try:
        return subprocess.run(["ipconfig", "getsummary", iface], capture_output=True, text=True, timeout=3, check=False).stdout
    except Exception:  # noqa: BLE001 - not known
        return ""


def _network(fresh: bool = False) -> dict:
    """How this Mac reaches AWS: {"metered": True/False/None, "interface", "why"}. macOS marks a phone hotspot
    (and Low Data Mode) as expensive; an iPhone hotspot is also known by its gateway. Asked at most every 20 s."""
    if not fresh and _NET["v"] and time.time() - _NET["at"] < 20:
        return _NET["v"]
    out = {"metered": None, "interface": "", "why": "not known on this system"}
    if sys.platform == "darwin":
        try:
            r = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=3, check=False).stdout
            m_if, m_gw = re.search(r"interface:\s*(\S+)", r), re.search(r"gateway:\s*(\S+)", r)
            iface, gw = (m_if.group(1) if m_if else ""), (m_gw.group(1) if m_gw else "")
            ifaces = [iface] if iface and not iface.startswith(("utun", "ipsec", "ppp")) else []
            if not ifaces:  # a VPN (Zscaler) owns the default route: look at the links with an address underneath
                lst = subprocess.run(["ipconfig", "getiflist"], capture_output=True, text=True, timeout=3, check=False).stdout.split()
                ifaces = [i for i in lst if i.startswith("en") and subprocess.run(
                    ["ipconfig", "getifaddr", i], capture_output=True, text=True, timeout=3, check=False).stdout.strip()]  # fmt: skip
            exp = [bool(re.search(r"IsExpensive\s*:\s*TRUE", _ifsummary(i))) for i in ifaces]
            if not ifaces and not gw:
                out = {"metered": None, "interface": "", "why": "no network"}
            elif gw.startswith(HOTSPOT_GATEWAY) or (exp and all(exp)):
                out = {"metered": True, "interface": ", ".join(ifaces) or iface,
                       "why": "a phone hotspot" if gw.startswith(HOTSPOT_GATEWAY) else "macOS marks this connection as metered (a phone hotspot or Low Data Mode)"}
            else:
                out = {"metered": False, "interface": ", ".join(ifaces) or iface, "why": "Wi-Fi or a wired network"}
        except Exception as exc:  # noqa: BLE001 - not known
            out["why"] = f"not known ({exc})"[:200]
    before = _NET["v"]
    _NET.update(at=time.time(), v=out)
    if before and before.get("metered") != out.get("metered"):
        for hook in list(_NET["hooks"]):
            try:
                hook(before, out)
            except Exception:  # noqa: BLE001
                pass
    return out


def _ago(secs: float | None) -> str:
    """A span as people say it: 40 s, 12 min, 3 h, 2 days."""
    s = max(0.0, float(secs or 0))
    if s < 90:
        return f"{round(s)} s"
    if s < 5400:
        return f"{round(s / 60)} min"
    if s < 172800:
        return f"{round(s / 3600)} h"
    return f"{round(s / 86400)} days"


def _has_dist(md, name: str) -> bool:
    try:
        md.version(name)
        return True
    except Exception:  # noqa: BLE001
        return False


def _keep_awake():
    """On macOS, stop the machine sleeping while a long read runs (sleep drops every query and the SSO
    session runs out meanwhile). Returns the process to terminate afterwards, or None."""
    if sys.platform != "darwin":
        return None
    try:
        return subprocess.Popen(["caffeinate", "-i", "-w", str(os.getpid())], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)  # fmt: skip
    except OSError:
        return None


def _date_range(frm, to) -> tuple[float | None, float | None]:
    """From and To dates (YYYY-MM-DD, UTC) as epoch seconds: From at its start, To at its end, so To is included."""
    import datetime as _dt

    def day(v, name):
        if not v:
            return None
        try:
            d = _dt.datetime.strptime(str(v), "%Y-%m-%d").replace(tzinfo=_dt.timezone.utc)
        except ValueError:
            raise ConsoleError(400, f"{name} is a date, YYYY-MM-DD")
        return d.timestamp()

    start, end = day(frm, "From"), day(to, "To")
    return start, (end + 86400 if end is not None else None)


PLAN_FORMAT = 6  # 6: totals count every group, those on no interface too; 5: suggestions share the group's rule budget, as plan does; raised when a plan gains fields, so plans kept on disk are built again (2: critical rules)


class ConsoleError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class Console:
    """What the HTTP handler calls: every read and write, against the database and AWS."""

    def __init__(self, db_path: str | None, profile: str | None = None, role_name: str = sg_db.DEFAULT_ROLE,
                 external_id: str = "", targets=None, sso=None, service: Service | None = None, keys=None):  # fmt: skip
        self.db_path = db_path
        self.args = argparse.Namespace(profile=profile, role_name=role_name, external_id=external_id)
        self._targets = targets
        self._fixed = targets is not None  # tests hand in their own
        self._lock = threading.Lock()
        self._refused_cache: dict = {}
        self._report_lock = threading.Lock()
        self._ip_idx = None  # (signature, index) of the estate's address book
        self._report_gates: dict = {}
        self._warming: threading.Thread | None = None
        self._plans: dict = {}  # the last remediation plans built, newest last
        self._plan_pending: dict = {}  # plan key -> the build in progress, so a second request waits for the same one
        self._plan_pool = None  # processes that build plans: the console stays responsive while a big one builds
        self._owner_failed, self._owner_why = 0.0, ""
        self._reports_mem: dict | None = None
        self._sched_wait = ""  # why a scheduled read due now has not started
        self._builds: dict = {}  # "kind|range" -> progress of the latest report build, for the page and the log
        self.sso = sso
        self.keys = keys  # sg_keys.Keys: signing in with a profile or keys on this computer instead of SSO
        self.batch: dict | None = None  # reading many accounts at once (an OU)
        self.service = service
        self.jobs: dict[int, dict] = {}
        self._job_extra: dict[int, dict] = {}
        self._owner_thread: threading.Thread | None = None
        self._spend_failed = 0.0
        self._verdicts: dict = {}
        self._flow_status: dict = {}  # account: (mtime of its read, its flow log status)  # account: (mtime of its read, the engine's plan)
        self.httpd = None
        self._db_start: dict | None = None

    # ------------------------------------------------------------------ plumbing
    def store(self) -> sg_db.Store:
        return sg_db.Store(self.db_path)

    def auth(self):
        """The sign-in in use: keys on this computer once a profile was chosen on the page, else AWS SSO."""
        if self.keys is not None and self.keys.state.get("active"):
            return self.keys
        return self.sso

    def _sso_ready(self) -> bool:
        a = self.auth()
        return bool(not self._fixed and a is not None and a.chosen() and a.token())

    def targets(self, fresh: bool = False):
        with self._lock:
            if self._sso_ready():  # signed in from the page: that identity acts, in the accounts chosen
                import sg_sso

                a = self.auth()
                key = (a.start_url, json.dumps(a.chosen()), a.token())
                if fresh or getattr(self._targets, "_key", None) != key:
                    self._targets = sg_sso.SsoTargets(a)
                    self._targets._key = key
                return self._targets
            if self._targets is None or (fresh and not self._fixed) or (not self._fixed and hasattr(self._targets, "sso")):
                failed = getattr(self, "_targets_failed", None)
                if failed and not fresh and time.time() - failed[0] < 60:
                    raise failed[1]  # no AWS identity a moment ago: do not wait on the credential chain each page load
                try:
                    self._targets = sg_db.Targets(self.args)
                except Exception as exc:
                    self._targets, self._targets_failed = None, (time.time(), exc)
                    raise
                self._targets_failed = None
            return self._targets

    def actor(self) -> str:
        """Who acts, read again for each change (an SSO session can expire or be renewed meanwhile)."""
        return self.targets(fresh=True).actor

    # ------------------------------------------------------------------ reads
    def state(self) -> dict:
        st = self.store()
        try:
            ok, n, why = st.verify()
            names = st.account_names()
            perms = {(p["account"], p["region"]): p for p in st.permissions()}
            accounts: dict[str, dict] = {}
            modes = st.modes()
            mode = lambda a: modes.get(a) or modes.get(sg_db.ANY_ACCOUNT) or sg_db.SURVEILLANCE  # noqa: E731
            # every figure in one query per table: one query per region and group took seconds across an OU
            q = st.db.execute
            groups: dict = {}
            for account, region, gid in q("SELECT account, region, group_id FROM groups"):
                groups.setdefault((account, region), []).append(gid)
            n_rules = {(a, r, g): n for a, r, g, n in q("SELECT account, region, group_id, COUNT(*) FROM rules WHERE "
                                                          "state = 'desired' GROUP BY account, region, group_id")}  # fmt: skip
            used: dict = {}
            n_assets: dict = {}
            for account, region, gs in q("SELECT account, region, groups FROM assets"):
                n_assets[(account, region)] = n_assets.get((account, region), 0) + 1
                u = used.setdefault((account, region), {})
                for g in json.loads(gs):
                    u[g] = u.get(g, 0) + 1
            key = "account, region, group_id, direction, proto, from_port, to_port, source"
            diff = (f"(SELECT {key} FROM rules WHERE state = 'desired' EXCEPT SELECT {key} FROM rules WHERE state = 'synced') "
                    f"UNION ALL (SELECT {key} FROM rules WHERE state = 'synced' EXCEPT SELECT {key} FROM rules WHERE "
                    f"state = 'desired')")  # fmt: skip
            pending = {(a, r): n for a, r, n in q(f"SELECT account, region, COUNT(*) FROM ({diff}) d GROUP BY account, region")}
            for account, region, synced in q("SELECT account, region, synced_at FROM regions ORDER BY account, region"):
                a = accounts.setdefault(account, {"account": account, "name": names.get(account, ""), "regions": [],
                                                  "mode": mode(account)})  # fmt: skip
                p = perms.get((account, region))
                every = groups.get((account, region), [])
                u = used.get((account, region))  # None: the region's interfaces were never read
                kept = every if u is None else [g for g in every if g in u]
                a["regions"].append({"region": region, "groups": len(kept),
                                     "rules": sum(n_rules.get((account, region, g), 0) for g in kept),
                                     "assets": n_assets.get((account, region), 0), "unused": len(every) - len(kept),
                                     "pending": pending.get((account, region), 0), "synced_at": synced,
                                     "permissions": None if p is None else {
                                         "ok": p["ok"], "at": p["checked_at"], "by": sg_db.principal(p["actor"]),
                                         "problems": sg_db._permission_problems(p["result"])[:20]}})  # fmt: skip
            try:
                me = self.targets().actor
                me_account = self.targets().account
            except Exception as exc:  # noqa: BLE001 - the page still shows the database without AWS
                me, me_account = f"not signed in to AWS ({exc})", ""
            try:
                import sg_review

                read = set(sg_review.cached_accounts())
            except Exception:  # noqa: BLE001 - no sg_review data directory yet
                read = set()
            for a in accounts.values():
                a["reviewed"] = a["account"] in read
            chosen = self.auth().chosen() if self.auth() else []
            for c in chosen:  # an account chosen in the sign-in but not read yet still has a row to read it from
                accounts.setdefault(c["account"], {"account": c["account"], "name": c["name"], "regions": [],
                                                   "mode": mode(c["account"]), "reviewed": c["account"] in read})  # fmt: skip
            for a in accounts.values():
                a["chosen"] = any(c["account"] == a["account"] for c in chosen)
            return {"me": me, "me_principal": sg_db.principal(me), "account": me_account,
                    "service": self.service.status() if self.service else None,
                    "sso": bool(self.sso), "jobs": self.job_list(), "batch": self.batch_status(),
                    "approvals": st.approvals(), "db": str(st.path),
                    "apply_strategy": st.meta_get("apply_strategy", "room") or "room",
                    "network": {**_network(), "wifi_only": bool(st.meta_get("wifi_only", False))},
                    "verify": {"ok": ok, "entries": n, "why": why}, "accounts": list(accounts.values()),
                    "pending_requests": len(st.requests("pending"))}  # fmt: skip
        finally:
            st.close()

    @staticmethod
    def _in_use(st, account: str, region: str) -> dict[str, int] | None:
        """Each group's number of network interfaces; None when the region's interfaces were never read."""
        import sg_assets

        assets = sg_assets.list_assets(st, account, region)
        if not assets:
            return None
        n: dict[str, int] = {}
        for a in assets:
            for g in a["groups"]:
                n[g] = n.get(g, 0) + 1
        return n

    def groups(self, account: str, region: str) -> list[dict]:
        """Every group with its rules and its number of interfaces (``enis`` None when not known): a group on
        no interface protects nothing, and the page leaves it out unless asked."""
        st = self.store()
        try:
            used = self._in_use(st, account, region)
            out = []
            for gid, g in st.groups(account, region).items():
                want, have = st.rules(account, region, gid, "desired"), st.rules(account, region, gid, "synced")
                rules = []
                for r in sorted(set(want) | set(have)):
                    state = "both" if r in want and r in have else "want" if r in want else "have"
                    rules.append({**sg_db._rule_json(r, want.get(r) or have.get(r, "")), "state": state,
                                  "text": sg_db.rule_text(r)})  # fmt: skip
                out.append({"id": gid, **g, "rules": rules, "enis": None if used is None else used.get(gid, 0)})
            return out
        finally:
            st.close()

    def assets(self, account: str, region: str) -> list[dict]:
        import sg_assets

        st = self.store()
        try:
            names = {g: v["name"] for g, v in st.groups(account, region).items()}
            return [{**a, "group_names": [names.get(g, "") for g in a["groups"]], "alone": sg_assets.why_not_alone(a)}
                    for a in sg_assets.list_assets(st, account, region)]  # fmt: skip
        finally:
            st.close()

    def asset_history(self, eni: str) -> list[dict]:
        import sg_assets

        st = self.store()
        try:
            return sg_assets.asset_history(st, eni=eni)[::-1]
        finally:
            st.close()

    def profile(self, account: str, read: bool = False) -> dict:
        """The account at a glance (sg_profile): kept a day; ``read`` reads it from AWS now."""
        import sg_profile
        import sg_review

        prof = sg_profile.cached(account)
        if not read and (prof is None or time.time() - prof.get("at", 0) > sg_profile.KEEP):
            return {"account": account, "stale": True, **(prof or {})}
        if read:
            st = self.store()
            try:
                regions = sorted({r for a, r in st.regions(account)}) or ["af-south-1"]
            finally:
                st.close()
            t = self.targets(fresh=True)
            sess = t.session(account)
            ce = None
            auth = self.auth()
            if auth is not None and hasattr(auth, "ce_client"):
                try:
                    ce = auth.ce_client()
                except Exception as exc:  # noqa: BLE001 - not the management account: the account's own costs
                    LOG.info("Cost Explorer in the management account is out of reach (%s): asking %s", exc, account)
            prof = sg_profile.read(sess, account, regions, ce or sess.client("ce", region_name="us-east-1"),
                                   sg_review.BOTO_CONFIG)  # fmt: skip
            sg_profile.save(account, prof)
        return prof

    def drift(self, account: str, region: str) -> list[dict]:
        """Each rule where AWS differs from what is saved here: what changed in AWS, when the tool noticed it
        (and who made it, when CloudTrail said), what Apply would do and what keeping it means."""
        st = self.store()
        try:
            groups = st.groups(account, region)
            seen: dict = {}
            for e in st.log(account, region, "", "", 2000):
                if e["origin"] == "external" and e["group_id"]:
                    seen[e["group_id"]] = e  # oldest first: the latest wins
            approved = {}  # (group, op, rule) of an approved request not yet applied: wanted here, not drift
            for r in st.requests("approved", account, region):
                for c in r["changes"] if isinstance(r["changes"], list) else []:
                    j = c.get("rule") or {}
                    key = (j.get("direction"), j.get("proto"), j.get("from"), j.get("to"), j.get("source"))
                    approved[(c.get("group"), c.get("op"), key)] = r["id"]
            out = []
            for gid, op, rule, desc in st.pending(account, region):
                e = seen.get(gid) or {}
                rid = approved.get((gid, op, tuple(rule)))
                added = op == "remove"  # in AWS, not wanted here: someone added it in AWS
                if rid:
                    out.append({"group": gid, "name": (groups.get(gid) or {}).get("name", ""),
                                "change": f"approved in request #{rid}, not applied yet", "rule": sg_db.rule_text(rule),
                                "description": desc, "noticed": "", "by": "", "request": rid,
                                "apply": "adds it" if op == "add" else "removes it",
                                "keep": ""})  # fmt: skip
                    continue
                out.append({"group": gid, "name": (groups.get(gid) or {}).get("name", ""),
                            "change": "added in AWS" if added else "removed in AWS",
                            "rule": sg_db.rule_text(rule), "description": desc,
                            "noticed": e.get("at", ""), "by": (e.get("detail") or {}).get("changed_by", ""),
                            "apply": "removes it again" if added else "adds it back",
                            "keep": "keeps it" if added else "leaves it removed"})  # fmt: skip
            return out
        finally:
            st.close()

    def audit(self, q: dict) -> list[dict]:
        st = self.store()
        try:
            rows = st.log(q.get("account", ""), q.get("region", ""), q.get("group", ""), q.get("since", ""),
                          int(q.get("limit") or 500))  # fmt: skip
        finally:
            st.close()
        text = (q.get("q") or "").lower()
        if text:
            rows = [r for r in rows if text in json.dumps(r).lower()]
        return rows[::-1]

    def requests(self, status: str = "") -> list[dict]:
        st = self.store()
        try:
            return st.requests(status)
        finally:
            st.close()

    def review(self, account: str, token: str) -> str:
        """The sg_review page for an account, from what sg_review read, able to propose its Tighten plan here."""
        import sg_review

        if account not in sg_review.cached_accounts():
            raise ConsoleError(404, f"sg_review has not read {account}: run `sg_review.py read` (or `org`) first")
        doc = sg_review.load(account)
        if not doc or not doc.get("chunks"):
            raise ConsoleError(404, f"nothing read for {account}")
        data = sg_review.page_data(doc, names=sg_review.load_names())
        data["console"] = {"token": token}
        return sg_review.render_page(data)

    # ------------------------------------------------------------------ the database
    def database(self) -> dict:
        """Does the database answer, can this computer start it, and how a start is going."""
        import sg_store

        return {**sg_store.server_status(), "starting": bool(self._db_start and self._db_start["running"]),
                "steps": list((self._db_start or {}).get("steps") or []), "error": (self._db_start or {}).get("error", "")}

    def db_metrics(self) -> dict:
        """The Settings tab's figures: the database (size, rows and storage of each table, connections, cache),
        its container (CPU, memory, disk) when it runs on this computer, and the console's own process."""
        import sg_store

        out: dict = {"at": time.time()}
        st = self.store()
        try:
            out["db"] = sg_store.metrics(st.db)
        except Exception as exc:  # noqa: BLE001 - shown on the page
            out["error"] = str(exc)[:300]
        finally:
            st.close()
        out["container"] = sg_store.container_stats()
        rss = cpu = None
        try:
            got = subprocess.run(["ps", "-o", "rss=,%cpu=", "-p", str(os.getpid())], capture_output=True, text=True,
                                 timeout=5).stdout.split()  # fmt: skip
            rss, cpu = int(got[0]) * 1024, float(got[1])
        except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
            pass
        try:
            load = os.getloadavg()
        except OSError:
            load = None
        out["console"] = {"rss": rss, "cpu": cpu, "threads": threading.active_count(), "load": load,
                          "cores": os.cpu_count(), "memory": _mem_bytes(), "pid": os.getpid()}
        return out

    def database_start(self, _body: dict | None = None) -> dict:
        """Start the local database in the background (colima first if Docker's engine is not running)."""
        import sg_store

        with self._lock:
            if self._db_start and self._db_start["running"]:
                return self.database()
            job = self._db_start = {"running": True, "steps": [], "error": ""}

        def go():
            try:
                sg_store.start_server(say=job["steps"].append)
                self._database_back()
            except Exception as exc:  # noqa: BLE001 - shown on the page
                LOG.warning("starting the database: %s", exc)
                job["error"] = str(exc)
            finally:
                job["running"] = False

        threading.Thread(target=go, daemon=True).start()
        return self.database()

    def _database_back(self) -> None:
        """The database answers again: read what was kept in it, and build the reports."""
        for auth in (self.sso, self.keys):
            if auth is not None and getattr(auth, "unloaded", False):
                auth.state, auth.unloaded = auth._load(), False
        self._reports_mem = None
        try:
            _keep_unsaved_token()
        except Exception as exc:  # noqa: BLE001
            LOG.warning("console key not kept: %s", exc)
        self.warm_reports()

    def warm_reports(self) -> None:
        """Build every tab's report rows in the background (at start, and after a read), so a tab opened later
        answers at once instead of building 150 accounts while the page waits."""
        def go():
            for name, call in (("flow", self.flow_accounts), ("macro", lambda: self.macro("1m")),
                               ("estimate", self.read_estimate), ("refused", lambda: self.refused("24h"))):
                t = time.time()
                try:
                    call()
                    LOG.info("reports ready: %s in %.0f s", name, time.time() - t)
                except Exception as exc:  # noqa: BLE001 - a page builds it itself if this could not
                    LOG.warning("warming %s: %s", name, exc)

        with self._report_lock:
            if self._warming and self._warming.is_alive():
                return
            self._warming = threading.Thread(target=go, daemon=True)
            self._warming.start()

    def macro(self, range_key: str = "1m") -> dict:
        """Every account sg_review has read, side by side: over-provisioning by owner, exposure, probing, attention."""
        import sg_review

        if range_key not in RANGES:
            raise ConsoleError(400, f"range must be one of {', '.join(RANGES)}")
        modes = {}
        try:
            st = self.store()
            try:
                names = st.account_names()
                # one query, not one per region: 2,850 regions took 1.2 s on every Risk overview load
                every = st.modes()
                default = every.get(sg_db.ANY_ACCOUNT) or sg_db.SURVEILLANCE
                modes = {a: every.get(a) or default for a in {a for a, _ in st.regions()}}
            finally:
                st.close()
        except Exception:  # noqa: BLE001 - the overview still works from the reads alone
            names = {}
        rows, unread = [], []
        got_rows, building = self._reports_soon("macro", range_key, names)
        for account, got in got_rows.items():
            if got is None:
                unread.append(account)
                continue
            rows.append({**got, "mode": modes.get(account, "surveillance")})
        spend, owners, pending, why = self._facts([r["account"] for r in rows])
        for r in rows:
            r["spend"] = None if spend is None else spend.get(r["account"], 0.0)
            got = owners.get(r["account"]) or {}
            r["owner"] = got.get("owner")  # None: not looked up yet; "": no owner tag
            r["tags"] = got.get("tags") or {}  # every Organizations tag: the page groups risk by any of them
        kinds = {k: sg_review.CAT_NAME[k] for k in sg_review.CATS}
        types = {k: n for k, (n, _) in sg_review.SOURCE_TYPES.items()}
        rag = {"green_max": sg_review.RAG_GREEN_MAX, "amber_max": sg_review.RAG_AMBER_MAX}
        return {"range": range_key, "accounts": rows, "kinds": kinds, "types": types, "rag": rag,
                "owners_pending": pending, "facts_note": why, "no_flow_logs_read": len(unread),
                "building": building}  # fmt: skip

    # ------------------------------------------------------------------ who owns each account, and what it spends
    def _owners_path(self):
        import sg_ipintel
        import sg_store

        return sg_store.File(sg_ipintel.DATA_DIR / "owners.json")

    def _facts(self, accounts: list[str]) -> tuple[dict | None, dict, bool, str]:
        """Each account's spend (last 30 days) and owner tag, for the risk charts. Neither is ever waited for long:
        spend is one Cost Explorer call kept a day; owners are looked up in the background and kept a day."""
        auth, why, spend = self.auth(), [], None
        if auth is not None and hasattr(auth, "org_spend") and time.time() - self._spend_failed > 600:
            try:
                spend = auth.org_spend()
            except Exception as exc:  # noqa: BLE001 - said on the page; the charts fall back to asset counts
                self._spend_failed = time.time()
                why.append(f"spend not known ({str(exc)[:160]})")
        try:
            got = json.loads(self._owners_path().read_text())
        except (OSError, ValueError):
            got = {}
        fresh = time.time() - 86400
        owners = {a: v for a, v in got.items() if a in set(accounts) and v.get("at", 0) > fresh and "tags" in v}
        missing = [a for a in accounts if a not in owners]
        if missing and time.time() - self._owner_failed < 600:
            why.append(f"owners not known ({self._owner_why})")
        pending = bool(missing) and auth is not None and hasattr(auth, "org_client") and time.time() - self._owner_failed > 600
        if pending and not (self._owner_thread and self._owner_thread.is_alive()):
            self._owner_thread = threading.Thread(target=self._look_up_owners, args=(auth, missing), daemon=True)
            self._owner_thread.start()
        return spend, owners, pending, "; ".join(why)

    def _look_up_owners(self, auth, accounts: list[str]) -> None:
        import sg_review

        try:
            org = auth.org_client()
        except Exception as exc:  # noqa: BLE001 - not known is not "no owner tag": said on the page, tried again later
            LOG.warning("owners: %s", exc)
            self._owner_failed, self._owner_why = time.time(), str(exc)[:160]
            return
        else:
            self._owner_failed, self._owner_why = 0.0, ""
            found = {}
            for a in accounts:
                try:
                    tags = [t for page in org.get_paginator("list_tags_for_resource").paginate(ResourceId=a)
                            for t in page.get("Tags", [])]  # fmt: skip
                    found[a] = {"owner": sg_review.owner_of(tags),
                                "tags": {t["Key"]: t["Value"] for t in tags if str(t.get("Value", "")).strip()}}
                except Exception as exc:  # noqa: BLE001 - one account out of reach must not stop the rest
                    LOG.warning("owner of %s: %s", a, exc)
                    found[a] = {"owner": "", "tags": {}}
        with self._lock:
            path = self._owners_path()
            try:
                got = json.loads(path.read_text())
            except (OSError, ValueError):
                got = {}
            got.update({a: {**o, "at": time.time()} for a, o in found.items()})
            path.write_text(json.dumps(got))

    def _reports_soon(self, kind: str, range_key: str, names: dict) -> tuple[dict, int]:
        """(rows there are now, how many accounts are still being built). Never waits for a build: what is
        missing is built in the background, once, and the page asks again."""
        if REPORTS_WAIT:
            return self._reports(kind, range_key, names), 0
        import sg_review

        last = self._builds.get(f"{kind}|{range_key}") or {}
        # an account whose build just failed is not tried again on every page load: its error is shown instead
        failed = last.get("failed_accounts", set()) if time.time() - (last.get("finished") or 0) < 600 else set()
        with self._report_lock:
            cache = self._report_cache()
            out, missing = {}, 0
            for account in sorted(sg_review.stamps()):
                hit = cache.get(f"{kind}|{range_key}|{account}")
                if hit:
                    out[account] = hit["row"]
                elif account not in failed:
                    missing += 1
            key = ("soon", kind, range_key)
            busy = self._report_gates.get(key)
            if missing and (busy is None or not busy.is_alive()):
                t = threading.Thread(target=self._reports, args=(kind, range_key, names), daemon=True)
                self._report_gates[key] = t
                t.start()
        if not missing:  # every row there: answer from them at once, brought up to date behind the page
            key = ("bg", kind, range_key)
            with self._report_lock:
                busy = self._report_gates.get(key)
                if busy is None or not busy.is_alive():
                    t = threading.Thread(target=self._reports, args=(kind, range_key, names), daemon=True)
                    self._report_gates[key] = t
                    t.start()
            return out, 0
        return out, missing

    def _reports(self, kind: str, range_key: str, names: dict) -> dict:
        """{account: row or None (no flow logs read)} for every account sg_review has read. Each row is kept
        (in memory and on disk) until that account's read changes; one being written right now keeps its
        last row until it settles, so a long OU read does not rebuild every report on every page load.
        What is missing is built in parallel processes: the build is CPU work, one account at a time."""
        with self._report_lock:  # one build of each report at a time: a second page load waits for it, not repeats it
            gate = self._report_gates.setdefault((kind, range_key), threading.Lock())
        with gate:
            out, stale = self._reports_now(kind, range_key, names)
        if stale:  # shown at once from the last rows, brought up to date in the background
            key = ("refresh", kind, range_key)
            with self._report_lock:
                busy, last = self._report_gates.get(key) or (None, 0.0)
                if (busy is None or not busy.is_alive()) and time.time() - last > SETTLING:  # not every page load
                    t = threading.Thread(target=self._reports_now, args=(kind, range_key, names, False), daemon=True)
                    self._report_gates[key] = (t, time.time())
                    t.start()
        return out

    def _reports_now(self, kind: str, range_key: str, names: dict, stale_ok: bool = True) -> tuple[dict, bool]:
        """(rows, some shown stale). With ``stale_ok`` an account read since its row was built keeps that row
        (rebuilt later, in the background); only accounts with no row at all are built before answering."""
        import sg_review

        now, todo, out, stale = time.time(), [], {}, False
        with self._report_lock:
            cache = self._report_cache()
            for account, mtime in sorted(sg_review.stamps().items()):
                hit = cache.get(f"{kind}|{range_key}|{account}")
                if hit and kind in AGES and now - hit["at"] > AGES[kind]:  # e.g. the cost of what is unread grows by the hour
                    out[account], stale = hit["row"], True
                    if not stale_ok:
                        todo.append((account, mtime))
                elif hit and (hit["mtime"] == mtime or (now - mtime < SETTLING and now - hit["at"] < SETTLING)):
                    out[account] = hit["row"]
                elif hit and stale_ok:
                    out[account], stale = hit["row"], True
                else:
                    out[account] = None
                    todo.append((account, mtime))
        if todo:
            got = self._build_reports(kind, range_key, [(a, names.get(a, "")) for a, _ in todo])
            failed = self._builds.get(f"{kind}|{range_key}", {}).get("failed_accounts", set())
            with self._report_lock:
                cache = self._report_cache()
                for (account, mtime), row in zip(todo, got):
                    if account in failed:  # not kept: an error is not "no flow logs", and the next build tries again
                        continue
                    out[account] = row
                    cache[f"{kind}|{range_key}|{account}"] = {"mtime": mtime, "at": now, "row": row}
                self._save_report_cache([f"{kind}|{range_key}|{a}" for a, _ in todo if a not in failed])
        return out, stale

    def _build_reports(self, kind: str, range_key: str, items: list[tuple[str, str]]) -> list:
        """Build each account's row, counting progress in ``self._builds`` for the page and the log. An account whose
        build fails gets no row (None) and its error is kept: one bad account never stops the others."""
        import sg_review

        st = {"todo": len(items), "done": 0, "failed": 0, "errors": [], "started": time.time(), "finished": None,
              "failed_accounts": set()}
        self._builds[f"{kind}|{range_key}"] = st
        LOG.info("building %s %s for %d account(s)", kind, range_key, len(items))
        out = []

        def took(account, got):
            row, err, secs = got
            st["done"] += 1
            if err:
                st["failed"] += 1
                st["failed_accounts"].add(account)
                st["errors"] = (st["errors"] + [{"account": account, "error": err, "at": time.time()}])[-5:]
                LOG.warning("report %s %s for %s failed after %.1f s: %s", kind, range_key, account, secs, err)
            elif secs > 30:
                LOG.info("report %s %s for %s took %.0f s", kind, range_key, account, secs)
            out.append(row)

        args = [(kind, a, n, range_key) for a, n in items]
        try:
            if len(items) < 8 or REPORT_PROCS < 2:
                for x in args:
                    took(x[1], sg_review.report_row_safe(x))
            else:
                import multiprocessing

                try:
                    # a process is replaced after a few accounts: one large account leaves gigabytes behind in the
                    # process that built it, and a long-lived one would keep them for every account after
                    with REPORT_GATE, multiprocessing.get_context("spawn").Pool(
                            min(REPORT_PROCS, len(items)), maxtasksperchild=4, **_child_data_dir(nice=True)) as pool:
                        for (_, a, _, _), got in zip(args, pool.imap(sg_review.report_row_safe, args, chunksize=1)):
                            took(a, got)
                except Exception:  # processes not available here: build the rest one by one
                    LOG.exception("building %s reports in parallel failed after %d; building the rest one by one",
                                  kind, len(out))
                    for x in args[len(out):]:
                        took(x[1], sg_review.report_row_safe(x))
        finally:
            st["finished"] = time.time()
            LOG.info("built %s %s: %d of %d account(s) in %.0f s, %d failed", kind, range_key, st["done"],
                     st["todo"], st["finished"] - st["started"], st["failed"])
        return out

    def reports_retry(self, body: dict) -> dict:
        """Forget which accounts failed the last build of a report and build what is missing again, now."""
        kind, range_key = body.get("kind", "refused"), body.get("range", "24h")
        if kind not in ("refused", "macro") or range_key not in RANGES:
            raise ConsoleError(400, "kind must be refused or macro, range one of " + ", ".join(RANGES))
        st = self._builds.get(f"{kind}|{range_key}")
        if st and st["finished"] is None:
            return {"started": False, "why": "a build is already running", "build": self.build_status(kind, range_key)}
        if st:
            st["failed_accounts"], st["finished"] = set(), 0.0
        LOG.info("building %s %s again, asked from the page", kind, range_key)
        _, building = self._reports_soon(kind, range_key, {})
        return {"started": True, "building": building}

    # ------------------------------------------------------------------ settings
    def settings(self) -> dict:
        """Everything the Settings tab shows: version (and the newest release), the repository and its author,
        the schedule, how rules are narrowed and applied, performance, approvals, always running, the database
        and the data kept."""
        import sg_ipintel
        import sg_review
        import sg_store
        import sg_tightener

        st = self.store()
        try:
            approvals = st.approvals()
            strategy = st.meta_get("apply_strategy", "room") or "room"
            data_use = {"wifi_only": bool(st.meta_get("wifi_only", False)), "keep_prices": bool(st.meta_get("keep_prices", True))}
        finally:
            st.close()
        try:
            dsn = sg_store.dsn()
        except Exception:  # noqa: BLE001 - shown as not set up
            dsn = ""
        bdir = sg_store.backup_dir()
        backups = sorted(bdir.glob("*.dump")) if bdir.exists() else []
        names = sg_review.names_path()
        return {
            "about": {"version": sg_tightener.__version__, "latest": self._latest_release(),
                      "repo": "https://github.com/andrewbakercloudscale/sg-tightener", "author": "Andrew Baker",
                      "license": "MIT", "site": "https://andrewbaker.ninja", "python": sys.version.split()[0]},
            "schedule": self.schedule(),
            "tighten": {**sg_review.tighten_prefs(), "defaults": dict(sg_review.TIGHTEN), "strategy": strategy,
                        "strategies": dict(sg_db.APPLY_STRATEGIES)},
            "performance": {"procs": REPORT_PROCS, "auto": _report_procs(), "cores": os.cpu_count(),
                            "memory_gb": round(_mem_bytes() / 2**30), "from_env": bool(os.environ.get("SG_REPORT_PROCS")),
                            "builds": {k: self.build_status(*k.split("|")) for k in list(self._builds)}},
            "approvals": approvals, "service": self.service.status() if self.service else None,
            "data_use": {**data_use, "network": _network(fresh=True)},
            "database": {"dsn": _mask_dsn(dsn), "from_env": bool(os.environ.get(sg_store.DSN_ENV)),
                         "file": str(sg_store.dsn_file()), **sg_store.server_status()},
            "data": {"dir": str(sg_ipintel.DATA_DIR), "names": str(names), "names_exists": Path(names).exists(),
                     "retention_days": sg_store.RETENTION_DAYS, "backups_dir": str(bdir), "backups": len(backups),
                     "last_backup": backups[-1].stat().st_mtime if backups else None, "backups_kept": sg_store.BACKUP_KEEP},
        }

    # ------------------------------------------------------------------ support: activity log, health, bundle
    @property
    def journal(self):
        """The activity log (sg_journal), in the data folder in use: a file, so it works with the database down."""
        import sg_ipintel
        import sg_journal

        path = Path(sg_ipintel.DATA_DIR) / "journal.jsonl"
        j = getattr(self, "_journal", None)
        if j is None or j.path != path:
            j = self._journal = sg_journal.Journal(path)
        return j

    def _rec(self, kind: str, message: str, level: str = "info", account: str = "", **detail) -> None:
        try:
            self.journal.record(kind, message, level, account, **detail)
        except Exception:  # noqa: BLE001 - recording must never stop what it records
            pass

    def activity(self, q: dict) -> dict:
        """The activity log, newest first, filtered as the Support tab asks."""
        import sg_journal

        hours = float(q.get("hours") or 0)
        rows = self.journal.recent(int(q.get("limit") or 500), str(q.get("level") or ""), str(q.get("kind") or ""),
                                   str(q.get("q") or ""), time.time() - hours * 3600 if hours else 0,
                                   str(q.get("account") or ""))  # fmt: skip
        return {"rows": rows, "kinds": sg_journal.KINDS, "file": str(self.journal.path), "bytes": self.journal.size()}

    def _log_file(self) -> Path:
        import sg_ipintel

        return Path(sg_ipintel.DATA_DIR) / "console.log"

    def health(self) -> dict:
        """Every check the Support tab shows, each {"key", "name", "status" (ok, warn, bad, info), "value",
        "detail", "fix"}: what to look at first when something seems wrong. Uses no internet."""
        import shutil

        import sg_ipintel
        import sg_store
        import sg_tightener

        checks: list[dict] = []

        def add(key, name, status, value, detail="", fix=""):
            checks.append({"key": key, "name": name, "status": status, "value": value, "detail": detail, "fix": fix})

        started = getattr(self, "started", None) or time.time()
        up = time.time() - started
        add("version", "Console", "ok", f"{sg_tightener.__version__}, running {_ago(up)}",
            f"process {os.getpid()} · Python {sys.version.split()[0]} · {platform.system()} {platform.release()}"
            + (" · started by the background service" if self.service and self.service.running_as_service else ""))
        db_ok, why = False, ""
        try:
            db_ok, why = sg_store.reachable()
        except Exception as exc:  # noqa: BLE001
            why = str(exc)
        if db_ok:
            try:
                st = self.store()
                try:
                    intact, n, broken = st.verify()
                finally:
                    st.close()
                add("database", "Database", "ok", "answering", why or "")
                add("audit", "Audit trail", "ok" if intact else "bad",
                    f"{n:,} entries, intact" if intact else f"{n:,} entries, BROKEN", broken,
                    "" if intact else "An entry was changed or removed outside the tool. Keep a backup and report it.")
            except Exception as exc:  # noqa: BLE001
                add("database", "Database", "bad", "answers, but reading failed", plain_error(exc),
                    "Look at the activity log below for the error.")
        else:
            add("database", "Database", "bad", "not answering", why,
                "Start Docker (or Colima), then press Start the database on the banner, or run "
                "python sg_store.py setup.")
        try:
            a = self.auth()
            s = a.status() if a is not None else {}
            if a is None:
                add("signin", "AWS sign-in", "info", "not set up", "", "Sign in on Overview.")
            elif s.get("signed_in") or (a is self.keys and s.get("active")):
                exp = s.get("expires", "")
                left = None
                if exp:
                    try:
                        import datetime as _dt

                        left = _dt.datetime.fromisoformat(exp.replace("Z", "+00:00")).timestamp() - time.time()
                    except ValueError:
                        left = None
                status = "warn" if left is not None and left < 3600 else "ok"
                add("signin", "AWS sign-in", status, "signed in" + (f", {_ago(left)} left" if left and left > 0 else ""),
                    f"{len(s.get('chosen') or [])} account(s) chosen" + (f" · until {exp}" if exp else ""),
                    "Renew the sign-in on Overview before a long read." if status == "warn" else "")  # fmt: skip
            else:
                add("signin", "AWS sign-in", "warn", "not signed in", s.get("error") or "",
                    "Sign in on Overview. Behind Zscaler, Zscaler must be on for the company sign-in.")
        except Exception as exc:  # noqa: BLE001
            add("signin", "AWS sign-in", "warn", "not known", plain_error(exc))
        n = _network()
        add("network", "Network", "warn" if n.get("metered") else "ok" if n.get("metered") is False else "info",
            "phone hotspot" if n.get("metered") else "Wi-Fi or wired" if n.get("metered") is False else "not known",
            f"{n.get('why', '')}{(' on ' + n['interface']) if n.get('interface') else ''}",
            "Reads use a little data (about 0.5 MB an account to price). Settings → Data use can make them wait for Wi-Fi."
            if n.get("metered") else "")  # fmt: skip
        b = self.batch_status() if self.batch else None
        if b:
            c = b.get("count") or {}
            failed = c.get("failed", 0)
            add("batch", "Read of many accounts", "warn" if failed else "ok" if b["status"] != "confirm" else "info",
                {"pricing": "pricing", "confirm": "waiting for your yes", "running": "reading", "done": "finished",
                 "stopped": "stopped"}.get(b["status"], b["status"]),
                f"{b['accounts']} accounts: " + ", ".join(f"{v} {k}" for k, v in sorted(c.items()))
                + (f" · about US${b['cost']:.2f}" if b.get("cost") else ""),
                f"{failed} account(s) failed: their reason is in the activity log (kind: read)." if failed else "")  # fmt: skip
        else:
            add("batch", "Read of many accounts", "info", "none under way")
        try:
            sch = self.schedule()
            last = (sch.get("runs") or [{}])[-1] if sch.get("runs") else {}
            wait = self._sched_wait
            add("schedule", "Scheduled read", "warn" if last.get("status") == "failed" else "ok" if sch.get("on") else "info",
                ("on" if sch.get("on") else "off") + (f", waiting: {wait}" if wait else ""),
                (f"last: {last.get('status', '')} {last.get('why', '')}".strip() if last else "not run yet"),
                "Look at the reason above; the next run is tried at the next scheduled time." if last.get("status") == "failed" else "")  # fmt: skip
        except Exception as exc:  # noqa: BLE001
            add("schedule", "Scheduled read", "info", "not known", plain_error(exc))
        bad = [f"{k.replace('|', ' ')}: {v['failed']} failed" for k in list(self._builds)
               for v in [self.build_status(*k.split("|"))] if v and v.get("failed")]  # fmt: skip
        add("reports", "Report builds", "warn" if bad else "ok", "some accounts failed" if bad else "no failures",
            "; ".join(bad), "The failures are in the activity log (kind: error)." if bad else "")
        if self.service:
            s = self.service.status()
            add("service", "Always running", "ok" if s.get("installed") else "info",
                "on" if s.get("installed") else "off", s.get("file", "") if s.get("installed") else "",
                "" if s.get("installed") else "Settings → Approvals and running → Always running keeps it up after a restart.")
        try:
            where = Path(sg_ipintel.DATA_DIR)
            while not where.exists() and where != where.parent:  # not made yet: the disk it will be on
                where = where.parent
            du = shutil.disk_usage(where)
            free = du.free / 1e9
            add("disk", "Disk space", "bad" if free < 2 else "warn" if free < 10 else "ok", f"{free:.0f} GB free",
                str(sg_ipintel.DATA_DIR), "Free some space: the database and reports need room to grow." if free < 10 else "")
        except OSError:
            pass
        c = self.journal.counts(time.time() - 86400)
        last = c["last_error"]
        add("errors", "Errors, last 24 hours", "warn" if c["error"] else "ok",
            f"{c['error']} error(s), {c['warning']} warning(s)",
            (f"latest {time.strftime('%H:%M', time.localtime(last['at']))}: {last['message']}" if last else ""),
            "Open the activity log below with Problems only." if c["error"] else "")
        logf = self._log_file()
        size = logf.stat().st_size if logf.exists() else 0
        add("log", "Console log", "warn" if size > 500e6 else "ok", f"{size / 1e6:.0f} MB" if size else "none",
            str(logf), "It is large: python sg_console.py install starts a new one." if size > 500e6 else "")
        if self.journal.failed:
            add("journal", "Activity log", "bad", "cannot be written", self.journal.failed,
                f"Check {self.journal.path.parent} is writable.")
        worst = "bad" if any(x["status"] == "bad" for x in checks) else "warn" if any(x["status"] == "warn" for x in checks) else "ok"
        return {"at": time.time(), "status": worst, "checks": checks, "journal": str(self.journal.path),
                "log": str(logf), "version": sg_tightener.__version__}

    def support_bundle(self) -> tuple[str, bytes]:
        """(file name, zip) for whoever helps: health, versions, settings, the activity log and the end of the
        console's log, every secret taken out. Nothing about the security groups themselves."""
        import sg_journal
        import sg_tightener

        h = self.health()
        try:
            cfg = self.settings()
            cfg["about"].pop("latest", None)
        except Exception as exc:  # noqa: BLE001 - the database may be the very problem
            cfg = {"error": plain_error(exc)}
        env = {k: ("set" if os.environ.get(k) else "") for k in PASS_ENV + ("SG_REPORT_PROCS", "SG_NO_SCHEDULE")}
        try:
            import importlib.metadata as md

            pkgs = {p: md.version(p) for p in ("boto3", "botocore", "psycopg", "PyYAML") if _has_dist(md, p)}
        except Exception:  # noqa: BLE001
            pkgs = {}
        stamp = time.strftime("%Y%m%d-%H%M%S")
        self._rec("action", "support bundle downloaded")
        data = sg_journal.bundle({
            "README.txt": ("sg-tightener support bundle\n\nhealth.json    what the Support tab showed\n"
                           "settings.json  the console's settings (connection strings masked)\n"
                           "activity.json  the activity log, newest first\nconsole.log    the end of the console's log\n"
                           "versions.json  versions of the tool, Python and its packages, and which environment "
                           "variables are set (not their values)\n\nTokens, keys and passwords are replaced by ***. "
                           "Account ids and security group ids are kept: they are needed to follow what happened.\n"),
            "health.json": h,
            "settings.json": cfg,
            "activity.json": self.journal.recent(5000),
            "console.log": sg_journal.tail(self._log_file()),
            "versions.json": {"sg_tightener": sg_tightener.__version__, "python": sys.version, "platform": platform.platform(),
                              "packages": pkgs, "environment": env, "batch": self.batch_status() if self.batch else None,
                              "jobs": [{k: j.get(k) for k in ("id", "account", "status", "lines", "cost", "done", "total")}
                                       for j in list(self.jobs.values())[-300:]]},  # fmt: skip
        })
        return f"sg-tightener-support-{stamp}.zip", data

    def _latest_release(self) -> dict:
        """The newest version tag on GitHub, asked at most every six hours; {} when it cannot be asked."""
        got = getattr(self, "_latest", None)
        if got and time.time() - got[0] < 6 * 3600:
            return got[1]
        out: dict = {}
        try:
            import urllib.request

            req = urllib.request.Request("https://api.github.com/repos/andrewbakercloudscale/sg-tightener/tags?per_page=30",
                                         headers={"User-Agent": "sg-tightener", "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 - a fixed https address
                tags = [t["name"] for t in json.loads(r.read().decode()) if re.fullmatch(r"v?\d+\.\d+\.\d+", t.get("name", ""))]
            if tags:
                best = max(tags, key=lambda x: tuple(int(n) for n in x.lstrip("v").split(".")))
                out = {"version": best.lstrip("v"), "url": f"https://github.com/andrewbakercloudscale/sg-tightener/releases/tag/{best}"}
        except Exception as exc:  # noqa: BLE001 - offline, private repository or rate limited: shown as not known
            out = {"error": str(exc)[:200]}
        self._latest = (time.time(), out)
        return out

    def load_saved_procs(self) -> None:
        """The number of report workers chosen on the Settings tab (0: automatic); SG_REPORT_PROCS wins."""
        global REPORT_PROCS
        if os.environ.get("SG_REPORT_PROCS"):
            return
        try:
            st = self.store()
            try:
                n = int(st.meta_get("report_procs", 0) or 0)
            finally:
                st.close()
        except Exception:  # noqa: BLE001 - automatic
            return
        if n:
            REPORT_PROCS = n

    def set_settings(self, body: dict) -> dict:
        """Save the settings this tab owns: the default apply strategy and the number of report workers."""
        global REPORT_PROCS
        st = self.store()
        try:
            with st:
                if "strategy" in body:
                    if body["strategy"] not in sg_db.APPLY_STRATEGIES:
                        raise ConsoleError(400, "strategy is one of " + ", ".join(sg_db.APPLY_STRATEGIES))
                    st.meta_set("apply_strategy", body["strategy"])
                for k in ("wifi_only", "keep_prices"):
                    if k in body:
                        st.meta_set(k, bool(body[k]))
                        LOG.info("setting %s now %s", k, bool(body[k]))
                if "procs" in body:
                    try:
                        n = int(body["procs"] or 0)
                    except (TypeError, ValueError):
                        raise ConsoleError(400, "workers is a whole number") from None
                    if not 0 <= n <= max(1, os.cpu_count() or 1):
                        raise ConsoleError(400, f"workers is 0 (automatic) to {os.cpu_count()}")
                    st.meta_set("report_procs", n)
                    REPORT_PROCS = n or _report_procs()
                    LOG.info("report workers now %d", REPORT_PROCS)
        finally:
            st.close()
        return self.settings()

    def backup_now(self, _body: dict | None = None) -> dict:
        import sg_store

        try:
            path = sg_store.backup(say=LOG.info)
        except Exception as exc:  # noqa: BLE001 - shown on the page
            raise ConsoleError(500, f"backup failed: {exc}") from None
        return {"path": str(path), "settings": self.settings()}

    def test_dsn(self, body: dict) -> dict:
        """Try a PostgreSQL connection string; with "save", write it to pg.dsn (used from the next start)."""
        import sg_store

        dsn = str(body.get("dsn") or "").strip()
        if not dsn:
            raise ConsoleError(400, "give a connection string, e.g. postgresql://user:password@host:5432/db")
        try:
            psy = sg_store._psycopg()
            with psy.connect(dsn, connect_timeout=5) as c:
                ver = c.execute("SELECT version()").fetchone()[0]
        except Exception as exc:  # noqa: BLE001 - the answer to the test
            return {"ok": False, "error": str(exc).splitlines()[0][:300]}
        if body.get("save"):
            if os.environ.get(sg_store.DSN_ENV):
                raise ConsoleError(409, f"{sg_store.DSN_ENV} is set in the environment and wins over the file: change it there")
            f = sg_store.dsn_file()
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(dsn + "\n")
            os.chmod(f, 0o600)
            LOG.info("database connection changed (takes effect when the console restarts)")
        return {"ok": True, "version": ver.split(",")[0], "saved": bool(body.get("save")), "restart": bool(body.get("save"))}

    def tighten_prefs(self) -> dict:
        import sg_review

        return {**sg_review.tighten_prefs(), "defaults": dict(sg_review.TIGHTEN)}

    def set_tighten_prefs(self, body: dict) -> dict:
        """Save how rules are narrowed. Plans are kept per settings, so the next Remediate view is built again."""
        import sg_review

        try:
            got = sg_review.save_tighten_prefs(body)
        except (ValueError, TypeError) as exc:
            raise ConsoleError(400, str(exc)) from None
        LOG.info("tightening settings now %s", got)
        return {**got, "defaults": dict(sg_review.TIGHTEN)}

    def build_status(self, kind: str, range_key: str) -> dict | None:
        """How the latest build of one report went, for the page: counts, the last errors, whether it still runs."""
        st = self._builds.get(f"{kind}|{range_key}")
        if not st:
            return None
        return {**st, "errors": list(st["errors"]), "failed_accounts": sorted(st["failed_accounts"]),
                "running": st["finished"] is None}

    # ------------------------------------------------------------------ scheduled reads
    def schedule(self) -> dict:
        """When the console reads every chosen account's new flow logs by itself, the most it may spend each time
        without asking, and how the last runs went."""
        st = self.store()
        try:
            cfg = {**SCHEDULE_DEFAULT, **(st.meta_get("schedule", {}) or {})}
            runs = st.meta_get("schedule_runs", []) or []
        finally:
            st.close()
        nxt = _next_slot(cfg, time.time()) if cfg["on"] else None
        return {**cfg, "runs": runs[-10:], "next": nxt, "waiting": self._sched_wait}

    def set_schedule(self, body: dict) -> dict:
        times = sorted({str(t).strip() for t in body.get("times") or [] if str(t).strip()})
        for t in times:
            if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", t):
                raise ConsoleError(400, f"{t!r} is not a time of day like 08:00")
        if body.get("on") and not times:
            raise ConsoleError(400, "give at least one time of day, or turn the schedule off")
        if len(times) > 6:
            raise ConsoleError(400, "at most six reads a day")
        try:
            max_cost = max(0.0, float(body.get("max_cost", SCHEDULE_DEFAULT["max_cost"])))
            days = int(body.get("days", SCHEDULE_DEFAULT["days"]))
        except (TypeError, ValueError):
            raise ConsoleError(400, "max_cost is US dollars and days a whole number")
        if not 1 <= days <= 90:
            raise ConsoleError(400, "days is from 1 to 90")
        cfg = {"on": bool(body.get("on")), "times": times or SCHEDULE_DEFAULT["times"], "max_cost": max_cost, "days": days,
               "on_wake": bool(body.get("on_wake", True))}
        st = self.store()
        try:
            with st:
                st.meta_set("schedule", cfg)
        finally:
            st.close()
        return self.schedule()

    def _sched_log(self, entry: dict) -> None:
        st = self.store()
        try:
            with st:
                runs = (st.meta_get("schedule_runs", []) or [])[-29:]
                st.meta_set("schedule_runs", runs + [{"at": time.time(), **entry}])
        finally:
            st.close()
            self._rec("schedule", f"scheduled read {entry.get('slot', '')}: {entry.get('status', '')}"
                      + (f", {entry['why']}" if entry.get("why") else ""),
                      "warning" if entry.get("status") == "failed" else "info", **entry)  # fmt: skip

    def scheduler(self, stop: threading.Event | None = None, now=time.time) -> None:
        """Each scheduled time of day, read every chosen account's flow logs since they were last read: priced
        first, and started without asking when the price is within the limit set on the page. A time missed
        (asleep, or not signed in) is caught up later that day, once; the next day starts afresh."""
        stop = stop or threading.Event()
        while not stop.is_set():
            try:
                self.schedule_tick(now())
            except Exception:  # noqa: BLE001 - tried again next minute
                LOG.exception("scheduled read failed")
            stop.wait(SCHEDULE_POLL)

    def schedule_tick(self, t: float) -> str:
        """One look at the clock: what was done ("" for nothing)."""
        st = self.store()
        try:
            cfg = {**SCHEDULE_DEFAULT, **(st.meta_get("schedule", {}) or {})}
            done = st.meta_get("schedule_done", "") or ""
        finally:
            st.close()
        if not cfg["on"]:
            return ""
        slot = _due_slot(cfg, t)
        if not slot or slot <= done:
            return ""
        if self.batch and self.batch["status"] in ("pricing", "running", "confirm"):
            self._sched_wait = "another read of many accounts is under way: it starts when that one ends"
            return ""
        if not self._sso_ready():
            if self._sched_wait != "sign-in":
                self._sched_log({"slot": slot, "status": "waiting", "why": "not signed in to AWS: it runs once you sign in"})
            self._sched_wait = "sign-in"
            return ""
        if self.metered_hold():
            if self._sched_wait != "wifi":
                self._sched_log({"slot": slot, "status": "waiting", "why": "on a phone hotspot: it runs once on Wi-Fi"})
            self._sched_wait = "wifi"
            return ""
        self._sched_wait = ""
        st = self.store()
        try:
            with st:
                st.meta_set("schedule_done", slot)  # before starting: a failure is not retried every minute
        finally:
            st.close()
        threading.Thread(target=self._scheduled_read, args=(slot, cfg), daemon=True, name="scheduled-read").start()
        return slot

    def _scheduled_read(self, slot: str, cfg: dict) -> None:
        try:
            self.read_all({"days": cfg["days"], "min_spend": MIN_SPEND})
        except ConsoleError as exc:
            return self._sched_log({"slot": slot, "status": "failed", "why": str(exc)})
        b = self.batch
        while b["status"] == "pricing":
            time.sleep(5)
        s = self.batch_status() or {}
        if b["status"] != "confirm":
            return self._sched_log({"slot": slot, "status": "nothing", "why": "nothing new to read", "accounts": s.get("accounts", 0)})
        cost = float(s.get("cost") or 0)
        if cost > cfg["max_cost"] or s.get("cost_unknown"):
            why = (f"about US${cost:.2f} is over the US${cfg['max_cost']:.2f} limit" if cost > cfg["max_cost"] else
                   f"{s['cost_unknown']} account(s) could not be priced")  # fmt: skip
            return self._sched_log({"slot": slot, "status": "asking", "cost": cost, "accounts": s.get("to_read", 0),
                                    "why": why + ": waiting on the Overview for you to confirm it"})  # fmt: skip
        self.read_all_confirm({})
        self._sched_log({"slot": slot, "status": "started", "cost": cost, "accounts": s.get("to_read", 0)})

    def warm(self, stop: threading.Event | None = None) -> None:
        """Keep every report view built in the background: at start, then every WARM_EVERY seconds for accounts
        read since. A page then answers from rows already built instead of building 160 accounts while it waits."""
        stop = stop or threading.Event()
        while not stop.is_set():
            names: dict = {}
            try:
                st = self.store()
                try:
                    names = st.account_names()
                finally:
                    st.close()
            except Exception:  # noqa: BLE001 - names are a nicety
                pass
            for kind, range_key in WARM:
                if stop.is_set():
                    return
                try:
                    self._reports_now(kind, range_key, names if kind == "macro" else {}, False)
                except Exception:  # noqa: BLE001 - the page builds what is missing
                    LOG.exception("warming %s %s failed", kind, range_key)
            stop.wait(WARM_EVERY)

    def _report_cache(self) -> dict:
        if self._reports_mem is None:
            import sg_store

            try:
                got = sg_store.report_rows(_kind_version)
                # an earlier version's row is shown until rebuilt only where the page reads it (it may lack new fields)
                self._reports_mem = {k: v for k, v in got.items() if not v.get("old") or k.split("|", 1)[0] in SHOW_OLD}
                old = sum(1 for v in self._reports_mem.values() if v.get("old"))
                if old:
                    LOG.info("%d report row(s) from an earlier version shown until rebuilt", old)
            except Exception as exc:  # noqa: BLE001 - rebuilt from the reads
                LOG.warning("report rows not loaded: %s", exc)
                self._reports_mem = {}
        return self._reports_mem

    def _save_report_cache(self, keys=None) -> None:
        """Keep the rows named by ``keys`` (all of them by default) in the database."""
        import sg_store

        rows = self._reports_mem or {}
        try:
            sg_store.save_report_rows(_kind_version, {k: rows[k] for k in (rows if keys is None else keys)
                                                             if k in rows and not rows[k].get("old")})
        except Exception as exc:  # noqa: BLE001 - rebuilt from the reads
            LOG.warning("report rows not saved: %s", exc)

    def refused(self, range_key: str = "24h") -> dict:
        """Every refused source across the accounts sg_review has read, worst verdict first."""
        import sg_review

        if range_key not in RANGES:
            raise ConsoleError(400, f"range must be one of {', '.join(RANGES)}")
        rows, accounts, unread = [], [], []
        got_rows, building = self._reports_soon("refused", range_key, {})
        for account, got in got_rows.items():
            if got is None:
                unread.append(account)
                continue
            rows += got["rows"]
            accounts.append({**got["account"], "trend": got.get("trend")})
        rows.sort(key=lambda x: (sg_review.SEV_RANK.get(x["sev"], 9), -x["flows"]))
        types = {k: n for k, (n, _) in sg_review.SOURCE_TYPES.items()}
        with self._report_lock:
            cache = self._report_cache()
            old = sum(1 for a in got_rows if (cache.get(f"refused|{range_key}|{a}") or {}).get("old"))
        return {"range": range_key, "rows": rows, "accounts": accounts, "types": types, "no_flow_logs_read": len(unread),
                "building": building, "old": old, "build": self.build_status("refused", range_key),
                "gnames": self._group_names({a["account"] for a in accounts})}

    def _group_names(self, accounts: set) -> dict:
        """{group id: name} for these accounts' security groups, from the database; kept ten minutes."""
        now = time.time()
        got = getattr(self, "_gnames", None)
        if got and now - got[0] < 600 and accounts <= got[1]:
            return got[2]
        names: dict = {}
        try:
            st = self.store()
            try:
                for account in accounts:
                    for _, region in st.regions(account):
                        for gid, g in st.groups(account, region).items():
                            if g.get("name"):
                                names[gid] = g["name"]
            finally:
                st.close()
        except Exception as exc:  # noqa: BLE001 - names are a nicety: ids are shown without them
            LOG.warning("security group names not read: %s", exc)
            return {}
        self._gnames = (now, set(accounts), names)
        return names

    # ------------------------------------------------------------------ the estate's address book
    def _ip_index(self) -> tuple[dict, int]:
        """{"seen": ip -> [(account, sighting)], "own": ip -> [(account, eni, interface)], "names": account -> name},
        and how many accounts are still being added. Rebuilt only when an account's sightings change."""
        rows, building = self._reports_soon("seen", "all", {})
        sig = tuple(sorted((a, id(r)) for a, r in rows.items()))
        got = self._ip_idx
        if got and got[0] == sig:
            return got[1], building
        seen: dict[str, list] = {}
        own: dict[str, list] = {}
        for account, r in rows.items():
            if not r:
                continue
            for ip, x in (r.get("seen") or {}).items():
                seen.setdefault(ip, []).append((account, x))
            for eid, e in (r.get("own") or {}).items():
                for ip in e[8]:
                    own.setdefault(ip, []).append((account, eid, e))
        idx = {"seen": seen, "own": own, "names": {a: (r or {}).get("name", "") for a, r in rows.items()},
               "indexed": sum(1 for r in rows.values() if r)}
        self._ip_idx = (sig, idx)
        return idx, building

    def _who(self, src: str, proto: str, port, account: str) -> dict | None:
        """What a source being let in is, for the apply preview: one address answered in full, a range by its size,
        a security group by name. None when nothing can be said."""
        import ipaddress as _ipa

        try:
            net = _ipa.ip_network(src, strict=False)
        except ValueError:
            return {"group": src} if src.startswith("sg-") else None
        if net.num_addresses > 1:
            return {"addresses": net.num_addresses, "answers": [{"q": "How many addresses?", "tone": "warn" if net.num_addresses > 256 else "info",
                    "a": f"{net.num_addresses:,} addresses: every one of them is let in, not just the ones seen."}]}  # fmt: skip
        try:
            got = self.ip_profile(str(net.network_address), proto, port, account)
        except Exception as exc:  # noqa: BLE001 - the preview still lists the change
            LOG.warning("no profile of %s: %s", src, exc)
            return None
        return {"addresses": 1, "answers": got["answers"], "ip": got["ip"]}

    def ip_profile(self, ip: str, proto: str = "", port=None, account: str = "") -> dict:
        """Everything known about one IP address across the estate, as answers to what anyone asks before letting it
        in: who owns it (AWS service and region, one of our accounts, or an AS number and its owner), whether it is
        on a threat list or a Tor exit, which of our interfaces it is (and that instance's operating system), every
        account that let it in or refused it and on which ports, whether it scanned, when first and last seen, and
        what the port it asks for is. Nothing is sent to it: the tool only reads."""
        import ipaddress as _ipa

        import sg_ipintel
        import sg_review

        ip = str(ip or "").strip().split("/")[0]
        try:
            addr = _ipa.ip_address(ip)
        except ValueError:
            raise ConsoleError(400, f"{ip or 'nothing'} is not an IP address")
        ip = str(addr)
        idx, building = self._ip_index()
        names = dict(idx["names"])
        try:
            st = self.store()
            try:
                names.update({a: n for a, n in st.account_names().items() if n})
            finally:
                st.close()
        except Exception:  # noqa: BLE001 - names are a nicety
            pass
        private = sg_review.private_ip(ip)
        intel = {} if private else sg_ipintel.get().label(ip)
        ours = [{"account": a, "account_name": names.get(a, ""), "eni": eid, "kind": e[0], "instance": e[1], "name": e[2],
                 "os": e[3], "type": e[4], "groups": e[5], "region": e[6], "desc": e[7],
                 "launched": e[9] if len(e) > 9 else None, "image": e[10] if len(e) > 10 else "",
                 "vpc": e[11] if len(e) > 11 else ""}
                for a, eid, e in idx["own"].get(ip, [])]  # fmt: skip
        seen = []
        for a, x in idx["seen"].get(ip, []):
            ports = []
            for pr, pt, n_in, n_ref in x[8]:
                pc = sg_review.port_class(pr, pt)
                ports.append({"proto": sg_review.PROTO_NAME.get(str(pr), str(pr)), "port": pt, "svc": pc["svc"],
                              "cls": pc["name"], "risky": pc["risky"], "let_in": n_in, "refused": n_ref})  # fmt: skip
            seen.append({"account": a, "account_name": names.get(a, ""), "let_in": x[0], "refused": x[1], "replies": x[2],
                         "first": x[3], "last": x[4], "ports_refused": x[5], "addresses": x[6], "regions": x[7],
                         "ports": ports, "ports_let_in": x[9] if len(x) > 9 else 0,
                         "scan": x[5] >= 10 or (x[6] >= 5 and x[5] > 1)})  # fmt: skip
        seen.sort(key=lambda r: -(r["let_in"] + r["refused"] + r["replies"]))
        pnum = {"tcp": "6", "udp": "17", "icmp": "1"}.get(str(proto).lower(), str(proto)) or "6"  # a port alone: TCP
        port_info = None
        if port not in (None, ""):
            try:
                pc = sg_review.port_class(pnum or "6", int(port))
                port_info = {"proto": sg_review.PROTO_NAME.get(pnum, pnum), "port": int(port), **pc,
                             "database": pc["cls"] == "database",
                             "why": sg_review.PORT_CLASSES.get(pc["cls"], ("", ""))[1]}  # fmt: skip
            except (TypeError, ValueError):
                raise ConsoleError(400, "port is a number")
        return {"ip": ip, "private": private, "intel": intel, "ours": ours, "seen": seen, "port": port_info,
                "answers": _ip_answers(ip, private, intel, ours, seen, port_info, account, names, building),
                "accounts_indexed": idx["indexed"], "building": building}  # fmt: skip

    # ------------------------------------------------------------------ AWS sign-in (SSO)
    def _need_sso(self):
        if self.sso is None:
            raise ConsoleError(400, "SSO sign-in is not available in this console")
        return self.sso

    def sso_status(self) -> dict:
        out = self._need_sso().status()
        out["method"] = "keys" if self.auth() is self.keys and self.keys is not None else "sso"
        out["keys"] = self.keys.status() if self.keys is not None else None
        if out["method"] == "keys":  # the page shows who acts and what is chosen from the sign-in in use
            out["chosen"] = out["keys"]["chosen"]
        return out

    def _auth_call(self, fn, *a, status: int = 400):
        import sg_keys
        import sg_sso

        try:
            return fn(*a)
        except (sg_sso.SsoError, sg_keys.KeysError) as exc:
            raise ConsoleError(status, str(exc))

    def sso_start(self, body: dict) -> dict:
        sso = self._need_sso()
        out = self._auth_call(sso.start, str(body.get("start_url") or ""), str(body.get("region") or ""),
                              bool(body.get("renew")))
        if self.keys is not None and self.keys.state.get("active"):
            self.keys.state["active"] = False
            self.keys._save()
        return out

    ZSCALER_CHECK = "http://ip.zscaler.com/"  # plain HTTP: no certificate trouble under TLS inspection

    def net_check(self, _body: dict | None = None) -> dict:
        """Whether this computer's traffic goes out through Zscaler now, on a new connection, and from which IP
        address: a company sign-in that allows only Zscaler's addresses fails without it."""
        import re
        import urllib.request

        try:
            with urllib.request.urlopen(self.ZSCALER_CHECK, timeout=6) as r:  # noqa: S310 - a fixed http URL
                text = re.sub(r"<[^>]+>", " ", r.read(200_000).decode("utf-8", "replace"))
        except Exception as exc:  # noqa: BLE001 - offline, or the check site blocked: not known
            return {"zscaler": None, "ip": "", "error": plain_error(exc)}
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        on = True if re.search(r"via\s+(?:(?:a|the)\s+)?Zscaler", text, re.I) else False if re.search(r"not going through", text, re.I) else None
        return {"zscaler": on, "ip": ips[0] if ips else ""}

    def net_reset(self, _body: dict | None = None) -> dict:
        """After turning Zscaler on: the browser keeps using connections it opened before (to Microsoft's and AWS's
        sign-in pages), so sign-in still arrives from the old address for minutes. Clears this computer's DNS
        cache and opens Chrome's connection page, where Flush socket pools closes them at once."""
        import shutil
        import subprocess

        done, failed = [], []
        for cmd, what in ((["dscacheutil", "-flushcache"], "DNS cache cleared"),
                          (["killall", "-HUP", "mDNSResponder"], "DNS resolver restarted")):  # fmt: skip
            if not shutil.which(cmd[0]):
                continue
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)  # noqa: S603 - fixed commands
            (done if r.returncode == 0 else failed).append(what if r.returncode == 0 else f"{what.split(' ')[0]} resolver not restarted (needs an administrator)")
        opened = False
        if sys.platform == "darwin" and shutil.which("open"):
            r = subprocess.run(["open", "-a", "Google Chrome", "chrome://net-internals/#sockets"], capture_output=True, timeout=10)  # noqa: S603, S607
            opened = r.returncode == 0
        return {"done": done, "failed": failed, "chrome": opened, **self.net_check()}

    def keys_use(self, body: dict) -> dict:
        if self.keys is None:
            raise ConsoleError(400, "signing in with keys is not available in this console")
        out = self._auth_call(self.keys.use, str(body.get("profile") or ""))
        self.keys.state["active"] = True
        self.keys._save()
        return out

    def sso_accounts(self, fresh: bool = False, roles: bool = True) -> list[dict]:
        a = self.auth() or self._need_sso()
        return self._auth_call(a.accounts, fresh, roles, status=401)

    def sso_roles(self) -> list[dict]:
        a = self.auth() or self._need_sso()
        return self._auth_call(a.role_options)

    def sso_ous(self, role: str, fresh: bool = False) -> dict:
        a = self.auth() or self._need_sso()
        return self._auth_call(a.org_tree, role, fresh, status=502)

    def sso_choose(self, body: dict) -> dict:
        picks = body.get("accounts")
        if not isinstance(picks, list) or not picks:
            raise ConsoleError(400, "choose at least one account")
        chosen = self._auth_call((self.auth() or self._need_sso()).choose, picks)
        st = self.store()
        try:
            with st:
                for c in chosen:
                    if c["name"]:
                        st.name_account(c["account"], c["name"])
        finally:
            st.close()
        return {"chosen": chosen}

    def sso_sign_out(self, body: dict) -> dict:
        a = self.auth() or self._need_sso()
        a.sign_out()
        if a is self.keys:  # back to the SSO sign-in
            self.keys.state["active"] = False
            self.keys._save()
        return {"signed_in": False}

    # ------------------------------------------------------------------ reading an account (background jobs)
    def job_list(self) -> list[dict]:
        """The latest read of each account (all of them while an OU is read), newest first."""
        latest: dict[str, dict] = {}
        for j in sorted(self.jobs.values(), key=lambda j: -j["id"]):
            latest.setdefault(j["account"], j)
        return [{**j, "lines": j["lines"][-12:]} for j in list(latest.values())[:JOBS_SHOWN]]

    # A read asked for is written down, so a console restart (an upgrade, a reboot) carries on with it instead
    # of dropping it. Confirmed reads carry on reading; unconfirmed ones are priced again and wait for a yes.
    _reads_lock = threading.Lock()

    @staticmethod
    def _reads_file():
        import sg_ipintel
        import sg_store

        return sg_store.File(sg_ipintel.DATA_DIR / "reads-asked.json")

    def _reads(self) -> dict:
        try:
            got = json.loads(self._reads_file().read_text())
            return got if isinstance(got, dict) else {}
        except FileNotFoundError:
            return {}
        except Exception:  # noqa: BLE001 - unreadable: nothing to carry on with
            LOG.exception("reading the reads asked for")
            return {}

    def _read_asked(self, job: dict, confirmed: bool) -> None:
        try:
            with self._reads_lock:
                got = self._reads()
                got[job["account"]] = {"days": job["days"], "regions": job["regions"], "name": job.get("name", ""),
                                       "confirmed": confirmed, "at": time.time()}  # fmt: skip
                self._reads_file().write_text(json.dumps(got))
        except Exception:  # noqa: BLE001 - the read itself goes on
            LOG.exception("writing down the read of %s", job["account"])

    def _read_settled(self, job: dict) -> None:
        try:
            with self._reads_lock:
                got = self._reads()
                if got.pop(job["account"], None) is not None:
                    self._reads_file().write_text(json.dumps(got))
        except Exception:  # noqa: BLE001
            LOG.exception("settling the read of %s", job["account"])

    def resume_reads(self) -> list[dict]:
        """Carry on with the reads a restart interrupted. A confirmed one reads its hours still unread (never
        more than was agreed: what was read meanwhile is kept); an unconfirmed one is priced again."""
        asked = self._reads()
        jobs = []
        for account, a in asked.items():
            if time.time() - float(a.get("at") or 0) > RESUME_FOR:  # too old to be wanted still
                self._read_settled({"account": account})
                continue
            if any(j["account"] == account and j["status"] in ("starting", "running", "confirm", "queued") for j in self.jobs.values()):
                continue
            try:
                job = self.read_start({"account": account, "days": a.get("days"), "regions": a.get("regions") or "all"}, start=False)
            except ConsoleError as exc:
                LOG.warning("not carrying on with the read of %s: %s", account, exc)
                continue
            job["name"] = job["name"] or a.get("name", "")
            job["resume"] = bool(a.get("confirmed"))
            self._say(job, "carried on after the console restarted" + ("" if job["resume"] else ": priced again, waiting for a yes"))
            jobs.append(job)
        if not jobs:
            return []
        LOG.info("carrying on with %d read(s) the restart interrupted: %s", len(jobs), ", ".join(j["account"] for j in jobs))

        def one(job):
            self._prepare(job)
            if job["status"] == "confirm" and job["resume"]:
                job["status"] = "running"
                self._read_asked(job, True)
                self._run(job, self._job_extra[job["id"]])
            elif job["status"] not in ("confirm", "starting", "failed"):  # nothing left to read
                self._read_settled(job)

        def go():
            from concurrent.futures import ThreadPoolExecutor

            if not self._wait_unmetered(f"carrying on with {len(jobs)} read(s)"):
                return
            awake = _keep_awake()
            try:
                with ThreadPoolExecutor(max_workers=BATCH_WORKERS) as pool:
                    list(pool.map(one, jobs))
            finally:
                if awake:
                    awake.terminate()
            self.warm_reports()

        threading.Thread(target=go, daemon=True, name="resume-reads").start()
        return jobs

    def _job(self, body: dict) -> dict:
        try:
            job = self.jobs[int(body.get("id"))]
        except (TypeError, ValueError, KeyError):
            raise ConsoleError(404, "no such read")
        return job

    def _pref(self, key: str, default):
        try:
            st = self.store()
            try:
                return st.meta_get(key, default)
            finally:
                st.close()
        except Exception:  # noqa: BLE001 - the default
            return default

    def metered_hold(self) -> str:
        """Why reads wait now: on a phone hotspot with "Read only on Wi-Fi" on ('' when they may go)."""
        if not self._pref("wifi_only", False):
            return ""
        n = _network()
        return (f"on {n['why']}: reads wait for Wi-Fi (Settings, Data use, Read only on Wi-Fi)") if n["metered"] else ""

    def _refuse_metered(self) -> None:
        why = self.metered_hold()
        if why:
            raise ConsoleError(409, why)

    def _wait_unmetered(self, what: str, limit: float = 12 * 3600) -> bool:
        """Block a background read (a resume, the schedule) until off the hotspot; False when it never was."""
        said, t0 = False, time.time()
        while self.metered_hold():
            if not said:
                LOG.info("%s waits for Wi-Fi: on a metered connection", what)
                said = True
            if time.time() - t0 > limit:
                return False
            time.sleep(60)
        return True

    def read_start(self, body: dict, start: bool = True) -> dict:
        """Read an account: its security groups into the database, then plan the flow-log read and price it.
        Nothing is spent until ``read_confirm``."""
        account = _need(body, "account")
        try:
            days = int(body.get("days") or DEFAULT_DAYS)
        except (TypeError, ValueError):
            raise ConsoleError(400, "days is a number")
        import sg_review

        if days not in sg_review.READ_DAYS:
            raise ConsoleError(400, f"days must be one of {', '.join(map(str, sg_review.READ_DAYS))}")
        raw = body.get("regions") or "all"
        regions = raw if isinstance(raw, list) else [r.strip() for r in str(raw).split(",") if r.strip()]
        if any(j["account"] == account and j["status"] in ("starting", "running", "confirm") for j in self.jobs.values()):
            raise ConsoleError(409, f"{account} is already being read")
        if start:
            self._refuse_metered()
        jid = max(self.jobs, default=0) + 1
        name = next((c["name"] for c in (self.auth().chosen() if self.auth() else []) if c["account"] == account), "")
        job = {"id": jid, "account": account, "name": name, "days": days, "regions": regions, "status": "starting",
               "lines": [], "done": 0, "total": 0, "bytes": 0, "cost": None, "started": time.time()}  # fmt: skip
        self.jobs[jid] = job
        if start:
            self._read_asked(job, False)
            threading.Thread(target=self._prepare, args=(job,), daemon=True).start()
        return job if not start else dict(job)

    def _too_small(self, job: dict, sess) -> bool:
        """True (and the job skipped) when the account spent less than the batch's minimum in the last 30 days.
        An account whose spend cannot be read is read anyway."""
        import sg_review

        spend = job.get("spend")
        if spend is None:
            try:
                spend = sg_review.account_spend(sess.client("ce", region_name="us-east-1")).get(job["account"], 0.0)
                job["spend"] = spend
            except Exception as exc:  # noqa: BLE001 - no Cost Explorer rights in this account: read it anyway
                self._say(job, f"spend not known ({sg_review.describe_error(exc)[:120]}): read anyway")
                return False
        if spend >= job["min_spend"]:
            self._say(job, f"spent US${spend:,.2f} in the last {sg_review.SPEND_DAYS} days")
            return False
        job["status"] = "skipped"
        self._read_settled(job)
        self._say(job, f"skipped: spent US${spend:,.2f} in the last {sg_review.SPEND_DAYS} days, under "
                       f"US${job['min_spend']:,.0f}")  # fmt: skip
        return True

    def _say(self, job: dict, line: str) -> None:
        job["lines"] = (job["lines"] + [line])[-60:]
        self._rec("read", line, "error" if line.startswith("failed") else "info", job.get("account", ""),
                  job=job.get("id"), batch=job.get("batch"), status=job.get("status"))  # fmt: skip

    def _prepare(self, job: dict) -> None:
        import sg_assets
        import sg_review

        try:
            t = self.targets()  # not fresh: that signed in again (one STS call, under the lock) for every account
            sess = sg_review.SafeSession(t.session(job["account"]))  # its regions are read at once
            if self._priced_restore(job, sess):
                return
            if job.get("min_spend") and self._too_small(job, sess):
                self._priced_put(job)
                return
            regions = job["regions"]
            doc = sg_review.load(job["account"])  # loaded once
            if regions == ["all"] and job.get("flow_regions"):
                found = self._flow_regions(job["account"], "all", doc)
                if found != "all":
                    regions = job["regions"] = found
            if regions == ["all"]:
                ec2 = sess.client("ec2", region_name=sess.region_name or "us-east-1")
                regions = sorted(r["RegionName"] for r in ec2.describe_regions()["Regions"])
                self._say(job, f"{len(regions)} enabled regions")
            job["regions"] = regions
            if job["name"]:
                st = self.store()
                try:
                    with st:
                        st.name_account(job["account"], job["name"])
                finally:
                    st.close()

            def one(region):
                if self._batch_stopped(job):  # Stop pressed: the regions not yet started are not read
                    return
                st = self.store()  # a connection each: the regions are read at once
                try:
                    try:
                        ec2 = sess.client("ec2", region_name=region)
                        changes = sg_db.ensure_current(st, ec2, job["account"], region, t.actor, assets=True)
                        n = len(st.groups(job["account"], region))
                        n_assets = len(sg_assets.list_assets(st, job["account"], region))
                        used = len(self._in_use(st, job["account"], region) or {})
                        self._say(job, f"{region}: {used} security group(s) in use"
                                       + (f" ({n - used} on no interface, left out)" if n > used else "")
                                       + f", {n_assets} interface(s)"
                                       + (f", {len(changes)} changed outside the tool" if changes else ""))  # fmt: skip
                    except Exception as exc:  # noqa: BLE001 - one region out of reach must not stop the others
                        self._say(job, f"{region}: not read ({sg_review.describe_error(exc)[:200]})")
                finally:
                    st.close()

            sg_review.each_region(one, regions)
            now = time.time()
            doc = doc or sg_review.new_doc(job["account"], job["name"])
            doc["name"] = job["name"] or doc.get("name", "")
            tasks = sg_review.plan_read(sess, doc, regions, job["days"], now, say=lambda s: None)
            sg_review.save(doc)
            with_logs = [r for r in regions if (doc["regions"].get(r) or {}).get("query_sets")]
            if not tasks:
                job["status"] = "done"
                self._priced_put(job)
                self._read_settled(job)
                self._say(job, f"flow logs already read for the last {job['days']} day(s) in {', '.join(with_logs)}"
                          if with_logs else "no VPC flow logs in CloudWatch Logs in these regions: the security groups "
                          "are in the console, but there is no traffic to review (turn on VPC flow logs)")  # fmt: skip
                self._refused_cache.clear()
                return
            est = sg_review.estimate(doc, job["account"], with_logs, now)
            hours = sum(x[2] - x[1] for x in tasks) / 3600
            cost = est["rate"] * hours * 3600 / 1e9 * sg_review.INSIGHTS_PER_GB if est["rate"] is not None else None
            job.update(status="confirm", total=len(tasks), cost=None if cost is None else round(cost, 2), hours=round(hours),
                       logs_in=with_logs)  # fmt: skip
            # not the doc: an OU's worth of read caches kept while waiting for confirmation took over 16 GB
            self._job_extra[job["id"]] = {"sess": sess, "tasks": tasks, "now": now, "stop": threading.Event(),
                                          "hours_total": round(hours, 1)}  # fmt: skip
            del doc
            self._say(job, f"flow logs in {', '.join(with_logs)}: {len(tasks)} slice(s), {round(hours)} hours to read, "
                           + (f"about US${cost:.2f}" if cost is not None else "cost not known until a first 1-day read"))  # fmt: skip
            self._priced_put(job, self._job_extra[job["id"]])
        except Exception as exc:
            LOG.exception("reading %s failed", job["account"])
            job["status"] = "failed"
            self._say(job, f"failed: {sg_review.describe_error(exc) if hasattr(sg_review, 'describe_error') else exc}")

    def read_confirm(self, body: dict) -> dict:
        job = self._job(body)
        extra = self._job_extra.get(job["id"])
        if job["status"] != "confirm" or not extra:
            raise ConsoleError(409, "this read is not waiting for confirmation")
        self._refuse_metered()
        job["status"] = "running"
        self._read_asked(job, True)
        threading.Thread(target=self._run, args=(job, extra), daemon=True).start()
        return dict(job)

    def _run(self, job: dict, x: dict, first: tuple[int, int] = (0, 0)) -> None:
        """Read the job's slices. ``first`` is (slices, bytes) a first pass already read, so progress adds up."""
        import sg_review

        d0, b0 = first

        def progress(done, total, nbytes, secs=0):
            job.update(done=d0 + done, total=d0 + total, bytes=b0 + nbytes, secs=secs, hours_total=x.get("hours_total"))

        try:
            doc = sg_review.load(job["account"]) or sg_review.new_doc(job["account"], job.get("name", ""))
            state = sg_review.run_read(x["sess"], doc, x["tasks"], job["days"], x["now"], x["stop"].is_set, progress)
            del doc
            state = {"done": d0 + state["done"], "bytes": b0 + state["bytes"]}
            job.update(done=state["done"], bytes=state["bytes"])
            job["status"] = "stopped" if x["stop"].is_set() else "done"
            self._say(job, f"read {state['done']} of {len(x['tasks'])} slices, {state['bytes'] / 1e9:.2f} GB scanned, "
                           f"about US${state['bytes'] / 1e9 * sg_review.INSIGHTS_PER_GB:.2f}")  # fmt: skip
        except Exception as exc:
            LOG.exception("reading %s failed", job["account"])
            job["status"] = "failed"
            self._say(job, f"failed: {exc}")
        finally:
            self._job_extra.pop(job["id"], None)
            self._refused_cache.clear()
            self._read_settled(job)

    def read_stop(self, body: dict) -> dict:
        job = self._job(body)
        extra = self._job_extra.get(job["id"])
        if job["status"] == "confirm":
            self._job_extra.pop(job["id"], None)
            job["status"] = "cancelled"
            self._read_settled(job)
            self._say(job, "not read")
        elif extra:
            extra["stop"].set()
            job["stopping"] = True
            self._say(job, "stopping: cancelling the queries running now")
        return dict(job)

    # ------------------------------------------------------------------ reading many accounts at once (an OU)
    def batch_status(self) -> dict | None:
        b = self.batch
        if not b:
            return None
        jobs = [self.jobs[i] for i in b["jobs"] if i in self.jobs]
        count: dict[str, int] = {}
        for j in jobs:
            count[j["status"]] = count.get(j["status"], 0) + 1
        ready = [j for j in jobs if j["status"] in ("confirm", "queued", "running", "done", "stopped") and j.get("total")]
        costs = [j["cost"] for j in ready if j.get("cost") is not None]
        slices, done = sum(j.get("total") or 0 for j in ready), sum(j.get("done") or 0 for j in ready)
        now, eta = time.time(), None
        if b["status"] == "pricing":
            finished = len(jobs) - count.get("starting", 0)
            if finished:
                eta = (now - b["started"]) / finished * count.get("starting", 0)
        elif b["status"] == "running" and b.get("run_started"):
            gained = done - b.get("run_done0", 0)
            if gained > 0:
                eta = (now - b["run_started"]) / gained * (slices - done)
        if b["status"] in ("done", "stopped") and not b.get("forgotten"):
            b["forgotten"] = True
            self._batch_keep(None)
            self._priced_clear()
        return {"id": b["id"], "status": b["status"], "accounts": len(jobs), "count": count, "days": b["days"],
                "resumed": bool(b.get("resumed")),
                "min_spend": b.get("min_spend", 0), "spend_from": b.get("spend_from", ""),
                "eta": None if eta is None else round(eta), "elapsed": round(now - b.get("run_started", b["started"])),
                "regions": b["regions"], "started": b["started"], "cost": round(sum(costs), 2),
                "cost_unknown": len(ready) - len(costs), "to_read": len(ready),
                "read": sum(1 for j in ready if j["status"] == "done"),
                "slices": slices, "done": done,
                "bytes": sum(j.get("bytes") or 0 for j in jobs)}  # fmt: skip

    def read_all(self, body: dict) -> dict:
        """Price a read of many accounts (every one chosen, or those listed): their security groups go into
        the database, then one total for their flow logs. Nothing is spent until ``read_all_confirm``."""
        if self.batch and self.batch["status"] in ("pricing", "running"):
            raise ConsoleError(409, "a read of many accounts is already under way")
        self._refuse_metered()
        chosen = (self.auth().chosen() if self.auth() else [])
        want = body.get("accounts")
        accounts = [c["account"] for c in chosen if not want or c["account"] in set(want)]
        if not accounts:
            raise ConsoleError(400, "choose the accounts to read first")
        busy = {j["account"] for j in self.jobs.values() if j["status"] in ("starting", "running", "confirm", "queued")}
        jobs = [self.read_start({"account": a, "regions": body.get("regions") or "all", "days": body.get("days") or DEFAULT_DAYS},
                                start=False) for a in accounts if a not in busy]  # fmt: skip
        for j in jobs:  # narrowed to the regions with flow logs while it is prepared: loading every cache here hung the click
            j["flow_regions"] = True
        if not jobs:
            raise ConsoleError(409, "every one of these accounts is already being read")
        try:
            min_spend = max(0.0, float(body.get("min_spend") if body.get("min_spend") is not None else MIN_SPEND))
        except (TypeError, ValueError):
            raise ConsoleError(400, "min_spend is a number of US dollars a month")
        b = {"id": (self.batch["id"] if self.batch else 0) + 1, "status": "pricing", "jobs": [j["id"] for j in jobs],
             "days": jobs[0]["days"], "regions": jobs[0]["regions"], "started": time.time(), "stop": threading.Event(),
             "min_spend": min_spend, "spend_from": ""}  # fmt: skip
        ask_at = float(body.get("_resume_at") or time.time())
        keep = bool(self._pref("keep_prices", True))
        if not body.get("_resume_at"):
            self._priced_clear()  # a new read: prices kept for an earlier one are not used
        for j in jobs:
            j["batch"], j["min_spend"] = b["id"], min_spend
            j["resume_at"] = ask_at if keep else None
        self.batch = b
        self._batch_keep({"accounts": [j["account"] for j in jobs], "regions": body.get("regions") or "all",
                          "days": jobs[0]["days"], "min_spend": min_spend, "at": ask_at})
        threading.Thread(target=self._batch_price, args=(b, jobs), daemon=True).start()
        return self.batch_status()

    # A read of many accounts lives in this process: a restart (an upgrade, a crash) lost it, and the page went
    # back to "Read all" as if nothing had been asked. What was asked is kept in the database until it finishes
    # or is stopped, and a restarted console prices it again (spending still waits for a yes).
    BATCH_KEY = "batch_resume"

    def _batch_keep(self, ask: dict | None) -> None:
        try:
            st = self.store()
            try:
                with st:
                    st.meta_set(self.BATCH_KEY, json.dumps(ask) if ask else "")
            finally:
                st.close()
        except Exception as exc:  # noqa: BLE001 - only the resume after a restart is lost
            LOG.warning("read of many accounts not remembered: %s", exc)

    # The price of each account of that read is kept as it is worked out, so a restart does not price all of
    # them again (five minutes and tens of MB of AWS calls for 167 accounts): only those not reached are.
    PRICED_KEY = "batch_priced:"

    def _priced_put(self, job: dict, extra: dict | None = None) -> None:
        if not job.get("resume_at"):
            return
        v = {"at": job["resume_at"], "days": job["days"], "status": job["status"], "spend": job.get("spend"),
             "regions": job.get("regions"), "lines": job["lines"][-3:]}  # fmt: skip
        if extra:
            v.update(tasks=extra["tasks"], now=extra["now"], hours_total=extra.get("hours_total"), total=job.get("total"),
                     cost=job.get("cost"), hours=job.get("hours"), logs_in=job.get("logs_in"))  # fmt: skip
        try:
            st = self.store()
            try:
                with st:
                    st.meta_set(self.PRICED_KEY + job["account"], v)
            finally:
                st.close()
        except Exception as exc:  # noqa: BLE001 - priced again after a restart
            LOG.warning("price of %s not kept: %s", job["account"], exc)

    def _priced_get(self, job: dict) -> dict | None:
        if not job.get("resume_at"):
            return None
        v = self._pref(self.PRICED_KEY + job["account"], None)
        if not isinstance(v, dict) or v.get("at") != job["resume_at"] or v.get("days") != job["days"]:
            return None
        return v

    def _priced_clear(self) -> None:
        try:
            st = self.store()
            try:
                with st:
                    st.db.execute("DELETE FROM meta WHERE key LIKE ?", (self.PRICED_KEY + "%",))
            finally:
                st.close()
        except Exception as exc:  # noqa: BLE001 - left over prices are ignored (they name an older read)
            LOG.warning("kept prices not cleared: %s", exc)

    def _priced_restore(self, job: dict, sess) -> bool:
        """True when the job got back the price worked out before a restart."""
        v = self._priced_get(job)
        if not v or v["status"] not in ("skipped", "done", "confirm") or (v["status"] == "confirm" and not v.get("tasks")):
            return False
        job["spend"], job["regions"] = v.get("spend"), v.get("regions") or job["regions"]
        if v["status"] in ("skipped", "done"):
            job["status"] = v["status"]
            self._read_settled(job)
            for line in v.get("lines") or []:
                self._say(job, line)
            self._say(job, "(from before the console restarted)")
            return True
        tasks = [tuple(t) for t in v["tasks"]]
        job.update(status="confirm", total=v.get("total") or len(tasks), cost=v.get("cost"), hours=v.get("hours"),
                   logs_in=v.get("logs_in") or [])  # fmt: skip
        self._job_extra[job["id"]] = {"sess": sess, "tasks": tasks, "now": v["now"], "stop": threading.Event(),
                                      "hours_total": v.get("hours_total")}  # fmt: skip
        self._say(job, f"{len(tasks)} slice(s), about US${v['cost']:.2f}" if v.get("cost") is not None else f"{len(tasks)} slice(s)")
        self._say(job, "priced before the console restarted: kept, not priced again")
        return True

    def resume_batch(self) -> None:
        """After a restart: price again the read of many accounts that was under way (asked within 12 hours)."""
        try:
            st = self.store()
            try:
                ask = json.loads(st.meta_get(self.BATCH_KEY, "") or "null")
            finally:
                st.close()
        except Exception:  # noqa: BLE001 - nothing to resume
            return
        if not ask or time.time() - float(ask.get("at") or 0) > 12 * 3600:
            return
        for _ in range(60):  # the sign-in is read in the background at start
            try:
                if self.auth() and self.auth().chosen():
                    break
            except Exception:  # noqa: BLE001 - not signed in yet
                pass
            time.sleep(10)
        else:
            LOG.warning("read of many accounts not resumed: not signed in to AWS")
            return
        if not self._wait_unmetered("the read of many accounts a restart stopped"):
            return
        try:
            self.read_all({"accounts": ask["accounts"], "regions": ask["regions"], "days": ask["days"],
                           "min_spend": ask["min_spend"], "_resume_at": ask.get("at")})
            self.batch["resumed"] = True
            LOG.info("resumed the read of %d account(s) that a restart stopped", len(ask["accounts"]))
        except ConsoleError as exc:
            LOG.warning("read of many accounts not resumed: %s", exc)

    @staticmethod
    def _flow_regions(account: str, regions, doc: dict | None = None):
        """For "all": only the regions an earlier read found readable flow logs in, so reading an OU again does
        not walk every region of every account. Any other choice, or no earlier read, is left as it is."""
        import sg_review

        if regions != "all":
            return regions
        try:
            doc = doc or (sg_review.load(account) if account in sg_review.cached_accounts() else None)
        except Exception:  # noqa: BLE001 - an unreadable cache is read again in full
            doc = None
        found = sorted(r for r, x in ((doc or {}).get("regions") or {}).items() if x.get("query_sets"))
        return found or regions

    def _pool(self, b: dict, fn, items: list) -> None:
        from concurrent.futures import ThreadPoolExecutor

        def one(x):
            if not b["stop"].is_set():
                fn(x)

        with ThreadPoolExecutor(max_workers=BATCH_WORKERS) as pool:
            list(pool.map(one, items))

    def _batch_price(self, b: dict, jobs: list[dict]) -> None:
        if b["min_spend"]:
            try:  # one Cost Explorer read for the whole organisation, when the management account is in reach
                spend = self.auth().org_spend()
                b["spend_from"] = "organisation"
                for j in jobs:
                    j["spend"] = spend.get(j["account"], 0.0)  # an account with no cost at all is not listed
            except Exception as exc:  # noqa: BLE001 - each account is asked for its own instead
                LOG.warning("spend for the organisation: %s", exc)
                b["spend_from"] = "each account"
        self._pool(b, self._prepare, jobs)
        for j in jobs:
            if b["stop"].is_set() and j["status"] == "confirm":  # priced after Stop was pressed: not offered
                self._job_extra.pop(j["id"], None)
                j["status"] = "starting"
            if j["status"] == "starting":  # stopped before its turn
                j["status"] = "cancelled"
                self._say(j, "not read")
        b["status"] = "stopped" if b["stop"].is_set() else ("confirm" if any(j["status"] == "confirm" for j in jobs) else "done")
        self._rec_batch(b, jobs, "priced")

    def read_all_confirm(self, body: dict) -> dict:
        b = self.batch
        if not b or b["status"] != "confirm":
            raise ConsoleError(409, "no read of many accounts is waiting for confirmation")
        self._refuse_metered()
        self._priced_clear()  # confirmed reads carry on after a restart on their own (resume_reads)
        jobs = [self.jobs[i] for i in b["jobs"] if self.jobs[i]["status"] == "confirm" and self._job_extra.get(i)]
        for j in jobs:
            j["status"] = "queued"
            self._read_asked(j, True)
        b["status"], b["run_started"] = "running", time.time()
        b["run_done0"] = sum(j.get("done") or 0 for j in jobs)

        import sg_review

        first: dict[int, tuple[int, int]] = {}

        def recent(j):
            """First pass: the last day of every account, so every report fills in early."""
            x = self._job_extra.get(j["id"])
            if not x:
                return
            now, tasks = x["now"], x["tasks"]
            new = [t for t in tasks if t[1] >= now - FIRST_PASS]
            x["tasks"] = [t for t in tasks if t[1] < now - FIRST_PASS]
            if not new:
                return
            j["status"] = "running"
            try:
                doc = sg_review.load(j["account"]) or sg_review.new_doc(j["account"], j.get("name", ""))
                got = sg_review.run_read(x["sess"], doc, new, j["days"], now, x["stop"].is_set,
                                         lambda d, t, n, *_: j.update(done=d, total=len(tasks), bytes=n))  # fmt: skip
                del doc  # loaded for this pass only: holding every account's at once filled the memory
                first[j["id"]] = (got["done"], got["bytes"])
            except Exception:  # the second pass reads it again and reports the failure
                LOG.exception("first pass of %s failed", j["account"])
                x["tasks"] = tasks
            j["status"] = "queued"

        def run(j):
            x = self._job_extra.get(j["id"])
            if not x:
                return
            if not x["tasks"] and j["id"] in first:  # the first pass read it all
                d, n = first[j["id"]]
                j.update(done=d, total=d, bytes=n, status="stopped" if x["stop"].is_set() else "done")
                self._say(j, f"read {d} slices, {n / 1e9:.2f} GB scanned, about US${n / 1e9 * sg_review.INSIGHTS_PER_GB:.2f}")
                self._job_extra.pop(j["id"], None)
                self._refused_cache.clear()
                self._read_settled(j)
                return
            j["status"] = "running"
            self._run(j, self._job_extra[j["id"]], first.get(j["id"], (0, 0)))

        def go():
            awake = _keep_awake()
            try:
                self._pool(b, recent, jobs)
                self._pool(b, run, jobs)
            finally:
                if awake:
                    awake.terminate()
            for j in jobs:
                if j["status"] == "queued":
                    j["status"] = "cancelled"
                    self._job_extra.pop(j["id"], None)
                    self._read_settled(j)
                    self._say(j, "not read")
            b["status"] = "stopped" if b["stop"].is_set() else "done"
            self._rec_batch(b, jobs, "read")
            self.warm_reports()

        threading.Thread(target=go, daemon=True).start()
        return self.batch_status()

    def read_all_stop(self, body: dict) -> dict:
        b = self.batch
        if not b:
            raise ConsoleError(409, "no read of many accounts")
        b["stop"].set()
        for i in b["jobs"]:
            j, extra = self.jobs.get(i), self._job_extra.get(i)
            if not j:
                continue
            if j["status"] == "confirm":
                self._job_extra.pop(i, None)
                j["status"] = "cancelled"
                self._say(j, "not read")
            elif extra and j["status"] == "running":
                extra["stop"].set()
            elif j["status"] == "starting" and b["status"] == "pricing":  # not priced yet: say so now, not when
                j["status"] = "cancelled"                                 # the accounts being priced finish
                self._say(j, "not read")
        if b["status"] in ("confirm", "pricing"):  # pricing reads no flow logs: what is still finishing costs nothing
            b["status"] = "stopped"
        return self.batch_status()

    def _rec_batch(self, b: dict, jobs: list[dict], stage: str) -> None:
        count: dict[str, int] = {}
        for j in jobs:
            count[j["status"]] = count.get(j["status"], 0) + 1
        cost = sum(j.get("cost") or 0 for j in jobs if j["status"] in ("confirm", "done", "stopped"))
        self._rec("read", f"read of {len(jobs)} accounts {stage}: {b['status']} ("
                  + ", ".join(f"{v} {k}" for k, v in sorted(count.items())) + (f", about US${cost:.2f}" if cost else "") + ")",
                  "warning" if count.get("failed") else "info", batch=b.get("id"), count=count,
                  minutes=round((time.time() - b.get("started", time.time())) / 60, 1))  # fmt: skip

    def _batch_stopped(self, job: dict) -> bool:
        b = self.batch
        return bool(b and job.get("batch") == b["id"] and b["stop"].is_set())

    # ------------------------------------------------------------------ always running
    def autostart(self, body: dict) -> dict:
        if self.service is None:
            raise ConsoleError(400, "always running is not available here")
        on = bool(body.get("on"))
        if not on:
            st = self.service.status()
            self.service.uninstall(later=self.service.running_as_service)
            return {**st, "installed": False, "stopping": self.service.running_as_service}
        self.service.install()
        handover = not self.service.running_as_service and self.httpd is not None
        if handover:  # the background copy takes over this port once this one stops
            threading.Thread(target=self._hand_over, daemon=True).start()
        return {**self.service.status(), "handover": handover}

    def _hand_over(self) -> None:
        time.sleep(1.5)
        LOG.info("always running is on: this copy stops and the background one takes over the same address")
        self.httpd.shutdown()

    # ------------------------------------------------------------------ writes


    # ---- remediating an account: the plan, the proposal, the merge
    def _account_groups(self, account: str) -> tuple[dict, dict]:
        """Every region's groups (with the inbound and outbound rules AWS holds) and interfaces, for an account."""
        import sg_assets

        st = self.store()
        try:
            groups, assets = {}, {}
            for _, region in st.regions(account):
                gs = {}
                for gid, g in st.groups(account, region).items():
                    have = st.rules(account, region, gid, "synced")
                    gs[gid] = {**g, "in": {r: d for r, d in have.items() if r[0] == sg_db.IN},
                               "out": {r: d for r, d in have.items() if r[0] == sg_db.OUT}}  # fmt: skip
                groups[region] = gs
                assets[region] = sg_assets.list_assets(st, account, region)
            return groups, assets
        finally:
            st.close()

    def read_estimate(self) -> dict:
        """What a read of every account read before would cost in CloudWatch Logs Insights, for each look back,
        from the bytes per second each account's earlier reads scanned (what is already read is not read again),
        and what reads have cost so far."""
        import sg_review

        rows = [r for r in self._reports("estimate", "all", {}).values() if r]
        out = {}
        for days in sg_review.READ_DAYS:
            known = [r["cost"].get(str(days)) for r in rows if r["rate"] is not None and r["regions"]]
            nbytes = [(r.get("bytes") or {}).get(str(days)) for r in rows if r["rate"] is not None and r["regions"]]
            out[str(days)] = {"cost": round(sum(c or 0 for c in known), 2), "accounts": len(known),
                              "bytes": round(sum(b or 0 for b in nbytes))}
        return {"by_days": out, "per_gb": sg_review.INSIGHTS_PER_GB, "evidence_days": sg_review.EVIDENCE_DAYS,
                "spent": round(sum(r["spent"] for r in rows), 2), "default_days": DEFAULT_DAYS,
                "unknown": sum(1 for r in rows if r["rate"] is None and r["regions"])}

    def flow_accounts(self) -> list[dict]:
        """Every account in the console with whether its flow logs were read, how many days, or why not."""
        st = self.store()
        try:
            names = st.account_names()
            accounts = sorted({a for a, _ in st.regions()})
        finally:
            st.close()
        known = self._reports("flow", "all", {})
        never = {"status": sg_remediate.flow_status(None), "days": 0.0}
        return [{"account": a, "name": names.get(a, ""), **(known.get(a) or never)} for a in accounts]

    def remediation(self, account: str, days: int = sg_remediate.DEFAULT_DAYS, start: float | None = None,
                    end: float | None = None) -> dict:
        """The remediation of one account over its flow logs from ``start`` to ``end`` (epoch seconds), or the
        last ``days`` days of them."""
        if start is not None and end is not None and start >= end:
            raise ConsoleError(400, "the From date is after the To date")
        import sg_review

        try:
            mtime = sg_review.stamp(account)
        except KeyError:
            mtime = None
        if mtime is None:
            return {"status": "unknown", "days": days, "have_days": 0, "groups": [], "merges": [], "totals": {}}
        groups, assets = self._account_groups(account)
        # kept until the account's read or its groups change: building a plan takes seconds, opening it again none
        key = (account, int(days), start, end, mtime, hashlib.sha1(repr((groups, assets)).encode()).hexdigest(),
               PLAN_FORMAT, json.dumps(sg_review.tighten_prefs(), sort_keys=True))  # fmt: skip
        with self._report_lock:
            hit = self._plans.get(key)
        if hit is not None:
            return hit
        disk = hashlib.sha1(repr(key).encode()).hexdigest()
        out = _plan_kept(account, disk)  # built before, perhaps before a restart
        if out is None:
            with self._report_lock:
                pending = self._plan_pending.get(key)
                if pending is None:
                    if REPORTS_WAIT:
                        pending = _Done(_plan_job(account, days, groups, assets, start, end))
                    else:
                        if self._plan_pool is None:
                            import multiprocessing

                            # a fresh process for every plan: one of 15 million rows peaks near 8 GB, given back at once
                            self._plan_pool = multiprocessing.get_context("spawn").Pool(PLAN_PROCS, maxtasksperchild=1,
                                                                                        **_child_data_dir())  # fmt: skip
                        pending = self._plan_pool.apply_async(_plan_job, (account, days, groups, assets, start, end))
                    self._plan_pending[key] = pending
            try:
                out = pending.get(PLAN_TIMEOUT)
            except multiprocessing_timeout():
                raise ConsoleError(504, f"working out this account's plan is taking over {PLAN_TIMEOUT // 60} minutes "
                                        "(it has a very large number of flow-log rows); it carries on in the "
                                        "background, so open it again in a few minutes")  # fmt: skip
            finally:
                if pending.ready():
                    with self._report_lock:
                        self._plan_pending.pop(key, None)
            if out is None:
                return {"status": "unknown", "days": days, "have_days": 0, "groups": [], "merges": [], "totals": {}}
            _plan_keep(account, disk, out)
        with self._report_lock:
            self._plans[key] = out
            while len(self._plans) > 20:
                self._plans.pop(next(iter(self._plans)))
        return out

    def remediate(self, body: dict) -> dict:
        account = _need(body, "account")
        try:
            days = int(body.get("days") or sg_remediate.DEFAULT_DAYS)
        except (TypeError, ValueError):
            raise ConsoleError(400, "days is a number")
        import sg_review

        doc = sg_review.load(account)
        if not doc:
            raise ConsoleError(409, f"read {account}'s flow logs first: the plan comes from them")
        groups, assets = self._account_groups(account)
        start, end = _date_range(body.get("from"), body.get("to"))
        p = sg_remediate.plan(doc, days, groups, assets, start, end)
        st = self.store()
        try:
            made = sg_remediate.propose(st, account, p, groups, assets, list(body.get("groups") or []),
                                        list(body.get("merges") or []), self.actor(), str(body.get("ticket") or ""))  # fmt: skip
        except (sg_remediate.RemediateError, sg_db.Refused) as exc:
            raise ConsoleError(400, str(exc))
        finally:
            st.close()
        return {"requests": made}

    def block_propose(self, body: dict) -> dict:
        """Propose blocking an internet source at the network ACLs of the subnets it was reset in."""
        account, region, src = _need(body, "account"), _need(body, "region"), _need(body, "src")
        st = self.store()
        try:
            return sg_remediate.propose_block(st, account, region, src, list(body.get("subnets") or []), self.actor(),
                                              str(body.get("reason") or ""), str(body.get("ticket") or ""),
                                              body.get("detail") if isinstance(body.get("detail"), dict) else None)  # fmt: skip
        except sg_remediate.RemediateError as exc:
            raise ConsoleError(400, str(exc))
        finally:
            st.close()

    def block_apply(self, body: dict) -> dict:
        try:
            rid = int(body.get("id"))
        except (TypeError, ValueError):
            raise ConsoleError(400, "id is a request number")
        st = self.store()
        try:
            r = st._request(rid)
            t, ec2 = self._ec2(r["account"], r["region"])
            return sg_remediate.apply_block(st, ec2, r["account"], rid, t.actor)
        except sg_remediate.RemediateError as exc:
            raise ConsoleError(409, str(exc))
        finally:
            st.close()

    LB_METRICS = {"net": ("AWS/NetworkELB", (("TCP_Client_Reset_Count", "client"), ("TCP_ELB_Reset_Count", "lb"),
                                             ("TCP_Target_Reset_Count", "target"))),
                  "app": ("AWS/ApplicationELB", (("RejectedConnectionCount", "rejected"),
                                                 ("ClientTLSNegotiationErrorCount", "tls"), ("HTTPCode_ELB_5XX_Count", "elb5xx")))}  # fmt: skip

    def lb_metrics(self, account: str, days: int = 7) -> dict:
        """Each load balancer's resets as CloudWatch counts them, hourly for the last ``days``: for network load
        balancers the resets sent by clients, by the balancer and by targets; for application load balancers the
        connections rejected, failed TLS handshakes and the balancer's own 5xx. Cached ten minutes."""
        days = max(1, min(14, int(days)))
        key = (account, days)
        hit = self._lbm.get(key) if hasattr(self, "_lbm") else None
        if hit and time.time() - hit[0] < 600:
            return hit[1]
        import sg_review

        doc = sg_review.load(account)
        regions = sorted({r for r, x in (doc or {}).get("regions", {}).items()
                          if any(e.get("kind") == "load balancer" for e in ((x.get("snapshot") or {}).get("enis") or {}).values())})  # fmt: skip
        if not regions:
            return {"account": account, "lbs": [], "note": "no load balancers seen in its flow-log read"}
        sess = self.targets(fresh=True).session(account)
        end = int(time.time()) // 3600 * 3600
        start = end - days * 86400
        out, errors = [], []
        for region in regions:
            try:
                lbs = []
                for page in sess.client("elbv2", region_name=region).get_paginator("describe_load_balancers").paginate():
                    lbs += page.get("LoadBalancers", [])
                cw = sess.client("cloudwatch", region_name=region)
                lbs = [x for x in lbs if x.get("Type") in ("network", "application")]
                for i in range(0, len(lbs), 50):  # get_metric_data takes 500 queries; three metrics each
                    batch, qs = lbs[i : i + 50], []
                    for j, lb in enumerate(batch):
                        dim = lb["LoadBalancerArn"].split(":loadbalancer/", 1)[-1]
                        ns, mets = self.LB_METRICS["net" if lb["Type"] == "network" else "app"]
                        for k, (m, short) in enumerate(mets):
                            qs.append({"Id": f"m{j}_{k}", "Label": short, "ReturnData": True,
                                       "MetricStat": {"Metric": {"Namespace": ns, "MetricName": m,
                                                                 "Dimensions": [{"Name": "LoadBalancer", "Value": dim}]},
                                                      "Period": 3600, "Stat": "Sum"}})  # fmt: skip
                    got: dict[str, dict] = {}
                    for page in cw.get_paginator("get_metric_data").paginate(MetricDataQueries=qs, StartTime=start, EndTime=end):
                        for res in page.get("MetricDataResults", []):
                            d = got.setdefault(res["Id"], {})
                            for t, v in zip(res.get("Timestamps", []), res.get("Values", [])):
                                d[int(t.timestamp())] = d.get(int(t.timestamp()), 0) + v
                    for j, lb in enumerate(batch):
                        _, mets = self.LB_METRICS["net" if lb["Type"] == "network" else "app"]
                        series = {short: [int(got.get(f"m{j}_{k}", {}).get(t, 0)) for t in range(start, end, 3600)]
                                  for k, (_, short) in enumerate(mets)}  # fmt: skip
                        out.append({"name": lb["LoadBalancerName"], "type": "net" if lb["Type"] == "network" else "app",
                                    "region": region, "scheme": lb.get("Scheme", ""), "vpc": lb.get("VpcId", ""),
                                    "lb": lb["LoadBalancerArn"].split(":loadbalancer/", 1)[-1], "series": series,
                                    "total": {k: sum(v) for k, v in series.items()}})  # fmt: skip
            except Exception as exc:  # noqa: BLE001 - one region's failure leaves the others
                errors.append(f"{region}: {plain_error(exc)}")
        out.sort(key=lambda x: -sum(x["total"].values()))
        res = {"account": account, "days": days, "start": start, "step": 3600, "lbs": out, "errors": errors}
        if not hasattr(self, "_lbm"):
            self._lbm = {}
        self._lbm[key] = (time.time(), res)
        return res

    def merge_apply(self, body: dict) -> dict:
        try:
            rid = int(body.get("id"))
        except (TypeError, ValueError):
            raise ConsoleError(400, "id is a request number")
        st = self.store()
        try:
            r = st._request(rid)
            t, ec2 = self._ec2(r["account"], r["region"])
            return sg_remediate.apply_merge(st, ec2, r["account"], rid, t.actor)
        except sg_remediate.RemediateError as exc:
            raise ConsoleError(409, str(exc))
        finally:
            st.close()

    # ---- the engine's plan for an account: every inbound rule, old and new
    def verdicts(self, account: str, region: str = "") -> dict:
        """What the flow logs say each inbound rule should become, for one account (and region): the old rule, the
        new rule or rules (none to remove it), and how many addresses and ports that takes away. From the same
        reading as the review page; kept until the account is read again."""
        import sg_review

        try:
            mtime = sg_review.stamp(account)
        except KeyError:
            mtime = None
        if mtime is None:
            return {"read": False, "rules": [], "groups": {}}
        got = self._verdicts.get(account)
        if not got or got[0] != mtime:
            doc = sg_review.load(account)
            if not doc or not doc.get("chunks"):
                return {"read": False, "rules": [], "groups": {}}
            data = sg_review.build(doc, "24h", "", "", sg_review.load_names())  # the rules use the whole read, whatever the window
            rows = [_plan_rule(r) for r in data.get("rules") or []]
            got = (mtime, {"days": (data.get("summary") or {}).get("history_days"), "rules": rows})
            self._verdicts[account] = got
        rules = [r for r in got[1]["rules"] if not region or r["region"] == region]
        groups: dict = {}
        for r in rules:
            g = groups.setdefault(r["group"], {"tighten": 0, "remove": 0, "ports": 0, "keep": 0, "wait": 0, "cut": 0})
            g[r["action"]] = g.get(r["action"], 0) + 1
            g["cut"] += r["cut_addresses"]
        return {"read": True, "days": got[1]["days"], "rules": rules, "groups": groups}

    def tighten(self, body: dict) -> dict:
        """Propose the engine's plan as one change request: for each rule chosen (by ``keys``, or every rule in the
        ``groups`` given, or the whole account and region), remove the old rule and add the new ones."""
        account, region = _need(body, "account"), _need(body, "region")
        plan = self.verdicts(account, region)
        if not plan["read"]:
            raise ConsoleError(409, f"read {account}'s flow logs first: the plan comes from them")
        keys, groups = set(body.get("keys") or []), set(body.get("groups") or [])
        chosen = [r for r in plan["rules"] if r["action"] in ACTIONABLE
                  and (r["key"] in keys if keys else r["group"] in groups if groups else True)]  # fmt: skip
        if not chosen:
            raise ConsoleError(400, "nothing to change: the flow logs support every rule chosen as it is")
        changes = []
        for r in chosen:
            old = {"direction": "in", "proto": r["proto"], "from": r["from"], "to": r["to"], "source": r["source"],
                   "description": r["desc"]}  # fmt: skip
            changes.append({"group": r["group"], "op": "remove", "rule": old})
            for n in r["new"]:
                changes.append({"group": r["group"], "op": "add", "rule": {"direction": "in", **n, "description": r["desc"]}})
        cut = sum(r["cut_addresses"] for r in chosen)
        reason = str(body.get("reason") or "").strip() or (
            f"Tighten {len(chosen)} rule(s) to what {plan['days'] or '?'} days of VPC flow logs show in use "
            f"({cut:,} fewer IP addresses let in)")
        return {**self.propose({"account": account, "region": region, "changes": changes, "reason": reason,
                                "ticket": body.get("ticket") or ""}), "rules": len(chosen), "cut_addresses": cut}

    def propose(self, body: dict) -> dict:
        account, region = _need(body, "account"), _need(body, "region")
        changes = []
        for c in body.get("changes") or []:
            r = c.get("rule") or {}
            try:
                rule = (r["direction"], sg_db._proto(r["proto"]), int(r["from"]), int(r["to"]), str(r["source"]).strip())
            except (KeyError, TypeError, ValueError):
                raise ConsoleError(400, "each change needs a rule: direction, proto, from, to, source")
            if rule[0] not in (sg_db.IN, sg_db.OUT) or not rule[4]:
                raise ConsoleError(400, "direction is in or out, and source is required")
            if rule[1] == "-1":
                rule = (rule[0], "-1", -1, -1, rule[4])
            changes.append((_need(c, "group"), c.get("op"), rule, str(r.get("description") or "")))
        if not changes:
            raise ConsoleError(400, "no change given")
        actor = self.actor()
        st = self.store()
        try:
            with st:
                rid = st.propose(account, region, actor, str(body.get("reason") or ""), str(body.get("ticket") or ""),
                                 changes)  # fmt: skip
            return {"id": rid, "status": st._request(rid)["status"] if rid else "nothing to change"}
        finally:
            st.close()

    def decide(self, body: dict) -> dict:
        action = body.get("action")
        if action not in ("approve", "reject", "cancel"):
            raise ConsoleError(400, "action is approve, reject or cancel")
        try:
            rid = int(body.get("id"))
        except (TypeError, ValueError):
            raise ConsoleError(400, "id is a request number")
        actor = self.actor()
        st = self.store()
        try:
            with st:
                if action == "cancel":
                    st.cancel(rid, actor)
                else:
                    st.decide(rid, actor, action == "approve", str(body.get("note") or ""))
            return {"id": rid, "status": st._request(rid)["status"]}
        finally:
            st.close()

    def set_approvals(self, body: dict) -> dict:
        """Two-person approval on or off (audited). Off suits one person running the console on their own laptop."""
        on = bool(body.get("on"))
        reason = str(body.get("reason") or "").strip() or ("two-person approval from the console" if on else
                                                           "one person runs this console: the proposer may approve")  # fmt: skip
        st = self.store()
        try:
            with st:
                st.set_approvals(on, self.actor(), reason)
            return {"approvals": st.approvals()}
        except sg_db.Refused as exc:
            raise ConsoleError(400, str(exc))
        finally:
            st.close()

    def _ec2(self, account: str, region: str):
        t = self.targets(fresh=True)
        return t, t.session(account).client("ec2", region_name=region)

    def apply(self, body: dict) -> dict:
        account, region = _need(body, "account"), _need(body, "region")
        t, ec2 = self._ec2(account, region)
        st = self.store()
        try:
            res = sg_db.push(st, ec2, account, region, t.actor, body.get("group") or "",
                             str(body.get("reason") or "applied from the console"), str(body.get("ticket") or ""),
                             str(body.get("strategy") or "room"), self._hits(account, region))  # fmt: skip
            return res
        finally:
            st.close()

    def _hits(self, account: str, region: str) -> dict:
        """Flow-log use of each inbound rule, {sg_db.hit_key: (flows, last used)}, for apply's least-impact order.
        Rules whose interfaces are not all logged, or whose region's reading was cut short, have no entry (their
        use is unknown, so they go after rules known to carry little)."""
        try:
            rules = self.verdicts(account, region)["rules"]
        except Exception as exc:  # noqa: BLE001 - apply still runs, ranked by addresses alone
            LOG.warning("no flow-log hits for the apply order of %s: %s", account, exc)
            return {}
        return {f"{r['group']}|{r['proto']}|{r['from']}|{r['to']}|{r['source']}": (int(r.get("flows") or 0), r.get("last_used"))
                for r in rules if r.get("status") != "not logged" and not r.get("cut") and r.get("flows") is not None}

    def apply_preview(self, body: dict) -> dict:
        """What Apply would change, before it does: every rule added or removed, on which groups and how many
        interfaces, the change request it came from, and what the flow logs say about each rule removed (who
        used it, and whether the rules left still let those sources in). Nothing is sent to AWS."""
        account, region = _need(body, "account"), _need(body, "region")
        st = self.store()
        try:
            try:
                todo = st.pending(account, region, str(body.get("group") or ""), str(body.get("strategy") or "room"),
                                  hits := self._hits(account, region))
            except sg_db.Refused as exc:
                raise ConsoleError(400, str(exc)) from None
            over = st.over_limit(account, region, str(body.get("group") or ""))
            names = {g: v["name"] for g, v in st.groups(account, region).items()}
            assets = _assets_quiet(st, account, region)
            on: dict[str, list] = {}
            for a in assets:
                for g in a["groups"]:
                    on.setdefault(g, []).append(a)
            asked = st.requests("approved", account, region)
            wanted = {g: st.rules(account, region, g, "desired") for g in {c[0] for c in todo}}
            mode = st.mode(account)
        finally:
            st.close()
        try:
            plan = {r["key"]: r for r in self.verdicts(account, region)["rules"]}
        except Exception as exc:  # noqa: BLE001 - the preview still lists the changes without the evidence
            LOG.warning("no flow-log evidence for the apply preview of %s: %s", account, exc)
            plan = {}
        changes, at_risk = [], 0
        for gid, op, rule, desc in todo:
            d, proto, lo, hi, src = rule
            c = {"group": gid, "name": names.get(gid, ""), "op": op, "rule": sg_db._rule_json(rule, desc),
                 "text": sg_db.rule_text(rule), "interfaces": len(on.get(gid, [])),
                 "instances": sorted({a["instance"] or a["eni"] for a in on.get(gid, [])})[:8],
                 "requests": [{"id": q["id"], "reason": q["reason"], "ticket": q.get("ticket") or ""} for q in asked
                              if _asks(q, gid, op, rule)]}  # fmt: skip
            ev = plan.get(f"{region}|{gid}|{proto}|{lo}|{hi}|{src}") if op == "remove" and d == sg_db.IN else None
            if ev:
                left = wanted.get(gid) or {}
                lost = [x for x in ev.get("top") or [] if x and not any(_covers(r, x, proto, lo, hi) for r in left)]
                c["evidence"] = {"days": ev.get("days"), "sources": ev.get("seen", 0), "last_used": ev.get("last_used"),
                                 "action": ev.get("action"), "lost": lost}  # fmt: skip
                at_risk += bool(lost)
            if op == "add" and d == sg_db.IN:
                c["who"] = self._who(src, proto, lo, account)
            hit = hits.get(sg_db.hit_key(gid, rule)) if op == "remove" and d == sg_db.IN else None
            if hit:
                c["flows"] = hit[0]
            changes.append(c)
        enis = {a["eni"] for g in {c["group"] for c in changes} for a in on.get(g, [])}
        return {"account": account, "region": region, "mode": mode, "changes": changes, "over_limit": over,
                "strategy": str(body.get("strategy") or "room"), "limit": sg_db.rule_limit(),
                "summary": {"add": sum(c["op"] == "add" for c in changes), "remove": sum(c["op"] == "remove" for c in changes),
                            "groups": len({c["group"] for c in changes}), "interfaces": len(enis),
                            "known": bool(assets), "at_risk": at_risk}}  # fmt: skip

    def fix_refused(self, body: dict) -> dict:
        """For one refused source on one interface and port: everything known about it, and where a rule letting
        it in belongs. An existing group that already serves this port on that interface; a group on that interface
        alone; or, when every group there is shared and none serves the port, a group of its own (so the others are
        not opened too). Scans, threat lists and Tor exits are recommended to stay refused; a network ACL refusal is
        not a security group's to fix."""
        account, region = _need(body, "account"), _need(body, "region")
        eni, src = _need(body, "eni"), _need(body, "src")
        proto = PROTO_NAMES.get(str(body.get("proto")), str(body.get("proto") or ""))
        try:
            port = int(body.get("port"))
        except (TypeError, ValueError):
            raise ConsoleError(400, "port is a number")
        flags = {k: bool(body.get(k)) for k in ("scan", "threat", "tor", "internal")}
        by = str(body.get("by") or "")
        st = self.store()
        try:
            if not st.imported(account, region):
                raise ConsoleError(409, f"{account} {region} is not in the database yet: read it on the Overview first")
            groups = st.groups(account, region)
            assets = _assets_quiet(st, account, region)
            asset = next((a for a in assets if a["eni"] == eni), None)
            used: dict[str, int] = {}
            for a in assets:
                for g in a["groups"]:
                    used[g] = used.get(g, 0) + 1
            gids = (asset or {}).get("groups") or [g for g in body.get("groups") or [] if g in groups]
            info = []
            for g in gids:
                have = st.rules(account, region, g, "synced")
                serving = sorted({r[4] for r in have if r[0] == sg_db.IN and _port_in(r, proto, port)})
                info.append({"id": g, "name": (groups.get(g) or {}).get("name", ""), "vpc": (groups.get(g) or {}).get("vpc", ""),
                             "description": (groups.get(g) or {}).get("description", ""), "interfaces": used.get(g, 0),
                             "serves_port": bool(serving), "sources": serving[:12],
                             "lets_in": any(_covers(r, src, proto, port, port) for r in have)})  # fmt: skip
            broke = _broken_by(st, account, region, gids, src, proto, port)
            mine = next((a for a in assets if src.split("/")[0] in (a.get("ips") or [])), None)
            waiting = [q["id"] for q in st.requests("pending", account, region) + st.requests("approved", account, region)
                       if any(_asks(q, g, "add", None, src=src, proto=proto, port=port) for g in gids)]  # fmt: skip
        finally:
            st.close()
        same_vpc = mine and asset and mine.get("vpc_id") == asset.get("vpc_id") and mine.get("groups")
        if same_vpc:
            source, source_why = mine["groups"][0], (f"{src} is {mine['instance'] or mine['eni']}, in the same VPC: allowing its "
                                                     f"security group follows it if its IP address changes")  # fmt: skip
        else:
            source = src if "/" in src else src + ("/128" if ":" in src else "/32")
            source_why = f"just {src}, not its whole network"
        rule = {"direction": "in", "proto": proto, "from": port, "to": port, "source": source,
                "description": str(body.get("name") or src)[:200]}  # fmt: skip
        alts = [{"group": g["id"], "name": g["name"], "interfaces": g["interfaces"], "serves_port": g["serves_port"]}
                for g in sorted(info, key=lambda g: (not g["serves_port"], g["interfaces"]))]  # fmt: skip
        rec = _recommend(info, flags, by, broke, waiting, asset, proto, port, eni)
        return {"account": account, "region": region, "eni": eni, "src": src, "proto": proto, "port": port,
                "asset": asset, "groups": info, "broken_by": broke, "source_interface": mine, "rule": rule,
                "source_why": source_why, "recommend": rec, "alternatives": alts, "waiting": waiting}  # fmt: skip

    def check(self, body: dict) -> dict:
        """DryRun every call apply needs on every group in this region (and an asset swap): nothing changes."""
        import sg_assets

        account, region = _need(body, "account"), _need(body, "region")
        t, ec2 = self._ec2(account, region)
        st = self.store()
        try:
            sg_db.ensure_current(st, ec2, account, region, t.actor)
            assets = [a for a in sg_assets.list_assets(st, account, region) if not sg_assets.why_not_alone(a)][:1]
            res = sg_db.check_permissions(ec2, sorted(st.groups(account, region)), assets)
            with st:
                st.record_permissions(account, region, t.actor, res)
            return {"ok": not sg_db._permission_problems(res), "checked": len(res),
                    "problems": sg_db._permission_problems(res)[:20], "mode": st.mode(account)}  # fmt: skip
        finally:
            st.close()

    def asset_apply(self, body: dict) -> dict:
        import sg_assets

        try:
            rid = int(body.get("id"))
        except (TypeError, ValueError):
            raise ConsoleError(400, "id is a request number")
        st = self.store()
        try:
            r = st._request(rid)
            t, ec2 = self._ec2(r["account"], r["region"])
            return sg_assets.apply(st, ec2, r["account"], rid, t.actor)
        finally:
            st.close()

    def asset_revert(self, body: dict) -> dict:
        import sg_assets

        account, region, eni = _need(body, "account"), _need(body, "region"), _need(body, "eni")
        t, ec2 = self._ec2(account, region)
        st = self.store()
        try:
            return sg_assets.revert(st, ec2, account, region, eni, t.actor, str(body.get("reason") or ""))
        finally:
            st.close()

    def reconcile(self, body: dict) -> dict:
        account, region = _need(body, "account"), _need(body, "region")
        t, ec2 = self._ec2(account, region)
        st = self.store()
        try:
            who = sg_db._who_from_cloudtrail(t.session(account), region) if body.get("cloudtrail", True) else None
            changes = sg_db.ensure_current(st, ec2, account, region, t.actor, who, assets=True)
            return {"changes": changes, "pending": len(st.pending(account, region))}
        finally:
            st.close()

    def adopt(self, body: dict) -> dict:
        account, region = _need(body, "account"), _need(body, "region")
        actor = self.actor()
        st = self.store()
        try:
            with st:
                rid = st.propose(account, region, actor, str(body.get("reason") or ""), str(body.get("ticket") or ""),
                                 st.adoption(account, region, body.get("group") or ""))  # fmt: skip
            return {"id": rid, "status": st._request(rid)["status"] if rid else "nothing to adopt"}
        finally:
            st.close()


# ---------------------------------------------------------------------------------------------- always running
class Service:
    """Start the console at login and restart it if it stops: a launchd agent (macOS) or a systemd user
    service (Linux), running ``serve --service`` with the same port, database and data directory."""

    def __init__(self, cmd: list[str], running_as_service: bool = False, system: str | None = None, run=subprocess.run,
                 home: Path | None = None, src: Path | None = None):  # fmt: skip
        self.cmd = list(cmd)
        self.running_as_service = running_as_service
        self.system = system or platform.system()
        self._run = run
        self.home = home or Path.home()
        self.src = src or Path(__file__).resolve().parent
        self.pythonpath = ""

    @property
    def app_dir(self) -> Path:
        return self.home / ".sg-tightener" / "app"

    def needs_copy(self) -> bool:
        """macOS does not let a background program read Desktop, Documents, Downloads or iCloud Drive."""
        if self.system != "Darwin":
            return False
        src = self.src.resolve()
        return any(src == (self.home / p).resolve() or (self.home / p).resolve() in src.parents for p in PROTECTED)

    def bundle(self) -> None:
        """Copy the tool and the packages it runs on to ~/.sg-tightener/app, and run that copy with the base
        Python (a virtual environment in a protected folder cannot be read either)."""
        import importlib.metadata as md
        import re
        import shutil

        dest, tmp = self.app_dir, self.app_dir.with_name("app.new")
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.copytree(self.src / "assets", tmp / "assets")
        for f in self.src.glob("*.py"):
            shutil.copy2(f, tmp / f.name)
        seen, todo = set(), list(RUNTIME)
        while todo:
            name = todo.pop()
            key = name.lower().replace("_", "-")
            if key in seen:
                continue
            seen.add(key)
            try:
                dist = md.distribution(name)
            except md.PackageNotFoundError:
                continue
            todo += [re.split(r"[ <>=!;\[(~]", r, 1)[0] for r in dist.requires or [] if "extra ==" not in r]
            for f in dist.files or []:
                if f.parts[0] == ".." or f.suffix == ".pyc":
                    continue
                out = tmp / "lib" / f
                out.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(dist.locate_file(f), out)
        shutil.rmtree(dest, ignore_errors=True)
        tmp.rename(dest)
        base = Path(sys.base_prefix) / "bin" / f"python{sys.version_info[0]}.{sys.version_info[1]}"
        self.cmd[0] = str(base if base.exists() else Path(sys.executable))
        self.cmd[1] = str(dest / Path(self.cmd[1]).name)
        self.pythonpath = str(dest / "lib")

    @property
    def supported(self) -> bool:
        return self.system in ("Darwin", "Linux")

    @property
    def path(self) -> Path:
        if self.system == "Darwin":
            return self.home / "Library" / "LaunchAgents" / f"{LABEL}.plist"
        return self.home / ".config" / "systemd" / "user" / UNIT

    def status(self) -> dict:
        return {"supported": self.supported, "installed": self.supported and self.path.exists(), "copy": self.needs_copy(),
                "running_as_service": self.running_as_service, "system": self.system, "file": str(self.path)}

    def _env(self) -> dict:
        env = {k: os.environ[k] for k in PASS_ENV if os.environ.get(k)}
        env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
        if self.pythonpath:
            env["PYTHONPATH"] = self.pythonpath
        return env

    def content(self) -> bytes:
        log = str(self.home / ".sg-tightener" / "console.log")
        if self.system == "Darwin":
            # "Standard", not "Background": macOS keeps a background job on its slowest cores and throttles its
            # disk, which made every page the console builds about four times slower
            return plistlib.dumps({"Label": LABEL, "ProgramArguments": self.cmd, "RunAtLoad": True, "KeepAlive": True,
                                   "ThrottleInterval": 10, "StandardOutPath": log, "StandardErrorPath": log,
                                   "EnvironmentVariables": self._env(), "ProcessType": "Standard"})  # fmt: skip
        quote = lambda a: '"' + a.replace("\\", "\\\\").replace('"', '\\"') + '"'
        env = "".join(f"Environment={quote(f'{k}={v}')}\n" for k, v in self._env().items())
        return (f"[Unit]\nDescription=sg-tightener security group console\n\n[Service]\n"
                f"ExecStart={' '.join(quote(a) for a in self.cmd)}\n{env}Restart=always\nRestartSec=5\n\n"
                f"[Install]\nWantedBy=default.target\n").encode()  # fmt: skip

    def install(self) -> dict:
        if not self.supported:
            raise ConsoleError(400, f"always running is set up on macOS and Linux; on {self.system} start "
                                    "`sg_console.py serve` from Task Scheduler at log on")  # fmt: skip
        self.path.parent.mkdir(parents=True, exist_ok=True)
        (self.home / ".sg-tightener").mkdir(parents=True, exist_ok=True)
        if self.needs_copy():
            self.bundle()
        self.path.write_bytes(self.content())
        if self.system == "Darwin":
            target = f"gui/{os.getuid()}"
            self._run(["launchctl", "bootout", f"{target}/{LABEL}"], capture_output=True)
            # bootout returns before the old console has exited (its report workers take a few seconds), and
            # bootstrap fails with "Input/output error" until it has: try again for up to half a minute
            for _ in range(30):
                r = self._run(["launchctl", "bootstrap", target, str(self.path)], capture_output=True, text=True)
                if r.returncode == 0:
                    break
                time.sleep(1)
        else:
            self._run(["systemctl", "--user", "daemon-reload"], capture_output=True)
            r = self._run(["systemctl", "--user", "enable", "--now", UNIT], capture_output=True, text=True)
        if r.returncode != 0:
            raise ConsoleError(500, f"could not start the background console: {(r.stderr or r.stdout or '').strip()[:300]}")
        return self.status()

    def uninstall(self, later: bool = False) -> None:
        """Stop and remove it. ``later`` when this process is the service: it answers the page first."""
        if not self.supported:
            return

        def go():
            if later:
                time.sleep(1.0)
            if self.system == "Darwin":
                path = self.path
                if path.exists():
                    path.unlink()
                self._run(["launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"], capture_output=True)
            else:
                self._run(["systemctl", "--user", "disable", "--now", UNIT], capture_output=True)
                if self.path.exists():
                    self.path.unlink()
                self._run(["systemctl", "--user", "daemon-reload"], capture_output=True)

        if later:
            threading.Thread(target=go, daemon=True).start()
        else:
            go()


def token_file():
    import sg_ipintel
    import sg_store

    return sg_store.File(sg_ipintel.DATA_DIR / "console-token")


def lasting_token(new: bool = False) -> str:
    """The key the console's own page puts on every change (it never appears in the address), kept (in the
    database) so a page left open keeps working when the console restarts or hands over to the always-running copy."""
    import sg_store

    global _UNSAVED_TOKEN
    path = token_file()
    try:
        if not new:
            try:
                got = path.read_text().strip()
                if len(got) >= 24:
                    return got
            except OSError:
                pass
        tok = secrets.token_urlsafe(24)
        path.write_text(tok + "\n")
        return tok
    except sg_store.NotConfigured:  # the database is not running: this run's own key, kept once it starts
        _UNSAVED_TOKEN = _UNSAVED_TOKEN or secrets.token_urlsafe(24)
        return _UNSAVED_TOKEN


_UNSAVED_TOKEN = ""


def _keep_unsaved_token() -> None:
    global _UNSAVED_TOKEN
    if _UNSAVED_TOKEN:
        token_file().write_text(_UNSAVED_TOKEN + "\n")
        _UNSAVED_TOKEN = ""


def _database_down(exc: Exception) -> bool:
    """The database is not set up, not running, or went away mid-request."""
    import sg_store

    if isinstance(exc, sg_store.NotConfigured):
        return True
    try:
        import psycopg

        return isinstance(exc, psycopg.OperationalError)
    except ImportError:
        return False


def _need(body: dict, key: str) -> str:
    v = body.get(key)
    if not isinstance(v, str) or not v.strip():
        raise ConsoleError(400, f"{key} is required")
    return v.strip()


# ---------------------------------------------------------------------------------------------- HTTP
def make_handler(console: Console, token: str, port: int):
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    origins = {f"http://{h}" for h in hosts}

    class Handler(BaseHTTPRequestHandler):
        server_version = "sg-console"
        sys_version = ""

        def log_message(self, fmt, *a):  # requests are logged at debug only: URLs carry no secrets after login
            LOG.debug("%s %s", self.address_string(), fmt % a)

        # ---- auth
        def _same_site(self) -> bool:
            """Refuse what another web site makes the browser send (Fetch Metadata and Origin)."""
            if self.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
                return False
            origin = self.headers.get("Origin")
            return origin is None or origin in origins

        def _keyed(self) -> bool:
            return hmac.compare_digest(self.headers.get("X-SG-Token", ""), token)

        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in hosts  # refuses DNS rebinding

        def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
            try:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("X-Frame-Options", "DENY")
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):  # the page was closed or reloaded before the answer
                self.close_connection = True
                LOG.info("%s: the page left before the answer", self.path)

        def _json(self, status: int, obj):
            self._send(status, json.dumps(obj, default=str).encode(), "application/json")

        def _page(self, page: str | None = None):
            nonce = secrets.token_urlsafe(16)
            if page is None:
                page = ASSET.read_text(encoding="utf-8").replace("{{NONCE}}", nonce).replace("{{TOKEN}}", token)
            else:  # the sg_review page: its scripts are inline, so each gets the nonce
                page = page.replace("<script>", f'<script nonce="{nonce}">').replace("connect-src 'none'", "connect-src 'self'", 1)
            csp = (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'unsafe-inline'; connect-src 'self'; "
                   "img-src 'self' data: blob:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")  # fmt: skip
            self._send(200, page.encode(), "text/html; charset=utf-8", {"Content-Security-Policy": csp})

        # ---- routes
        def do_GET(self):
            t0 = time.time()
            try:
                return self._get()
            finally:
                secs = time.time() - t0
                path = urlparse(self.path).path
                if secs >= SLOW_GET and path != "/api/support/bundle":
                    console._rec("system", f"slow answer: {path} took {secs:.0f} s", "warning", path=path,
                                 seconds=round(secs, 1), query=urlparse(self.path).query[:300])  # fmt: skip

        def _get(self):
            if not self._host_ok():
                return self._send(421, b"wrong host", "text/plain")
            url = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            if url.path == "/" and "token" in q:  # an old bookmark: the address no longer needs a token
                return self._send(303, b"", "text/plain", {"Location": "/"})
            if url.path.startswith("/api/") and not self._same_site():
                return self._json(403, {"error": "requests from other sites are refused"})
            try:
                if url.path == "/":
                    return self._page()
                if url.path == "/review":
                    return self._page(console.review(_need(q, "account"), token))
                if url.path == "/api/database":
                    return self._json(200, console.database())
                if url.path == "/api/db-metrics":
                    return self._json(200, console.db_metrics())
                if url.path == "/api/state":
                    return self._json(200, console.state())
                if url.path == "/api/remediation":
                    return self._json(200, console.remediation(_need(q, "account"), int(q.get("days") or sg_remediate.DEFAULT_DAYS),
                                                               *_date_range(q.get("from"), q.get("to"))))  # fmt: skip
                if url.path == "/api/read/estimate":
                    return self._json(200, console.read_estimate())
                if url.path == "/api/flow-accounts":
                    return self._json(200, console.flow_accounts())
                if url.path == "/api/verdicts":
                    return self._json(200, console.verdicts(_need(q, "account"), str(q.get("region") or "")))
                if url.path == "/api/groups":
                    return self._json(200, console.groups(_need(q, "account"), _need(q, "region")))
                if url.path == "/api/assets":
                    return self._json(200, console.assets(_need(q, "account"), _need(q, "region")))
                if url.path == "/api/asset-history":
                    return self._json(200, console.asset_history(_need(q, "eni")))
                if url.path == "/api/profile":
                    return self._json(200, console.profile(_need(q, "account")))
                if url.path == "/api/drift":
                    return self._json(200, console.drift(_need(q, "account"), _need(q, "region")))
                if url.path == "/api/audit":
                    return self._json(200, console.audit(q))
                if url.path == "/api/requests":
                    return self._json(200, console.requests(q.get("status", "")))
                if url.path == "/api/macro":
                    return self._json(200, console.macro(q.get("range", "1m")))
                if url.path == "/api/lb-metrics":
                    return self._json(200, console.lb_metrics(_need(q, "account"), int(q.get("days") or 7)))
                if url.path == "/api/ip":
                    return self._json(200, console.ip_profile(_need(q, "ip"), q.get("proto", ""), q.get("port"),
                                                              q.get("account", "")))  # fmt: skip
                if url.path == "/api/refused":
                    return self._json(200, console.refused(q.get("range", "24h")))
                if url.path == "/api/sso":
                    return self._json(200, console.sso_status())
                if url.path == "/api/net-check":
                    return self._json(200, console.net_check())
                if url.path == "/api/sso/accounts":
                    return self._json(200, console.sso_accounts(q.get("fresh") == "1", q.get("roles") != "0"))
                if url.path == "/api/sso/roles":
                    return self._json(200, console.sso_roles())
                if url.path == "/api/sso/ous":
                    return self._json(200, console.sso_ous(q.get("role", ""), q.get("fresh") == "1"))
                if url.path == "/api/batch":
                    return self._json(200, console.batch_status())
                if url.path == "/api/schedule":
                    return self._json(200, console.schedule())
                if url.path == "/api/settings":
                    return self._json(200, console.settings())
                if url.path == "/api/tighten":
                    return self._json(200, console.tighten_prefs())
                if url.path == "/api/jobs":
                    return self._json(200, console.job_list())
                if url.path == "/api/health":
                    return self._json(200, console.health())
                if url.path == "/api/activity":
                    return self._json(200, console.activity(q))
                if url.path == "/api/support/bundle":
                    name, data = console.support_bundle()
                    return self._send(200, data, "application/zip", {"Content-Disposition": f'attachment; filename="{name}"'})
                return self._json(404, {"error": "not found"})
            except ConsoleError as exc:
                return self._json(exc.status, {"error": str(exc)})
            except Exception as exc:
                if _database_down(exc):
                    return self._json(503, {"error": f"the database is not running: {exc}", "database": False})
                LOG.exception("GET %s failed", url.path)
                return self._json(500, {"error": plain_error(exc)})

        def do_POST(self):
            if not self._host_ok():
                return self._send(421, b"wrong host", "text/plain")
            if not self._same_site() or not self._keyed():
                return self._json(403, {"error": "only the console's own page can make changes; reload it"})
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self._json(415, {"error": "JSON only"})
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                return self._json(413, {"error": "too large"})
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except ValueError as exc:
                return self._json(400, {"error": f"bad JSON: {exc}"})
            if not isinstance(body, dict):
                return self._json(400, {"error": "bad JSON: an object is expected"})
            route = {"/api/propose": console.propose, "/api/tighten": console.tighten, "/api/remediate": console.remediate, "/api/merge-apply": console.merge_apply, "/api/block": console.block_propose, "/api/block-apply": console.block_apply, "/api/decide": console.decide, "/api/approvals": console.set_approvals, "/api/apply": console.apply, "/api/apply-preview": console.apply_preview, "/api/refused-fix": console.fix_refused,
                     "/api/reconcile": console.reconcile, "/api/adopt": console.adopt, "/api/check": console.check,
                     "/api/profile": lambda body: console.profile(_need(body, "account"), read=True),
                     "/api/asset-apply": console.asset_apply, "/api/asset-revert": console.asset_revert,
                     "/api/sso/start": console.sso_start, "/api/sso/choose": console.sso_choose,
                     "/api/sso/signout": console.sso_sign_out, "/api/net-reset": console.net_reset, "/api/read": console.read_start,
                     "/api/read/confirm": console.read_confirm, "/api/read/stop": console.read_stop,
                     "/api/read/all": console.read_all, "/api/read/all/confirm": console.read_all_confirm, "/api/schedule": console.set_schedule,
                     "/api/reports/retry": console.reports_retry, "/api/tighten": console.set_tighten_prefs,
                     "/api/settings": console.set_settings, "/api/backup": console.backup_now, "/api/dsn-test": console.test_dsn,
                     "/api/read/all/stop": console.read_all_stop, "/api/keys/use": console.keys_use,
                     "/api/autostart": console.autostart,
                     "/api/database/start": console.database_start}.get(urlparse(self.path).path)  # fmt: skip
            if not route:
                return self._json(404, {"error": "not found"})
            path, t0 = urlparse(self.path).path, time.time()

            def rec(status: int, error: str = ""):
                if path in QUIET_POSTS and status < 400:
                    return
                console._rec("action", f"{ACTION_NAMES.get(path, path)}" + (f": {error}" if error else ""),
                             "info" if status < 400 else "warning" if status < 500 else "error",
                             str(body.get("account") or ""), path=path, status=status,
                             ms=round((time.time() - t0) * 1000), asked=_asked(body))  # fmt: skip

            try:
                out = route(body)
                rec(200)
                return self._json(200, out)
            except ConsoleError as exc:
                rec(exc.status, str(exc))
                return self._json(exc.status, {"error": str(exc)})
            except sg_db.Refused as exc:
                rec(409, str(exc))
                return self._json(409, {"error": str(exc)})
            except Exception as exc:
                if _database_down(exc):
                    rec(503, f"the database is not running: {exc}")
                    return self._json(503, {"error": f"the database is not running: {exc}", "database": False})
                LOG.exception("POST %s failed", self.path)
                rec(500, plain_error(exc))
                return self._json(500, {"error": plain_error(exc)})

    return Handler



PLAN_PROCS = 2  # remediation plans built at once, each in its own process
PLAN_TIMEOUT = 600  # a request waits this long for a plan; the build carries on after it


SLOW_GET = 20  # seconds: a page answer slower than this is noted in the activity log
QUIET_POSTS = {"/api/net-check"}  # asked by the page on its own: only a failure is worth a line
ACTION_NAMES = {
    "/api/propose": "proposed a change", "/api/tighten": "tighten plan", "/api/remediate": "remediation plan",
    "/api/merge-apply": "merged and applied", "/api/block": "proposed a block", "/api/block-apply": "applied a block",
    "/api/decide": "decided a change request", "/api/approvals": "two-person approval switched",
    "/api/apply": "applied changes in AWS", "/api/apply-preview": "previewed an apply",
    "/api/refused-fix": "let rejected traffic in", "/api/reconcile": "reconciled with AWS", "/api/adopt": "adopted AWS's rules",
    "/api/check": "checked permissions", "/api/profile": "read an account's profile", "/api/asset-apply": "changed an interface's groups",
    "/api/asset-revert": "reverted an interface's groups", "/api/sso/start": "started signing in to AWS",
    "/api/sso/choose": "chose accounts", "/api/sso/signout": "signed out of AWS", "/api/net-reset": "reset the network check",
    "/api/read": "read one account", "/api/read/confirm": "confirmed a read", "/api/read/stop": "stopped a read",
    "/api/read/all": "read many accounts", "/api/read/all/confirm": "confirmed reading many accounts",
    "/api/read/all/stop": "stopped reading many accounts", "/api/schedule": "changed the scheduled read",
    "/api/reports/retry": "retried reports", "/api/settings": "changed settings", "/api/backup": "backed up the database",
    "/api/dsn-test": "tested a database connection", "/api/keys/use": "signed in with keys on this computer",
    "/api/autostart": "switched Always running", "/api/database/start": "started the database",
}  # fmt: skip


def _asked(body: dict) -> dict:
    """What a request asked, small and with no secrets: which account, group and the like, not the rules."""
    keep = {}
    for k, v in body.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            keep[k] = v if not isinstance(v, str) else v[:200]
        elif isinstance(v, list):
            keep[k] = f"{len(v)} item(s)"
        elif isinstance(v, dict):
            keep[k] = f"{len(v)} field(s)"
    return keep


def multiprocessing_timeout():
    import multiprocessing

    return multiprocessing.TimeoutError


class _Done:
    """A finished result shaped like a pool's, for building in this process (tests)."""

    def __init__(self, value):
        self.value = value

    def get(self, timeout=None):
        return self.value

    def ready(self) -> bool:
        return True


def _child_init(data_dir: str, nice: bool = False) -> None:
    import sg_ipintel

    sg_ipintel.set_data_dir(data_dir)
    if nice:
        try:
            os.nice(15)  # background work: the person at the Mac comes first
        except OSError:
            pass


def _child_data_dir(nice: bool = False) -> dict:
    """Pool arguments that give a spawned process this console's data directory: a fresh process starts at the
    default one, so a console run with --data-dir built its plans and reports from the wrong account data."""
    import sg_ipintel

    return {"initializer": _child_init, "initargs": (str(sg_ipintel.DATA_DIR), nice)}


def _plan_job(account: str, days: int, groups: dict, assets: dict, start, end) -> dict | None:
    """One account's remediation plan, from its stored flow logs. A top-level function: it runs in its own process."""
    import sg_review

    doc = sg_review.load(account)
    if not doc:
        return None
    out = sg_remediate.plan(doc, int(days), groups, assets, start, end)
    out["account"], out["name"] = account, doc.get("name", "")
    return out


def _plan_file(account: str):
    import sg_ipintel
    import sg_store

    return sg_store.File(sg_ipintel.DATA_DIR / "plans" / f"{account}.json")


def _plan_kept(account: str, key: str) -> dict | None:
    """A plan kept for this account and exactly these inputs (its flow logs, groups and window), or None."""
    try:
        got = json.loads(_plan_file(account).read_text())
    except (FileNotFoundError, ValueError, OSError):
        return None
    except Exception:  # noqa: BLE001 - a cache: the plan is built again
        LOG.exception("reading the kept plan of %s", account)
        return None
    return got.get(key)


def _plan_keep(account: str, key: str, out: dict) -> None:
    """Keep the account's last few plans, so a restart or another window does not build them again."""
    try:
        try:
            got = json.loads(_plan_file(account).read_text())
        except (FileNotFoundError, ValueError):
            got = {}
        got[key] = out
        while len(got) > 4:
            got.pop(next(iter(got)))
        _plan_file(account).write_text(json.dumps(got, default=str))
    except Exception:  # noqa: BLE001 - a cache: nothing is lost but time
        LOG.exception("keeping the plan of %s", account)


def plain_error(exc: BaseException) -> str:
    """What went wrong, in words someone can act on, for a request that failed unexpectedly."""
    import sg_tightener

    hint = sg_tightener.login_hint(exc)
    if hint:
        return f"Your AWS sign-in has run out or was not accepted: sign in again on the Overview. ({hint})"
    names = {k.__name__ for k in type(exc).__mro__}
    resp = getattr(exc, "response", None)
    code = (resp or {}).get("Error", {}).get("Code", "") if isinstance(resp, dict) else ""
    msg = (resp or {}).get("Error", {}).get("Message", "") if isinstance(resp, dict) else ""
    if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError"):
        return f"The role used in this account is not allowed to do this ({code}): {msg or exc}"
    if code in ("Throttling", "ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded"):
        return f"AWS is limiting how fast this account can be asked ({code}): wait a minute and try again."
    if names & {"EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError", "ConnectionClosedError"}:
        return f"AWS could not be reached ({type(exc).__name__}): check the network or VPN, then try again."
    if code:
        return f"AWS refused this ({code}): {msg or exc}"
    return f"Something went wrong here ({type(exc).__name__}: {exc}). The details are on Support → Activity log, and in ~/.sg-tightener/console.log."


ACTIONABLE = sg_remediate.ACTIONABLE
_port_ranges = sg_remediate.port_ranges
_plan_rule = sg_remediate.plan_rule

PROTO_NAMES = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6", "-1": "-1", "tcp": "tcp", "udp": "udp"}


def _when(t) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(t)) if t else "?"


def _port_text(p: dict) -> str:
    return f"{p['port']}" if p["proto"] in ("tcp", "udp") else p["proto"]


def _ip_answers(ip, private, intel, ours, seen, port, account, names, building: int = 0) -> list[dict]:
    """The questions asked before letting an address in, answered from what the estate knows: [{q, a, tone}], tone
    good | warn | bad | info."""
    out = []

    def say(q, a, tone="info"):
        out.append({"q": q, "a": a, "tone": tone})

    def acct(a):
        return f"{names.get(a) or a} ({a})" if names.get(a) else a

    if ours:
        o = ours[0]
        say("Whose is it?", f"Ours: {o['kind'] or 'interface'} {o['instance'] or o['eni']}"
            + (f" \u201c{o['name']}\u201d" if o["name"] else "") + f" in {acct(o['account'])}, {o['region']}"
            + (f"; groups {', '.join(o['groups'])}" if o["groups"] else "")
            + (f" (and {len(ours) - 1} more interface(s) with this address in other accounts or VPCs)" if len(ours) > 1 else ""),
            "good")  # fmt: skip
    elif private:
        say("Whose is it?", "A private address inside our networks (not the internet, so no AS number or company), "
            "but none of the interfaces read in any account: on premises, another network over Direct Connect, VPN or "
            "transit gateway, an interface in an account not read yet, or one since deleted.", "warn")
    elif intel.get("kind") == "aws":
        say("Whose is it?", f"{intel.get('name')} (AWS publishes {intel.get('prefix', '')} for {intel.get('service', '')}). "
            "Not one of our accounts' interfaces: another AWS customer's, or an AWS service.", "info")
    else:
        asn = f"AS{intel['asn']} {intel.get('owner', '')}".strip() if intel.get("asn") else "no AS number on the lists"
        say("Whose is it?", f"{intel.get('name') or ip}: {asn}" + (f", {intel['country']}" if intel.get("country") else "")
            + (f", block {intel['block']}" if intel.get("block") else "") + ".", "info")
    if intel.get("threat") or intel.get("group") in ("threat", "anon"):
        say("Is it on a threat list or Tor?", intel.get("what") or intel.get("threat") or "Yes", "bad")
    elif not private:
        say("Is it on a threat list or Tor?", "No: not on the threat lists or the Tor exit list read.", "good")
    if account and (ours or private):
        mine = [o for o in ours if o["account"] == account]
        if mine:
            say("Is it in this account?", f"Yes: {acct(account)}, {mine[0]['region']}"
                + (f", VPC {mine[0]['vpc']}" if mine[0].get("vpc") else "") + ".", "info")
        elif ours:
            say("Is it in this account?", "No: it is in " + ", ".join(sorted({acct(o["account"]) for o in ours}))
                + ". The same private address can exist in several VPCs, so check the routes between them.", "warn")
        else:
            say("Is it in this account?", f"Not found in {acct(account)} or any other account read.", "warn")
    os_ = sorted({o["os"] for o in ours if o["os"]})
    say("What operating system?", ", ".join(os_) + f" ({ours[0].get('type') or 'instance'})" if os_ else
        ("Not an EC2 instance: " + (ours[0]["kind"] or "a network interface") + (f" ({ours[0]['desc']})" if ours[0]["desc"] else "")
         + ". Only EC2 instances report an operating system." if ours else
         "Unknown: only our own EC2 instances report one. Nothing is probed or scanned: this tool only reads."),
        "info")  # fmt: skip
    made = [o for o in ours if o.get("launched")]
    if made:
        o = min(made, key=lambda o: o["launched"])
        say("When was it created?", f"Instance {o['instance']} launched {_when(o['launched'])}"
            + (f" from image {o['image']}" if o.get("image") else "") + ".", "info")
    elif ours:
        say("When was it created?", "Not known: the account was read before launch times were kept (read it again)."
            if any(o["instance"] for o in ours) else "Not known: AWS gives a launch time for EC2 instances only, and this "
            "interface is not one.", "info")
    if port:
        say("What port is it asking for?", f"{port['port']}/{port['proto']}: {port['svc']} ({port['name']})"
            + (". A database port: only its own application tier and admin hosts should reach it." if port["database"]
               else ". " + port["why"] if port.get("why") and not (private and "internet" in port["why"]) else
               ". The source is a private address inside our networks, not the internet." if private else ""),
            "bad" if port["risky"] else "info")  # fmt: skip
    scans = [r for r in seen if r["scan"]]
    if scans:
        r = max(scans, key=lambda r: r["ports_refused"])
        others = [x for x in scans if x["account"] != r["account"]]
        say("Has it scanned?", f"Yes: {r['ports_refused']} ports refused on {r['addresses']} addresses in "
            f"{acct(r['account'])}" + (": also " + "; ".join(f"{x['ports_refused']} ports on {x['addresses']} addresses in "
                                                              f"{acct(x['account'])}" for x in others[:3])
                                        + (f" and {len(others) - 3} more account(s)" if len(others) > 3 else "")
                                        if others else ", and no other account") + ".", "bad")  # fmt: skip
    elif seen:
        most = max(r["ports_refused"] for r in seen)
        say("Has it scanned?", f"No: at most {most} port(s) refused in any account." if most else "No: nothing refused in any account.", "good")
    if not seen:
        say("Have we seen it before?", f"Not known yet: {building} account(s) are still being added to the address book; "
            "look again in a few minutes." if building else "Never: in no account's flow logs read so far.", "warn")
    else:
        first, last = min(r["first"] for r in seen), max(r["last"] for r in seen)
        say("Have we seen it before?", f"Yes, in {len(seen)} account(s): first {_when(first)}, last {_when(last)}.", "info")
        other = " other" if account else ""
        homes = {o["account"] for o in ours}
        reuse = (" Private addresses repeat across VPCs: in an account other than "
                 + (", ".join(acct(a) for a in sorted(homes)) if homes else "its own") + " it may be a different host."
                 if private and any(r["account"] not in homes for r in seen) else "")  # fmt: skip
        let = [r for r in seen if r["let_in"] and r["account"] != account]
        if let:
            top = ", ".join(f"{acct(r['account'])} on " + ", ".join(_port_text(p) for p in r["ports"] if p["let_in"])[:60]
                            for r in let[:3])  # fmt: skip
            say("Is it already let in elsewhere?", f"Yes, {len(let)}{other} account(s): {top}"
                + (f" and {len(let) - 3} more" if len(let) > 3 else "") + "." + reuse, "good")
        else:
            say("Is it already let in elsewhere?", f"No{other} account lets it in." + reuse, "warn")
        talk = [r for r in seen if r["replies"]]
        if talk:
            say("Do our hosts connect to it?", f"Yes, from {len(talk)} account(s): "
                + ", ".join(acct(r["account"]) for r in talk[:3]) + (f" and {len(talk) - 3} more" if len(talk) > 3 else "")
                + " (it answered their connections).", "info")  # fmt: skip
        ref = [r for r in seen if r["refused"] and r["account"] != account]
        if ref:
            say("Is it refused elsewhere?", f"Yes, {len(ref)}{other} account(s): "
                + ", ".join(acct(r["account"]) for r in ref[:3]) + (f" and {len(ref) - 3} more" if len(ref) > 3 else "") + ".", "info")
    return out


def _assets_quiet(st, account: str, region: str) -> list[dict]:
    import sg_assets

    try:
        return sg_assets.list_assets(st, account, region)
    except Exception as exc:  # noqa: BLE001 - shown without the interfaces rather than not at all
        LOG.warning("interfaces of %s %s not read: %s", account, region, exc)
        return []


def _port_in(rule, proto: str, port: int) -> bool:
    _d, p, lo, hi, _s = rule
    return p == "-1" or (p == proto and (lo == -1 or lo <= port <= hi))


def _covers(rule, src: str, proto: str, lo: int, hi: int) -> bool:
    """Does an inbound ``rule`` let ``src`` (an address or CIDR) in on every port from lo to hi? A rule naming a
    security group or prefix list cannot be checked from an address, so it is not counted as covering."""
    import ipaddress

    d, p, rlo, rhi, source = rule
    if d != sg_db.IN or not (p == "-1" or (p == proto and (rlo == -1 or (rlo <= lo and hi <= rhi)))):
        return False
    try:
        net, ip = ipaddress.ip_network(source, strict=False), ipaddress.ip_network(src, strict=False)
    except ValueError:
        return False
    return net.version == ip.version and ip.subnet_of(net)


def _asks(q: dict, gid: str, op: str, rule, src: str = "", proto: str = "", port: int = 0) -> bool:
    """Does change request ``q`` ask for ``op`` of ``rule`` on ``gid`` (or, with ``src``, add a rule letting src in
    on proto/port there)?"""
    if not isinstance(q.get("changes"), list):
        return False
    for c in q["changes"]:
        if c.get("group") != gid or c.get("op") != op:
            continue
        r = c.get("rule") or {}
        try:
            t = sg_db._rule_tuple(r)
        except KeyError:
            continue
        if rule is not None and t == rule:
            return True
        if rule is None and src and (_covers(t, src, proto, port, port) or t[4] == src):
            return True
    return False


def _broken_by(st, account: str, region: str, gids: list[str], src: str, proto: str, port: int) -> list[dict]:
    """Changes in the audit trail that took away a rule letting ``src`` in on this port, on these groups:
    applied by this tool or made in AWS outside it. Newest first."""
    out, done = [], st.requests("applied", account, region)
    for g in gids:
        for e in st.log(account, region, g, limit=200):
            if e["action"] not in ("applied", "rules-changed") or e["origin"] not in ("apply", "external"):
                continue
            gone = [r for r in (e["detail"] or {}).get("removed") or []
                    if _covers(sg_db._rule_tuple(r), src, proto, port, port)]
            if gone:
                asked = [{"id": q["id"], "reason": q["reason"], "ticket": q.get("ticket") or "", "proposer": q.get("proposer", "")}
                         for q in done if any(_asks(q, g, "remove", sg_db._rule_tuple(r)) for r in gone)]  # the request behind it
                out.append({"at": e["at"], "group": g, "origin": e["origin"], "actor": e["actor"], "reason": e["reason"],
                            "ticket": e["ticket"], "requests": asked,
                            "removed": [sg_db.rule_text(sg_db._rule_tuple(r)) for r in gone]})  # fmt: skip
    return sorted(out, key=lambda x: x["at"], reverse=True)[:5]


def _recommend(info, flags, by, broke, waiting, asset, proto, port, eni) -> dict:
    """Where a rule letting this source in belongs, in words: ``kind`` is keep (leave it refused), nacl, done,
    waiting, add (to ``group``) or own (a group of its own for the interface)."""
    if flags["threat"] or flags["tor"]:
        return {"kind": "keep", "why": "It is on a threat list or a Tor exit: keep refusing it. Nothing should open a "
                                       "port to it."}  # fmt: skip
    if flags["scan"]:
        return {"kind": "keep", "why": "It swept many ports or addresses: that is a scan, and refusing it is the "
                                       "security group doing its job." + (" A scan from inside your network is worth "
                                       "finding out about." if flags["internal"] else "")}  # fmt: skip
    if by.startswith("Network ACL"):
        return {"kind": "nacl", "why": f"{by} refuses it, before any security group sees it: a security group rule "
                                       "would not let it in. Change the network ACL if it is wanted."}  # fmt: skip
    if any(g["lets_in"] for g in info):
        g = next(g for g in info if g["lets_in"])
        return {"kind": "done", "group": g["id"], "why": f"{g['name'] or g['id']} lets it in now: a rule was added "
                                                         "since it was refused. Nothing to do."}  # fmt: skip
    if waiting:
        return {"kind": "waiting", "why": f"Change request {', '.join('#' + str(i) for i in waiting)} already lets it in, "
                                          "once approved and applied."}  # fmt: skip
    if not info:
        return {"kind": "unknown", "why": f"{eni} is not among the interfaces read for this account: refresh it from "
                                          "AWS, then look again."}  # fmt: skip
    if broke:
        b = next((g for g in info if g["id"] == broke[0]["group"]), None)
        if b:
            return {"kind": "add", "group": b["id"], "why": f"It was let in until {broke[0]['removed'][0]} was removed "
                                                            f"from {b['name'] or b['id']}: put it back there, for this "
                                                            "source only."}  # fmt: skip
    serving = sorted((g for g in info if g["serves_port"]), key=lambda g: g["interfaces"])
    if serving:
        g = serving[0]
        return {"kind": "add", "group": g["id"], "why": f"{g['name'] or g['id']} already lets others in on {proto} {port}"
                                                        f" to this interface: it is the group for that service"
                                                        + (f" (on {g['interfaces']} interfaces, which all serve it)" if g["interfaces"] > 1 else "")
                                                        + "."}  # fmt: skip
    alone = sorted((g for g in info if g["interfaces"] <= 1), key=lambda g: g["name"] == "default")
    if alone:
        g = alone[0]
        return {"kind": "add", "group": g["id"], "why": f"{g['name'] or g['id']} is on this interface only, so the new "
                                                        "rule opens nothing else."}  # fmt: skip
    fewest = min(info, key=lambda g: g["interfaces"])
    import sg_assets

    managed = sg_assets.why_not_alone(asset) if asset else ""
    if managed:
        return {"kind": "add", "group": fewest["id"], "why": f"This interface cannot get a group of its own ({managed}): "
                                                             f"{fewest['name'] or fewest['id']} is shared by "
                                                             f"{fewest['interfaces']} interfaces, which all get the rule."}  # fmt: skip
    return {"kind": "own", "group": fewest["id"],
            "why": f"Every group on this interface is shared (the least by {fewest['interfaces']} interfaces) and none lets "
                   f"anything in on {proto} {port}: adding it to one would open {proto} {port} on all of them. Give this "
                   f"interface a group of its own for it.",
            "command": f"python sg_db.py asset-plan --eni {eni} --approved approved.json, then asset-propose; once it is "
                       f"applied, add this rule to its new group (sgt-{eni}-…)"}



def serve(console: Console, port: int = 8765, token: str | None = None) -> tuple[ThreadingHTTPServer, str]:
    token = token or secrets.token_urlsafe(24)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(console, token, port))
    if os.environ.get("SG_NO_WARM") != "1":
        threading.Thread(target=console.warm, daemon=True, name="warm-reports").start()
    console.load_saved_procs()
    if os.environ.get("SG_NO_SCHEDULE") != "1" and os.environ.get("SG_NO_WARM") != "1":
        threading.Thread(target=console.resume_batch, daemon=True, name="resume-read").start()
    if os.environ.get("SG_NO_SCHEDULE") != "1" and os.environ.get("SG_NO_WARM") != "1":
        threading.Thread(target=console.scheduler, daemon=True, name="scheduled-reads").start()
    httpd.daemon_threads = True
    return httpd, token


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sg_console.py", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the console on 127.0.0.1")
    i = sub.add_parser("install", help="always running: start the console at login and restart it if it stops")
    for q in (s, i):
        q.add_argument("--port", type=int, default=8765)
        q.add_argument("--db", help=f"PostgreSQL connection string (default ${sg_db.DB_ENV}, else sg_store.py setup's database)")
        q.add_argument("--role-name", default=sg_db.DEFAULT_ROLE, help="role assumed in other accounts to apply and reconcile")
        q.add_argument("--external-id", default="")
        q.add_argument("--data-dir", help="a separate set of reads and caches (its own database schema; default ~/.sg-tightener)")
        add_profile_arg(q)
    s.add_argument("--service", action="store_true", help=argparse.SUPPRESS)  # run by launchd / systemd
    s.add_argument("--new-token", action="store_true", help="make a new page key (pages already open must be reloaded)")
    s.add_argument("--no-browser", action="store_true", help="do not open the browser")
    sub.add_parser("uninstall", help="stop running the console in the background")
    o = sub.add_parser("open", help="open the console in the browser")
    o.add_argument("--port", type=int, default=8765)
    o.add_argument("--data-dir", help=argparse.SUPPRESS)
    d = sub.add_parser("doctor", help="check everything the console needs, even when it does not start, and say how to fix what is wrong")
    b = sub.add_parser("support", help="write a support bundle (health, settings, activity log, the end of the log; secrets taken out)")
    b.add_argument("--out", help="where to write the zip (default: the current folder)")
    for q in (d, b):
        q.add_argument("--port", type=int, default=8765)
        q.add_argument("--db", help=argparse.SUPPRESS)
        q.add_argument("--data-dir", help="the data folder to look at (default ~/.sg-tightener)")
    return p


def _get_running(port: int, path: str, timeout: float = 30) -> tuple[int, bytes]:
    """(status, body) of a GET to the console on this computer; (0, why) when nothing answers."""
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=timeout) as r:  # noqa: S310 - loopback
            return r.status, r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except Exception as exc:  # noqa: BLE001
        return 0, str(exc).encode()


def doctor(port: int = 8765, db: str | None = None, out=None) -> int:
    """Check, in order, what the console needs, print each with how to fix it; 0 when nothing is wrong."""
    import importlib
    import shutil

    import sg_ipintel
    import sg_journal
    import sg_store

    out = out or sys.stdout
    bad = 0

    def line(ok, name, value, fix=""):
        nonlocal bad
        mark = {True: "ok  ", False: "FAIL", None: "note"}[ok]
        bad += ok is False
        print(f"  {mark}  {name:<24} {value}", file=out)
        if fix and ok is not True:
            print(f"        {'':<24} → {fix}", file=out)

    print("sg-tightener doctor\n", file=out)
    v = sys.version_info
    line(v >= (3, 9), "Python", sys.version.split()[0], "Python 3.9 or newer is needed.")
    for mod, pkg in (("boto3", "boto3"), ("yaml", "pyyaml"), ("psycopg", "psycopg[binary]")):
        try:
            importlib.import_module(mod)
            line(True, f"package {pkg}", "installed")
        except ImportError:
            line(False, f"package {pkg}", "missing", "pip install -r requirements.txt")
    data = Path(sg_ipintel.DATA_DIR)
    try:
        data.mkdir(parents=True, exist_ok=True)
        probe = data / ".doctor"
        probe.write_text("x")
        probe.unlink()
        free = shutil.disk_usage(data).free / 1e9
        line(True if free >= 10 else None if free >= 2 else False, "data folder", f"{data} ({free:.0f} GB free)",
             "Free some disk space: the database and reports need room.")
    except OSError as exc:
        line(False, "data folder", f"{data}: {exc}", f"Make {data} writable by you.")
    try:
        ok, why = sg_store.reachable()
        line(ok, "database", "answering" if ok else f"not answering: {why}",
             "Start Docker (or Colima), then: python sg_store.py setup")
    except Exception as exc:  # noqa: BLE001
        line(False, "database", f"not set up: {exc}", "python sg_store.py setup")
    svc = Service([]).status()
    if svc["supported"]:
        line(True if svc["installed"] else None, "always running", "on" if svc["installed"] else "off",
             "python sg_console.py install keeps it running and starts it at login.")
    code, body = _get_running(port, "/api/health")
    if code == 200:
        h = json.loads(body)
        line(True, "console", f"answering on {_url(port)} (version {h.get('version')})")
        for c in h["checks"]:
            if c["key"] in ("database", "version"):
                continue
            line({"ok": True, "info": None, "warn": None, "bad": False}[c["status"]], c["name"],
                 c["value"] + (f" ({c['detail']})" if c.get("detail") and c["status"] != "ok" else ""), c.get("fix", ""))
    elif code:
        line(False, "console", f"answers on port {port} but /api/health gave {code}: {body[:200].decode(errors='replace')}",
             "An older version is running: python sg_console.py install")
    else:
        line(False, "console", f"not answering on port {port} ({body.decode(errors='replace')[:120]})",
             "Start it: python sg_console.py install (or serve). If it does not stay up, the reason is at the end "
             f"of {data / 'console.log'}")
        j = sg_journal.Journal(data / "journal.jsonl")
        for e in j.recent(5, level="problems"):
            print(f"        {time.strftime('%Y-%m-%d %H:%M', time.localtime(e['at']))}  {e['message'][:160]}", file=out)
    logf = data / "console.log"
    if logf.exists():
        mb = logf.stat().st_size / 1e6
        line(mb < 500, "console log", f"{logf} ({mb:.0f} MB)", "Large: move it aside; the console starts a new one.")
    print(f"\n{'Nothing wrong found.' if not bad else f'{bad} problem(s) found.'} For help: python sg_console.py support "
          f"writes a bundle to send (secrets are taken out).", file=out)  # fmt: skip
    return 1 if bad else 0


def write_support(port: int = 8765, db: str | None = None, dest: str | None = None) -> int:
    """Write a support bundle: from the running console (it knows the reads under way), else built here."""
    code, body = _get_running(port, "/api/support/bundle", timeout=120)
    name = f"sg-tightener-support-{time.strftime('%Y%m%d-%H%M%S')}.zip"
    if code != 200:
        print(f"The console is not answering on port {port}: building the bundle here (no reads under way in it).")
        name, body = Console(db).support_bundle()
    path = Path(dest).expanduser() if dest else Path.cwd() / name
    if path.is_dir():
        path = path / name
    path.write_bytes(body)
    print(f"Wrote {path} ({len(body) / 1e3:.0f} kB). Tokens, keys and passwords are replaced by ***; look inside before sending.")
    return 0


def _service_cmd(args) -> list[str]:
    cmd = [sys.executable, str(Path(__file__).resolve()), "serve", "--service", "--port", str(args.port)]
    for flag, v in (("--db", args.db), ("--data-dir", args.data_dir), ("--profile", args.profile),
                    ("--external-id", args.external_id)):  # fmt: skip
        if v:
            cmd += [flag, str(Path(v).expanduser().resolve()) if flag in ("--db", "--data-dir") else v]
    if args.role_name != sg_db.DEFAULT_ROLE:
        cmd += ["--role-name", args.role_name]
    return cmd


def _url(port: int) -> str:
    return f"http://127.0.0.1:{port}/"


def _bind(console: Console, port: int, token: str, wait: float) -> ThreadingHTTPServer:
    """Serve on the port; as the background service, wait for a foreground copy handing over to stop."""
    deadline = time.time() + wait
    while True:
        try:
            return serve(console, port, token)[0]
        except OSError:
            if time.time() >= deadline:
                raise
            time.sleep(1)


@friendly_login_errors
def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = _build_parser().parse_args(argv)
    import webbrowser

    import sg_ipintel

    if getattr(args, "data_dir", None):
        sg_ipintel.set_data_dir(Path(args.data_dir))
    if args.cmd == "uninstall":
        Service([]).uninstall()
        print("The console no longer runs in the background (start it with: sg_console.py serve).")
        return 0
    if args.cmd == "open":
        webbrowser.open(_url(args.port))
        print(f"Opened {_url(args.port)}")
        return 0
    if args.cmd == "doctor":
        return doctor(args.port, args.db)
    if args.cmd == "support":
        return write_support(args.port, args.db, args.out)
    if args.cmd == "install":
        Service(_service_cmd(args)).install()
        url = _url(args.port)
        print(f"\n  The console now runs in the background and starts when you log in.\n  Bookmark: {url}\n"
              f"  Stop it with: sg_console.py uninstall\n", flush=True)  # fmt: skip
        time.sleep(2)
        webbrowser.open(url)
        return 0
    use_profile(args.profile)
    import sg_keys
    import sg_sso

    sso = sg_sso.Sso(sg_ipintel.DATA_DIR / "sso.json")
    keys = sg_keys.Keys(sg_ipintel.DATA_DIR / "keys.json")
    console = Console(args.db, args.profile, args.role_name, args.external_id, sso=sso, keys=keys,
                      service=Service(_service_cmd(args), running_as_service=args.service))  # fmt: skip
    token = lasting_token(args.new_token)
    _journal_start(console, args)
    httpd = _bind(console, args.port, token, 120 if args.service else 0)
    console.httpd = httpd
    try:
        st = console.state()
        LOG.info("acting as %s; database %s; two-person approval %s", st["me"], st["db"], "on" if st["approvals"] else "off")
        console.warm_reports()
        threading.Timer(5, console.resume_reads).start()  # after the page can answer
    except Exception as exc:  # noqa: BLE001 - the page offers to start it
        if not _database_down(exc):
            raise
        LOG.warning("the database is not running (%s): the page offers to start it", exc)
    url = _url(args.port)
    print(f"\n  Security group console: {url}\n  (Ctrl-C stops it)\n", flush=True)
    if not args.service and not args.no_browser:
        threading.Timer(0.5, webbrowser.open, (url,)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        console._rec("system", "console stopped", stopped=True)
    return 0


def _journal_start(console: Console, args) -> None:
    """Record the start in the activity log (and whether the run before ended without stopping: a crash, a
    kill, the Mac losing power), send every warning and error logged to it, note network changes, and stop
    cleanly on SIGTERM (what launchd sends on an upgrade) so that stop is recorded too."""
    import signal

    import sg_journal
    import sg_tightener

    console.started = time.time()
    before = [e for e in console.journal.recent(50, kind="system")]
    last = before[0] if before else None
    if last and last.get("message", "").startswith("console started"):
        console._rec("system", "the console before this one ended without stopping (a crash, a kill or the Mac "
                     "losing power): look at the entries just before this one", "warning",
                     previous_start=last.get("at"))  # fmt: skip
    console._rec("system", f"console started: version {sg_tightener.__version__}, port {args.port}"
                 + (", as the background service" if args.service else ""), pid=os.getpid(),
                 python=sys.version.split()[0], platform=platform.platform(), data_dir=str(console.journal.path.parent))  # fmt: skip
    root = logging.getLogger()
    if not any(isinstance(h, sg_journal.JournalHandler) for h in root.handlers):
        root.addHandler(sg_journal.JournalHandler(console.journal))

    def net(old, new):
        console._rec("network", f"network changed: {('phone hotspot' if new.get('metered') else 'Wi-Fi or wired' if new.get('metered') is False else 'not known')}"
                     f" (was {'phone hotspot' if old.get('metered') else 'Wi-Fi or wired' if old.get('metered') is False else 'not known'})",
                     interface=new.get("interface", ""), why=new.get("why", ""))  # fmt: skip

    _NET["hooks"].append(net)

    def uncaught(a):  # a background thread that dies: into the log and the activity log, not lost on stderr
        if a.exc_type is not SystemExit:
            LOG.error("background thread %s stopped: %s", getattr(a.thread, "name", "?"), a.exc_value,
                      exc_info=(a.exc_type, a.exc_value, a.exc_traceback))  # fmt: skip

    threading.excepthook = uncaught

    def term(signum, _frame):  # as quick as before: recorded, then gone (reads carry on at the next start)
        console._rec("system", "console stopped: asked to by the system (an upgrade, Always running switched off, "
                     "or logging out)", stopped=True, signal=signum)  # fmt: skip
        os._exit(0)

    try:
        signal.signal(signal.SIGTERM, term)
    except (ValueError, OSError):  # not the main thread
        pass


if __name__ == "__main__":
    sys.exit(main())
