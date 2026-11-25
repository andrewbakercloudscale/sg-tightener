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
REPORT_PROCS = max(1, min(8, (os.cpu_count() or 2) - 1))  # processes building report rows at once
REPORT_CACHE_VERSION = 4
# a page asking for a report some accounts have no row in yet gets the rows there are at once, and the rest are
# built in the background (it asks again); tests set SG_NO_WARM and get every row before the answer
REPORTS_WAIT = os.environ.get("SG_NO_WARM") == "1"
WARM = (("macro", "1m"), ("refused", "24h"), ("macro", "1w"), ("macro", "3m"), ("macro", "24h"), ("macro", "6m"),
        ("macro", "1y"))  # built in the background, default views first, so a page opens from rows already built
WARM_EVERY = 600
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
        self._report_gates: dict = {}
        self._warming: threading.Thread | None = None
        self._plans: dict = {}  # the last remediation plans built, newest last
        self._plan_pending: dict = {}  # plan key -> the build in progress, so a second request waits for the same one
        self._plan_pool = None  # processes that build plans: the console stays responsive while a big one builds
        self._owner_failed, self._owner_why = 0.0, ""
        self._reports_mem: dict | None = None
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
                modes = {a: st.mode(a) for a, _ in st.regions()}
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

        with self._report_lock:
            cache = self._report_cache()
            out, missing = {}, 0
            for account in sorted(sg_review.stamps()):
                hit = cache.get(f"{kind}|{range_key}|{account}")
                if hit:
                    out[account] = hit["row"]
                else:
                    missing += 1
            key = ("soon", kind, range_key)
            busy = self._report_gates.get(key)
            if missing and (busy is None or not busy.is_alive()):
                t = threading.Thread(target=self._reports, args=(kind, range_key, names), daemon=True)
                self._report_gates[key] = t
                t.start()
        if not missing:
            return self._reports(kind, range_key, names), 0  # every row there: the usual path, stale ones refreshed
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
            with self._report_lock:
                cache = self._report_cache()
                for (account, mtime), row in zip(todo, got):
                    out[account] = row
                    cache[f"{kind}|{range_key}|{account}"] = {"mtime": mtime, "at": now, "row": row}
                self._save_report_cache([f"{kind}|{range_key}|{a}" for a, _ in todo])
        return out, stale

    def _build_reports(self, kind: str, range_key: str, items: list[tuple[str, str]]) -> list:
        import sg_review

        if len(items) < 8 or REPORT_PROCS < 2:
            return [sg_review.report_row(kind, a, n, range_key) for a, n in items]
        import multiprocessing

        try:
            # a process is replaced after a few accounts: one large account leaves gigabytes behind in the process
            # that built it, and a long-lived one would keep them for every account after
            with multiprocessing.get_context("spawn").Pool(min(REPORT_PROCS, len(items)), maxtasksperchild=4) as pool:
                return pool.starmap(sg_review.report_row, [(kind, a, n, range_key) for a, n in items], chunksize=1)
        except Exception:  # processes not available here: build them one by one
            LOG.exception("building reports in parallel failed; building them one by one")
            return [sg_review.report_row(kind, a, n, range_key) for a, n in items]

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
                self._reports_mem = sg_store.report_rows(REPORT_CACHE_VERSION)
            except Exception as exc:  # noqa: BLE001 - rebuilt from the reads
                LOG.warning("report rows not loaded: %s", exc)
                self._reports_mem = {}
        return self._reports_mem

    def _save_report_cache(self, keys=None) -> None:
        """Keep the rows named by ``keys`` (all of them by default) in the database."""
        import sg_store

        rows = self._reports_mem or {}
        try:
            sg_store.save_report_rows(REPORT_CACHE_VERSION, {k: rows[k] for k in (rows if keys is None else keys) if k in rows})
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
            accounts.append(got["account"])
        rows.sort(key=lambda x: (sg_review.SEV_RANK.get(x["sev"], 9), -x["flows"]))
        types = {k: n for k, (n, _) in sg_review.SOURCE_TYPES.items()}
        return {"range": range_key, "rows": rows, "accounts": accounts, "types": types, "no_flow_logs_read": len(unread),
                "building": building}

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

    def _prepare(self, job: dict) -> None:
        import sg_assets
        import sg_review

        try:
            t = self.targets()  # not fresh: that signed in again (one STS call, under the lock) for every account
            sess = sg_review.SafeSession(t.session(job["account"]))  # its regions are read at once
            if job.get("min_spend") and self._too_small(job, sess):
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
            self._job_extra[job["id"]] = {"sess": sess, "tasks": tasks, "now": now, "stop": threading.Event()}
            del doc
            self._say(job, f"flow logs in {', '.join(with_logs)}: {len(tasks)} slice(s), {round(hours)} hours to read, "
                           + (f"about US${cost:.2f}" if cost is not None else "cost not known until a first 1-day read"))  # fmt: skip
        except Exception as exc:
            LOG.exception("reading %s failed", job["account"])
            job["status"] = "failed"
            self._say(job, f"failed: {sg_review.describe_error(exc) if hasattr(sg_review, 'describe_error') else exc}")

    def read_confirm(self, body: dict) -> dict:
        job = self._job(body)
        extra = self._job_extra.get(job["id"])
        if job["status"] != "confirm" or not extra:
            raise ConsoleError(409, "this read is not waiting for confirmation")
        job["status"] = "running"
        self._read_asked(job, True)
        threading.Thread(target=self._run, args=(job, extra), daemon=True).start()
        return dict(job)

    def _run(self, job: dict, x: dict, first: tuple[int, int] = (0, 0)) -> None:
        """Read the job's slices. ``first`` is (slices, bytes) a first pass already read, so progress adds up."""
        import sg_review

        d0, b0 = first

        def progress(done, total, nbytes):
            job.update(done=d0 + done, total=d0 + total, bytes=b0 + nbytes)

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
        return {"id": b["id"], "status": b["status"], "accounts": len(jobs), "count": count, "days": b["days"],
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
        for j in jobs:
            j["batch"], j["min_spend"] = b["id"], min_spend
        self.batch = b
        threading.Thread(target=self._batch_price, args=(b, jobs), daemon=True).start()
        return self.batch_status()

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

    def read_all_confirm(self, body: dict) -> dict:
        b = self.batch
        if not b or b["status"] != "confirm":
            raise ConsoleError(409, "no read of many accounts is waiting for confirmation")
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
                                         lambda d, t, n: j.update(done=d, total=len(tasks), bytes=n))  # fmt: skip
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
        key = (account, int(days), start, end, mtime, hashlib.sha1(repr((groups, assets)).encode()).hexdigest())
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
                            self._plan_pool = multiprocessing.get_context("spawn").Pool(PLAN_PROCS, maxtasksperchild=1)
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
                             str(body.get("reason") or "applied from the console"), str(body.get("ticket") or ""))  # fmt: skip
            return res
        finally:
            st.close()

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
                if url.path == "/api/refused":
                    return self._json(200, console.refused(q.get("range", "24h")))
                if url.path == "/api/sso":
                    return self._json(200, console.sso_status())
                if url.path == "/api/sso/accounts":
                    return self._json(200, console.sso_accounts(q.get("fresh") == "1", q.get("roles") != "0"))
                if url.path == "/api/sso/roles":
                    return self._json(200, console.sso_roles())
                if url.path == "/api/sso/ous":
                    return self._json(200, console.sso_ous(q.get("role", ""), q.get("fresh") == "1"))
                if url.path == "/api/batch":
                    return self._json(200, console.batch_status())
                if url.path == "/api/jobs":
                    return self._json(200, console.job_list())
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
            route = {"/api/propose": console.propose, "/api/tighten": console.tighten, "/api/remediate": console.remediate, "/api/merge-apply": console.merge_apply, "/api/decide": console.decide, "/api/approvals": console.set_approvals, "/api/apply": console.apply,
                     "/api/reconcile": console.reconcile, "/api/adopt": console.adopt, "/api/check": console.check,
                     "/api/profile": lambda body: console.profile(_need(body, "account"), read=True),
                     "/api/asset-apply": console.asset_apply, "/api/asset-revert": console.asset_revert,
                     "/api/sso/start": console.sso_start, "/api/sso/choose": console.sso_choose,
                     "/api/sso/signout": console.sso_sign_out, "/api/read": console.read_start,
                     "/api/read/confirm": console.read_confirm, "/api/read/stop": console.read_stop,
                     "/api/read/all": console.read_all, "/api/read/all/confirm": console.read_all_confirm,
                     "/api/read/all/stop": console.read_all_stop, "/api/keys/use": console.keys_use,
                     "/api/autostart": console.autostart,
                     "/api/database/start": console.database_start}.get(urlparse(self.path).path)  # fmt: skip
            if not route:
                return self._json(404, {"error": "not found"})
            try:
                return self._json(200, route(body))
            except ConsoleError as exc:
                return self._json(exc.status, {"error": str(exc)})
            except sg_db.Refused as exc:
                return self._json(409, {"error": str(exc)})
            except Exception as exc:
                if _database_down(exc):
                    return self._json(503, {"error": f"the database is not running: {exc}", "database": False})
                LOG.exception("POST %s failed", self.path)
                return self._json(500, {"error": plain_error(exc)})

    return Handler



PLAN_PROCS = 2  # remediation plans built at once, each in its own process
PLAN_TIMEOUT = 600  # a request waits this long for a plan; the build carries on after it


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
    return f"Something went wrong here ({type(exc).__name__}: {exc}). The details are in ~/.sg-tightener/console.log."


ACTIONABLE = sg_remediate.ACTIONABLE
_port_ranges = sg_remediate.port_ranges
_plan_rule = sg_remediate.plan_rule


def serve(console: Console, port: int = 8765, token: str | None = None) -> tuple[ThreadingHTTPServer, str]:
    token = token or secrets.token_urlsafe(24)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(console, token, port))
    if os.environ.get("SG_NO_WARM") != "1":
        threading.Thread(target=console.warm, daemon=True, name="warm-reports").start()
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
    return p


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
    return 0


if __name__ == "__main__":
    sys.exit(main())
