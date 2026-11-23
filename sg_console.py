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
  sg_console.py serve [--port 8765] [--profile P] [--role-name OrganizationAccountAccessRole] [--db FILE]
  sg_console.py install [--port 8765]     # always running: start at login, restart if it stops
  sg_console.py uninstall                 # stop running in the background
  sg_console.py open                      # open the console in the browser
"""

from __future__ import annotations

import argparse
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
from sg_tightener import add_profile_arg, friendly_login_errors, use_profile

LOG = logging.getLogger("sg_console")
ASSET = Path(__file__).resolve().parent / "assets" / "sg_console.html"
MAX_BODY = 1 << 20
RANGES = ("24h", "1w", "1m", "3m", "6m", "1y")
BATCH_WORKERS = 4  # accounts read at once when reading an OU: each runs its own Logs Insights queries
JOBS_SHOWN = 1000
LABEL = "com.sg-tightener.console"
UNIT = "sg-console.service"
PROTECTED = ("Desktop", "Documents", "Downloads", "Library/Mobile Documents")  # macOS keeps background programs out
RUNTIME = ("boto3", "pyyaml")
PASS_ENV = ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy", "AWS_CA_BUNDLE",
            "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "SG_TIGHTENER_DB")


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
        self.sso = sso
        self.keys = keys  # sg_keys.Keys: signing in with a profile or keys on this computer instead of SSO
        self.batch: dict | None = None  # reading many accounts at once (an OU)
        self.service = service
        self.jobs: dict[int, dict] = {}
        self._job_extra: dict[int, dict] = {}
        self.httpd = None

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
            for account, region in st.regions():
                a = accounts.setdefault(account, {"account": account, "name": names.get(account, ""), "regions": [],
                                                  "mode": st.mode(account)})  # fmt: skip
                p = perms.get((account, region))
                groups = st.groups(account, region)
                rules = sum(len(st.rules(account, region, g, "desired")) for g in groups)
                synced = st.db.execute("SELECT synced_at FROM regions WHERE account = ? AND region = ?",
                                       (account, region)).fetchone()[0]  # fmt: skip
                n_assets = st.db.execute("SELECT COUNT(*) FROM assets WHERE account = ? AND region = ?",
                                         (account, region)).fetchone()[0]  # fmt: skip
                a["regions"].append({"region": region, "groups": len(groups), "rules": rules, "assets": n_assets,
                                     "pending": len(st.pending(account, region)), "synced_at": synced,
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
                                                   "mode": st.mode(c["account"]), "reviewed": c["account"] in read})  # fmt: skip
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

    def groups(self, account: str, region: str) -> list[dict]:
        st = self.store()
        try:
            out = []
            for gid, g in st.groups(account, region).items():
                want, have = st.rules(account, region, gid, "desired"), st.rules(account, region, gid, "synced")
                rules = []
                for r in sorted(set(want) | set(have)):
                    state = "both" if r in want and r in have else "want" if r in want else "have"
                    rules.append({**sg_db._rule_json(r, want.get(r) or have.get(r, "")), "state": state,
                                  "text": sg_db.rule_text(r)})  # fmt: skip
                out.append({"id": gid, **g, "rules": rules})
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
        rows = []
        for account in sg_review.cached_accounts():
            try:
                mtime = sg_review._path(account).stat().st_mtime
            except OSError:
                continue
            key = ("macro", account, mtime, range_key)
            got = self._refused_cache.get(key)
            if got is None:
                doc = sg_review.load(account)
                if not doc or not any(c["st"] in ("ok", "cut") for c in doc["chunks"]):
                    continue
                rep = sg_review.build(doc, range_key, names=sg_review.load_names(), assets=True)
                got = sg_review.macro_row(account, doc.get("name") or names.get(account, ""), rep)
                self._refused_cache = {k: v for k, v in self._refused_cache.items() if not (k[0] == "macro" and k[1] == account)}
                self._refused_cache[key] = got
            rows.append({**got, "mode": modes.get(account, "surveillance")})
        kinds = {k: sg_review.CAT_NAME[k] for k in sg_review.CATS}
        types = {k: n for k, (n, _) in sg_review.SOURCE_TYPES.items()}
        rag = {"green_max": sg_review.RAG_GREEN_MAX, "amber_max": sg_review.RAG_AMBER_MAX}
        return {"range": range_key, "accounts": rows, "kinds": kinds, "types": types, "rag": rag}

    def refused(self, range_key: str = "24h") -> dict:
        """Every refused source across the accounts sg_review has read, worst verdict first."""
        import sg_review

        if range_key not in RANGES:
            raise ConsoleError(400, f"range must be one of {', '.join(RANGES)}")
        rows, accounts = [], []
        for account in sg_review.cached_accounts():
            try:
                mtime = sg_review._path(account).stat().st_mtime
            except OSError:
                continue
            key = (account, mtime, range_key)
            got = self._refused_cache.get(key)
            if got is None:
                doc = sg_review.load(account)
                if not doc or not any(c["st"] in ("ok", "cut") for c in doc["chunks"]):
                    continue
                rep = sg_review.build(doc, range_key)
                name = doc.get("name", "")
                cov = rep.get("covered") or [1.0]
                got = {"rows": sg_review.refused_rows(account, name, rep, limit=1000),
                       "account": {"account": account, "name": name, "refused": rep["summary"]["refused"],
                                   "attention": rep["summary"]["attention"], "end": rep.get("end"),
                                   "first": sg_review._evidence(doc)[0],
                                   "covered": round(sum(cov) / len(cov), 2)}}  # fmt: skip
                self._refused_cache = {k: v for k, v in self._refused_cache.items() if k[0] != account}
                self._refused_cache[key] = got
            rows += got["rows"]
            accounts.append(got["account"])
        rows.sort(key=lambda x: (sg_review.SEV_RANK.get(x["sev"], 9), -x["flows"]))
        return {"range": range_key, "rows": rows, "accounts": accounts}

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
        out = self._auth_call(sso.start, str(body.get("start_url") or ""), str(body.get("region") or ""))
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
            days = int(body.get("days") or 1)
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
            threading.Thread(target=self._prepare, args=(job,), daemon=True).start()
        return job if not start else dict(job)

    def _say(self, job: dict, line: str) -> None:
        job["lines"] = (job["lines"] + [line])[-60:]

    def _prepare(self, job: dict) -> None:
        import sg_assets
        import sg_review

        try:
            t = self.targets(fresh=True)
            sess = t.session(job["account"])
            regions = job["regions"]
            if regions == ["all"]:
                ec2 = sess.client("ec2", region_name=sess.region_name or "us-east-1")
                regions = sorted(r["RegionName"] for r in ec2.describe_regions()["Regions"])
                self._say(job, f"{len(regions)} enabled regions")
            job["regions"] = regions
            st = self.store()
            try:
                if job["name"]:
                    with st:
                        st.name_account(job["account"], job["name"])
                for region in regions:
                    try:
                        ec2 = sess.client("ec2", region_name=region)
                        changes = sg_db.ensure_current(st, ec2, job["account"], region, t.actor, assets=True)
                        n = len(st.groups(job["account"], region))
                        n_assets = len(sg_assets.list_assets(st, job["account"], region))
                        self._say(job, f"{region}: {n} security group(s), {n_assets} interface(s)"
                                       + (f", {len(changes)} changed outside the tool" if changes else ""))  # fmt: skip
                    except Exception as exc:  # noqa: BLE001 - one region out of reach must not stop the others
                        self._say(job, f"{region}: not read ({sg_review.describe_error(exc)[:200]})")
            finally:
                st.close()
            now = time.time()
            doc = sg_review.load(job["account"]) or sg_review.new_doc(job["account"], job["name"])
            doc["name"] = job["name"] or doc.get("name", "")
            tasks = sg_review.plan_read(sess, doc, regions, job["days"], now, say=lambda s: None)
            sg_review.save(doc)
            with_logs = [r for r in regions if (doc["regions"].get(r) or {}).get("query_sets")]
            if not tasks:
                job["status"] = "done"
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
            self._job_extra[job["id"]] = {"sess": sess, "doc": doc, "tasks": tasks, "now": now, "stop": threading.Event()}
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
        threading.Thread(target=self._run, args=(job, extra), daemon=True).start()
        return dict(job)

    def _run(self, job: dict, x: dict) -> None:
        import sg_review

        def progress(done, total, nbytes):
            job.update(done=done, total=total, bytes=nbytes)

        try:
            state = sg_review.run_read(x["sess"], x["doc"], x["tasks"], job["days"], x["now"], x["stop"].is_set, progress)
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

    def read_stop(self, body: dict) -> dict:
        job = self._job(body)
        extra = self._job_extra.get(job["id"])
        if job["status"] == "confirm":
            self._job_extra.pop(job["id"], None)
            job["status"] = "cancelled"
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
        return {"id": b["id"], "status": b["status"], "accounts": len(jobs), "count": count, "days": b["days"],
                "regions": b["regions"], "started": b["started"], "cost": round(sum(costs), 2),
                "cost_unknown": len(ready) - len(costs), "to_read": len(ready),
                "read": sum(1 for j in ready if j["status"] == "done"),
                "slices": sum(j.get("total") or 0 for j in ready), "done": sum(j.get("done") or 0 for j in ready),
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
        jobs = [self.read_start({"account": a, "regions": body.get("regions") or "all", "days": body.get("days") or 1}, start=False)
                for a in accounts if a not in busy]  # fmt: skip
        if not jobs:
            raise ConsoleError(409, "every one of these accounts is already being read")
        b = {"id": (self.batch["id"] if self.batch else 0) + 1, "status": "pricing", "jobs": [j["id"] for j in jobs],
             "days": jobs[0]["days"], "regions": jobs[0]["regions"], "started": time.time(), "stop": threading.Event()}  # fmt: skip
        for j in jobs:
            j["batch"] = b["id"]
        self.batch = b
        threading.Thread(target=self._batch_price, args=(b, jobs), daemon=True).start()
        return self.batch_status()

    def _pool(self, b: dict, fn, items: list) -> None:
        from concurrent.futures import ThreadPoolExecutor

        def one(x):
            if not b["stop"].is_set():
                fn(x)

        with ThreadPoolExecutor(max_workers=BATCH_WORKERS) as pool:
            list(pool.map(one, items))

    def _batch_price(self, b: dict, jobs: list[dict]) -> None:
        self._pool(b, self._prepare, jobs)
        for j in jobs:
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
        b["status"] = "running"

        def run(j):
            j["status"] = "running"
            self._run(j, self._job_extra[j["id"]])

        def go():
            self._pool(b, run, jobs)
            for j in jobs:
                if j["status"] == "queued":
                    j["status"] = "cancelled"
                    self._job_extra.pop(j["id"], None)
                    self._say(j, "not read")
            b["status"] = "stopped" if b["stop"].is_set() else "done"

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
        if b["status"] == "confirm":
            b["status"] = "stopped"
        return self.batch_status()

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
            return plistlib.dumps({"Label": LABEL, "ProgramArguments": self.cmd, "RunAtLoad": True, "KeepAlive": True,
                                   "ThrottleInterval": 10, "StandardOutPath": log, "StandardErrorPath": log,
                                   "EnvironmentVariables": self._env(), "ProcessType": "Background"})  # fmt: skip
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
            r = self._run(["launchctl", "bootstrap", target, str(self.path)], capture_output=True, text=True)
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


def token_file() -> Path:
    import sg_ipintel

    return sg_ipintel.DATA_DIR / "console-token"


def lasting_token(new: bool = False) -> str:
    """The key the console's own page puts on every change (it never appears in the address), kept (mode
    0600) so a page left open keeps working when the console restarts or hands over to the always-running copy."""
    path = token_file()
    if not new:
        try:
            got = path.read_text().strip()
            if len(got) >= 24:
                return got
        except OSError:
            pass
    tok = secrets.token_urlsafe(24)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(tok + "\n")
    return tok


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
                if url.path == "/api/state":
                    return self._json(200, console.state())
                if url.path == "/api/groups":
                    return self._json(200, console.groups(_need(q, "account"), _need(q, "region")))
                if url.path == "/api/assets":
                    return self._json(200, console.assets(_need(q, "account"), _need(q, "region")))
                if url.path == "/api/asset-history":
                    return self._json(200, console.asset_history(_need(q, "eni")))
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
                LOG.exception("GET %s failed", url.path)
                return self._json(500, {"error": str(exc)})

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
            route = {"/api/propose": console.propose, "/api/decide": console.decide, "/api/apply": console.apply,
                     "/api/reconcile": console.reconcile, "/api/adopt": console.adopt, "/api/check": console.check,
                     "/api/asset-apply": console.asset_apply, "/api/asset-revert": console.asset_revert,
                     "/api/sso/start": console.sso_start, "/api/sso/choose": console.sso_choose,
                     "/api/sso/signout": console.sso_sign_out, "/api/read": console.read_start,
                     "/api/read/confirm": console.read_confirm, "/api/read/stop": console.read_stop,
                     "/api/read/all": console.read_all, "/api/read/all/confirm": console.read_all_confirm,
                     "/api/read/all/stop": console.read_all_stop, "/api/keys/use": console.keys_use,
                     "/api/autostart": console.autostart}.get(urlparse(self.path).path)  # fmt: skip
            if not route:
                return self._json(404, {"error": "not found"})
            try:
                return self._json(200, route(body))
            except ConsoleError as exc:
                return self._json(exc.status, {"error": str(exc)})
            except sg_db.Refused as exc:
                return self._json(409, {"error": str(exc)})
            except Exception as exc:
                LOG.exception("POST %s failed", self.path)
                return self._json(500, {"error": str(exc)})

    return Handler


def serve(console: Console, port: int = 8765, token: str | None = None) -> tuple[ThreadingHTTPServer, str]:
    token = token or secrets.token_urlsafe(24)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(console, token, port))
    httpd.daemon_threads = True
    return httpd, token


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sg_console.py", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the console on 127.0.0.1")
    i = sub.add_parser("install", help="always running: start the console at login and restart it if it stops")
    for q in (s, i):
        q.add_argument("--port", type=int, default=8765)
        q.add_argument("--db", help=f"database file (default ${sg_db.DB_ENV} or ~/.sg-tightener/sg.db)")
        q.add_argument("--role-name", default=sg_db.DEFAULT_ROLE, help="role assumed in other accounts to apply and reconcile")
        q.add_argument("--external-id", default="")
        q.add_argument("--data-dir", help="where sg_review keeps what it read (default ~/.sg-tightener)")
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
    st = console.state()
    LOG.info("acting as %s; database %s; two-person approval %s", st["me"], st["db"], "on" if st["approvals"] else "off")
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
