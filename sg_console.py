#!/usr/bin/env python3
"""sg_console.py: the security group console, a local web page for every account in the database.

One place to see every security group and rule (as the database wants them and as AWS holds them),
propose a change with a reason, approve or reject someone else's, apply approved changes, reconcile
with AWS, search the audit trail, and see every rejected flow across the accounts sg_review has read
(an OU, with ``sg_review.py org``).

It listens on 127.0.0.1 only. Start it and open the URL it prints: the one-time token in it logs the
browser in (an HttpOnly, SameSite=Strict cookie); every change also carries the token in a header.
Who acts is the AWS identity the console runs as (``--profile``), exactly as with ``sg_db.py``: a
second person approves from their own console or ``sg_db.py approve``, with their own credentials.

Usage:
  sg_console.py serve [--port 8765] [--profile P] [--role-name OrganizationAccountAccessRole] [--db FILE]
"""

from __future__ import annotations

import argparse
import hmac
import json
import logging
import secrets
import sys
import threading
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import sg_db
from sg_tightener import add_profile_arg, friendly_login_errors, use_profile

LOG = logging.getLogger("sg_console")
ASSET = Path(__file__).resolve().parent / "assets" / "sg_console.html"
COOKIE = "sgc"
MAX_BODY = 1 << 20
RANGES = ("24h", "1w", "1m", "3m", "6m", "1y")


class ConsoleError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class Console:
    """What the HTTP handler calls: every read and write, against the database and AWS."""

    def __init__(self, db_path: str | None, profile: str | None = None, role_name: str = sg_db.DEFAULT_ROLE,
                 external_id: str = "", targets=None):  # fmt: skip
        self.db_path = db_path
        self.args = argparse.Namespace(profile=profile, role_name=role_name, external_id=external_id)
        self._targets = targets
        self._fixed = targets is not None  # tests hand in their own
        self._lock = threading.Lock()
        self._refused_cache: dict = {}

    # ------------------------------------------------------------------ plumbing
    def store(self) -> sg_db.Store:
        return sg_db.Store(self.db_path)

    def targets(self, fresh: bool = False):
        with self._lock:
            if self._targets is None or (fresh and not self._fixed):
                self._targets = sg_db.Targets(self.args)
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
            return {"me": me, "me_principal": sg_db.principal(me), "account": me_account,
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


def _need(body: dict, key: str) -> str:
    v = body.get(key)
    if not isinstance(v, str) or not v.strip():
        raise ConsoleError(400, f"{key} is required")
    return v.strip()


# ---------------------------------------------------------------------------------------------- HTTP
def make_handler(console: Console, token: str, port: int):
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "sg-console"
        sys_version = ""

        def log_message(self, fmt, *a):  # requests are logged at debug only: URLs carry no secrets after login
            LOG.debug("%s %s", self.address_string(), fmt % a)

        # ---- auth
        def _authed(self) -> bool:
            c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            got = c[COOKIE].value if COOKIE in c else ""
            return bool(got) and hmac.compare_digest(got, token)

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
            if url.path == "/" and "token" in q:
                if not hmac.compare_digest(q["token"], token):
                    return self._send(403, b"wrong token: use the URL sg_console.py printed", "text/plain")
                return self._send(303, b"", "text/plain", {
                    "Location": "/", "Set-Cookie": f"{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/"})
            if not self._authed():
                return self._send(403, b"open the URL sg_console.py printed (it carries a one-time token)", "text/plain")
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
                if url.path == "/api/refused":
                    return self._json(200, console.refused(q.get("range", "24h")))
                return self._json(404, {"error": "not found"})
            except ConsoleError as exc:
                return self._json(exc.status, {"error": str(exc)})
            except Exception as exc:
                LOG.exception("GET %s failed", url.path)
                return self._json(500, {"error": str(exc)})

        def do_POST(self):
            if not self._host_ok():
                return self._send(421, b"wrong host", "text/plain")
            if not self._authed() or not hmac.compare_digest(self.headers.get("X-SG-Token", ""), token):
                return self._json(403, {"error": "not signed in"})
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
                     "/api/asset-apply": console.asset_apply, "/api/asset-revert": console.asset_revert}.get(urlparse(self.path).path)  # fmt: skip
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
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--db", help=f"database file (default ${sg_db.DB_ENV} or ~/.sg-tightener/sg.db)")
    s.add_argument("--role-name", default=sg_db.DEFAULT_ROLE, help="role assumed in other accounts to apply and reconcile")
    s.add_argument("--external-id", default="")
    s.add_argument("--data-dir", help="where sg_review keeps what it read (default ~/.sg-tightener)")
    add_profile_arg(s)
    return p


@friendly_login_errors
def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = _build_parser().parse_args(argv)
    use_profile(args.profile)
    if args.data_dir:
        import sg_ipintel

        sg_ipintel.set_data_dir(Path(args.data_dir))
    console = Console(args.db, args.profile, args.role_name, args.external_id)
    httpd, token = serve(console, args.port)
    st = console.state()
    LOG.info("acting as %s; database %s; two-person approval %s", st["me"], st["db"], "on" if st["approvals"] else "off")
    print(f"\n  Security group console: http://127.0.0.1:{args.port}/?token={token}\n  (Ctrl-C stops it)\n", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
