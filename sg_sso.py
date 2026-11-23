#!/usr/bin/env python3
"""sg_sso.py: sign in to AWS IAM Identity Center (SSO) from the console, with no AWS CLI needed.

The browser device flow, as ``aws sso login`` does it: the console registers itself with Identity Center,
shows a code and opens the AWS sign-in page; once the person approves there, it lists the accounts and
roles they may use and takes short-lived credentials for the ones chosen. Nothing long-lived is kept:
the sign-in token (good for the session length Identity Center sets, usually 8 hours) is cached in
``~/.sg-tightener/sso.json`` (mode 0600) so an always-running console survives a restart, and role
credentials are only ever held in memory.

A token ``aws sso login`` already cached for the same start URL is used too, so someone signed in with
the AWS CLI is signed in here.
"""

from __future__ import annotations

import configparser
import json
import logging
import os
import threading
import time
from pathlib import Path

LOG = logging.getLogger("sg_sso")
CLIENT_NAME = "sg-tightener-console"
ROLE_WORKERS = 3  # Identity Center throttles ListAccountRoles hard; more threads only means more 429s
ROLE_RETRY_PAUSE = 1.0
HOME_TRIES = 5  # chosen accounts tried for who acts, when the role is missing in the first
GRANT = "urn:ietf:params:oauth:grant-type:device_code"
EARLY = 300  # treat a token or credentials as expired this many seconds before they are
READ_ONLY_HINTS = ("readonly", "read-only", "read_only", "viewonly", "view-only", "securityaudit", "audit", "security")


def _now() -> float:
    return time.time()


def _iso(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def _parse_iso(s: str) -> float:
    s = str(s).replace("UTC", "Z").strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            from datetime import datetime, timezone

            d = datetime.strptime(s, fmt)
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return d.timestamp()
        except ValueError:
            continue
    return 0.0


def known_portals(config_path: Path | None = None) -> list[dict]:
    """Every SSO start URL and region in ~/.aws/config (``sso-session`` sections and older SSO profiles)."""
    path = config_path or Path(os.environ.get("AWS_CONFIG_FILE") or Path.home() / ".aws" / "config")
    cp = configparser.RawConfigParser()
    try:
        cp.read(path)
    except (configparser.Error, OSError):
        return []
    out, seen = [], set()
    for sec in cp.sections():
        url, region = cp.get(sec, "sso_start_url", fallback=""), cp.get(sec, "sso_region", fallback="")
        if url and region and url not in seen:
            seen.add(url)
            out.append({"start_url": url, "region": region, "name": sec.replace("sso-session ", "").replace("profile ", "")})
    return out


def role_rank(role: str) -> tuple:
    """Read-only roles first: the console only needs to read until someone applies a change."""
    low = role.lower()
    return (0 if any(h in low for h in READ_ONLY_HINTS) else 1, low)


class SsoError(Exception):
    pass


class Sso:
    """One Identity Center sign-in: the device flow, the accounts and roles, and a session per account."""

    def __init__(self, cache: Path, client_factory=None, cli_cache: Path | None = None):
        self.cache = Path(cache)
        self.cli_cache = cli_cache if cli_cache is not None else Path.home() / ".aws" / "sso" / "cache"
        self._client = client_factory or self._boto_client
        self._lock = threading.Lock()
        self._sessions: dict = {}
        self._accounts: list | None = None
        self._plain: list | None = None
        self.pending: dict | None = None
        self.error = ""
        self.state = self._load()

    # ---------------------------------------------------------------- persistence
    def _load(self) -> dict:
        try:
            got = json.loads(self.cache.read_text())
            return got if isinstance(got, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        self.cache.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.cache.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")  # saves can overlap
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.state, f, indent=1)
        os.replace(tmp, self.cache)

    @staticmethod
    def _boto_client(service: str, region: str):
        import boto3
        from botocore import UNSIGNED
        from botocore.config import Config

        # adaptive retries back off when Identity Center throttles (it allows only a few calls a second)
        return boto3.client(service, region_name=region, config=Config(signature_version=UNSIGNED,
                                                                       retries={"mode": "adaptive", "max_attempts": 10}))

    # ---------------------------------------------------------------- status
    @property
    def start_url(self) -> str:
        return self.state.get("start_url", "")

    @property
    def region(self) -> str:
        return self.state.get("region", "")

    def token(self) -> str:
        """The access token, if signed in: ours, or one ``aws sso login`` cached for the same start URL."""
        t = self.state.get("token") or {}
        if t.get("access") and t.get("expires", 0) - EARLY > _now():
            return t["access"]
        cli = None if self.state.get("signed_out") else self._cli_token()
        if cli:
            self.state["token"] = cli
            return cli["access"]
        return ""

    def _cli_token(self) -> dict | None:
        if not self.start_url or not self.cli_cache.is_dir():
            return None
        best = None
        for f in self.cli_cache.glob("*.json"):
            try:
                d = json.loads(f.read_text())
            except (OSError, ValueError):
                continue
            if not isinstance(d, dict) or d.get("startUrl", "").rstrip("/#") != self.start_url.rstrip("/#"):
                continue
            exp = _parse_iso(d.get("expiresAt", ""))
            if d.get("accessToken") and exp - EARLY > _now() and (best is None or exp > best["expires"]):
                best = {"access": d["accessToken"], "expires": exp, "from": "aws cli"}
        return best

    def status(self) -> dict:
        tok = self.token()
        t = self.state.get("token") or {}
        p = self.pending
        return {"start_url": self.start_url, "region": self.region, "signed_in": bool(tok),
                "expires": _iso(t["expires"]) if tok and t.get("expires") else "",
                "from": t.get("from", "console") if tok else "",
                "pending": None if not p else {"code": p["code"], "url": p["url"], "expires": _iso(p["expires"])},
                "error": self.error, "chosen": self.chosen(), "portals": known_portals()}

    # ---------------------------------------------------------------- sign in
    def start(self, start_url: str, region: str) -> dict:
        """Begin the device flow: the code to show and the AWS page to open. A thread waits for approval."""
        start_url, region = start_url.strip(), region.strip()
        if not start_url.startswith("https://"):
            raise SsoError("the start URL is the AWS access portal address, https://….awsapps.com/start")
        if not region:
            raise SsoError("the Identity Center region is required, for example eu-west-1")
        with self._lock:
            if (start_url, region) != (self.start_url, self.region):
                self.state = {"start_url": start_url, "region": region, "chosen": []}
                self._sessions.clear()
                self._accounts = None
                self._plain = None
            self.state.pop("signed_out", None)
            if self.token():  # already signed in (here, or with `aws sso login` for this portal)
                self.pending, self.error = None, ""
                self._save()
                return {"signed_in": True}
            oidc = self._client("sso-oidc", region)
            reg = self.state.get("client") or {}
            if not reg.get("id") or reg.get("expires", 0) - EARLY < _now() or reg.get("region") != region:
                r = oidc.register_client(clientName=CLIENT_NAME, clientType="public")
                reg = {"id": r["clientId"], "secret": r["clientSecret"], "expires": r.get("clientSecretExpiresAt", 0),
                       "region": region}  # fmt: skip
                self.state["client"] = reg
            d = oidc.start_device_authorization(clientId=reg["id"], clientSecret=reg["secret"], startUrl=start_url)
            self.pending = {"code": d["userCode"], "url": d.get("verificationUriComplete") or d["verificationUri"],
                            "device": d["deviceCode"], "interval": max(1, int(d.get("interval") or 5)),
                            "expires": _now() + int(d.get("expiresIn") or 600)}  # fmt: skip
            self.error = ""
            self._save()
            p = dict(self.pending)
        threading.Thread(target=self._wait, args=(oidc, p), daemon=True).start()
        return {"signed_in": False, "code": p["code"], "url": p["url"]}

    def _wait(self, oidc, p: dict) -> None:
        reg = self.state["client"]
        interval = p["interval"]
        while _now() < p["expires"]:
            if not self.pending or self.pending.get("device") != p["device"]:
                return  # a newer sign-in replaced this one
            time.sleep(interval)
            try:
                t = oidc.create_token(clientId=reg["id"], clientSecret=reg["secret"], grantType=GRANT, deviceCode=p["device"])
            except Exception as exc:  # noqa: BLE001 - the error class names come from the service model
                name = type(exc).__name__
                code = getattr(exc, "response", {}).get("Error", {}).get("Code", "") if hasattr(exc, "response") else ""
                if "AuthorizationPending" in name or code == "AuthorizationPendingException":
                    continue
                if "SlowDown" in name or code == "SlowDownException":
                    interval += 5
                    continue
                self.error = f"sign-in failed: {exc}"
                self.pending = None
                return
            with self._lock:
                self.state["token"] = {"access": t["accessToken"], "expires": _now() + int(t.get("expiresIn") or 3600),
                                       "from": "console"}  # fmt: skip
                self.pending = None
                self._sessions.clear()
                self._accounts = None
                self._plain = None
                self._save()
            LOG.info("signed in to AWS IAM Identity Center at %s", self.start_url)
            return
        self.error = "the sign-in code expired before it was approved: sign in again"
        self.pending = None

    def sign_out(self) -> None:
        with self._lock:
            tok = self.token()
            if tok and self.region:
                try:
                    self._client("sso", self.region).logout(accessToken=tok)
                except Exception as exc:  # noqa: BLE001 - signing out locally is what matters
                    LOG.debug("SSO logout call failed: %s", exc)
            self.state.pop("token", None)
            self.state["signed_out"] = True
            self._sessions.clear()
            self._accounts = None
            self._plain = None
            self.pending = None
            self._save()

    # ---------------------------------------------------------------- accounts
    def _need_token(self) -> str:
        tok = self.token()
        if not tok:
            raise SsoError("not signed in to AWS: sign in with AWS SSO first")
        return tok

    def _list_accounts(self, fresh: bool = False) -> list[dict]:
        tok = self._need_token()
        if self._plain is not None and not fresh:
            return self._plain
        found = []
        for page in self._client("sso", self.region).get_paginator("list_accounts").paginate(accessToken=tok):
            found += page.get("accountList", [])
        self._plain = found
        return found

    def accounts(self, fresh: bool = False, roles: bool = True) -> list[dict]:
        """Every account this person may use, each with its roles (read-only ones first). With roles=False,
        quickly, without asking for each account's roles (a large organisation has hundreds): the roles
        found before are given where known."""
        tok = self._need_token()
        if not roles:
            known = dict(self.state.get("roles") or {})
            return sorted(({"account": a["accountId"], "name": a.get("accountName", ""), "email": a.get("emailAddress", ""),
                            "roles": list(known.get(a["accountId"], []))} for a in self._list_accounts(fresh)),
                          key=lambda x: (x["name"].lower(), x["account"]))  # fmt: skip
        if self._accounts is not None and not fresh:
            return self._accounts
        sso = self._client("sso", self.region)
        found = self._list_accounts(fresh=True)

        known = dict(self.state.get("roles") or {})  # roles found before: used when AWS is too busy to say

        def roles(a):
            try:
                names = []
                for page in sso.get_paginator("list_account_roles").paginate(accessToken=tok, accountId=a["accountId"]):
                    names += [r["roleName"] for r in page.get("roleList", [])]
                return sorted(names, key=role_rank)
            except Exception as exc:  # throttled even after retries: keep the rest of the list
                if "TooManyRequests" not in str(exc) and "Throttl" not in str(exc):
                    raise
                LOG.warning("SSO roles for %s: %s", a["accountId"], exc)
                return None

        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=ROLE_WORKERS) as pool:
            all_roles = list(pool.map(roles, found))
        for i, a in enumerate(found):  # a second, gentler pass for the accounts AWS turned away
            if all_roles[i] is None:
                time.sleep(ROLE_RETRY_PAUSE)
                all_roles[i] = roles(a)
        out = []
        for a, r in zip(found, all_roles):
            row = {"account": a["accountId"], "name": a.get("accountName", ""), "email": a.get("emailAddress", ""),
                   "roles": r if r is not None else list(known.get(a["accountId"], []))}  # fmt: skip
            if r is None and not row["roles"]:
                row["busy"] = True
            out.append(row)
        self.state["roles"] = {x["account"]: x["roles"] for x in out if x["roles"]}
        self._save()
        self._accounts = sorted(out, key=lambda x: (x["name"].lower(), x["account"]))
        if any(x.get("busy") for x in out):
            accounts = self._accounts
            self._accounts = None  # ask again next time rather than keep the gaps
            return accounts
        return self._accounts

    def _roles_of(self, account: str) -> list[str]:
        tok = self._need_token()
        names = []
        for page in self._client("sso", self.region).get_paginator("list_account_roles").paginate(accessToken=tok, accountId=account):
            names += [r["roleName"] for r in page.get("roleList", [])]
        return sorted(names, key=role_rank)

    def role_options(self, sample: int = 8) -> list[dict]:
        """The roles to offer for every account at once: those in a few accounts (and any found before),
        with how many of the looked-at accounts have each, read-only roles first."""
        known = dict(self.state.get("roles") or {})
        accts = self._list_accounts()
        for a in [a for a in accts if a["accountId"] not in known][:max(0, sample - len(known))]:
            try:
                known[a["accountId"]] = self._roles_of(a["accountId"])
            except Exception as exc:  # noqa: BLE001 - throttled: offer what is known
                LOG.warning("SSO roles for %s: %s", a["accountId"], exc)
                break
        with self._lock:
            self.state["roles"] = {**(self.state.get("roles") or {}), **known}
            self._save()
        count: dict[str, int] = {}
        for names in known.values():
            for r in names:
                count[r] = count.get(r, 0) + 1
        return [{"role": r, "accounts": n, "of": len(known)} for r, n in sorted(count.items(), key=lambda x: (-x[1], role_rank(x[0])))]

    def org_tree(self, role: str, fresh: bool = False) -> dict:
        """The organisation's OUs and accounts, read with `role` in the management account (any account can
        say which that is). Kept for a day: OUs rarely move."""
        got = self.state.get("org") or {}
        if not fresh and got.get("tree") and got.get("role") == role and got.get("at", 0) > _now() - 86400:
            return got["tree"]
        mine = {a["accountId"] for a in self._list_accounts()}
        if not mine:
            raise SsoError("this sign-in has no AWS accounts")
        probe = next(iter(sorted(mine)))
        try:
            org = self.role_session(probe, role).client("organizations", region_name="us-east-1")
            mgmt = org.describe_organization()["Organization"]["MasterAccountId"]
        except Exception as exc:  # noqa: BLE001 - said in words on the page
            raise SsoError(f"could not find your organisation with {role} in {probe}: {exc}")
        if mgmt not in mine:
            raise SsoError(f"your sign-in has no access to the management account {mgmt}, which holds the OUs: "
                           "choose accounts by name instead")  # fmt: skip
        try:
            import sg_review

            tree = sg_review.org_tree(self.role_session(mgmt, role).client("organizations", region_name="us-east-1",
                                                                           config=sg_review.BOTO_CONFIG))  # fmt: skip
        except Exception as exc:  # noqa: BLE001 - said in words on the page
            raise SsoError(f"{role} in the management account {mgmt} cannot list the OUs ({exc}): "
                           "choose another role, or choose accounts by name")  # fmt: skip
        with self._lock:
            self.state["org"] = {"tree": tree, "role": role, "at": _now()}
            self._save()
        return tree

    def chosen(self) -> list[dict]:
        return list(self.state.get("chosen") or [])

    def choose(self, picks: list[dict]) -> list[dict]:
        """Keep these accounts (each with the role to use) for the console."""
        known = {a["account"]: a for a in self.accounts(roles=False)}
        out = []
        for p in picks:
            acct, role = str(p.get("account", "")), str(p.get("role", ""))
            a = known.get(acct)
            if not a:
                raise SsoError(f"{acct} is not an account this sign-in can use")
            if not role or (a["roles"] and role not in a["roles"]):  # roles not looked up yet: reading will say
                raise SsoError(f"{role or 'no role'} is not a role you have in {acct}")
            out.append({"account": acct, "name": a["name"], "role": role})
        with self._lock:
            self.state["chosen"] = out
            self._sessions.clear()
            self._save()
        return out

    def session(self, account: str):
        """A boto3 session in this account with the chosen role's short-lived credentials (held in memory)."""
        pick = next((c for c in self.chosen() if c["account"] == account), None)
        if not pick:
            raise SsoError(f"{account} is not one of the accounts chosen in the console")
        return self.role_session(account, pick["role"])

    def role_session(self, account: str, role: str):
        with self._lock:
            got = self._sessions.get((account, role))
            if got and got[1] - EARLY > _now():
                return got[0]
            tok = self._need_token()
            try:
                c = self._client("sso", self.region).get_role_credentials(roleName=role, accountId=account, accessToken=tok)
            except Exception as exc:
                if "Forbidden" in type(exc).__name__ or "ForbiddenException" in str(exc) or "No access" in str(exc):
                    raise SsoError(f"you do not have {role} in {account}") from exc
                raise
            rc = c["roleCredentials"]
            import boto3

            sess = boto3.Session(aws_access_key_id=rc["accessKeyId"], aws_secret_access_key=rc["secretAccessKey"],
                                 aws_session_token=rc["sessionToken"], region_name=self.region)  # fmt: skip
            self._sessions[(account, role)] = (sess, rc["expiration"] / 1000.0)
            return sess


class SsoTargets:
    """What sg_db.Targets gives the console (who acts, and a session per account), from an SSO sign-in."""

    def __init__(self, sso: Sso, home: str | None = None):
        chosen = sso.chosen()
        if not chosen:
            raise SsoError("signed in, but no account chosen yet")
        self.sso = sso
        tries = [home] if home else [c["account"] for c in chosen[:HOME_TRIES]]
        for i, acct in enumerate(tries):  # who acts: from the first chosen account the role works in
            try:
                self.account, self.base = acct, sso.session(acct)
                arn = self.base.client("sts").get_caller_identity().get("Arn", "")
                break
            except Exception:  # an account without the role: try the next
                if i == len(tries) - 1:
                    raise
        import sg_db

        self.actor = sg_db.actor_name(arn)

    def session(self, account: str):
        return self.sso.session(account or self.account)
