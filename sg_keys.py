#!/usr/bin/env python3
"""sg_keys.py: signing the console in with keys on this computer: a profile or access key in ~/.aws.

The console's other sign-in is AWS SSO (sg_sso.py). With keys, the chosen profile is who acts; in other
accounts it assumes one role (the same name in every account, OrganizationAccountAccessRole unless you
choose another). The organisation's accounts and OUs are read with the profile itself, so it works from
the management account or a delegated administrator; from anywhere else only the profile's own account
is offered. Nothing secret is kept: only the profile name, the role and the accounts chosen.
"""

from __future__ import annotations

import configparser
import json
import os
import threading
import time
from pathlib import Path

import sg_store

DEFAULT_ROLE = "OrganizationAccountAccessRole"


class KeysError(Exception):
    pass


def known_profiles(config: Path | None = None, credentials: Path | None = None) -> list[dict]:
    """Every profile in ~/.aws/config and ~/.aws/credentials, with what kind it is (not its secrets)."""
    cfg = config or Path(os.environ.get("AWS_CONFIG_FILE") or Path.home() / ".aws" / "config")
    cred = credentials or Path(os.environ.get("AWS_SHARED_CREDENTIALS_FILE") or Path.home() / ".aws" / "credentials")
    out: dict[str, dict] = {}
    for path, is_cfg in ((cred, False), (cfg, True)):
        cp = configparser.RawConfigParser()
        try:
            cp.read(path)
        except (configparser.Error, OSError):
            continue
        for sec in cp.sections():
            if is_cfg and not (sec == "default" or sec.startswith("profile ")):
                continue  # sso-session and services sections are not profiles
            name = sec.replace("profile ", "", 1).strip()
            kind = ("sso" if cp.has_option(sec, "sso_start_url") or cp.has_option(sec, "sso_session")
                    else "role" if cp.has_option(sec, "role_arn") else "process" if cp.has_option(sec, "credential_process")
                    else "keys" if cp.has_option(sec, "aws_access_key_id") else out.get(name, {}).get("kind", "settings"))  # fmt: skip
            out[name] = {"profile": name, "kind": kind}
    if os.environ.get("AWS_ACCESS_KEY_ID") and "(environment)" not in out:
        out["(environment)"] = {"profile": "(environment)", "kind": "keys"}
    return sorted(out.values(), key=lambda p: (p["profile"] != "default", p["profile"].lower()))


class Keys:
    """The keys sign-in, with the same face the console uses for the SSO one."""

    def __init__(self, cache: Path, session_factory=None):
        self.cache = sg_store.File(cache)  # kept in the database under its old path
        self._factory = session_factory or self._boto_session
        self._lock = threading.Lock()
        self._base = None
        self._sessions: dict = {}
        self._accounts: list | None = None
        self.error = ""
        self.state = self._load()

    # ---------------------------------------------------------------- persistence
    def _load(self) -> dict:
        """What was kept; empty (and ``unloaded``) while the database is not running."""
        self.unloaded = False
        try:
            d = json.loads(self.cache.read_text())
            return d if isinstance(d, dict) else {}
        except sg_store.NotConfigured:
            self.unloaded = True
            return {}
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        if getattr(self, "unloaded", False):  # loaded while the database was down: keep what it holds
            kept = self._load()
            if not self.unloaded:
                self.state = {**kept, **self.state}
        self.cache.write_text(json.dumps(self.state, indent=1))

    @staticmethod
    def _boto_session(profile: str | None):
        import boto3

        return boto3.Session(profile_name=None if profile in (None, "", "(environment)") else profile)

    # ---------------------------------------------------------------- who
    @property
    def profile(self) -> str:
        return self.state.get("profile", "")

    @property
    def start_url(self) -> str:  # the console keys its cached targets on this
        return f"profile:{self.profile}"

    def base(self):
        """The profile's own session, checked once (an expired SSO profile says so here)."""
        if not self.profile:
            raise KeysError("choose a profile first")
        with self._lock:
            if self._base is None:
                sess = self._factory(self.profile)
                ident = sess.client("sts").get_caller_identity()
                self._base = sess
                self.state.update(account=ident["Account"], arn=ident.get("Arn", ""))
            return self._base

    def token(self) -> str:
        """Truthy while the profile works (the console's sign-in check)."""
        if not self.profile or self.state.get("signed_out"):
            return ""
        try:
            self.base()
            return self.start_url
        except Exception as exc:  # noqa: BLE001 - expired or missing keys: shown on the page
            self.error = str(exc)
            return ""

    def status(self) -> dict:
        tok = self.token()
        return {"signed_in": bool(tok), "profile": self.profile, "account": self.state.get("account", "") if tok else "",
                "arn": self.state.get("arn", "") if tok else "", "error": "" if tok else self.error,
                "role": self.state.get("role", DEFAULT_ROLE), "chosen": self.chosen(), "profiles": known_profiles()}  # fmt: skip

    def use(self, profile: str) -> dict:
        names = {p["profile"] for p in known_profiles()}
        if profile not in names:
            raise KeysError(f"{profile} is not a profile in your AWS settings")
        with self._lock:
            if profile != self.profile:
                self.state = {"profile": profile, "chosen": [], "role": self.state.get("role", DEFAULT_ROLE)}
                self._base, self._accounts = None, None
                self._sessions.clear()
            self.state.pop("signed_out", None)
        self.error = ""
        try:
            self.base()
        except Exception as exc:
            self.error = str(exc)
            raise KeysError(f"{profile} does not work: {exc}") from exc
        self._save()
        return self.status()

    def sign_out(self) -> None:
        with self._lock:
            self.state["signed_out"] = True
            self.state["chosen"] = []
            self._base, self._accounts = None, None
            self._sessions.clear()
            self._save()

    # ---------------------------------------------------------------- accounts
    def _org(self):
        import sg_review

        return self.base().client("organizations", region_name="us-east-1", config=sg_review.BOTO_CONFIG)

    def accounts(self, fresh: bool = False, roles: bool = True) -> list[dict]:
        """The organisation's active accounts when the profile may list them; else just its own."""
        if self._accounts is not None and not fresh:
            return self._accounts
        own = self.base() and self.state["account"]
        try:
            found = []
            for page in self._org().get_paginator("list_accounts").paginate():
                found += [a for a in page.get("Accounts", []) if a.get("Status", "ACTIVE") == "ACTIVE"]
            out = [{"account": a["Id"], "name": a.get("Name", ""), "email": a.get("Email", ""), "roles": []} for a in found]
        except Exception as exc:  # noqa: BLE001 - not the management account or a delegated administrator
            self.error = f"only this profile's own account: it cannot list the organisation ({exc})"
            out = [{"account": own, "name": "", "email": "", "roles": []}]
        self._accounts = sorted(out, key=lambda x: (x["account"] != own, x["name"].lower(), x["account"]))
        return self._accounts

    def role_options(self, sample: int = 0) -> list[dict]:
        role = self.state.get("role") or DEFAULT_ROLE
        out = [{"role": role, "accounts": 0, "of": 0}]
        if role != DEFAULT_ROLE:
            out.append({"role": DEFAULT_ROLE, "accounts": 0, "of": 0})
        return out

    def org_tree(self, role: str = "", fresh: bool = False) -> dict:
        got = self.state.get("org") or {}
        if not fresh and got.get("tree") and got.get("at", 0) > time.time() - 86400:
            return got["tree"]
        import sg_review

        try:
            tree = sg_review.org_tree(self._org())
        except Exception as exc:  # noqa: BLE001 - said in words on the page
            raise KeysError(f"profile {self.profile} cannot list the OUs ({exc}): use the management account or a "
                            "delegated administrator, or choose accounts by name")  # fmt: skip
        with self._lock:
            self.state["org"] = {"tree": tree, "at": time.time()}
            self._save()
        return tree

    def org_client(self):
        return self._org()

    def org_spend(self) -> dict[str, float]:
        """Each account's spend over the last 30 days, when this profile is the management account (only it sees
        every account's costs). Raises otherwise: each account is then asked for its own."""
        org = self._org().describe_organization()["Organization"]
        if org["MasterAccountId"] != self.state.get("account"):
            raise KeysError("this profile is not the management account, which alone sees every account's costs")
        import sg_review

        return sg_review.account_spend(self.base().client("ce", region_name="us-east-1"))

    def ce_client(self):
        """Cost Explorer as this profile: every account's costs from the management account, else its own."""
        return self.base().client("ce", region_name="us-east-1")

    def chosen(self) -> list[dict]:
        return [] if self.state.get("signed_out") else list(self.state.get("chosen") or [])

    def choose(self, picks: list[dict]) -> list[dict]:
        known = {a["account"]: a for a in self.accounts()}
        out = []
        for p in picks:
            acct, role = str(p.get("account", "")), str(p.get("role", "")).strip() or DEFAULT_ROLE
            if acct not in known:
                raise KeysError(f"{acct} is not an account this profile can see")
            if not all(c.isalnum() or c in "+=,.@-_/" for c in role):
                raise KeysError(f"{role} is not a role name")
            mine = acct == self.state.get("account")
            out.append({"account": acct, "name": known[acct]["name"], "role": "(this profile)" if mine else role})
        with self._lock:
            self.state["chosen"] = out
            roles = [c["role"] for c in out if c["role"] != "(this profile)"]
            if roles:
                self.state["role"] = roles[0]
            self._sessions.clear()
            self._save()
        return out

    def session(self, account: str):
        pick = next((c for c in self.chosen() if c["account"] == account), None)
        if not pick:
            raise KeysError(f"{account} is not one of the accounts chosen in the console")
        base = self.base()
        if account == self.state.get("account"):
            return base
        with self._lock:
            got = self._sessions.get(account)
            if got and got[1] - 300 > time.time():
                return got[0]
        import sg_review

        try:
            sess = sg_review._assume(base, account, pick["role"])
        except Exception as exc:
            raise KeysError(f"cannot assume {pick['role']} in {account}: {exc}") from exc
        with self._lock:
            self._sessions[account] = (sess, time.time() + 3000)  # assumed roles last an hour by default
        return sess
