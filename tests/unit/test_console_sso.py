"""sg_console: signing in with AWS SSO from the page, reading an account from it, and always running."""

from __future__ import annotations

import json
import os
import plistlib
import time
from typing import ClassVar

import pytest

import sg_console
import sg_db
import sg_ipintel as ipintel
import sg_review
import sg_sso

ACCOUNT, OTHER = "111122223333", "444455556666"


class Pending(Exception):
    pass


Pending.__name__ = "AuthorizationPendingException"


class FakeOidc:
    def __init__(self, pending=1):
        self.pending, self.registered = pending, 0

    def register_client(self, **kw):
        self.registered += 1
        return {"clientId": "cid", "clientSecret": "sec", "clientSecretExpiresAt": time.time() + 86400}

    def start_device_authorization(self, **kw):
        assert kw["startUrl"] == "https://acme.awsapps.com/start"
        return {"deviceCode": "dev", "userCode": "ABCD-EFGH", "verificationUri": "https://device.sso.eu-west-1.amazonaws.com/",
                "verificationUriComplete": "https://device.sso.eu-west-1.amazonaws.com/?user_code=ABCD-EFGH",
                "expiresIn": 600, "interval": 1}

    def create_token(self, **kw):
        if self.pending:
            self.pending -= 1
            raise Pending()
        return {"accessToken": "tok-1", "expiresIn": 28800}


class Pager:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **kw):
        return self.pages(kw)


class FakeSso:
    def __init__(self):
        self.creds_for, self.logged_out = [], False

    def get_paginator(self, name):
        if name == "list_accounts":
            return Pager(lambda kw: [{"accountList": [
                {"accountId": ACCOUNT, "accountName": "payments-prod", "emailAddress": "a@x"},
                {"accountId": OTHER, "accountName": "data-prod", "emailAddress": "b@x"}]}])
        return Pager(lambda kw: [{"roleList": [{"roleName": "AdministratorAccess"}, {"roleName": "ReadOnlyAccess"}]}])

    def get_role_credentials(self, **kw):
        assert kw["accessToken"] == "tok-1"
        self.creds_for.append((kw["accountId"], kw["roleName"]))
        return {"roleCredentials": {"accessKeyId": "AK", "secretAccessKey": "SK", "sessionToken": "ST",
                                    "expiration": int((time.time() + 3600) * 1000)}}

    def logout(self, **kw):
        self.logged_out = True


@pytest.fixture
def sso(tmp_path, monkeypatch):
    monkeypatch.setattr(sg_sso.time, "sleep", lambda s: None)
    oidc, svc = FakeOidc(), FakeSso()
    s = sg_sso.Sso(tmp_path / "sso.json", lambda name, region: oidc if name == "sso-oidc" else svc, cli_cache=tmp_path / "cli")
    s.fakes = (oidc, svc)
    return s


def _signed_in(s):
    out = s.start("https://acme.awsapps.com/start", "eu-west-1")
    for _ in range(200):
        if s.token():
            return out
        time.sleep(0.01)
    raise AssertionError("never signed in")


def test_sign_in_shows_a_code_then_lists_accounts_with_read_only_roles_first(sso):
    out = _signed_in(sso)
    assert out["code"] == "ABCD-EFGH" and "user_code=ABCD-EFGH" in out["url"] and not out["signed_in"]
    st = sso.status()
    assert st["signed_in"] and st["pending"] is None and st["from"] == "console"
    accts = sso.accounts()
    assert [a["name"] for a in accts] == ["data-prod", "payments-prod"]
    assert accts[0]["roles"][0] == "ReadOnlyAccess"
    assert oct((sso.cache.stat().st_mode) & 0o777) == "0o600"


def test_a_throttled_role_listing_keeps_the_list_and_retries_gently(sso):
    _signed_in(sso)
    svc, busy = sso.fakes[1], {"n": 0}
    real = svc.get_paginator

    def throttled(name):
        if name != "list_account_roles":
            return real(name)

        def pages(kw):
            if kw["accountId"] == OTHER and busy["n"] < busy.get("limit", 1):
                busy["n"] += 1
                raise RuntimeError("An error occurred (TooManyRequestsException) when calling the ListAccountRoles operation")
            return real(name).paginate(**kw)
        return Pager(pages)

    svc.get_paginator = throttled
    accts = {a["account"]: a for a in sso.accounts(fresh=True)}
    assert accts[OTHER]["roles"] and "busy" not in accts[OTHER], "the second, gentler pass got it"
    busy.update(n=0, limit=99)
    accts = {a["account"]: a for a in sso.accounts(fresh=True)}
    assert accts[OTHER]["roles"][0] == "ReadOnlyAccess", "roles found before are used while AWS is busy"
    sso.state["roles"] = {}
    busy.update(n=0)
    accts = {a["account"]: a for a in sso.accounts(fresh=True)}
    assert accts[OTHER]["busy"] and accts[OTHER]["roles"] == [] and accts[ACCOUNT]["roles"]
    svc.get_paginator = real
    assert "busy" not in {a["account"]: a for a in sso.accounts()}[OTHER], "a busy list is not kept"


def test_choosing_accounts_gives_a_session_per_account_with_the_chosen_role(sso):
    _signed_in(sso)
    assert sso.choose([{"account": ACCOUNT, "role": "NotMine"}]), "roles not looked up yet: reading will say"
    sso.accounts()  # now the roles are known
    with pytest.raises(sg_sso.SsoError):
        sso.choose([{"account": ACCOUNT, "role": "NotMine"}])
    with pytest.raises(sg_sso.SsoError):
        sso.choose([{"account": "999999999999", "role": "ReadOnlyAccess"}])
    sso.choose([{"account": ACCOUNT, "role": "ReadOnlyAccess"}])
    sess = sso.session(ACCOUNT)
    assert sess.get_credentials().access_key == "AK"
    sso.session(ACCOUNT)  # held until it nearly expires
    assert sso.fakes[1].creds_for == [(ACCOUNT, "ReadOnlyAccess")]
    with pytest.raises(sg_sso.SsoError):
        sso.session(OTHER)
    # a restart (the always-running copy) keeps the sign-in and the choice, not the credentials
    again = sg_sso.Sso(sso.cache, sso._client, cli_cache=sso.cli_cache)
    assert again.token() == "tok-1" and again.chosen()[0]["role"] == "ReadOnlyAccess"
    assert "AK" not in sso.cache.read_text()


def test_a_token_from_aws_sso_login_for_the_same_portal_signs_in_and_sign_out_stops_using_it(sso, tmp_path):
    (tmp_path / "cli").mkdir()
    (tmp_path / "cli" / "x.json").write_text(json.dumps({
        "startUrl": "https://acme.awsapps.com/start", "accessToken": "tok-1",
        "expiresAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600))}))
    out = sso.start("https://acme.awsapps.com/start", "eu-west-1")
    assert out == {"signed_in": True} and sso.status()["from"] == "aws cli"
    sso.sign_out()
    assert not sso.token() and sso.fakes[1].logged_out


def test_the_portal_and_region_are_read_from_the_aws_config(tmp_path):
    cfg = tmp_path / "config"
    cfg.write_text("[sso-session acme]\nsso_start_url = https://acme.awsapps.com/start\nsso_region = eu-west-1\n\n"
                   "[profile old]\nsso_start_url = https://old.awsapps.com/start\nsso_region = us-east-1\n"
                   "[profile plain]\nregion = eu-west-1\n")
    got = sg_sso.known_portals(cfg)
    assert [(p["start_url"], p["region"], p["name"]) for p in got] == [
        ("https://acme.awsapps.com/start", "eu-west-1", "acme"), ("https://old.awsapps.com/start", "us-east-1", "old")]


def test_a_start_url_that_is_not_https_is_refused(sso):
    with pytest.raises(sg_sso.SsoError):
        sso.start("acme.awsapps.com/start", "eu-west-1")


# ---------------------------------------------------------------------------------------------- reading from the page
class FakeTargets:
    actor, account = "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_ReadOnly_x/alice", ACCOUNT

    def session(self, account):
        class S:
            region_name = "eu-west-1"

            def client(self, *a, **k):
                return object()

        return S()


def test_read_from_the_page_imports_groups_prices_the_flow_logs_then_reads_on_confirm(tmp_path, monkeypatch):
    old = ipintel.DATA_DIR
    ipintel.set_data_dir(tmp_path / "data")
    try:
        imported = []
        monkeypatch.setattr(sg_db, "ensure_current", lambda st, ec2, a, r, actor, who=None, assets=False: imported.append(r) or [])

        def plan(sess, doc, regions, days, now, say=None):
            for r in regions:
                doc["regions"][r] = {"query_sets": [["lg"]]} if r == "eu-west-1" else {}
            return [("eu-west-1", now - 3600, now, [["lg"]], [])] * 3

        monkeypatch.setattr(sg_review, "plan_read", plan)
        monkeypatch.setattr(sg_review, "estimate", lambda doc, a, r, now=None: {"rate": 1e6})
        ran = {}

        def run(sess, doc, tasks, days, now, cancelled, progress=None):
            progress(3, 3, 2e9)
            ran["n"] = len(tasks)
            return {"done": 3, "bytes": 2e9}

        monkeypatch.setattr(sg_review, "run_read", run)
        c = sg_console.Console(str(tmp_path / "sg.db"), targets=FakeTargets())
        job = c.read_start({"account": ACCOUNT, "regions": "eu-west-1,us-east-1", "days": 1})
        for _ in range(200):
            if c.jobs[job["id"]]["status"] != "starting":
                break
            time.sleep(0.01)
        j = c.jobs[job["id"]]
        assert j["status"] == "confirm" and j["logs_in"] == ["eu-west-1"] and j["cost"] == 0.05, j
        assert imported == ["eu-west-1", "us-east-1"]
        with pytest.raises(sg_console.ConsoleError):
            c.read_start({"account": ACCOUNT})  # one read of an account at a time
        c.read_confirm({"id": job["id"]})
        for _ in range(200):
            if c.jobs[job["id"]]["status"] != "running":
                break
            time.sleep(0.01)
        assert j["status"] == "done" and ran["n"] == 3 and j["done"] == 3 and "2.00 GB" in j["lines"][-1]
        with pytest.raises(sg_console.ConsoleError):
            c.read_start({"account": ACCOUNT, "days": 2})
    finally:
        ipintel.set_data_dir(old)


# ---------------------------------------------------------------------------------------------- always running
def test_always_running_on_macos_writes_a_launch_agent_and_starts_it(tmp_path, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy:8080")
    calls = []

    class R:
        returncode, stdout, stderr = 0, "", ""

    svc = sg_console.Service(["/py", "/sg_console.py", "serve", "--service"], system="Darwin", home=tmp_path,
                             run=lambda cmd, **k: calls.append(cmd) or R())
    st = svc.install()
    assert st["installed"] and svc.path.name == "com.sg-tightener.console.plist"
    p = plistlib.loads(svc.path.read_bytes())
    assert p["ProgramArguments"][-1] == "--service" and p["KeepAlive"] and p["RunAtLoad"]
    assert p["EnvironmentVariables"]["HTTPS_PROXY"] == "http://proxy:8080"
    assert calls[-1][:2] == ["launchctl", "bootstrap"]
    svc.uninstall()
    assert not svc.path.exists() and calls[-1][:2] == ["launchctl", "bootout"]


def test_always_running_on_linux_is_a_systemd_user_service(tmp_path):
    calls = []

    class R:
        returncode, stdout, stderr = 0, "", ""

    svc = sg_console.Service(["/py", "/a b/sg_console.py", "serve"], system="Linux", home=tmp_path,
                             run=lambda cmd, **k: calls.append(cmd) or R())
    svc.install()
    text = svc.path.read_text()
    assert 'ExecStart="/py" "/a b/sg_console.py" "serve"' in text and "Restart=always" in text
    assert ["systemctl", "--user", "enable", "--now", "sg-console.service"] in calls
    assert not sg_console.Service([], system="Windows", home=tmp_path).status()["supported"]


def test_the_console_address_stays_the_same_across_restarts(tmp_path):
    old = ipintel.DATA_DIR
    ipintel.set_data_dir(tmp_path)
    try:
        a = sg_console.lasting_token()
        assert sg_console.lasting_token() == a and len(a) >= 24
        assert oct(os.stat(sg_console.token_file()).st_mode & 0o777) == "0o600"
        assert sg_console.lasting_token(new=True) != a
    finally:
        ipintel.set_data_dir(old)


def test_the_page_has_sign_in_read_and_always_running():
    page = sg_console.ASSET.read_text()
    for needle in ('id="ssoGo"', 'id="ssoAccounts"', 'id="chosenRows"', 'id="svcOn"', "/api/sso/start", "/api/read/confirm",
                   "/api/autostart", 'data-method="keys"', "/api/keys/use", 'id="ouTree"', "/api/sso/ous", "/api/sso/roles",
                   'id="pRole"', "/api/read/all", "/api/read/all/confirm", 'id="batch"'):
        assert needle in page


def test_on_macos_a_copy_in_a_protected_folder_is_bundled_so_the_background_copy_can_read_it(tmp_path, monkeypatch):
    src = tmp_path / "Desktop" / "sg-tightener"
    (src / "assets").mkdir(parents=True)
    (src / "assets" / "sg_console.html").write_text("page")
    (src / "sg_console.py").write_text("# app")
    monkeypatch.setattr(sg_console, "RUNTIME", ("six",))

    class R:
        returncode, stdout, stderr = 0, "", ""

    svc = sg_console.Service(["/venv/bin/python", str(src / "sg_console.py"), "serve", "--service"], system="Darwin",
                             home=tmp_path, src=src, run=lambda cmd, **k: R())
    assert svc.needs_copy()
    svc.install()
    p = plistlib.loads(svc.path.read_bytes())
    app = tmp_path / ".sg-tightener" / "app"
    assert p["ProgramArguments"][1] == str(app / "sg_console.py") and (app / "assets" / "sg_console.html").exists()
    assert p["EnvironmentVariables"]["PYTHONPATH"] == str(app / "lib") and (app / "lib" / "six.py").exists()
    assert "/venv/" not in p["ProgramArguments"][0]
    assert not sg_console.Service([], system="Darwin", home=tmp_path, src=tmp_path / "code").needs_copy()


# ---------------------------------------------------------------------------------------------- an OU at once
class FakeOrg:
    """root -> Prod (2 accounts, with Payments OU under it holding 1) and Sandbox (1)."""

    TREE: ClassVar[dict] = {"r-1": (["111111111111"], ["ou-prod", "ou-sbx"]), "ou-prod": (["222222222222", "333333333333"], ["ou-pay"]),
            "ou-pay": (["444444444444"], []), "ou-sbx": (["555555555555"], [])}
    NAMES: ClassVar[dict] = {"ou-prod": "Prod", "ou-pay": "Payments", "ou-sbx": "Sandbox"}

    def list_roots(self):
        return {"Roots": [{"Id": "r-1", "Name": "Root"}]}

    def describe_organization(self):
        return {"Organization": {"MasterAccountId": "111111111111"}}

    def get_paginator(self, op):
        def pages(kw):
            accts, ous = self.TREE[kw["ParentId"]]
            if op == "list_accounts_for_parent":
                return [{"Accounts": [{"Id": a, "Name": f"acct-{a[:3]}", "Status": "ACTIVE"} for a in accts]}]
            return [{"OrganizationalUnits": [{"Id": o, "Name": self.NAMES[o]} for o in ous]}]
        if op == "list_accounts":
            return Pager(lambda kw: [{"Accounts": [{"Id": a, "Name": f"acct-{a[:3]}", "Status": "ACTIVE"}
                                                   for v in self.TREE.values() for a in v[0]]}])
        return Pager(pages)


def _walk(n):
    yield n
    for c in n["children"]:
        yield from _walk(c)


def test_the_ou_tree_has_every_ou_with_its_own_accounts_and_the_ous_under_it():
    tree = sg_review.org_tree(FakeOrg())
    assert tree["name"] == "Root" and [a["account"] for a in tree["accounts"]] == ["111111111111"]
    prod = next(n for n in _walk(tree) if n["name"] == "Prod")
    assert [a["account"] for a in prod["accounts"]] == ["222222222222", "333333333333"]
    assert [c["name"] for c in prod["children"]] == ["Payments"]
    assert [c["name"] for c in tree["children"]] == ["Prod", "Sandbox"]


def test_sso_reads_the_ou_tree_with_the_chosen_role_in_the_management_account(sso, monkeypatch):
    _signed_in(sso)
    used = []

    class Sess:
        def client(self, *a, **k):
            return FakeOrg()

    def role_session(account, role):
        used.append((account, role))
        return Sess()

    monkeypatch.setattr(sso, "role_session", role_session)
    monkeypatch.setattr(sso, "_list_accounts", lambda fresh=False: [{"accountId": "111111111111"}, {"accountId": "222222222222"}])
    tree = sso.org_tree("CTO-Read")
    assert tree["children"][0]["name"] == "Prod" and ("111111111111", "CTO-Read") in used
    n = len(used)
    sso.org_tree("CTO-Read")
    assert len(used) == n, "kept for a day"
    monkeypatch.setattr(sso, "_list_accounts", lambda fresh=False: [{"accountId": "222222222222"}])
    with pytest.raises(sg_sso.SsoError, match="management account"):
        sso.org_tree("Other")


def test_one_role_for_every_account_is_offered_from_a_few_accounts(sso):
    _signed_in(sso)
    opts = sso.role_options()
    assert opts[0]["role"] == "ReadOnlyAccess" and opts[0]["accounts"] == 2 and opts[0]["of"] == 2
    fast = sso.accounts(roles=False)
    assert {a["account"] for a in fast} == {ACCOUNT, OTHER} and fast[0]["roles"], "roles found before are given"
    sso.choose([{"account": a["account"], "role": "ReadOnlyAccess"} for a in fast])
    assert {c["role"] for c in sso.chosen()} == {"ReadOnlyAccess"}


def test_keys_on_this_computer_list_profiles_and_read_the_organisation_with_the_profile(tmp_path, monkeypatch):
    (tmp_path / "config").write_text("[default]\nregion = eu-west-1\n[profile mgmt]\nsso_session = acme\n"
                                     "[sso-session acme]\nsso_start_url = https://x\n[profile ci]\nrole_arn = arn:aws:iam::1:role/x\n")
    (tmp_path / "credentials").write_text("[default]\naws_access_key_id = AKIA\naws_secret_access_key = s\n")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials"))
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    import sg_keys

    got = {p["profile"]: p["kind"] for p in sg_keys.known_profiles()}
    assert got == {"default": "keys", "mgmt": "sso", "ci": "role"}

    class Sess:
        def __init__(self, can_list=True):
            self.can_list = can_list

        def client(self, name, **k):
            if name == "sts":
                class Sts:
                    def get_caller_identity(self):
                        return {"Account": "111111111111", "Arn": "arn:aws:iam::111111111111:user/alice"}
                return Sts()
            if not self.can_list:
                raise RuntimeError("AccessDenied")
            return FakeOrg()

    k = sg_keys.Keys(tmp_path / "keys.json", session_factory=lambda p: Sess())
    with pytest.raises(sg_keys.KeysError):
        k.use("nope")
    st = k.use("mgmt")
    assert st["signed_in"] and st["account"] == "111111111111" and "AKIA" not in (tmp_path / "keys.json").read_text()
    assert len(k.accounts()) == 5 and k.accounts()[0]["account"] == "111111111111", "its own account first"
    assert next(n for n in _walk(k.org_tree()) if n["name"] == "Payments")["accounts"][0]["account"] == "444444444444"
    chosen = k.choose([{"account": "111111111111", "role": "CTO-Read"}, {"account": "222222222222", "role": "CTO-Read"}])
    assert [c["role"] for c in chosen] == ["(this profile)", "CTO-Read"] and k.status()["role"] == "CTO-Read"
    assert k.session("111111111111") is k.base()
    k2 = sg_keys.Keys(tmp_path / "keys2.json", session_factory=lambda p: Sess(can_list=False))
    k2.use("default")
    assert [a["account"] for a in k2.accounts()] == ["111111111111"], "not the management account: its own only"


class Chosen:
    def __init__(self, accounts):
        self._c = [{"account": a, "name": f"n{a[:3]}", "role": "CTO-Read"} for a in accounts]

    def chosen(self):
        return self._c


def test_reading_an_ou_prices_every_account_then_reads_them_all_on_one_confirm(tmp_path, monkeypatch):
    old = ipintel.DATA_DIR
    ipintel.set_data_dir(tmp_path / "data")
    try:
        monkeypatch.setattr(sg_db, "ensure_current", lambda *a, **k: [])
        accts = [f"{i}" * 12 for i in range(1, 7)]

        def plan(sess, doc, regions, days, now, say=None):
            if doc["account"] == accts[1]:
                raise RuntimeError("AccessDenied: no CTO-Read here")
            for r in regions:
                doc["regions"][r] = {"query_sets": [["lg"]]}
            return [] if doc["account"] == accts[2] else [("eu-west-1", now - 3600, now, [["lg"]], [])] * 2

        monkeypatch.setattr(sg_review, "plan_read", plan)
        monkeypatch.setattr(sg_review, "estimate", lambda doc, a, r, now=None: {"rate": 1e6})
        ran = []
        monkeypatch.setattr(sg_review, "run_read", lambda sess, doc, tasks, days, now, cancelled, progress=None:
                            ran.append(doc["account"]) or {"done": len(tasks), "bytes": 1e9})
        c = sg_console.Console(str(tmp_path / "sg.db"), targets=FakeTargets(), sso=Chosen(accts))

        def wait(status):
            for _ in range(500):
                if c.batch_status()["status"] != status:
                    return c.batch_status()
                time.sleep(0.01)
            raise AssertionError(c.batch_status())

        b = c.read_all({"regions": "eu-west-1", "days": 1})
        assert b["accounts"] == 6
        with pytest.raises(sg_console.ConsoleError):
            c.read_all({"regions": "eu-west-1"})  # one at a time
        b = wait("pricing")
        assert b["status"] == "confirm" and b["to_read"] == 4 and b["count"]["failed"] == 1 and b["count"]["done"] == 1
        assert b["cost"] > 0 and b["cost_unknown"] == 0
        assert not ran, "nothing is spent before the confirm"
        c.read_all_confirm({})
        b = wait("running")
        assert b["status"] == "done" and sorted(ran) == sorted([accts[0], *accts[3:]]) and b["bytes"] == 4e9
        assert len(c.job_list()) == 6 and all(j["batch"] == b["id"] for j in c.job_list())
        # stopping while it is priced leaves the rest unread
        c.read_all({"regions": "eu-west-1"})
        c.read_all_stop({})
        b = wait("pricing")
        assert b["status"] in ("stopped", "confirm")  # stopped, unless every account was priced first
    finally:
        ipintel.set_data_dir(old)
