"""sg_console: the local web console. Who may talk to it, and the propose -> approve flow through its API."""

from __future__ import annotations

import http.client
import json
import threading
import time

import pytest

import sg_console
import sg_db
import sg_ipintel as ipintel
import sg_review
import sg_review_demo as demo

ACCOUNT, REGION, GID = "111122223333", "eu-west-1", "sg-0aaa000000000001"


class FakeTargets:
    def __init__(self, actor):
        self.actor, self.account = actor, ACCOUNT

    def session(self, account):
        raise AssertionError("these tests do not reach AWS")


@pytest.fixture
def console(tmp_path):
    old = ipintel.DATA_DIR
    ipintel.set_data_dir(tmp_path / "data")
    db = tmp_path / "sg.db"
    st = sg_db.Store(db)
    with st:
        st.import_region(ACCOUNT, REGION, {GID: {"name": "web", "vpc": "vpc-1", "description": "web tier", "rules": {
            (sg_db.IN, "tcp", 443, 443, "10.0.0.0/16"): "lb"}}}, "arn:aws:sts::111122223333:assumed-role/Admin/alice")
        st.name_account(ACCOUNT, "payments-prod")
    st.close()
    targets = FakeTargets("arn:aws:sts::111122223333:assumed-role/Admin/alice")
    c = sg_console.Console(str(db), targets=targets)
    httpd, token = sg_console.serve(c, 0, "t0ken")
    port = httpd.server_address[1]
    # serve() built the Host check for port 0; rebuild it for the real one.
    httpd.RequestHandlerClass = sg_console.make_handler(c, token, port)
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    yield {"port": port, "token": token, "targets": targets, "db": db}
    httpd.shutdown()
    httpd.server_close()
    ipintel.set_data_dir(old)


def _req(port, method, path, body=None, header=True, host=None, ctype="application/json", extra=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Host": host or f"127.0.0.1:{port}", **(extra or {})}
    if body is not None:
        h["Content-Type"] = ctype
        if header:
            h["X-SG-Token"] = "t0ken"
    conn.request(method, path, json.dumps(body) if body is not None else None, h)
    r = conn.getresponse()
    data = r.read()
    try:
        out = json.loads(data)
    except ValueError:
        out = data.decode()
    return r.status, out, dict(r.getheaders())


def test_the_page_opens_without_a_token_and_other_sites_are_refused(console):
    p = console["port"]
    status, _, headers = _req(p, "GET", "/?token=from-an-old-bookmark")
    assert status == 303 and headers["Location"] == "/" and "Set-Cookie" not in headers
    assert _req(p, "GET", "/api/state", extra={"Sec-Fetch-Site": "same-origin"})[0] == 200
    assert _req(p, "GET", "/api/state", extra={"Sec-Fetch-Site": "cross-site"})[0] == 403
    assert _req(p, "GET", "/api/state", extra={"Sec-Fetch-Site": "same-site"})[0] == 403
    assert _req(p, "GET", "/api/state", extra={"Origin": "https://evil.example"})[0] == 403
    status, page, headers = _req(p, "GET", "/", extra={"Sec-Fetch-Site": "none"})
    assert status == 200 and "Security Group Console" in page
    assert "{{" not in page, "nonce and token are filled in"
    csp = headers["Content-Security-Policy"]
    nonce = csp.split("'nonce-")[1].split("'")[0]
    assert f'nonce="{nonce}"' in page and "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
    assert headers["X-Frame-Options"] == "DENY"


def test_another_host_name_is_refused_so_dns_rebinding_cannot_reach_it(console):
    p = console["port"]
    assert _req(p, "GET", "/api/state", host=f"evil.example:{p}")[0] == 421
    assert _req(p, "POST", "/api/decide", {"id": 1, "action": "approve"}, host="evil.example")[0] == 421


def test_a_change_needs_the_header_and_json_so_another_page_cannot_post_one(console):
    p = console["port"]
    body = {"id": 1, "action": "approve"}
    assert _req(p, "POST", "/api/decide", body, header=False)[0] == 403
    assert _req(p, "POST", "/api/decide", body, extra={"Sec-Fetch-Site": "cross-site"})[0] == 403
    assert _req(p, "POST", "/api/decide", body, extra={"Origin": "https://evil.example"})[0] == 403
    assert _req(p, "POST", "/api/decide", body, extra={"Origin": f"http://127.0.0.1:{p}"})[0] != 403
    assert _req(p, "POST", "/api/decide", body, ctype="text/plain")[0] == 415


def test_propose_then_a_different_person_approves_through_the_api(console):
    p, t = console["port"], console["targets"]
    status, state, _ = _req(p, "GET", "/api/state")
    assert status == 200 and state["approvals"] is True
    assert state["accounts"][0]["name"] == "payments-prod"
    assert state["accounts"][0]["regions"][0]["groups"] == 1 and state["verify"]["ok"]

    change = {"group": GID, "op": "add", "rule": {"direction": "in", "proto": "tcp", "from": 8443, "to": 8443,
                                                  "source": "10.1.0.0/24", "description": "admin"}}
    assert _req(p, "POST", "/api/propose", {"account": ACCOUNT, "region": REGION, "reason": "", "changes": [change]})[0] == 409
    status, res, _ = _req(p, "POST", "/api/propose", {"account": ACCOUNT, "region": REGION, "reason": "admin port",
                                                      "ticket": "CHG-9", "changes": [change]})
    assert status == 200 and res["status"] == "pending"
    rid = res["id"]

    status, err, _ = _req(p, "POST", "/api/decide", {"id": rid, "action": "approve"})
    assert status == 409 and "different person" in err["error"]

    t.actor = "arn:aws:sts::111122223333:assumed-role/Admin/bob"
    assert _req(p, "POST", "/api/decide", {"id": rid, "action": "reject"})[0] == 409, "a rejection needs a note"
    status, res, _ = _req(p, "POST", "/api/decide", {"id": rid, "action": "approve", "note": "ok"})
    assert status == 200 and res["status"] == "approved"

    _, groups, _ = _req(p, "GET", f"/api/groups?account={ACCOUNT}&region={REGION}")
    states = {(r["from"], r["state"]) for r in groups[0]["rules"]}
    assert (8443, "want") in states and (443, "both") in states
    _, pending, _ = _req(p, "GET", "/api/requests?status=approved")
    assert [r["id"] for r in pending] == [rid]
    _, drift, _ = _req(p, "GET", f"/api/drift?account={ACCOUNT}&region={REGION}")
    assert [(d["change"], d["apply"]) for d in drift] == [(f"approved in request #{rid}, not applied yet", "adds it")]

    _, log, _ = _req(p, "GET", "/api/audit?q=chg-9")
    acts = [e["action"] for e in log]
    assert {"request-proposed", "request-approved", "desired-changed"} <= set(acts)
    assert acts.index("request-approved") < acts.index("request-proposed"), "newest first"


def test_bad_input_is_a_400_not_a_traceback(console):
    p = console["port"]
    assert _req(p, "POST", "/api/propose", {"account": ACCOUNT, "region": REGION, "reason": "x",
                                            "changes": [{"group": GID, "op": "add", "rule": {}}]})[0] == 400
    assert _req(p, "POST", "/api/decide", {"id": "x", "action": "approve"})[0] == 400
    assert _req(p, "GET", "/api/refused?range=2y")[0] == 400
    assert _req(p, "GET", "/api/refused?range=1y")[0] == 200
    assert _req(p, "GET", "/api/nope")[0] == 404


def test_rejected_traffic_across_every_account_read(console):
    p = console["port"]
    _, empty, _ = _req(p, "GET", "/api/refused?range=1w")
    assert empty["rows"] == []
    doc = demo.build_doc(demo.ACCOUNT, time.time(), 7)
    doc["name"] = "demo-prod"
    sg_review.save(doc)
    status, got, _ = _req(p, "GET", "/api/refused?range=1w")
    assert status == 200 and got["rows"]
    assert got["accounts"][0]["account"] == demo.ACCOUNT and got["accounts"][0]["refused"] > 0
    assert got["accounts"][0]["covered"] == 1.0 and got["accounts"][0]["first"]
    _, year, _ = _req(p, "GET", "/api/refused?range=1y")
    assert 0 < year["accounts"][0]["covered"] < 0.1  # a week of a year: the page says what has no data
    ranks = [sg_review.SEV_RANK[r["sev"]] for r in got["rows"]]
    assert ranks == sorted(ranks), "worst verdict first"
    assert {"src", "port", "verdict", "groups", "account_name"} <= set(got["rows"][0])


def test_risk_overview_compares_every_account_read(console):
    p = console["port"]
    assert _req(p, "GET", "/api/macro?range=2y")[0] == 400
    _, empty, _ = _req(p, "GET", "/api/macro?range=1m")
    assert empty["accounts"] == [] and empty["kinds"] and empty["types"]
    for acct, name, days in ((demo.ACCOUNT, "demo-prod", 30), ("444455556666", "data-prod", 14)):
        doc = demo.build_doc(acct, time.time(), days)
        doc["name"] = name
        sg_review.save(doc)
    status, got, _ = _req(p, "GET", "/api/macro?range=1m")
    assert status == 200 and {a["account"] for a in got["accounts"]} == {demo.ACCOUNT, "444455556666"}
    a = next(x for x in got["accounts"] if x["account"] == demo.ACCOUNT)
    assert a["name"] == "demo-prod" and a["mode"] == "surveillance"
    assert a["over_now"] > 0 and abs(sum(a["over_by_cat"].values()) - a["over_now"]) <= 1
    assert abs(sum(a["over_by_type"].values()) - a["over_now"]) <= 1
    assert all(len(v) == len(a["bins"]) for v in a["over_series"].values()) and len(a["high_series"]) == len(a["bins"])
    assert a["open_risky"] >= 1 and all(r["ports"] and r["service"] for r in a["open_risky_list"])
    assert a["high_active"] >= 1 and a["high_refused"] >= 1
    assert a["external_refused"] + a["internal_refused"] <= a["refused"] + 1
    impact = [r["never"] * max(1, r["enis"]) for r in a["top_rules"]]
    assert impact and impact == sorted(impact, reverse=True), "biggest wins first: never seen times assets reached"
    # over-exposure per asset, rated red / amber / green
    assert got["rag"] == {"green_max": sg_review.RAG_GREEN_MAX, "amber_max": sg_review.RAG_AMBER_MAX}
    assert a["assets_total"] == sum(a["asset_rag"].values()) == len(a["assets"]) > 0
    by_eni = {x["eni"]: x for x in a["assets"]}
    assert by_eni["eni-0leg1"]["rag"] == "red" and by_eni["eni-0leg1"]["open_risky"], "RDP open to the internet is red"
    assert by_eni["eni-0app1"]["over"] > sg_review.RAG_AMBER_MAX and by_eni["eni-0app1"]["rag"] == "red"
    assert by_eni["eni-0alb1"]["rag"] == "green", "open on 443 is listed, not counted"
    assert all(sum(a["asset_rag_series"][k][i] for k in a["asset_rag"]) == a["assets_total"] for i in range(len(a["bins"])))
    assert a["rag"] == "red" and a["over_start"] == a["over_total_series"][0]
    assert set(a["attention"]) >= {"critical", "high", "medium"}
    again = _req(p, "GET", "/api/macro?range=1m")[1]
    assert again["accounts"] == got["accounts"], "cached while the read has not changed"


def test_remediate_has_a_box_to_find_an_account():
    page = sg_console.ASSET.read_text()
    assert 'id="xFind"' in page and '$("xFind").value' in page


def test_the_page_has_the_risk_overview():
    page = sg_console.ASSET.read_text()
    for needle in ('data-tab="macro"', 'id="tab-macro"', 'id="mHeat"', 'id="mOwner"', 'id="mOverTime"', 'id="mExposure"',
                   'id="mLetIn"', 'id="mBlind"', "/api/macro", 'data-tab="over"', 'id="oTiles"', 'id="oAccounts"',
                   'id="oAssets"', 'id="oRagTime"', 'id="oWins"', 'id="mFocus"', 'id="mOwn"', 'id="mOwnTag"', 'data-lens="external"',
                   'data-lens="saas"', 'data-lens="internal"'):
        assert needle in page


def test_overview_shows_each_accounts_mode_and_assets(console):
    p = console["port"]
    _, state, _ = _req(p, "GET", "/api/state")
    acct = state["accounts"][0]
    assert acct["mode"] == "surveillance", "every account starts in surveillance mode"
    assert acct["regions"][0]["permissions"] is None and acct["regions"][0]["assets"] == 0
    st = sg_db.Store(console["db"])
    with st:
        st.set_mode(ACCOUNT, "enforce", "arn:aws:sts::111122223333:assumed-role/Admin/alice", "ready")
    st.close()
    _, state, _ = _req(p, "GET", "/api/state")
    assert state["accounts"][0]["mode"] == "enforce"
    assert _req(p, "GET", f"/api/assets?account={ACCOUNT}&region={REGION}")[1] == []
    assert _req(p, "GET", "/api/asset-history?eni=eni-1")[1] == []


def test_rejected_traffic_tab_has_new_ipv6_and_origin_filters():
    import pathlib

    page = pathlib.Path(__file__).resolve().parents[2].joinpath("assets", "sg_console.html").read_text()
    for needle in ('id="fNew"', 'id="fWhere"', "r.new", "r.v6", "r.internal", "r.scan", "first seen"):
        assert needle in page, needle


def test_review_page_is_served_with_the_nonce_and_can_propose_its_plan(console):
    p = console["port"]
    status, body, _ = _req(p, "GET", f"/review?account={demo.ACCOUNT}")
    assert status == 404 and "sg_review" in body["error"]
    doc = demo.build_doc(demo.ACCOUNT, time.time(), 30)  # rules are fitted only from 30 days or more
    sg_review.save(doc)
    status, page, headers = _req(p, "GET", f"/review?account={demo.ACCOUNT}")
    assert status == 200 and 'id="fitWrap"' in page
    nonce = headers["Content-Security-Policy"].split("'nonce-", 1)[1].split("'", 1)[0]
    assert page.count(f'<script nonce="{nonce}">') == 2 and "<script>" not in page
    assert "connect-src 'self'" in page and "connect-src 'none'" not in page
    data = json.loads(page.split('<script type="application/json" id="data">', 1)[1].split("</script>", 1)[0])
    assert data["console"] == {"token": "t0ken"} and data["fit"]["rules"]
    st = sg_db.Store(console["db"])
    with st:
        st.import_region(demo.ACCOUNT, REGION, {"sg-0app0000000000001": {"name": "app", "vpc": "vpc-1", "description": "",
                         "rules": {(sg_db.IN, "tcp", 443, 443, "10.0.0.0/8"): "callers"}}}, "alice")  # fmt: skip
    st.close()
    _, state, _ = _req(p, "GET", "/api/state")
    assert {a["account"]: a["reviewed"] for a in state["accounts"]} == {ACCOUNT: False, demo.ACCOUNT: True}
    # What the page posts (fitPropose): proto as a number, one change per range.
    change = lambda op, src: {"group": "sg-0app0000000000001", "op": op, "rule": {
        "direction": "in", "proto": "6", "from": 443, "to": 443, "source": src, "description": "callers"}}
    status, got, _ = _req(p, "POST", "/api/propose", {"account": demo.ACCOUNT, "region": REGION, "reason": "fitted",
                                                       "changes": [change("remove", "10.0.0.0/8"), change("add", "10.20.1.0/24")]})  # fmt: skip
    assert status == 200 and got["status"] == "pending", got


def test_groups_on_no_interface_are_left_out_of_the_counts_and_flagged(console):
    import sg_assets

    r2 = "eu-west-2"
    st = sg_db.Store(console["db"])
    with st:
        st.import_region(ACCOUNT, r2, {"sg-0ccc000000000003": {"name": "app", "vpc": "vpc-2", "description": "", "rules": {
            (sg_db.IN, "tcp", 443, 443, "10.0.0.0/16"): ""}}, "sg-0bbb000000000002": {"name": "old", "vpc": "vpc-2",
            "description": "", "rules": {(sg_db.IN, "tcp", 22, 22, "0.0.0.0/0"): ""}}},
            "arn:aws:sts::111122223333:assumed-role/Admin/alice")  # fmt: skip
    st.close()
    p = console["port"]

    def region():
        _, state, _ = _req(p, "GET", "/api/state")
        return next(r for r in state["accounts"][0]["regions"] if r["region"] == r2)

    assert region()["groups"] == 2, "interfaces never read: every group counts"
    st = sg_db.Store(console["db"])
    with st:
        sg_assets.observe_assets(st, ACCOUNT, r2, [{"eni": "eni-1", "instance": "i-1", "asg": "", "kind": "instance",
                                                    "vpc_id": "vpc-2", "ips": ["10.0.0.5"], "groups": ["sg-0ccc000000000003"],
                                                    "description": ""}], "alice")  # fmt: skip
    st.close()
    r = region()
    assert r["groups"] == 1 and r["rules"] == 1 and r["unused"] == 1
    groups = {g["name"]: g["enis"] for g in _req(p, "GET", f"/api/groups?account={ACCOUNT}&region={r2}")[1]}
    assert groups == {"app": 1, "old": 0}


def test_changed_outside_the_tool_is_explained_rule_by_rule(console):
    r2 = "eu-west-3"
    gid = "sg-0ddd000000000004"
    keep, extra = (sg_db.IN, "tcp", 443, 443, "10.0.0.0/16"), (sg_db.IN, "tcp", 5432, 5432, "100.65.0.0/16")
    st = sg_db.Store(console["db"])
    with st:
        st.import_region(ACCOUNT, r2, {gid: {"name": "db", "vpc": "vpc-3", "description": "", "rules": {keep: "web"}}},
                         "arn:aws:sts::111122223333:assumed-role/Admin/alice")  # fmt: skip
        st.observe(ACCOUNT, r2, {gid: {"name": "db", "vpc": "vpc-3", "description": "", "rules": {extra: "eks"}}},
                   "alice", who=lambda g: "bob")  # fmt: skip
    st.close()
    p = console["port"]
    _, state, _ = _req(p, "GET", "/api/state")
    assert next(r for r in state["accounts"][0]["regions"] if r["region"] == r2)["pending"] == 2
    _, drift, _ = _req(p, "GET", f"/api/drift?account={ACCOUNT}&region={r2}")
    got = {(d["change"], d["rule"], d["apply"], d["keep"], d["by"], d["name"]) for d in drift}
    assert got == {("added in AWS", sg_db.rule_text(extra), "removes it again", "keeps it", "bob", "db"),
                   ("removed in AWS", sg_db.rule_text(keep), "adds it back", "leaves it removed", "bob", "db")}
    assert all(d["noticed"] for d in drift)
    assert _req(p, "GET", f"/api/drift?account={ACCOUNT}")[0] == 400


def test_spend_is_read_for_every_account_with_credits_left_out():
    calls = []

    class Ce:
        def get_cost_and_usage(self, **kw):
            calls.append(kw)
            page = [{"Groups": [{"Keys": ["111111111111"], "Metrics": {"UnblendedCost": {"Amount": "60.5"}}}]}]
            if "NextPageToken" not in kw:
                return {"ResultsByTime": page, "NextPageToken": "n"}
            return {"ResultsByTime": page + [{"Groups": [{"Keys": ["222222222222"], "Metrics": {"UnblendedCost": {"Amount": "5"}}}]}]}

    assert sg_review.account_spend(Ce()) == {"111111111111": 121.0, "222222222222": 5.0}
    assert calls[0]["Filter"]["Not"]["Dimensions"]["Values"] == ["Credit", "Refund"] and len(calls) == 2


def test_the_owner_comes_from_the_first_owner_like_tag():
    assert sg_review.owner_of([{"Key": "team", "Value": "core"}, {"Key": "Business-Owner", "Value": "Jo"}]) == "Jo"
    assert sg_review.owner_of([{"Key": "Owner", "Value": "  "}, {"Key": "Team", "Value": "core"}]) == "core"
    assert sg_review.owner_of([{"Key": "CostCentre", "Value": "1"}]) == "" and sg_review.owner_of([]) == ""


def test_the_risk_charts_get_each_accounts_spend_and_owner(tmp_path, monkeypatch):
    old = ipintel.DATA_DIR
    ipintel.set_data_dir(tmp_path / "data")
    try:
        class Org:
            def get_paginator(self, name):
                class P:
                    def paginate(self, ResourceId):
                        return [{"Tags": [{"Key": "Owner", "Value": "Jo"}] if ResourceId == "1" else []}]
                return P()

        class Auth:
            def chosen(self):
                return []

            def org_spend(self):
                return {"1": 250.0}

            def org_client(self):
                return Org()

        c = sg_console.Console(str(tmp_path / "sg.db"), targets=FakeTargets("x"), sso=Auth())
        spend, owners, pending, why = c._facts(["1", "2"])
        assert spend == {"1": 250.0} and pending and not why
        c._owner_thread.join(5)
        spend, owners, pending, _ = c._facts(["1", "2"])
        assert {a: v["owner"] for a, v in owners.items()} == {"1": "Jo", "2": ""} and not pending, "looked up once, kept a day"
        assert owners["1"]["tags"] == {"Owner": "Jo"}, "every tag is kept: the page groups risk by any of them"

        class NoCosts(Auth):
            def org_spend(self):
                raise RuntimeError("AccessDenied")

        c2 = sg_console.Console(str(tmp_path / "sg.db"), targets=FakeTargets("x"), sso=NoCosts())
        spend, _, _, why = c2._facts(["1"])
        assert spend is None and "AccessDenied" in why
    finally:
        ipintel.set_data_dir(old)


def _demo_store(tmp_path):
    """The demo account read by sg_review, and its groups in the console's database."""
    ipintel.set_data_dir(tmp_path / "data")
    doc = demo.build_doc(demo.ACCOUNT, time.time(), 90)
    sg_review.save(doc)
    st = sg_db.Store(tmp_path / "sg.db")
    with st:
        for region, x in doc["regions"].items():
            groups = {}
            for gid, g in x["snapshot"]["groups"].items():
                rules = {}
                for r in g["rules"]:
                    for c in list(r.get("cidrs") or []) + list(r.get("cidrs6") or []):
                        rules[(sg_db.IN, sg_db._proto(r["proto"]), r["from"], r["to"], c)] = ""
                groups[gid] = {"name": g["name"], "vpc": g["vpc"], "description": "", "rules": rules}
            st.import_region(demo.ACCOUNT, region, groups, "arn:aws:sts::111122223333:assumed-role/Admin/alice")
    st.close()
    return sg_console.Console(str(tmp_path / "sg.db"), targets=FakeTargets("arn:aws:sts::111122223333:assumed-role/Admin/alice"))


def test_the_plan_gives_each_rule_its_new_rule_and_what_it_takes_away(tmp_path):
    old = ipintel.DATA_DIR
    try:
        c = _demo_store(tmp_path)
        plan = c.verdicts(demo.ACCOUNT, REGION)
        assert plan["read"] and plan["rules"]
        by = {r["action"] for r in plan["rules"]}
        assert {"tighten", "remove"} <= by
        t = next(r for r in plan["rules"] if r["action"] == "tighten" and r["source"] == "10.0.0.0/8")
        assert t["new"] and all(n["proto"] == t["proto"] and n["from"] == t["from"] for n in t["new"])
        assert t["addresses"] == 2 ** 24 and 0 < t["new_addresses"] < t["addresses"]
        assert t["cut_addresses"] == t["addresses"] - t["new_addresses"]
        gone = next(r for r in plan["rules"] if r["action"] == "remove")
        assert gone["new"] == [] and gone["new_addresses"] == 0 and gone["new_ports"] == 0
        assert all(r["new"] is None for r in plan["rules"] if r["action"] in ("keep", "open", "wait"))
        assert sum(g["cut"] for g in plan["groups"].values()) == sum(r["cut_addresses"] for r in plan["rules"])
    finally:
        ipintel.set_data_dir(old)


def test_proposing_the_plan_removes_each_old_rule_and_adds_its_new_ones(tmp_path):
    old = ipintel.DATA_DIR
    try:
        c = _demo_store(tmp_path)
        plan = c.verdicts(demo.ACCOUNT, REGION)
        one = next(r for r in plan["rules"] if r["action"] == "tighten")
        res = c.tighten({"account": demo.ACCOUNT, "region": REGION, "keys": [one["key"]]})
        assert res["id"] and res["rules"] == 1 and res["cut_addresses"] == one["cut_addresses"]
        st = sg_db.Store(tmp_path / "sg.db")
        try:
            req = st._request(res["id"])
        finally:
            st.close()
        assert "flow logs" in req["reason"]
        body = json.dumps(req["changes"])
        assert one["source"] in body and one["new"][0]["source"] in body
        whole = c.tighten({"account": demo.ACCOUNT, "region": REGION})
        assert whole["rules"] == sum(1 for r in plan["rules"] if r["action"] in sg_console.ACTIONABLE)
        with pytest.raises(sg_console.ConsoleError):
            c.tighten({"account": demo.ACCOUNT, "region": REGION, "keys": ["no|such|rule"]})
    finally:
        ipintel.set_data_dir(old)


def test_a_port_range_narrows_to_the_ports_seen():
    assert sg_console._port_ranges({"proto": "6", "from": 8000, "to": 8100}, [("6", 8080), ("6", 8081), ("6", 8443), ("17", 8090)]) == [[8080, 8081]]
    assert sg_console._port_ranges({"proto": "6", "from": 0, "to": 65535}, [("6", 443), ("6", 40000)]) == [[443, 443], [40000, 40000]]
    # replies, folded into EPHEMERAL, need no inbound rule (groups are stateful): only the real port is kept
    assert sg_console._port_ranges({"proto": "6", "from": 0, "to": 65535}, [("6", 443), ("6", 32768)]) == [[443, 443]]
    assert sg_console._port_ranges({"proto": "6", "from": 443, "to": 443}, [("6", 443)]) is None
    assert sg_console._port_ranges({"proto": "-1", "from": 0, "to": 65535}, [("6", 443)]) is None
    assert sg_console._port_ranges({"proto": "6", "from": 1, "to": 100}, []) is None


def test_a_report_answers_from_its_last_rows_while_an_account_is_being_read(tmp_path, monkeypatch):
    import os

    import sg_review

    read_at = {"1": time.time()}
    monkeypatch.setattr(sg_review, "cached_accounts", lambda: list(read_at))
    monkeypatch.setattr(sg_review, "stamps", lambda: dict(read_at))
    built = []
    monkeypatch.setattr(sg_review, "report_row", lambda kind, a, n, r: built.append(a) or {"v": len(built)})
    c = sg_console.Console(str(tmp_path / "sg.db"), targets=FakeTargets("x"))
    assert c._reports("macro", "1m", {}) == {"1": {"v": 1}}
    read_at["1"] = 1  # read again long ago: past settling, so its row is out of date
    assert c._reports("macro", "1m", {}) == {"1": {"v": 1}}, "the last row, at once"
    c._report_gates[("refresh", "macro", "1m")][0].join(5)
    assert built == ["1", "1"], "rebuilt once, in the background"
    assert c._reports("macro", "1m", {}) == {"1": {"v": 2}}


def test_a_page_gets_the_rows_already_built_at_once_and_the_rest_are_built_in_the_background(tmp_path, monkeypatch):
    import threading

    import sg_review

    read_at = {"1": time.time() - 3600, "2": time.time() - 3600}
    monkeypatch.setattr(sg_review, "stamps", lambda: dict(read_at))
    gate, built = threading.Event(), []

    def slow(kind, a, n, r):
        gate.wait(5)
        built.append(a)
        return {"v": a}

    monkeypatch.setattr(sg_review, "report_row", lambda kind, a, n, r: {"v": a})
    monkeypatch.setattr(sg_console, "REPORTS_WAIT", False)
    monkeypatch.setattr(ipintel, "DATA_DIR", tmp_path / "data")  # its own report cache
    c = sg_console.Console(str(tmp_path / "sg.db"), targets=FakeTargets("x"))
    c._reports("macro", "1m", {})  # both built
    read_at["3"] = time.time() - 3600  # a third account read since
    monkeypatch.setattr(sg_review, "report_row", slow)
    t = time.time()
    rows, building = c._reports_soon("macro", "1m", {})
    assert time.time() - t < 2, "answered without waiting for the build"
    assert rows == {"1": {"v": "1"}, "2": {"v": "2"}} and building == 1
    gate.set()
    c._report_gates[("soon", "macro", "1m")].join(5)
    assert built == ["3"], "only the missing account is built"
    assert c._reports_soon("macro", "1m", {}) == ({"1": {"v": "1"}, "2": {"v": "2"}, "3": {"v": "3"}}, 0)


def test_the_read_cost_estimate_is_rebuilt_hourly_as_unread_hours_build_up(tmp_path, monkeypatch):
    import sg_review

    read_at = {"1": time.time()}
    monkeypatch.setattr(sg_review, "cached_accounts", lambda: list(read_at))
    monkeypatch.setattr(sg_review, "stamps", lambda: dict(read_at))
    built = []
    monkeypatch.setattr(sg_review, "report_row", lambda kind, a, n, r: built.append(a) or {"v": len(built)})
    c = sg_console.Console(str(tmp_path / "sg.db"), targets=FakeTargets("x"))
    assert c._reports("estimate", "all", {}) == {"1": {"v": 1}}
    assert c._reports("estimate", "all", {}) == {"1": {"v": 1}} and built == ["1"], "kept within the hour"
    real = time.time
    monkeypatch.setattr(sg_console.time, "time", lambda: real() + 2 * 3600)  # two hours on, the account not read again
    assert c._reports("estimate", "all", {}) == {"1": {"v": 1}}, "the last row, at once"
    c._report_gates[("refresh", "estimate", "all")][0].join(5)
    assert built == ["1", "1"], "rebuilt once, in the background"
    assert c._reports("estimate", "all", {}) == {"1": {"v": 2}}


def test_the_cost_of_a_read_is_estimated_for_every_look_back(tmp_path, monkeypatch):
    c = sg_console.Console(str(tmp_path / "sg.db"), targets=FakeTargets("x"))
    rows = {"1": {"rate": 1e3, "spent": 2.5, "regions": 1, "cost": {"7": 10.0, "30": 40.0}, "bytes": {"7": 2e12, "30": 8e12}},
            "2": {"rate": None, "spent": 0.0, "regions": 1, "cost": {}, "bytes": {}},  # never read: priced after a first look
            "3": None}  # no flow logs read
    monkeypatch.setattr(c, "_reports", lambda kind, r, n: rows if kind == "estimate" else {})
    e = c.read_estimate()
    assert e["by_days"]["7"] == {"cost": 10.0, "accounts": 1, "bytes": 2e12}
    assert e["by_days"]["30"]["cost"] == 40.0 and e["unknown"] == 1 and e["spent"] == 2.5
    assert e["default_days"] == 7, "a week by default: 30 days across an OU can cost hundreds of dollars"


def test_an_unexpected_failure_is_explained_in_words_someone_can_act_on():
    from botocore.exceptions import ClientError, EndpointConnectionError

    def aws(code, msg="no"):
        return ClientError({"Error": {"Code": code, "Message": msg}}, "Op")

    assert "not allowed" in sg_console.plain_error(aws("AccessDenied", "not authorised for ce:GetCostAndUsage"))
    assert "wait a minute" in sg_console.plain_error(aws("ThrottlingException"))
    assert "sign in again" in sg_console.plain_error(aws("ExpiredToken"))
    assert "network or VPN" in sg_console.plain_error(EndpointConnectionError(endpoint_url="https://ce"))
    assert "console.log" in sg_console.plain_error(KeyError("x"))


def test_remediate_has_an_audit_of_every_rule_before_and_after_and_why():
    import pathlib

    page = pathlib.Path(__file__).resolve().parents[2].joinpath("assets", "sg_console.html").read_text()
    assert 'id="xAudit"' in page and '<dialog id="auditDlg"' in page, "Explain beside Before and after opens the audit"
    for col in ("<th style=\"width:24%\">Before</th>", "<th style=\"width:24%\">After</th>", "<th>Why</th>"):
        assert col in page
    assert "function auditWhy" in page and "Download CSV" in page


def test_explain_buttons_look_like_buttons():
    """A quiet (borderless) Explain reads as a label, not a button."""
    import pathlib
    import re
    page = (pathlib.Path(__file__).resolve().parents[2] / "assets" / "sg_console.html").read_text()
    for tag in re.findall(r"<button[^>]*>Explain</button>", page):
        assert "quiet" not in tag, tag


def test_audit_exports_to_pdf_printing_only_the_audit():
    import pathlib
    page = (pathlib.Path(__file__).resolve().parents[2] / "assets" / "sg_console.html").read_text()
    assert 'id="auditPdf"' in page and ">Export to PDF</button>" in page
    assert "body.print-audit > *:not(#auditPrint) { display: none !important; }" in page
    assert '$("auditPdf").addEventListener("click", auditPdf)' in page


def test_remediate_can_propose_a_single_group():
    import pathlib
    page = (pathlib.Path(__file__).resolve().parents[2] / "assets" / "sg_console.html").read_text()
    assert 'data-xp="${esc(g.id)}"' in page and ">Propose this group</button>" in page
    assert "proposeFix(b, [b.dataset.xp], [])" in page


def test_change_request_has_a_cancel_button_at_the_top_for_its_proposer():
    """With 1,239 changes listed, a Withdraw button at the bottom of the card could not be found."""
    import pathlib
    page = (pathlib.Path(__file__).resolve().parents[2] / "assets" / "sg_console.html").read_text()
    head = page[page.index("proposed by ${who(r.proposer)}"):]
    head = head[:head.index("<ul>${changes}</ul>")]
    assert 'data-dec="cancel|${r.id}"' in head and ">Cancel request</button>" in head
    assert "Show all ${r.changes.length.toLocaleString()} changes" in page
    assert 'confirmInline(b, `Press again to cancel #${id}`)' in page
