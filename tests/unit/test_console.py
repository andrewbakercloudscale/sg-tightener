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


def _req(port, method, path, body=None, cookie=True, header=True, host=None, ctype="application/json"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Host": host or f"127.0.0.1:{port}"}
    if cookie:
        h["Cookie"] = "sgc=t0ken"
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


def test_the_token_logs_the_browser_in_and_nothing_works_without_it(console):
    p = console["port"]
    status, body, _ = _req(p, "GET", "/", cookie=False)
    assert status == 403 and "sg_console.py open" in body and "?token=" in body and "t0ken" not in body
    assert _req(p, "GET", "/api/state", cookie=False)[0] == 403
    status, body, _ = _req(p, "GET", "/?token=wrong", cookie=False)
    assert status == 403 and "wrong or out of date" in body and "t0ken" not in body
    status, _, headers = _req(p, "GET", "/?token=t0ken", cookie=False)
    assert status == 303
    assert "HttpOnly" in headers["Set-Cookie"] and "SameSite=Strict" in headers["Set-Cookie"]
    status, page, headers = _req(p, "GET", "/")
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
    assert _req(p, "POST", "/api/decide", body, cookie=False)[0] == 403
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


def test_the_page_has_the_risk_overview():
    page = sg_console.ASSET.read_text()
    for needle in ('data-tab="macro"', 'id="tab-macro"', 'id="mHeat"', 'id="mOwner"', 'id="mOverTime"', 'id="mExposure"',
                   'id="mLetIn"', 'id="mBlind"', "/api/macro", 'data-tab="over"', 'id="oTiles"', 'id="oAccounts"',
                   'id="oAssets"', 'id="oRagTime"', 'id="oWins"'):
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
    assert _req(p, "GET", f"/review?account={demo.ACCOUNT}", cookie=False)[0] == 403
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
