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
    assert _req(p, "GET", "/", cookie=False)[0] == 403
    assert _req(p, "GET", "/api/state", cookie=False)[0] == 403
    assert _req(p, "GET", "/?token=wrong", cookie=False)[0] == 403
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
    assert _req(p, "GET", "/api/refused?range=1y")[0] == 400
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
    ranks = [sg_review.SEV_RANK[r["sev"]] for r in got["rows"]]
    assert ranks == sorted(ranks), "worst verdict first"
    assert {"src", "port", "verdict", "groups", "account_name"} <= set(got["rows"][0])


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
