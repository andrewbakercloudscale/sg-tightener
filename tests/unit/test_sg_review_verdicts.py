"""sg_review verdicts: what each refused or let-in source looks like, "Needs attention", watch and the org roll-up."""

from __future__ import annotations

import json
import time

import pytest

import sg_ipintel as ipintel
import sg_review
import sg_review_demo as demo


@pytest.fixture(autouse=True, scope="module")
def _data_dir(tmp_path_factory):
    old = ipintel.DATA_DIR
    ipintel.set_data_dir(tmp_path_factory.mktemp("sgverdicts"))
    yield
    ipintel.set_data_dir(old)


@pytest.fixture(scope="module")
def week():
    doc = demo.build_doc(demo.ACCOUNT, time.time(), 7)
    return doc, sg_review.build(doc, "1w", "", demo.INTERNAL, sg_review.parse_names(demo.NAMES))


def _items(rep, key):
    return [it for it in rep["attention"] if it["key"] == key]


def test_needs_attention_lists_what_broke_worst_first(week):
    _, rep = week
    att = rep["attention"]
    assert att, "the demo has cases that need attention"
    ranks = [sg_review.SEV_RANK[it["sev"]] for it in att]
    assert ranks == sorted(ranks)
    assert all(it["sev"] in sg_review.ATTENTION for it in att)
    for it in att:
        for k in ("key", "sev", "label", "title", "reason", "action", "kind", "srcs", "flows", "days"):
            assert k in it, k
    counts = rep["summary"]["attention"]
    assert sum(counts.values()) == len(att)
    assert rep["summary"]["verdicts"]["info"] > 0  # scans turned away are counted, not listed


def test_internet_scans_turned_away_stay_out_of_needs_attention(week):
    _, rep = week
    listed = {s for it in rep["attention"] if it["kind"] == "refused" for s in it["srcs"]}
    scans = [x for x in rep["refused"] if x.get("verdict", {}).get("key") == "scan"]
    assert scans
    assert all(x["verdict"]["sev"] == "info" and not x["verdict"]["wanted"] for x in scans)
    assert not listed & {x["src"] for x in scans}


def test_every_refused_row_carries_a_verdict(week):
    _, rep = week
    assert rep["refused"]
    for x in rep["refused"]:
        v = x["verdict"]
        assert v["sev"] in sg_review.SEVERITIES and v["reason"] and v["label"]


def test_internal_scanner_is_critical_even_when_refused(week):
    _, rep = week
    (it,) = _items(rep, "internal-scan")
    assert it["sev"] == "critical" and it["srcs"] == ["10.20.3.77"]
    assert "12 ports" in it["reason"]


def test_a_revoked_rule_is_named_with_the_command_to_restore_it(week):
    _, rep = week
    (it,) = _items(rep, "changed")
    assert it["sev"] == "high"
    assert sorted(it["srcs"]) == ["10.40.3.20", "10.40.3.21"]
    assert it["event"]["who"] == "jsmith"
    r = it["restore"]
    assert r["group"].startswith("sg-0app") and r["region"] == demo.REGION
    (perm,) = r["perms"]
    assert perm["IpProtocol"] == "tcp" and perm["FromPort"] == perm["ToPort"] == 8443
    assert perm["IpRanges"][0]["CidrIp"] == "10.40.0.0/16"
    assert "jsmith" in perm["IpRanges"][0]["Description"]
    # the marker for that change knows which sources it cut off
    (m,) = [m for m in rep["markers"] if m.get("caused")]
    assert sorted(m["caused"]) == ["10.40.3.20", "10.40.3.21"] and m["who"] == "jsmith"
    # and the refused rows say so, wanted, so Extract rule ticks them
    rows = [x for x in rep["refused"] if x["src"] in it["srcs"]]
    assert rows and all(x["verdict"]["key"] == "changed" and x["verdict"]["wanted"] for x in rows)


def test_a_client_that_moved_address_is_flagged(week):
    _, rep = week
    (it,) = _items(rep, "moved")
    assert it["srcs"] == ["165.225.12.40"]
    assert "Acme payroll" in it["reason"] and "203.0.113.10" in it["reason"]


def test_scanners_and_tor_let_in_on_remote_admin_are_critical(week):
    _, rep = week
    got = _items(rep, "let-in")
    assert {s for it in got for s in it["srcs"]} >= {"185.220.101.33", "162.142.125.10"}
    assert all(it["sev"] == "critical" and it["kind"] == "active" and "3389" in it["target"] for it in got)
    tor = next(x for x in rep["active"] if x["src"] == "185.220.101.33")
    assert tor["verdict"]["key"] == "let-in"


def test_own_traffic_acl_health_and_known_services_are_medium(week):
    _, rep = week
    assert {s for it in _items(rep, "internal") for s in it["srcs"]} >= {"10.20.5.61", "10.40.4.44"}
    assert _items(rep, "nacl")[0]["srcs"] == ["10.200.9.9"]
    assert _items(rep, "health") and _items(rep, "service")
    for key in ("internal", "nacl", "health", "service"):
        assert all(it["sev"] == "medium" for it in _items(rep, key))


def test_the_page_has_the_attention_box_and_restore(tmp_path):
    out = tmp_path / "p.html"
    assert sg_review.main(["--data-dir", str(ipintel.DATA_DIR), "demo", "--offline", "--out", str(out)]) == 0
    page = out.read_text()
    for marker in ('id="attention"', "Needs attention", "data-att-restore", "authorize-security-group-ingress",
                   'id="refusedCause"', "verdictBlock"):  # fmt: skip
        assert marker in page, marker


# ------------------------------------------------------------------------------------------- watch
def test_fresh_items_posts_once_then_again_after_the_repeat_and_when_it_comes_back(week):
    _, rep = week
    items = rep["attention"]
    st = {"sent": {}}
    first = sg_review.fresh_items(items, st, 1000.0, "high", 3600)
    assert first and all(sg_review.SEV_RANK[it["sev"]] <= sg_review.SEV_RANK["high"] for it in first)
    assert sg_review.fresh_items(items, st, 1500.0, "high", 3600) == []
    assert len(sg_review.fresh_items(items, st, 5000.0, "high", 3600)) == len(first)
    # an item that closes is forgotten, so it is posted at once if it opens again
    sg_review.fresh_items(items[1:], st, 5100.0, "high", 3600)
    again = sg_review.fresh_items(items, st, 5200.0, "high", 3600)
    assert [sg_review.attention_id(it) for it in again] == [sg_review.attention_id(items[0])]


def test_alert_text_has_the_reason_action_and_restore(week):
    _, rep = week
    text = sg_review.alert_text("123456789012", "main", _items(rep, "changed"), markdown=False)
    assert text.startswith("sg_review: 1 item needs attention in main (123456789012)")
    assert "Do: Restore" in text and "authorize-security-group-ingress" in text and "10.40.0.0/16" in text


class _Sess:
    def __init__(self, account):
        self.account = account

    def client(self, name, **_):
        assert name == "sts"
        acct = self.account

        class _Sts:
            def get_caller_identity(self):
                return {"Account": acct}

        return _Sts()


def test_watch_reads_the_gap_posts_new_items_and_keeps_quiet_next_time(monkeypatch, tmp_path):
    monkeypatch.setattr(sg_review, "_session", lambda profile: _Sess(demo.ACCOUNT))
    sg_review.save(demo.build_doc(demo.ACCOUNT, time.time(), 7))
    asked = []
    monkeypatch.setattr(sg_review, "plan_read", lambda sess, doc, regions, days, now, say=None: asked.append(days) or [])
    monkeypatch.setattr(sg_review, "plan_tail", lambda doc, regions, now: asked.append("tail") or [])
    posted = []
    monkeypatch.setattr(sg_review, "post_slack", lambda url, text: posted.append((url, text)))
    argv = ["--data-dir", str(ipintel.DATA_DIR), "watch", "--regions", demo.REGION, "--offline",
            "--slack", "https://hooks.slack.test/x", "--min-severity", "critical"]  # fmt: skip
    assert sg_review.main(argv) == 0
    assert asked == [1, "tail"]
    assert len(posted) == 1 and "critical".upper() in posted[0][1]
    saved = json.loads((ipintel.DATA_DIR / "review" / f"{demo.ACCOUNT}.watch.json").read_text())
    assert saved["sent"]
    assert sg_review.main(argv) == 0
    assert len(posted) == 1  # nothing new: nothing posted


def test_watch_posts_only_rejected_traffic_unless_asked_for_all(monkeypatch):
    sg_review.save(demo.build_doc(demo.ACCOUNT, time.time(), 7))
    monkeypatch.setattr(sg_review, "plan_read", lambda *a, **k: [])
    monkeypatch.setattr(sg_review, "plan_tail", lambda *a, **k: [])
    posted = []
    monkeypatch.setattr(sg_review, "fresh_items", lambda items, *a, **k: posted.append(items) or [])

    class A:
        regions, name, max_cost, min_severity, repeat, alerts = demo.REGION, "", 0.5, "medium", 24, "refused"
        slack = email_to = names = None
        onprem = internal = ""

    sg_review.watch_once(_Sess(demo.ACCOUNT), A())
    A.alerts = "all"
    sg_review.watch_once(_Sess(demo.ACCOUNT), A())
    refused, every = posted
    assert refused and {it["kind"] for it in refused} == {"refused"}
    assert {"drift", "posture"} <= {it["kind"] for it in every}


def test_tail_reads_to_five_minutes_ago_and_gives_way_to_the_hourly_read():
    now = 1_800_000_000 + 40 * 60 + 17  # 40 minutes past an hour
    doc = {"regions": {"r": {"query_sets": [{"format": "f", "groups": ["g"]}], "snapshot": {"vpcs": []}}},
           "chunks": []}
    (t,) = sg_review.plan_tail(doc, ["r"], now)
    assert t[0] == "r" and t[1] == sg_review.read_end(now) and t[2] == (now - 300) // 60 * 60 and t[5] is True
    doc["chunks"].append({"r": "r", "s": t[1], "e": t[2], "st": "ok", "tail": True})
    (t2,) = sg_review.plan_tail(doc, ["r"], now + 120)  # the next watch starts where this one stopped
    assert t2[1] == t[2]
    assert sg_review.plan_tail(doc, ["r"], now + 30) == []  # under a minute new: nothing to read
    later = now + 3600  # the hourly read now covers the tail: it goes, and the tail starts at the new hour
    (t3,) = sg_review.plan_tail(doc, ["r"], later)
    assert not [c for c in doc["chunks"] if c.get("tail")] and t3[1] == sg_review.read_end(later)


def test_watch_skips_a_read_over_the_cost_cap(monkeypatch):
    doc = demo.build_doc(demo.ACCOUNT, time.time(), 7)
    sg_review.save(doc)
    monkeypatch.setattr(sg_review, "plan_read", lambda *a, **k: [(demo.REGION, 0, 3600, [], [])])
    monkeypatch.setattr(sg_review, "plan_tail", lambda *a, **k: [(demo.REGION, 3600, 4800, [], [], True)])
    monkeypatch.setattr(sg_review, "_read_cost", lambda *a: 9.0)
    monkeypatch.setattr(sg_review, "run_read", lambda *a, **k: pytest.fail("read over the cap"))

    class A:
        regions, name, max_cost, min_severity, repeat = demo.REGION, "", 0.5, "critical", 24
        slack = email_to = names = None
        onprem = internal = ""

    monkeypatch.setattr(sg_review, "post_slack", lambda *a: None)
    monkeypatch.delenv("SG_REVIEW_SLACK_WEBHOOK", raising=False)
    out = sg_review.watch_once(_Sess(demo.ACCOUNT), A())
    assert "over --max-cost" in out["skipped"]


# ------------------------------------------------------------------------------------------- org
def test_org_rolls_up_every_account_and_names_the_one_not_read(monkeypatch, tmp_path):
    from botocore.exceptions import ClientError

    other = "210987654321"
    monkeypatch.setattr(sg_review, "_session", lambda profile: object())
    monkeypatch.setattr(sg_review, "org_accounts", lambda sess, ou: [
        {"Id": demo.ACCOUNT, "Name": "main", "Status": "ACTIVE"}, {"Id": other, "Name": "locked", "Status": "ACTIVE"}])

    def assume(sess, account, role, external_id=""):
        if account == other:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "AssumeRole")
        return object()

    monkeypatch.setattr(sg_review, "_assume", assume)
    sg_review.save(demo.build_doc(demo.ACCOUNT, time.time(), 7))
    monkeypatch.setattr(sg_review, "plan_read", lambda *a, **k: [])
    out = tmp_path / "org"
    code = sg_review.main(["--data-dir", str(ipintel.DATA_DIR), "org", "--regions", demo.REGION, "--offline", "--yes",
                           "--out-dir", str(out)])  # fmt: skip
    assert code == 2  # one account not read
    roll = json.loads((out / "org.json").read_text())
    assert roll["schema"] == "sg-tightener.review-org/v1" and roll["accounts"] == 2 and roll["failed"] == 1
    main, locked = roll["rows"]
    assert main["account"] == demo.ACCOUNT and main["attention"]["critical"] >= 1 and main["items"]
    assert locked["status"] == "not read" and "AccessDenied" in locked["error"]
    index = (out / "index.html").read_text()
    assert f"sg-review-{demo.ACCOUNT}.html" in index and "locked" in index
    assert (out / f"sg-review-{demo.ACCOUNT}.html").exists()


# ------------------------------------------------------------------------------------------- PrivateLink
def test_privatelink_both_sides_in_the_demo(week):
    _, rep = week
    got = {it["key"]: it for it in rep["privatelink"]}
    svc = got["pl-service-anyone"]
    assert svc["sev"] == "critical" and "payments-api" in svc["title"]
    assert "--remove-allowed-principals '*'" in svc["cli"] and "arn:aws:iam::111122223333:root" in svc["cli"]
    assert "--acceptance-required" in svc["cli"]
    nlb = got["pl-nlb-no-sg"]
    assert nlb["sev"] == "medium" and "--enforce-security-group-inbound-rules-on-private-link-traffic on" in nlb["cli"]
    ep = got["pl-endpoint-open"]
    assert ep["sev"] == "medium" and "Flow logs saw 3 source(s)" in ep["reason"]
    # they join Needs attention, so watch and org carry them too
    keys = {it["key"] for it in rep["attention"]}
    assert {"pl-service-anyone", "pl-nlb-no-sg", "pl-endpoint-open"} <= keys
    assert rep["summary"]["privatelink"]["critical"] == 1


def test_privatelink_endpoint_open_to_everyone_is_high_and_named_principals_auto_accept_is_low():
    snap = {"groups": {"sg-1": {"name": "ep", "rules": [{"proto": "6", "from": 443, "to": 443,
                                                          "cidrs": ["0.0.0.0/0"], "pls": [], "refs": []}]}},
            "privatelink": {"services": [{"id": "vpce-svc-1", "name": "api", "service": "", "acceptance": False,
                                          "principals": ["arn:aws:iam::111122223333:root"], "connections": [],
                                          "nlbs": [], "gwlbs": []}],
                            "endpoints": [{"id": "vpce-1", "service": "com.amazonaws.eu-west-1.sts", "vpc": "v",
                                           "name": "", "groups": ["sg-1"], "enis": []}]}}  # fmt: skip
    got = {it["key"]: it for it in sg_review.privatelink_findings({"regions": {"eu-west-1": {"snapshot": snap}}}, [])}
    assert got["pl-endpoint-open"]["sev"] == "high" and "every address" in got["pl-endpoint-open"]["title"]
    assert got["pl-auto-accept"]["sev"] == "low"
    assert "pl-service-anyone" not in got


def test_alert_text_carries_the_privatelink_fix(week):
    _, rep = week
    text = sg_review.alert_text("123456789012", "", [it for it in rep["attention"] if it["key"] == "pl-service-anyone"],
                                markdown=False)  # fmt: skip
    assert "Fix: aws ec2 modify-vpc-endpoint-service-permissions" in text and "Sources:" not in text
