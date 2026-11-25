"""Applying rules says what it will change before it does, and a refused source's Fix says where a rule letting
it in belongs (or that it should stay refused), with everything known about it."""

from __future__ import annotations

import pytest

import sg_assets
import sg_console
import sg_db
import sg_ipintel as ipintel

ACCOUNT, REGION = "111122223333", "eu-west-1"
ALICE = "arn:aws:sts::111122223333:assumed-role/Admin/alice"
WEB, DB, SHARED, SOLO = "sg-0web000000000001", "sg-0db0000000000002", "sg-0shared00000003", "sg-0solo0000000004"
IN = sg_db.IN


class FakeTargets:
    def __init__(self):
        self.actor, self.account = ALICE, ACCOUNT

    def session(self, account):
        raise AssertionError("these tests do not reach AWS")


def _asset(eni, groups, ip, instance="", asg="", kind="interface", vpc="vpc-1", description=""):
    return {"eni": eni, "instance": instance, "asg": asg, "kind": kind, "vpc_id": vpc, "ips": [ip], "groups": groups,
            "description": description}


@pytest.fixture
def con(tmp_path, monkeypatch):
    old = ipintel.DATA_DIR
    ipintel.set_data_dir(tmp_path / "data")
    db = tmp_path / "sg.db"
    st = sg_db.Store(db)
    with st:
        st.import_region(ACCOUNT, REGION, {
            WEB: {"name": "web", "vpc": "vpc-1", "description": "web tier",
                  "rules": {(IN, "tcp", 443, 443, "10.0.0.0/8"): "clients", (IN, "tcp", 8080, 8080, "10.9.0.0/16"): "old"}},
            DB: {"name": "db", "vpc": "vpc-1", "description": "postgres",
                 "rules": {(IN, "tcp", 5432, 5432, "10.1.2.0/24"): "app"}},
            SHARED: {"name": "baseline", "vpc": "vpc-1", "description": "every host", "rules": {}},
            SOLO: {"name": "solo", "vpc": "vpc-1", "description": "one host", "rules": {}},
        }, ALICE)
        sg_assets.observe_assets(st, ACCOUNT, REGION, [
            _asset("eni-web1", [WEB, SHARED], "10.1.0.10", "i-web1"),
            _asset("eni-web2", [WEB, SHARED], "10.1.0.11", "i-web2"),
            _asset("eni-db1", [DB, SHARED], "10.1.2.20", "i-db1"),
            _asset("eni-app1", [SHARED, SOLO], "10.1.3.30", "i-app1"),
            _asset("eni-batch", [SHARED], "10.1.4.40", "i-batch"),
            _asset("eni-asg", [SHARED], "10.1.5.50", "i-asg", asg="workers"),
        ], ALICE)
        st.set_approvals(False, ALICE, "one person in these tests")
    st.close()
    c = sg_console.Console(str(db), targets=FakeTargets())
    yield c
    ipintel.set_data_dir(old)


def _fix(con, **kw):
    body = {"account": ACCOUNT, "region": REGION, "proto": "6", "port": 443, "src": "10.20.0.5", "eni": "eni-web1"}
    body.update(kw)
    return con.fix_refused(body)


# ---------------------------------------------------------------------------------------------- apply
def test_apply_shows_every_change_its_groups_interfaces_and_request_before_anything_is_sent(con, monkeypatch):
    res = con.propose({"account": ACCOUNT, "region": REGION, "reason": "only the LB subnet", "ticket": "CHG-1",
                       "changes": [{"group": WEB, "op": "remove", "rule": {"direction": "in", "proto": "tcp", "from": 443,
                                                                            "to": 443, "source": "10.0.0.0/8"}},
                                   {"group": WEB, "op": "add", "rule": {"direction": "in", "proto": "tcp", "from": 443,
                                                                         "to": 443, "source": "10.1.0.0/24",
                                                                         "description": "lb"}}]})
    assert res["status"] == "approved"
    monkeypatch.setattr(con, "verdicts", lambda a, r="": {"rules": [
        {"key": f"{REGION}|{WEB}|tcp|443|443|10.0.0.0/8", "top": ["10.1.0.7", "10.30.0.9"], "seen": 2, "days": 30,
         "last_used": 1, "action": "tighten"}]})
    p = con.apply_preview({"account": ACCOUNT, "region": REGION})
    assert p["summary"] == {"add": 1, "remove": 1, "groups": 1, "interfaces": 2, "known": True, "at_risk": 1}
    rm = next(c for c in p["changes"] if c["op"] == "remove")
    assert rm["name"] == "web" and rm["interfaces"] == 2 and rm["instances"] == ["i-web1", "i-web2"]
    assert rm["requests"] == [{"id": res["id"], "reason": "only the LB subnet", "ticket": "CHG-1"}]
    assert rm["evidence"]["lost"] == ["10.30.0.9"], "10.1.0.7 is still let in by the new rule; 10.30.0.9 is not"
    add = next(c for c in p["changes"] if c["op"] == "add")
    assert add["requests"][0]["id"] == res["id"] and "evidence" not in add


def test_the_apply_preview_says_when_nothing_seen_is_cut_off(con, monkeypatch):
    con.propose({"account": ACCOUNT, "region": REGION, "reason": "unused",
                 "changes": [{"group": WEB, "op": "remove", "rule": {"direction": "in", "proto": "tcp", "from": 8080,
                                                                      "to": 8080, "source": "10.9.0.0/16"}}]})
    monkeypatch.setattr(con, "verdicts", lambda a, r="": {"rules": [
        {"key": f"{REGION}|{WEB}|tcp|8080|8080|10.9.0.0/16", "top": [], "seen": 0, "days": 90, "action": "remove"}]})
    p = con.apply_preview({"account": ACCOUNT, "region": REGION})
    assert p["summary"]["at_risk"] == 0 and p["changes"][0]["evidence"]["sources"] == 0


def test_the_apply_preview_still_lists_the_changes_without_flow_logs(con, monkeypatch):
    con.propose({"account": ACCOUNT, "region": REGION, "reason": "x",
                 "changes": [{"group": DB, "op": "add", "rule": {"direction": "in", "proto": "tcp", "from": 5432,
                                                                  "to": 5432, "source": "10.1.9.0/24"}}]})

    def boom(*a, **k):
        raise RuntimeError("no read")

    monkeypatch.setattr(con, "verdicts", boom)
    p = con.apply_preview({"account": ACCOUNT, "region": REGION})
    assert len(p["changes"]) == 1 and p["changes"][0]["interfaces"] == 1


def test_nothing_to_apply_is_an_empty_preview(con):
    assert con.apply_preview({"account": ACCOUNT, "region": REGION})["changes"] == []


def test_the_page_previews_apply_and_only_a_second_button_applies():
    page = open(sg_console.Path(sg_console.__file__).parent / "assets" / "sg_console.html").read()
    i = page.index('$("gApply").addEventListener')
    body = page[i:i + 6000]
    assert body.index("/api/apply-preview") < body.index('"/api/apply", w')
    assert "gApplyGo" in body and "will be refused" in body and "Open Rejected traffic for this account" in body


def test_covers_checks_address_protocol_and_every_port():
    r = (IN, "tcp", 400, 500, "10.0.0.0/8")
    assert sg_console._covers(r, "10.2.3.4", "tcp", 443, 443)
    assert not sg_console._covers(r, "11.2.3.4", "tcp", 443, 443)
    assert not sg_console._covers(r, "10.2.3.4", "udp", 443, 443)
    assert not sg_console._covers(r, "10.2.3.4", "tcp", 443, 600)
    assert not sg_console._covers((IN, "tcp", 443, 443, "sg-0abc"), "10.2.3.4", "tcp", 443, 443)
    assert sg_console._covers((IN, "-1", -1, -1, "::/0"), "2001:db8::1", "tcp", 22, 22)
    assert not sg_console._covers((IN, "-1", -1, -1, "0.0.0.0/0"), "2001:db8::1", "tcp", 22, 22)


# ---------------------------------------------------------------------------------------------- fix
def test_fix_adds_to_the_group_that_already_serves_the_port(con):
    f = _fix(con, port=443, eni="eni-web1", src="198.51.100.5")
    assert f["recommend"]["kind"] == "add" and f["recommend"]["group"] == WEB
    assert f["rule"] == {"direction": "in", "proto": "tcp", "from": 443, "to": 443, "source": "198.51.100.5/32",
                         "description": "198.51.100.5"}
    assert f["asset"]["instance"] == "i-web1"
    web = next(g for g in f["groups"] if g["id"] == WEB)
    assert web["serves_port"] and web["sources"] == ["10.0.0.0/8"] and web["interfaces"] == 2
    assert f["alternatives"][0]["group"] == WEB


def test_fix_prefers_a_group_on_that_interface_alone(con):
    f = _fix(con, port=9000, eni="eni-app1")
    assert f["recommend"]["kind"] == "add" and f["recommend"]["group"] == SOLO


def test_fix_gives_a_group_of_its_own_rather_than_open_a_shared_group(con):
    f = _fix(con, port=9000, eni="eni-batch")
    assert f["recommend"]["kind"] == "own" and "asset-plan --eni eni-batch" in f["recommend"]["command"]
    assert "6 interfaces" in f["recommend"]["why"] or "shared" in f["recommend"]["why"]


def test_fix_on_an_auto_scaling_interface_says_every_instance_gets_it(con):
    f = _fix(con, port=9000, eni="eni-asg")
    assert f["recommend"]["kind"] == "add" and f["recommend"]["group"] == SHARED
    assert "auto scaling group workers" in f["recommend"]["why"]


@pytest.mark.parametrize("flags, kind", [({"scan": True}, "keep"), ({"threat": True}, "keep"), ({"tor": True}, "keep"),
                                         ({"by": "Network ACL acl-1 rule 100"}, "nacl")])
def test_fix_keeps_scans_and_threats_refused_and_sends_nacl_refusals_elsewhere(con, flags, kind):
    assert _fix(con, **flags)["recommend"]["kind"] == kind


def test_an_internal_scan_is_flagged_as_worth_finding(con):
    assert "worth finding" in _fix(con, scan=True, internal=True)["recommend"]["why"]


def test_fix_allows_an_internal_sources_own_group_in_the_same_vpc(con):
    f = _fix(con, port=5432, eni="eni-db1", src="10.1.3.30", internal=True)
    assert f["rule"]["source"] == SHARED and "i-app1" in f["source_why"]
    assert f["source_interface"]["eni"] == "eni-app1"


def test_fix_finds_the_change_that_cut_it_off_and_puts_it_back_there(con, tmp_path):
    st = sg_db.Store(tmp_path / "sg.db")
    with st:
        st.synced(ACCOUNT, REGION, DB, {"name": "db", "vpc": "vpc-1", "description": "postgres", "rules": {}},
                  ALICE, "apply", "applied", "tighten db", "CHG-7")
    st.close()
    f = _fix(con, port=5432, eni="eni-db1", src="10.1.2.99")
    assert f["broken_by"] and f["broken_by"][0]["group"] == DB and f["broken_by"][0]["ticket"] == "CHG-7"
    assert "10.1.2.0/24" in f["broken_by"][0]["removed"][0]
    assert f["recommend"]["kind"] == "add" and f["recommend"]["group"] == DB


def test_fix_says_when_a_request_already_lets_it_in(con):
    res = con.propose({"account": ACCOUNT, "region": REGION, "reason": "partner",
                       "changes": [{"group": SHARED, "op": "add", "rule": {"direction": "in", "proto": "tcp", "from": 9000,
                                                                            "to": 9000, "source": "10.20.0.0/24"}}]})
    f = _fix(con, port=9000, eni="eni-batch")
    assert f["recommend"]["kind"] == "waiting" and f["waiting"] == [res["id"]]


def test_fix_says_nothing_to_do_when_a_rule_lets_it_in_now(con):
    f = _fix(con, port=443, eni="eni-web1", src="10.3.3.3")
    assert f["recommend"]["kind"] == "done"


def test_fix_needs_the_region_in_the_database(con):
    with pytest.raises(sg_console.ConsoleError, match="not in the database"):
        _fix(con, region="ap-south-1")


def test_rejected_traffic_has_a_fix_button_with_everything_known_about_the_source():
    page = open(sg_console.Path(sg_console.__file__).parent / "assets" / "sg_console.html").read()
    assert 'data-rfix="' in page and "data-allow" not in page and 'id="fixDlg"' in page
    assert '$("refusedRows").querySelectorAll("[data-rfix]")' in page, "never the Remediate buttons (data-fix) elsewhere"
    for words in ("What it tried to reach", "Why it was refused", "Security groups on that interface",
                  "port scanning", "internal", "external", "IP addresses tried", "First ever seen",
                  "a group of its own for this interface", "It was let in until a rule was removed"):
        assert words in page, words


def test_refused_rows_carry_every_target_and_the_verdict():
    import sg_review

    rep = {"refused": [{"src": "198.51.100.7", "name": "x", "cat": "internet", "group": "other", "flows": 9, "ports": 3,
                        "dsts": 2, "sweep": False, "bins": [1, 2],
                        "verdict": {"sev": "low", "label": "Keeps retrying", "title": "An internet client keeps retrying",
                                    "reason": "r", "action": "Find out who it is", "wanted": False, "key": "retry"},
                        "targets": [{"eni": "eni-1", "dst": "10.0.0.1", "proto": "6", "port": 443, "flows": 6,
                                     "kind": "interface", "groups": ["sg-1"], "region": REGION,
                                     "pc": {"name": "Web", "risky": False}, "by": "Security group"},
                                    {"eni": "eni-2", "dst": "10.0.0.2", "proto": "6", "port": 22, "flows": 3,
                                     "kind": "interface", "groups": ["sg-2"], "region": REGION,
                                     "pc": {"name": "Remote admin", "risky": True}, "by": "Security group"}]}]}
    (row,) = sg_review.refused_rows(ACCOUNT, "acct", rep)
    assert row["title"] == "An internet client keeps retrying" and row["action"] == "Find out who it is"
    assert [t["port"] for t in row["targets"]] == [443, 22] and row["targets"][1]["risky"]
    assert row["by"] == "Security group" and row["periods"] == 2


def test_surveillance_previews_the_impact_but_offers_no_apply():
    page = open(sg_console.Path(sg_console.__file__).parent / "assets" / "sg_console.html").read()
    assert '$("gApply").disabled = surv' not in page and "Preview approved changes" in page
    i = page.index('$("gApply").addEventListener')
    assert 'P.mode === "enforce" ? `<div class="acts"><button class="btn primary" id="gApplyGo">' in page[i:i + 6000]


def test_the_preview_says_the_accounts_mode(con):
    assert con.apply_preview({"account": ACCOUNT, "region": REGION})["mode"] in ("surveillance", "enforce")


def test_fix_offers_the_other_groups_it_was_refused_on_in_the_same_request():
    page = open(sg_console.Path(sg_console.__file__).parent / "assets" / "sg_console.html").read()
    assert 'id="fixAlso" checked' in page and "the group${xs.length === 1 ? \"\" : \"s\"} on the other interfaces" in page
    i = page.index("function wireFix")
    assert '$("fixAlso")?.checked' in page[i:i + 1500] and "new Set(gs)" in page[i:i + 1500]
