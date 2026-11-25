"""sg_remediate: an account's plan from its flow logs, the merges, the requests it proposes and applying a merge."""

from __future__ import annotations

import copy
import time

import pytest

import sg_assets
import sg_console
import sg_db
import sg_ipintel as ipintel
import sg_remediate as rem
import sg_review
import sg_review_demo as demo

ACCOUNT = "123456789012"
ACTOR = "arn:aws:sts::123456789012:assumed-role/Admin/alice"
TWIN = "sg-0appb000000000013"


def _store_groups(doc: dict, store: sg_db.Store) -> None:
    with store:
        for region, x in doc["regions"].items():
            groups = {}
            for gid, g in x["snapshot"]["groups"].items():
                rules = {}
                for direction, rs in (("in", g["rules"]), ("out", g.get("egress") or [])):
                    for r in rs:
                        p = sg_db._proto(r["proto"])
                        f, t = (-1, -1) if p == "-1" else (r["from"], r["to"])
                        for c in list(r.get("cidrs") or []) + list(r.get("cidrs6") or []):
                            rules[(direction, p, f, t, c)] = ""
                groups[gid] = {"name": g["name"], "vpc": g["vpc"], "description": "", "rules": rules}
            store.import_region(ACCOUNT, region, groups, ACTOR)
            assets = [{"eni": e, "instance": "i-0" + e[-6:], "asg": "", "kind": "interface", "vpc_id": "vpc-0demo",
                       "ips": v.get("ips") or [], "groups": sorted(v.get("groups") or []), "description": ""}
                      for e, v in x["snapshot"]["enis"].items()]  # fmt: skip
            sg_assets.observe_assets(store, ACCOUNT, region, assets, ACTOR)


@pytest.fixture
def world(tmp_path):
    """The demo account, with a twin of app-servers on one of its interfaces: the two should merge."""
    old = ipintel.DATA_DIR
    ipintel.set_data_dir(tmp_path / "data")
    doc = demo.build_doc(ACCOUNT, time.time(), 90)
    for x in doc["regions"].values():
        g = x["snapshot"]["groups"]
        g[TWIN] = {**copy.deepcopy(g["sg-0app0000000000001"]), "name": "app-servers-blue"}
        x["snapshot"]["enis"]["eni-0app2"]["groups"] = [TWIN]
    sg_review.save(doc)
    st = sg_db.Store(tmp_path / "sg.db")
    _store_groups(doc, st)
    st.close()

    class T:
        actor = ACTOR

        def session(self, a):
            raise AssertionError("these tests do not reach AWS")

    c = sg_console.Console(str(tmp_path / "sg.db"), targets=T())
    yield {"console": c, "doc": doc, "db": tmp_path / "sg.db"}
    ipintel.set_data_dir(old)


def test_flow_status_and_window(world):
    doc = world["doc"]
    assert rem.flow_status(doc) == "read"
    assert rem.flow_status({"chunks": []}) in ("not-read", "unknown", "no-flow-logs")
    _, days = rem.window(doc, 30)
    assert 29 <= days <= 31
    _, all_days = rem.window(doc, 365)
    assert all_days > days


def test_the_plan_narrows_every_group_and_counts_before_and_after(world):
    p = world["console"].remediation(ACCOUNT, 90)
    assert p["status"] == "read" and p["account"] == ACCOUNT
    T = p["totals"]
    assert T["groups"] == len(p["groups"]) and T["new_addresses"] < T["addresses"]
    assert T["narrowed"] > 0 and T["removed"] > 0
    assert set(T["mix"]) <= set(sg_review.CATS) and sum(T["mix"].values()) > 0
    db = next(g for g in p["groups"] if g["name"] == "payments-db")
    assert db["new_addresses"] < db["addresses"] and "internal" in db["mix"]
    # rules open to everyone are left for a person, and not counted in the IPv4 totals
    assert T["open"] >= 1


def test_twins_merge_but_never_onto_a_public_source(world):
    p = world["console"].remediation(ACCOUNT, 90)
    merges = p["merges"]
    assert len(merges) == 1
    m = merges[0]
    assert {x["name"] for x in m["members"]} == {"app-servers", "app-servers-blue"}
    assert m["target_name"] == "app-servers"  # the one with the most interfaces
    for x in m["members"]:
        assert x["gain_addresses"] <= rem.MERGE_EXTRA_ADDRESSES and not x["gain_ports"]
        assert all(r["source"] not in rem.OPEN for r in x["extra"])


def test_fits_rules():
    own = {("in", "tcp", 443, 443, "10.0.0.1/32")}
    assert rem._fits(own, own | {("in", "tcp", 443, 443, "10.0.0.2/32")})  # a private address on a port it has
    assert not rem._fits(own, own | {("in", "tcp", 443, 443, "52.95.3.5/32")})  # never a public one
    assert not rem._fits(own, own | {("in", "tcp", 443, 443, "203.0.113.10/31")})  # documentation ranges are public too
    assert not rem._fits(own, own | {("in", "tcp", 443, 443, "0.0.0.0/0")})
    assert not rem._fits(own, own | {("in", "tcp", 443, 443, "10.1.0.0/16")})  # too many more addresses
    assert rem._fits(own, own | {("in", "tcp", 8443, 8443, "10.0.0.1/32")})  # one more port, same source
    assert not rem._fits(own, own | {("in", "tcp", 3389, 3389, "10.0.0.1/32")})  # never a risky port
    assert not rem._fits(own, own | {("in", "tcp", 8443, 8443, "10.0.0.1/32"), ("in", "tcp", 9443, 9443, "10.0.0.1/32")})


def test_unticking_a_member_drops_its_merge(world):
    p = world["console"].remediation(ACCOUNT, 90)
    groups, _ = world["console"]._account_groups(ACCOUNT)
    keep = {g["id"] for g in p["groups"]} - {TWIN}
    assert rem.find_merges(p["groups"], groups, keep) == []


def test_propose_makes_a_rules_request_and_a_merge_request(world):
    c = world["console"]
    p = c.remediation(ACCOUNT, 90)
    res = c.remediate({"account": ACCOUNT, "days": 90, "groups": [g["id"] for g in p["groups"]],
                       "merges": [m["id"] for m in p["merges"]]})
    kinds = sorted(r["kind"] for r in res["requests"])
    assert kinds == ["merge", "rules"]
    st = sg_db.Store(world["db"])
    try:
        merge = next(r for r in st.requests() if r["kind"] == "merge")
        assert merge["status"] == "pending" and merge["changes"]["target"] == "sg-0app0000000000001"
        assert "eni-0app2" in merge["changes"]["enis"]
        # the rule request gives the target every rule the merged groups need
        rules = next(r for r in st.requests() if r["kind"] == "rules")
        added = {sg_db._rule_tuple(x["rule"]) for x in rules["changes"] if x["op"] == "add" and x["group"] == merge["changes"]["target"]}
        removed = {sg_db._rule_tuple(x["rule"]) for x in rules["changes"] if x["op"] == "remove" and x["group"] == merge["changes"]["target"]}
        kept = set(st.rules(ACCOUNT, merge["region"], merge["changes"]["target"], "synced")) - removed
        assert {sg_db._rule_tuple(x) for x in merge["changes"]["need"]} <= added | kept
    finally:
        st.close()


def test_nothing_chosen_is_refused(world):
    c = world["console"]
    with pytest.raises(sg_console.ConsoleError):
        c.remediate({"account": ACCOUNT, "days": 90, "groups": [], "merges": []})


class FakeEC2:
    def __init__(self):
        self.calls = []

    def modify_network_interface_attribute(self, **kw):
        self.calls.append(kw)


def _approved_merge(world):
    c = world["console"]
    p = c.remediation(ACCOUNT, 90)
    c.remediate({"account": ACCOUNT, "days": 90, "groups": [g["id"] for g in p["groups"]],
                 "merges": [m["id"] for m in p["merges"]]})
    st = sg_db.Store(world["db"])
    rid = next(r["id"] for r in st.requests() if r["kind"] == "merge")
    with st:
        st.db.execute("UPDATE requests SET status = 'approved' WHERE id = ?", (rid,))
    return st, rid


def test_a_merge_waits_for_enforce_and_for_the_rules(world, monkeypatch):
    st, rid = _approved_merge(world)
    try:
        monkeypatch.setattr(sg_db, "ensure_current", lambda *a, **k: [])
        with pytest.raises(sg_db.Refused):
            rem.apply_merge(st, FakeEC2(), ACCOUNT, rid, ACTOR)  # surveillance mode
        with st:
            st.set_mode(ACCOUNT, sg_db.ENFORCE, ACTOR, "test")
        with pytest.raises(rem.RemediateError, match="apply the rule changes"):
            rem.apply_merge(st, FakeEC2(), ACCOUNT, rid, ACTOR)
    finally:
        st.close()


def test_a_merge_moves_the_interfaces_and_can_be_undone(world, monkeypatch):
    st, rid = _approved_merge(world)
    try:
        with st:
            st.set_mode(ACCOUNT, sg_db.ENFORCE, ACTOR, "test")
        m = st._request(rid)["changes"]
        monkeypatch.setattr(sg_db, "ensure_current", lambda *a, **k: [])
        monkeypatch.setattr(st, "rules", lambda *a, **k: {sg_db._rule_tuple(x): "" for x in m["need"]})
        live = [{"eni": e, "instance": "", "asg": "", "kind": "interface", "vpc_id": "vpc-0demo", "ips": [],
                 "groups": g, "description": ""} for e, g in m["enis"].items()]  # fmt: skip
        monkeypatch.setattr(sg_assets, "describe_assets", lambda ec2: live)
        ec2 = FakeEC2()
        out = rem.apply_merge(st, ec2, ACCOUNT, rid, ACTOR)
        assert out["moved"] == 1 and not out["skipped"]
        assert ec2.calls == [{"NetworkInterfaceId": "eni-0app2", "Groups": [m["target"]]}]
        assert st._request(rid)["status"] == "applied"
        events = [r[0] for r in st.db.execute("SELECT action FROM audit")]
        assert "asset-swapped" in events and "groups-merged" in events
    finally:
        st.close()


def test_flow_accounts_lists_read_accounts(world):
    rows = world["console"].flow_accounts()
    assert [r["account"] for r in rows] == [ACCOUNT] and rows[0]["status"] == "read"


def test_a_date_range_leaves_out_the_days_after_it(world):
    """Owner, 2026-11-25: evidence is From a date To a date, so a day under attack can be left out. A slice is used
    only when it lies wholly inside the range, and the plan says which range it used."""
    doc = world["doc"]
    first, last = rem.stored(doc)
    end = last - 2 * rem.DAY
    w, days = rem.window(doc, 90, first, end)
    assert w["chunks"] and all(c["e"] <= end and c["s"] >= first for c in w["chunks"])
    assert not any(c["e"] > end for c in w["chunks"])
    p = world["console"].remediation(ACCOUNT, 90, first, end)
    assert (p["from"], p["to"], p["stored_to"]) == (first, end, last)
    assert sg_console._date_range("2026-11-01", "2026-11-02") == (1793491200.0, 1793664000.0)  # To is included
    with pytest.raises(sg_console.ConsoleError):
        world["console"].remediation(ACCOUNT, 90, end, first)


def test_addresses_let_in_are_split_into_internal_and_external():
    assert rem._internal("10.0.0.0/8", 2**24) == 2**24
    assert rem._internal("sg-0abc", 12) == 12, "another security group is inside the VPC"
    assert rem._internal("8.8.8.0/24", 256) == 0
    every = rem._internal("0.0.0.0/0", 2**32)
    assert every == 2**24 + 2**20 + 2**16 + 2**22, "everyone includes all the private ranges"
    base = {"region": "eu-west-1", "group": "sg-1", "proto": "6", "from": 443, "to": 443}
    r = rem.plan_rule({**base, "source": "0.0.0.0/0", "status": "tighten", "allowed": 2**32,
                       "suggest": ["10.1.0.0/24", "52.1.2.3/32"], "suggest_size": 257})
    assert (r["internal"], r["addresses"] - r["internal"]) == (every, 2**32 - every)
    assert (r["new_internal"], r["new_addresses"] - r["new_internal"]) == (256, 1)
    gone = rem.plan_rule({**base, "source": "10.0.0.0/8", "status": "unused", "allowed": 2**24})
    assert (gone["internal"], gone["new_internal"]) == (2**24, 0)


def test_a_plan_is_kept_so_a_restarted_console_does_not_build_it_again(world, monkeypatch):
    first = world["console"].remediation(ACCOUNT, 90)
    built = []
    monkeypatch.setattr(sg_console, "_plan_job", lambda *a: built.append(a) or None)
    again = sg_console.Console(str(world["db"]), targets=world["console"].targets).remediation(ACCOUNT, 90)
    assert not built, "kept, not built again"
    assert again["totals"] == first["totals"] and len(again["groups"]) == len(first["groups"])
    other = sg_console.Console(str(world["db"]), targets=world["console"].targets).remediation(ACCOUNT, 30)
    assert built and other["status"] == "unknown", "another window is built"


def test_a_plan_is_built_in_another_process_and_a_second_request_waits_for_the_same_build(world, monkeypatch):
    import threading

    c = world["console"]
    monkeypatch.setattr(sg_console, "REPORTS_WAIT", False)
    calls, gate = [], threading.Event()

    class Pool:
        def apply_async(self, fn, args):
            calls.append(args)

            class R:
                def get(self, timeout=None):
                    gate.wait(5)
                    return sg_console._plan_job(*args)

                def ready(self):
                    return gate.is_set()

            return R()

    c._plan_pool = Pool()
    got = []
    ts = [threading.Thread(target=lambda: got.append(c.remediation(ACCOUNT, 90))) for _ in range(2)]
    for t in ts:
        t.start()
    time.sleep(0.3)
    gate.set()
    for t in ts:
        t.join(10)
    assert len(calls) == 1, "one build for both requests"
    assert len(got) == 2 and got[0]["totals"] == got[1]["totals"]


def test_open_to_all_with_no_internet_traffic_is_critical():
    """'if someone has a 0.0.0.0 rule (external) and there is no traffic coming from external make this a
    critical change'."""
    import sg_review
    base = {"region": "eu-west-1", "group": "sg-1", "proto": "6", "from": 22, "to": 22, "allowed": 2**32}
    inside = rem.plan_rule({**base, "source": "0.0.0.0/0", "status": "tighten", "suggest": ["10.1.0.0/24"],
                            "suggest_size": 256, "ext": 0})
    assert inside["urgent"] and inside["external"] == 0
    assert not rem.plan_rule({**base, "source": "0.0.0.0/0", "status": "tighten", "suggest": ["10.1.0.0/24"],
                              "suggest_size": 256, "ext": 5})["urgent"], "the internet uses it"
    assert rem.plan_rule({**base, "source": "0.0.0.0/0", "status": "tighten", "suggest": ["10.1.0.0/24"],
                          "suggest_size": 256, "ext": 0, "cut": True})["urgent"], "the user acts on what was seen"
    assert not rem.plan_rule({**base, "source": "0.0.0.0/0", "status": "open", "ext": 0})["urgent"], "kept: web on a public LB"
    assert not rem.plan_rule({**base, "source": "10.0.0.0/8", "status": "unused", "ext": 0})["urgent"]
    assert rem.plan_rule({**base, "source": "::/0", "status": "unused", "ext": 0})["urgent"]
    assert sg_review._external({"10.0.0.5": [3, 0], "100.64.1.1": [2, 0], "8.8.8.8": [4, 0], "fd00::1": [1, 0]}) == 4
