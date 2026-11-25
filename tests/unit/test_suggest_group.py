"""The console's suggestions share a group's rule budget the way sg_tightener.py plan does."""

import ipaddress

import pytest

import sg_review


@pytest.fixture(autouse=True)
def _own_prefs(tmp_path, monkeypatch):
    monkeypatch.setattr(sg_review, "_prefs_file", lambda: tmp_path / "tighten.json")
    monkeypatch.setattr(sg_review, "_prefs_seen", (None, {}))


def test_prefs_saved_checked_and_read_back():
    assert sg_review.tighten_prefs()["max_rules"] == 60
    got = sg_review.save_tighten_prefs({"tolerance": "0.1", "max_rules": 120, "fill": 1, "bogus": 3})
    assert got == {"max_rules": 120, "tolerance": 0.1, "fill": True, "out_rules": 10}
    assert sg_review.tighten_prefs() == got
    with pytest.raises(ValueError):
        sg_review.save_tighten_prefs({"tolerance": 2})


def test_fill_spends_free_rules_on_precision(monkeypatch):
    g = {"rules": [{"cidrs": ["10.0.0.0/8"]}]}
    srcs = [f"10.0.0.{i}" for i in (1, 2, 3, 9, 200)]  # a 30% tolerance gives one wide block; fill keeps them exact
    row = _row()
    monkeypatch.setitem(sg_review.TIGHTEN, "tolerance", 0.99)
    sg_review._suggest_group(g, [(row, srcs, ipaddress.IPv4Network("10.0.0.0/8"), 1 << 24)])
    loose = row["suggest_size"]
    monkeypatch.setitem(sg_review.TIGHTEN, "fill", True)
    row = _row()
    sg_review._suggest_group(g, [(row, srcs, ipaddress.IPv4Network("10.0.0.0/8"), 1 << 24)])
    assert row["suggest_size"] < loose and row["suggest_size"] == 5


def _row():
    return {"status": "tighten", "note": "", "suggest": [], "suggest_size": None}


def test_rules_share_the_group_budget(monkeypatch):
    monkeypatch.setitem(sg_review.TIGHTEN, "max_rules", 6)
    monkeypatch.setitem(sg_review.TIGHTEN, "tolerance", 0.0)
    g = {"rules": [{"cidrs": ["10.0.0.0/8", "172.16.0.0/12"]}, {"refs": ["sg-1"]}]}  # 3 rules, one left alone
    a = [f"10.{i}.0.1" for i in range(1, 9)]  # 8 scattered sources: would want 8 rules alone
    b = ["172.16.0.1", "172.16.0.2"]
    pending = [(_row(), a, ipaddress.IPv4Network("10.0.0.0/8"), 1 << 24),
               (_row(), b, ipaddress.IPv4Network("172.16.0.0/12"), 1 << 20)]
    sg_review._suggest_group(g, pending)
    got = [r["suggest"] for r, *_ in pending]
    assert sum(len(x) for x in got) <= 5  # 6 minus the one rule left alone
    for (_, _, within, _), cidrs in zip(pending, got):
        assert cidrs and all(ipaddress.IPv4Network(c).subnet_of(within) for c in cidrs)
    assert pending[0][0]["budget"] == 5


def test_nothing_to_take_away_is_in_use(monkeypatch):
    monkeypatch.setitem(sg_review.TIGHTEN, "tolerance", 0.0)
    g = {"rules": [{"cidrs": ["10.0.0.0/31"]}]}
    row = _row()
    sg_review._suggest_group(g, [(row, ["10.0.0.0", "10.0.0.1"], ipaddress.IPv4Network("10.0.0.0/31"), 2)])
    assert row["status"] == "used" and row["suggest"] == []


def test_group_rule_count_counts_every_entry():
    g = {"rules": [{"cidrs": ["10.0.0.0/8"], "cidrs6": ["::/0"], "pls": ["pl-1"], "refs": ["sg-1", "sg-2"]}]}
    assert sg_review.group_rule_count(g) == 5


def test_pod_addresses_in_shared_space_merge_like_private_ones():
    import sg_tightener

    pods = [f"100.64.{i}.{j}" for i in range(4) for j in range(1, 250, 3)]  # an EKS pod range, partly used
    cidrs = sg_tightener.collapse_ips_to_cidrs(pods, 60, 0.7)
    assert len(cidrs) < 10  # was one /32 per pod: 332 rules
    assert all(ipaddress.IPv4Network(c).subnet_of(ipaddress.IPv4Network("100.64.0.0/10")) for c in cidrs)
