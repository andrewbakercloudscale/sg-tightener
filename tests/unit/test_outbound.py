"""Outbound rules that leave the account, by risk class (no AWS, no network)."""

import pytest

import sg_ipintel as ipintel
import sg_review


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    old = ipintel.DATA_DIR
    ipintel.set_data_dir(tmp_path)
    monkeypatch.setattr(sg_review, "siblings", lambda doc: [
        {"account": "222233334444", "name": "other", "vpcs": [["eu-west-1", "vpc-9", "theirs", ["10.50.0.0/16"], []]]}])
    yield
    ipintel.set_data_dir(old)


def _rule(proto="-1", lo=0, hi=65535, cidrs=(), refs=(), xrefs=(), pls=()):
    return {"proto": proto, "from": lo, "to": hi, "cidrs": list(cidrs), "cidrs6": [], "refs": list(refs),
            "xrefs": list(xrefs), "pls": list(pls)}


def _doc(egress, extra_groups=None):
    groups = {"sg-app": {"name": "app", "vpc": "vpc-1", "rules": [], "egress": egress},
              "sg-idle": {"name": "idle", "vpc": "vpc-1", "rules": [], "egress": [_rule(cidrs=["0.0.0.0/0"])]},
              **(extra_groups or {})}
    enis = {"eni-a": {"kind": "RDS database", "groups": ["sg-app"], "ips": ["10.1.0.5"], "vpc": "vpc-1"},
            "eni-ep": {"kind": "vpc endpoint", "groups": ["sg-ep"], "ips": ["10.1.0.9"], "vpc": "vpc-1"}}
    pl = {"services": [], "endpoints": [{"id": "vpce-1", "service": "com.amazonaws.vpce.eu-west-1.vpce-svc-abc",
                                         "groups": ["sg-ep"], "enis": ["eni-ep"]}]}
    return {"account": "111122223333", "name": "t", "chunks": [], "regions": {"eu-west-1": {"snapshot": {
        "groups": groups, "enis": enis, "privatelink": pl, "vpcs": [{"id": "vpc-1", "cidrs": ["10.1.0.0/16"]}]}}}}


def test_outbound_rules_are_classed_riskiest_first_and_own_account_left_out():
    e = sg_review.egress_summary(_doc([
        _rule(cidrs=["0.0.0.0/0"]),
        _rule("6", 443, 443, cidrs=["198.51.100.7/32"]),
        _rule("6", 1433, 1433, cidrs=["10.0.0.0/8"]),
        _rule("6", 5432, 5432, cidrs=["10.50.3.0/24"]),
        _rule("6", 443, 443, cidrs=["10.1.2.0/24"]),  # its own VPC, no endpoint in it
        _rule("6", 443, 443, refs=["sg-ep"]),  # PrivateLink to another account's service
        _rule("6", 8080, 8090, xrefs=[{"group": "sg-x", "account": "333344445555", "peering": "pcx-1"}]),
    ]))
    got = [(r["cls"], r["dest"], r["sev"]) for r in e["rules"]]
    assert got[0] == ("internet", "0.0.0.0/0", "high")
    assert ("internet", "198.51.100.7/32", "medium") in got, "one host on one port: not too wide"
    dc = next(r for r in e["rules"] if r["cls"] == "datacentre")
    assert dc["dest"] == "10.0.0.0/8" and dc["wide"] == ["16,777,216 addresses"] and dc["accounts"] == ["222233334444"]
    assert dc["db"] and dc["sev"] == "medium"
    acct = [r for r in e["rules"] if r["cls"] == "account"]
    assert {r["dest"] for r in acct} == {"10.50.3.0/24", "sg-ep", "sg-x"}
    assert next(r for r in acct if r["dest"] == "sg-x")["wide"] == ["11 ports"]
    assert "10.1.2.0/24" not in {r["dest"] for r in e["rules"]}
    assert [r["cls"] for r in e["rules"]] == sorted((r["cls"] for r in e["rules"]), key=sg_review.EGRESS_CLASSES.index)
    assert e["by"]["internet"] == {"rules": 2, "wide": 1, "groups": 1, "enis": 1, "allow_all": 1,
                                   "why": {"all": 1, "ports": 0, "addresses": 1, "accounts": 0}}
    assert e["unattached"] == 1, "the idle group's rule is not counted"


def test_an_endpoint_in_the_own_vpc_reached_by_range_counts_as_another_account():
    e = sg_review.egress_summary(_doc([_rule("6", 443, 443, cidrs=["10.1.0.0/24"])]))
    (r,) = e["rules"]
    assert r["cls"] == "account" and "PrivateLink" in r["name"] and "vpce-svc-abc" in r["name"]


def test_outbound_fixes_name_the_group_assets_and_what_the_rule_should_be(monkeypatch):
    monkeypatch.setattr(sg_review, "tighten_prefs", lambda: {"out_rules": 10, "tolerance": 0.3})
    doc = _doc([_rule(cidrs=["0.0.0.0/0"]), _rule("6", 1433, 1433, cidrs=["10.0.0.0/8"])])
    f = sg_review.egress_fixes(doc)
    assert not f["egress_read"] and f["rules"] == 2
    g = f["groups"][0]
    assert g["group"] == "sg-app" and g["nassets"] == 1 and g["assets"][0]["kind"] == "RDS database"
    allow = next(r for r in g["rules"] if r["dest"] == "0.0.0.0/0")
    assert allow["how"] == "read" and "every protocol" in allow["why"] and allow["allow_all"]
    # once outbound flow logs are read, the fix is the rules actually used, with the commands
    doc["chunks"] = [{"egr": [["10.1.0.5", "203.0.113.9", "eni-a", "6", 443, 40], ["10.1.0.5", "10.20.0.4", "eni-a", "6", 1433, 5]]}]
    f = sg_review.egress_fixes(doc)
    rules = {r["dest"]: r for r in f["groups"][0]["rules"]}
    assert rules["0.0.0.0/0"]["how"] == "narrow"
    assert {(u["proto"], u["port"]) for u in rules["0.0.0.0/0"]["should"]} == {("tcp", 443), ("tcp", 1433)}
    assert rules["10.0.0.0/8"]["should"] == [{"proto": "tcp", "port": 1433, "cidrs": ["10.20.0.4/32"], "dests": 1, "flows": 5}]
    assert "revoke-security-group-egress" in rules["10.0.0.0/8"]["cli"] and "authorize-security-group-egress" in rules["10.0.0.0/8"]["cli"]
