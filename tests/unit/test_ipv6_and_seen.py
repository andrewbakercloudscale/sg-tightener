"""IPv6 sources named and tightened, and the seen-before memory: which sources are new."""

from __future__ import annotations

import gzip
import ipaddress
import json
import time

import pytest

import sg_ipintel as ipintel
import sg_review
import sg_review_demo as demo
import sg_tightener

ACCT = "123456789012"


# ------------------------------------------------------------------------------------------ attribution
def test_intel_names_ipv6_from_aws_providers_the_as_list_and_tor():
    intel = ipintel.Intel(
        [("2a05:d018::/36", "EC2", "eu-west-1"), ("2a05:d018::/36", "AMAZON", "eu-west-1")],
        [("2606:4700::/32", "Cloudflare")],
        [], ["2001:67c:e60:c0c:192:42:116:16"],
        [("2602:80d:1000::", "2602:80d:100f:ffff:ffff:ffff:ffff:ffff", 398324, "US", "CENSYS-ARIN-01")])  # fmt: skip
    aws = intel.label("2a05:d018:abc::1")
    assert (aws["kind"], aws["service"], aws["prefix"]) == ("aws", "EC2", "2a05:d018::/36")
    cf = intel.label("2606:4700:10::6814:1")
    assert (cf["kind"], cf["group"], cf["prefix"]) == ("saas", "cdn", "2606:4700::/32")
    sc = intel.label("2602:80d:1003::17")
    assert (sc["group"], sc["name"], sc["asn"]) == ("scanner", "Censys", 398324)
    assert sc["block"].startswith("2602:80d:1000::-")
    tor = intel.label("2001:67c:e60:c0c:192:42:116:16")
    assert (tor["group"], tor["name"]) == ("anon", "Tor exit")
    assert intel.counts["tor6"] == 1 and intel.counts["asn6"] == 1
    assert intel.label("2001:db8::1")["group"] == "other"  # no list knows it
    assert intel.aws_intervals() == []  # address-space counts stay IPv4


def test_feeds_keep_ipv6_prefixes(monkeypatch, tmp_path):
    assert ipintel.parse_feed("Cloudflare", "lines", b"173.245.48.0/20\n2400:cb00::/32\n") == [
        ("173.245.48.0/20", "Cloudflare"), ("2400:cb00::/32", "Cloudflare")]  # fmt: skip
    goog = json.dumps({"prefixes": [{"ipv4Prefix": "8.8.4.0/24"}, {"ipv6Prefix": "2001:4860::/32"}]}).encode()
    assert [c for c, _n in ipintel.parse_feed("Google", "google", goog)] == ["8.8.4.0/24", "2001:4860::/32"]
    old = ipintel.DATA_DIR
    ipintel.set_data_dir(tmp_path)
    aws = json.dumps({"prefixes": [{"ip_prefix": "3.5.0.0/16", "service": "S3", "region": "eu-west-1"}],
                      "ipv6_prefixes": [{"ipv6_prefix": "2a05:d07a::/32", "service": "S3", "region": "eu-west-1"}]})
    asn6 = gzip.compress(b"2a01:4f8::\t2a01:4f8:ffff:ffff:ffff:ffff:ffff:ffff\t24940\tDE\tHETZNER-AS\n")
    answers = {ipintel.AWS_URL: aws.encode(), ipintel.ASN6_URL: asn6}
    monkeypatch.setattr(ipintel, "_get", lambda url, timeout=30: answers.get(url, b"x"))
    try:
        got = ipintel.refresh(force=True)
        assert got["aws"] == 2 and got["asn6"]
        intel = ipintel.get()
        assert intel.label("2a05:d07a::9")["service"] == "S3"
        assert intel.label("2a01:4f8:c0c::1")["name"] == "Hetzner"
        assert "asn6" not in intel.counts["seed"]
    finally:
        ipintel.set_data_dir(old)


def _doc(snap: dict, chunks=()) -> dict:
    doc = sg_review.new_doc(ACCT, "t")
    doc["regions"]["eu-west-1"] = {"snapshot": snap}
    doc["chunks"] = list(chunks)
    return doc


def test_labeller_puts_ipv6_inside_or_outside():
    snap = {"vpcs": [{"id": "vpc-1", "name": "main", "cidrs": ["10.1.0.0/16"], "cidrs6": ["2a05:d018:1:2300::/56"]}],
            "enis": {"eni-1": {"ipv6": ["2a05:d018:9::5"], "kind": "EC2 instance"}},
            "vpns": [{"name": "DC", "routes": ["fd12:3456::/48"]}]}  # fmt: skip
    names = sg_review.parse_names([{"name": "Acme", "type": "partner", "ranges": ["2001:db8:acce::/48"]}])
    lab = sg_review.Labeller(_doc(snap), internal="fd99::/16 Lab", names=names)
    assert lab("2a05:d018:1:2311::7")["cat"] == "internal"
    assert lab("2a05:d018:9::5")["cat"] == "internal"  # an interface's own address
    assert lab("fd12:3456:0:4::1")["name"] == "Behind VPN DC"
    assert (lab("fd99::1")["cat"], lab("fd99::1")["name"]) == ("internal", "Lab")
    assert lab("fdab::1")["cat"] == "datacentre" and lab("fe80::1")["cat"] == "datacentre"  # private, outside
    acme = lab("2001:db8:acce:1::9")
    assert (acme["cat"], acme["group"], acme["name"], acme["v6"]) == ("saas", "partner", "Acme", True)
    assert lab("2606:4700::1")["v6"] and lab("2606:4700::1")["cat"] in ("saas", "internet")  # from the lists


def test_queries_treat_unique_local_ipv6_as_private_and_filter_by_vpc_ipv6():
    q = sg_review.detail_query(None, ["10.0.0.0/16", "2a05:d018:1::/56"])
    assert 'isIpv6InSubnet(f_srcaddr, "fc00::/7")' in q
    assert 'isIpv6InSubnet(f_dstaddr, "2a05:d018:1::/56")' in q and 'isIpv4InSubnet(f_dstaddr, "10.0.0.0/16")' in q
    snap = {"vpcs": [{"id": "v", "cidrs": ["10.0.0.0/16"], "cidrs6": ["2a05:d018:1::/56"]}]}
    assert sg_review._vpc_ranges(snap) == ["10.0.0.0/16", "2a05:d018:1::/56"]


def test_nacl_verdict_reads_the_ipv6_entries():
    nacl = {"id": "acl-1", "entries": [{"n": 100, "proto": "-1", "allow": True, "cidr": "0.0.0.0/0", "from": 0, "to": 0}],
            "entries6": [{"n": 90, "proto": "6", "allow": False, "cidr": "2001:db8::/32", "from": 22, "to": 22},
                         {"n": 100, "proto": "-1", "allow": True, "cidr": "::/0", "from": 0, "to": 0}]}  # fmt: skip
    assert sg_review.nacl_verdict(nacl, "2001:db8::9", "6", 22) == {"acl": "acl-1", "rule": 90}
    assert sg_review.nacl_verdict(nacl, "2001:db9::9", "6", 22) is None
    assert sg_review.nacl_verdict(nacl, int(ipaddress.IPv4Address("1.2.3.4")), "6", 22) is None


# ------------------------------------------------------------------------------------------ tightening
def test_ipv6_rules_in_scope_are_unique_local_or_the_accounts_own():
    own = ["2a05:d018:1:2300::/56"]
    assert sg_tightener.rule_is_eligible6("fd00::/16")
    assert sg_tightener.rule_is_eligible6("2a05:d018:1:2300::/56", own)
    assert not sg_tightener.rule_is_eligible6("2a05:d018:1:2300::/56")  # public, and not known to be ours
    assert not sg_tightener.rule_is_eligible6("::/0", own)
    assert not sg_tightener.rule_is_eligible6("fd00::/64")  # already a single subnet
    assert not sg_tightener.rule_is_eligible6("10.0.0.0/8") and not sg_tightener.rule_is_eligible("fd00::/16")


def test_collapse_ipv6_keeps_each_sources_64_and_fits_the_budget():
    ips = ["fd00:1:2:3::5", "fd00:1:2:3::9", "fd00:1:2:4::1", "fd00:9::1", "2a05:d018::1", "10.0.0.1"]
    assert sg_tightener.collapse_ipv6_to_cidrs(ips) == [
        "2a05:d018::/64", "fd00:1:2:3::/64", "fd00:1:2:4::/64", "fd00:9::/64"]  # fmt: skip
    two = sg_tightener.collapse_ipv6_to_cidrs(ips, max_rules=3)
    assert len(two) == 3 and "fd00:1:2::/61" in two  # merged inside one /32, never across networks
    within = sg_tightener.collapse_ipv6_to_cidrs(ips, max_rules=1, within="fd00:1::/32")
    assert within == ["fd00:1:2::/61"]
    for c in within:
        assert ipaddress.ip_network(c).subnet_of(ipaddress.ip_network("fd00:1::/32"))


def test_the_cover_is_the_same_exact_algorithm_at_64_bits():
    """_Cover is checked against brute force at 32 bits; at 64 bits (IPv6 /64 units) it must give the same
    costs for the same leaves, shifted into the wider space."""
    import random

    rnd = random.Random(5)
    for _ in range(20):
        xs = sorted({rnd.randrange(0, 4096) for _ in range(rnd.randint(2, 40))})
        leaves = [(x, 32, 1) for x in xs]
        leaves6 = [(x, 64, 1) for x in xs]
        for k in (1, 2, 5, 9):
            a = sg_tightener._Cover(leaves, k)
            b = sg_tightener._Cover(leaves6, k, bits=64)
            assert a.curve == b.curve
            assert [n.prefixlen + 32 for n in a.blocks(k)] == [n.prefixlen for n in b.blocks(k)]


def test_plan_narrows_an_ipv6_rule_and_leaves_v4_planning_as_it_was():
    sg = {"GroupId": "sg-1", "GroupName": "db", "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
         "Ipv6Ranges": [{"CidrIpv6": "fd00::/16", "Description": "ula"}]},
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]}  # fmt: skip
    ips = ["10.1.2.3", "fd00:1:2:3::5", "fd00:1:2:9::5", "2a05:d018::1"]
    plan = sg_tightener.build_plan([sg], ips)
    g = plan["groups"][0]
    assert g["revoke"] == [{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                            "Ipv6Ranges": [{"CidrIpv6": "fd00::/16"}]}]  # fmt: skip
    assert g["restore"][0]["Ipv6Ranges"] == [{"CidrIpv6": "fd00::/16", "Description": "ula"}]
    auth = g["authorise"][0]
    assert [r["CidrIp"] for r in auth["IpRanges"]] == ["10.1.2.3/32"]
    assert [r["CidrIpv6"] for r in auth["Ipv6Ranges"]] == ["fd00:1:2:3::/64", "fd00:1:2:9::/64"]  # never the public one
    v4only = sg_tightener.build_plan([{**sg, "IpPermissions": sg["IpPermissions"][:1]}], ["10.1.2.3"])
    assert v4only["groups"][0]["authorise"][0]["IpRanges"] == auth["IpRanges"]
    assert "Ipv6Ranges" not in sg_tightener.build_plan(
        [{"GroupId": "sg-2", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 1, "ToPort": 1,
                                                 "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}], ["10.0.0.1"]
    )["groups"][0]["authorise"][0]  # fmt: skip


def test_interface_index_owns_ipv6_addresses_and_prefixes():
    idx = sg_tightener.InterfaceIndex([{"NetworkInterfaceId": "eni-1", "PrivateIpAddress": "10.0.0.5",
                                        "Ipv6Addresses": [{"Ipv6Address": "2a05:d018::5"}],
                                        "Ipv6Prefixes": [{"Ipv6Prefix": "2a05:d018:0:1::/80"}],
                                        "Groups": [{"GroupId": "sg-1"}]}])  # fmt: skip
    assert idx.resolve("2a05:d018::5", "eni-1")[1] == "ok"
    assert idx.resolve("2a05:d018:0000:0000:0000:0000:0000:0005", "eni-1")[1] == "ok"
    assert idx.resolve("2a05:d018:0:1::9")[1] == "ok"


# ------------------------------------------------------------------------------------------ the demo
@pytest.fixture(scope="module")
def demo_report():
    doc = demo.build_doc(ACCT, time.time(), 90)
    names = sg_review.parse_names(demo.NAMES)
    return doc, sg_review.build(doc, "1m", "", demo.INTERNAL, names), names


def test_demo_shows_ipv6_sources_named_with_verdicts(demo_report):
    doc, rep, _names = demo_report
    by = {x["src"]: x for x in rep["refused"] + rep["active"]}
    scanner = by["2602:80d:1003::17"]
    assert (scanner["cat"], scanner["group"], scanner["v6"], scanner["sweep"]) == ("internet", "scanner", True, True)
    assert scanner["verdict"]["label"] == "Defence working"
    assert scanner["targets"][0]["pc"]["risky"]  # RDP
    assert (by["2001:db8:acce:10::25"]["group"], by["2001:db8:acce:10::25"]["name"]) == ("partner", "Acme payroll")
    assert by["fd12:3456:0:4::15"]["name"] == "Behind VPN Johannesburg DC"
    assert rep["summary"]["refused_v6"] == 1 and rep["summary"]["active_v6"] == 3
    rule = next(r for r in rep["rules"] if r.get("v6") and r["source"] == demo.ONPREM6)
    assert rule["status"] == "tighten" and rule["suggest"] == ["fd12:3456:0:4::/64"] and rule["unit"] == "/64"
    assert next(r for r in rep["rules"] if r["source"] == "::/0")["status"] == "open"
    ips = sg_review.approved(doc, demo.REGION)["ips"]
    assert "fd12:3456:0:4::15" in ips and ips.index("203.0.113.10") < ips.index("2001:db8:acce:10::25")


def test_new_sources_are_marked_and_told_in_verdicts_rows_and_alerts(demo_report):
    _doc, rep, _names = demo_report
    by = {x["src"]: x for x in rep["refused"] + rep["active"]}
    zs = by["165.225.12.40"]  # the partner's new Zscaler egress: refused for the last six days, never before
    assert zs["new"] and not zs["seen_before"] and zs["first_ever"] >= rep["end"] - 7 * 86400
    assert zs["verdict"]["label"] == "New IP address?" and "never before in" in zs["verdict"]["reason"]
    old = by["203.0.113.11"]  # the partner's other address: seen all along
    assert not old["new"] and old["first_ever"] < rep["end"] - 60 * 86400 and old["seen_before"]
    assert rep["summary"]["new_refused"] >= 3 and rep["summary"]["new_possible"]
    item = next(it for it in rep["attention"] if it["key"] == "moved")
    assert item["new"] == 1
    assert "1 new (never seen before)" in sg_review.alert_text(ACCT, "demo", [item])
    row = next(r for r in sg_review.refused_rows(ACCT, "demo", rep) if r["src"] == "165.225.12.40")
    assert row["new"] and not row["seen_before"] and row["first_ever"] == zs["first_ever"] and not row["internal"]
    v6row = next(r for r in sg_review.refused_rows(ACCT, "demo", rep) if r["src"] == "2602:80d:1003::17")
    assert v6row["v6"] and v6row["scan"] and v6row["new"]


def test_nothing_is_new_without_enough_history(demo_report):
    doc, _rep, names = demo_report
    end = max(c["e"] for c in doc["chunks"])
    short = {**doc, "chunks": [c for c in doc["chunks"] if c["s"] >= end - 10 * 86400]}
    rep = sg_review.build(short, "1w", "", demo.INTERNAL, names)
    assert not rep["summary"]["new_possible"] and rep["summary"]["new_refused"] == 0
    assert not any(x["new"] for x in rep["refused"] + rep["active"])
    assert all("never before in" not in x["verdict"]["reason"] for x in rep["refused"])


def test_a_new_address_verdict_says_when_the_source_is_not_new():
    v = {"key": "moved", "reason": "X was let in until 1 Nov; Y started being refused 2 Nov."}
    sg_review._note_novelty(v, {"first_ever": 1_700_000_000, "seen_before": True, "new": False}, 1_690_000_000)
    assert "Not a new IP address though: first seen" in v["reason"]
    s = {"key": "scan", "reason": "Scan refused."}
    sg_review._note_novelty(s, {"first_ever": 1_700_000_000, "seen_before": False, "new": True}, 1_690_000_000)
    assert s["reason"] == "Scan refused." and s["new"]
