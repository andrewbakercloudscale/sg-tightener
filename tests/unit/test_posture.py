"""Exposure and hygiene: reachability, IPv6, outbound, and group hygiene checks on the snapshot."""

import time

import pytest

import sg_ipintel as ipintel
import sg_review
import sg_review_demo
from sg_review import internet_path, posture_findings


def rule(proto="6", lo=22, hi=22, cidrs=(), v6=(), refs=(), xrefs=()):
    return {"proto": proto, "from": lo, "to": hi, "cidrs": list(cidrs), "descs": {}, "pls": [], "refs": list(refs),
            "any6": "::/0" in v6, "cidrs6": list(v6), "xrefs": list(xrefs)}


def eni(groups, subnet="subnet-pub", public="", ipv6=(), kind="EC2 instance"):
    return {"ips": ["10.0.1.5"], "prefixes": [], "groups": groups, "subnet": subnet, "vpc": "vpc-1", "kind": kind,
            "desc": "", "instance": "", "public": public, "ipv6": list(ipv6)}


def doc(groups, enis, routes=None, nacls=None, stale=()):
    for g in groups.values():
        g.setdefault("vpc", "vpc-1")
        g.setdefault("tag", "")
        g.setdefault("owner", "123456789012")
        g.setdefault("egress", [rule("-1", 0, 65535, ["0.0.0.0/0"])])
    routes = routes if routes is not None else {
        "read": True, "subnets": {"subnet-pub": {"igw4": True, "igw6": True, "table": "rtb-1"}},
        "main": {"vpc-1": {"igw4": False, "igw6": False, "table": "rtb-main"}}}
    snap = {"groups": groups, "enis": enis, "routes": routes, "nacls": nacls or {}, "stale": list(stale)}
    return {"account": "123456789012", "regions": {"eu-west-1": {"snapshot": snap}}}


def keys(items):
    return sorted((it["key"], it["sev"]) for it in items)


def test_open_ssh_on_a_public_routed_instance_is_critical_with_the_revoke():
    d = doc({"sg-1": {"name": "admin", "rules": [rule(cidrs=["0.0.0.0/0"])]}},
            {"eni-1": eni(["sg-1"], public="198.51.100.9")})
    (it,) = [i for i in posture_findings(d, {("eni-1", "6", 22): {"1.2.3.4"}}) if i["key"] == "exposed"]
    assert it["sev"] == "critical" and it["kind"] == "posture" and it["area"] == "exposure"
    assert "198.51.100.9" in it["reason"] and "1 internet source(s)" in it["reason"]
    assert it["cli"] == ("python sg_db.py exec --reason 'sg_review: remove tcp 22 from 0.0.0.0/0' -- "
                         "aws ec2 revoke-security-group-ingress --region eu-west-1 --group-id sg-1 "
                         "--ip-permissions 'IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0}]'")


def test_no_public_address_or_no_igw_route_or_a_nacl_deny_is_latent_not_exposed():
    g = {"sg-1": {"name": "admin", "rules": [rule(cidrs=["0.0.0.0/0"])]}}
    private = posture_findings(doc(g, {"eni-1": eni(["sg-1"])}))
    assert keys(private) == [("latent-open", "low")] and "no public IP address" in private[0]["reason"]
    unrouted = posture_findings(doc(g, {"eni-1": eni(["sg-1"], subnet="subnet-app", public="198.51.100.9")}))
    assert "internet gateway" in unrouted[0]["reason"] and unrouted[0]["key"] == "latent-open"
    nacl = {"subnet-pub": {"id": "acl-1", "entries": [
        {"n": 50, "proto": "6", "allow": False, "cidr": "0.0.0.0/0", "from": 22, "to": 22}]}}
    denied = posture_findings(doc(g, {"eni-1": eni(["sg-1"], public="198.51.100.9")}, nacls=nacl))
    assert "acl-1 rule 50" in denied[0]["reason"] and denied[0]["key"] == "latent-open"


def test_route_tables_not_read_means_unknown_not_safe():
    g = {"sg-1": {"name": "admin", "rules": [rule(cidrs=["0.0.0.0/0"])]}}
    d = doc(g, {"eni-1": eni(["sg-1"], public="198.51.100.9")}, routes={"read": False, "subnets": {}, "main": {}})
    (it,) = posture_findings(d)
    assert it["key"] == "latent-open" and "could not be checked" in it["reason"]


def test_public_load_balancer_on_443_is_not_flagged_but_an_instance_on_443_is_low():
    g = {"sg-1": {"name": "web", "rules": [rule(lo=443, hi=443, cidrs=["0.0.0.0/0"])]}}
    assert posture_findings(doc(g, {"eni-1": eni(["sg-1"], public="1.1.1.1", kind="load balancer")})) == []
    assert keys(posture_findings(doc(g, {"eni-1": eni(["sg-1"], public="1.1.1.1")}))) == [("exposed", "low")]


def test_ipv6_any_reaches_an_instance_with_an_ipv6_address_even_when_ipv4_is_narrow():
    g = {"sg-1": {"name": "sftp", "rules": [rule(cidrs=["203.0.113.0/24"], v6=["::/0"])]}}
    (it,) = posture_findings(doc(g, {"eni-1": eni(["sg-1"], ipv6=["2a05:d018::40"])}))
    assert it["key"] == "exposed" and it["sev"] == "critical" and it["v6"]
    assert "Ipv6Ranges=[{CidrIpv6=::/0}]" in it["cli"]


def test_ipv6_any_with_no_ipv6_address_is_medium_latent_and_wide_global_ranges_are_flagged():
    g = {"sg-1": {"name": "sftp", "rules": [rule(v6=["::/0", "2c0f:fb50::/32", "fd00::/8", "2a05:d018::/48"])]}}
    items = posture_findings(doc(g, {"eni-1": eni(["sg-1"])}))
    assert keys(items) == [("latent-open", "medium"), ("v6-wide", "medium")]
    (wide,) = [i for i in items if i["key"] == "v6-wide"]
    assert wide["source"] == "2c0f:fb50::/32"  # ULA fd00::/8 and a /48 are not "wide global"


def test_default_group_in_use_cross_account_trust_and_stale_references():
    groups = {
        "sg-d": {"name": "default", "rules": [rule("-1", 0, 65535, refs=["sg-d"]), rule(lo=22, hi=22, cidrs=["10.0.0.0/8"])]},
        "sg-db": {"name": "db", "rules": [rule(lo=5432, hi=5432, refs=["sg-x"],
                                               xrefs=[{"group": "sg-x", "account": "444455556666", "peering": ""}]),
                                          rule(lo=5432, hi=5432, refs=["sg-y"],
                                               xrefs=[{"group": "sg-y", "account": "123456789012", "peering": ""}])]},
    }
    stale = [{"group": "sg-db", "name": "db", "vpc": "vpc-1", "direction": "in", "proto": "6", "from": 8443,
              "to": 8443, "ref": "sg-gone", "account": "123456789012", "peering": ""}] * 2
    items = posture_findings(doc(groups, {"eni-1": eni(["sg-d"]), "eni-2": eni(["sg-db"])}, stale=stale))
    assert keys(items) == [("cross-account", "medium"), ("default-group", "medium"), ("stale-ref", "low")]
    (x,) = [i for i in items if i["key"] == "cross-account"]
    assert "444455556666" in x["title"] and "UserIdGroupPairs=[{GroupId=sg-x}]" in x["cli"]
    (s,) = [i for i in items if i["key"] == "stale-ref"]
    assert "FromPort=8443" in s["cli"]


def test_default_group_with_only_its_self_reference_and_unused_is_quiet():
    groups = {"sg-d": {"name": "default", "rules": [rule("-1", 0, 65535, refs=["sg-d"])]}}
    assert posture_findings(doc(groups, {})) == []


def test_shared_tiers_and_unused_open_groups():
    groups = {"sg-s": {"name": "shared", "rules": []},
              "sg-u": {"name": "spare", "rules": [rule(lo=3389, hi=3389, cidrs=["0.0.0.0/0"])]}}
    enis = {"eni-1": eni(["sg-s"], subnet="subnet-app"), "eni-2": eni(["sg-s"], subnet="subnet-app", kind="RDS database")}
    found = keys(posture_findings(doc(groups, enis)))
    assert ("shared-tiers", "low") in found and ("unused-open", "low") in found
    assert ("egress-open", "low") in found  # the database's outbound is open, and outbound was not read


def test_egress_fit_from_observed_destinations_and_tor_reported_on_its_own():
    groups = {"sg-a": {"name": "app", "rules": []}}
    enis = {"eni-1": eni(["sg-a"], subnet="subnet-app")}
    seen = {"eni-1": {("6", 5432): {"10.0.4.20": 100}, ("6", 443): {"52.218.48.10": 30}, ("6", 9001): {"185.220.101.33": 4}}}

    def lab(ip):
        return {"cat": "internet", "group": "anon", "name": "Tor exit"} if ip.startswith("185.") else {"cat": "aws"}

    items = posture_findings(doc(groups, enis), egress_seen=seen, lab=lab)
    assert keys(items) == [("egress-bad", "high"), ("egress-fit", "medium")]
    fit = next(i for i in items if i["key"] == "egress-fit")
    assert {(f["port"], tuple(f["cidrs"])) for f in fit["fit"]} == {(5432, ("10.0.4.20/32",)), (443, ("52.218.48.10/32",))}
    assert "9001" not in fit["cli"] and "revoke-security-group-egress" in fit["cli"]
    assert "authorize-security-group-egress" in fit["cli"]
    bad = next(i for i in items if i["key"] == "egress-bad")
    assert bad["dests"] == ["185.220.101.33"] and "Tor exit" in bad["reason"]


def test_many_web_destinations_keep_443_open():
    groups = {"sg-a": {"name": "app", "rules": []}}
    seen = {"eni-1": {("6", 443): {f"52.0.0.{i}": 1 for i in range(20)}}}
    items = posture_findings(doc(groups, {"eni-1": eni(["sg-a"], subnet="subnet-app")}), egress_seen=seen,
                             lab=lambda ip: {"cat": "internet"})
    (fit,) = items
    assert fit["fit"][0]["cidrs"] == ["0.0.0.0/0"]


def test_internet_path_reasons():
    r = rule(cidrs=["0.0.0.0/0"])
    d = doc({}, {})["regions"]["eu-west-1"]["snapshot"]
    assert internet_path(d, eni([], public="1.1.1.1"), r) == (True, "1.1.1.1 is public and routed to an internet gateway")
    assert internet_path(d, eni([]), r, v6=True)[0] is False

@pytest.fixture
def tor_list(tmp_path):
    """The demo's Tor relay on the Tor exit list, whatever lists this computer has downloaded."""
    old = ipintel.DATA_DIR
    ipintel.set_data_dir(tmp_path)
    (tmp_path / "ipintel").mkdir()
    (tmp_path / "ipintel" / "tor.json").write_text('["185.220.101.33"]')
    yield
    ipintel.set_data_dir(old)


def test_demo_shows_every_area_and_joins_needs_attention(tor_list):
    rep = sg_review.build(sg_review_demo.build_doc(sg_review_demo.ACCOUNT, time.time(), 30), "1m",
                          internal=sg_review_demo.INTERNAL, names=None)
    areas = {p["area"] for p in rep["posture"]}
    assert areas == {"exposure", "ipv6", "egress", "hygiene"}
    att = {(a["kind"], a["key"]) for a in rep["attention"]}
    assert ("posture", "exposed") in att and ("posture", "egress-bad") in att
    assert rep["summary"]["posture"]["critical"] == 2
    assert rep["egress_read"]["on"] and rep["egress_read"]["slices"] > 0


def test_egress_query_uses_flow_direction_or_the_vpc_ranges():
    with_dir = sg_review.DEFAULT_FORMAT + " ${flow-direction}"
    q = sg_review.egress_query(with_dir, ["10.0.0.0/16"])
    assert 'f_flow_direction = "egress"' in q and f"f_dstport < {sg_review.EPHEMERAL}" in q and 'f_action = "ACCEPT"' in q
    q = sg_review.egress_query(None, ["10.0.0.0/16"])
    assert 'isIpv4InSubnet(f_srcaddr, "10.0.0.0/16")' in q
    assert sg_review.egress_query(None, []) is None  # cannot tell outbound from inbound


def test_read_chunk_runs_the_outbound_query_only_when_asked(monkeypatch):
    calls = []

    def fake(logs, groups, query, s, e, cancelled=None, **kw):
        calls.append(query)
        if "egress" in query or "isIpv4InSubnet(f_srcaddr" in query:
            return [{"src": "10.0.1.5", "dst": "52.1.1.1", "eni": "eni-1", "proto": "6", "dport": "443", "flows": "3"}], 10, "Complete"
        return [], 10, "Complete"

    monkeypatch.setattr(sg_review, "run_query", fake)
    qs = [{"format": sg_review.DEFAULT_FORMAT, "groups": ["g"]}]
    (c,) = sg_review.read_chunk(None, "eu-west-1", 0, 3600, qs, ["10.0.0.0/16"])
    assert "egr" not in c and len(calls) == 2
    (c,) = sg_review.read_chunk(None, "eu-west-1", 0, 3600, qs, ["10.0.0.0/16"], egress=True)
    assert c["egr"] == [["10.0.1.5", "52.1.1.1", "eni-1", "6", 443, 3]] and c["b"] == 30


def test_the_worst_external_rules_come_first():
    import sg_review

    def rule(src, never_ext, enis=1, risky=False):
        return {"gname": src, "group": "sg-1", "region": "eu-west-1", "ports": "tcp 22", "source": src,
                "never_ext": never_ext, "enis": enis, "pc": {"risky": risky, "svc": "SSH" if risky else ""}}

    rules = [rule("100.0.0.0/8", 12_582_912, enis=6), rule("0.0.0.0/0", 0), rule("10.0.0.0/8", 0),
             rule("0.0.0.0/0", 0, risky=True), rule("13.0.0.0/8", 16_777_216, enis=2)]
    got = sg_review._external_rules(rules)
    assert [(x["source"], x["risky"]) for x in got] == [("0.0.0.0/0", True), ("0.0.0.0/0", False),
                                                        ("100.0.0.0/8", False), ("13.0.0.0/8", False)]
    assert got[0]["open"] and got[0]["service"] == "SSH"
