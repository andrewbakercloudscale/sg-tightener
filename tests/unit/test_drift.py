"""Drift: a rule opened wide in the last day becomes a "Needs attention" item, so watch alerts on it."""

import json
import time

import sg_review
import sg_review_demo
from sg_review import drift_findings, parse_event

NOW = 1_800_000_000.0


def ct(name, req, who="arn:aws:sts::1:assumed-role/Admin/jdoe", ip="41.13.7.200", t=NOW - 3600):
    return {"EventTime": None, "CloudTrailEvent": json.dumps({
        "eventName": name, "eventTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)),
        "userIdentity": {"arn": who}, "sourceIPAddress": ip, "requestParameters": req})}


def perms(cidr=None, cidr6=None, port=22):
    p = {"ipProtocol": "tcp", "fromPort": port, "toPort": port}
    if cidr:
        p["ipRanges"] = {"items": [{"cidrIp": cidr}]}
    if cidr6:
        p["ipv6Ranges"] = {"items": [{"cidrIpv6": cidr6}]}
    return {"items": [p]}


def test_parse_event_keeps_ipv6_and_who_and_where():
    ev = parse_event(ct("AuthorizeSecurityGroupIngress", {"groupId": "sg-1", "ipPermissions": perms("10.0.0.0/8", "::/0")}))
    assert ev["added"] == [["6", 22, 22, "10.0.0.0/8"]] and ev["added6"] == [["6", 22, 22, "::/0"]]
    assert ev["who"] == "jdoe" and ev["ip"] == "41.13.7.200"


def test_parse_event_reads_what_modify_set_the_rule_to():
    req = {"ModifySecurityGroupRulesRequest": {"GroupId": "sg-1", "SecurityGroupRule": {
        "SecurityGroupRuleId": "sgr-1", "SecurityGroupRule": {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
                                                              "CidrIpv4": "0.0.0.0/0"}}}}
    ev = parse_event(ct("ModifySecurityGroupRules", req))
    assert ev["unknown"] and ev["set"] == [["6", 3389, 3389, "0.0.0.0/0", "sgr-1"]]


def _doc(events, rules):
    return {"regions": {"eu-west-1": {"snapshot": {"groups": {"sg-1": {"name": "ops", "rules": rules}}},
                                      "history": {"events": events}}}}


def _rule(cidr, port=22, v6=False):
    return {"proto": "6", "from": port, "to": port, "cidrs": [] if v6 else [cidr], "cidrs6": [cidr] if v6 else []}


def _ev(entries, t=NOW - 3600, key="added", **kw):
    return {"t": t, "name": "AuthorizeSecurityGroupIngress", "who": "jdoe", "ip": "1.2.3.4", "group": "sg-1",
            "added": [], "removed": [], "unknown": False, key: entries, **kw}


def test_severity_by_range_and_port():
    cases = [
        (["6", 22, 22, "0.0.0.0/0"], "critical"),
        (["6", 443, 443, "0.0.0.0/0"], "medium"),
        (["6", 8081, 8081, "0.0.0.0/0"], "medium"),  # web (alternative)
        (["6", 7777, 7777, "0.0.0.0/0"], "high"),
        (["6", 22, 22, "41.0.0.0/11"], "high"),
        (["6", 7777, 7777, "41.0.0.0/16"], "medium"),
        (["6", 22, 22, "10.0.0.0/8"], "medium"),
    ]
    for entry, sev in cases:
        (it,) = drift_findings(_doc([_ev([entry])], [_rule(entry[3], entry[1])]), NOW)
        assert it["sev"] == sev, (entry, it["sev"])
        assert it["kind"] == "drift" and "jdoe" in it["title"] and "1.2.3.4" in it["reason"]


def test_narrow_or_old_or_removed_changes():
    assert drift_findings(_doc([_ev([["6", 22, 22, "41.0.0.0/24"]])], []), NOW) == []
    assert drift_findings(_doc([_ev([["6", 443, 443, "10.0.0.0/8"]])], []), NOW) == []
    assert drift_findings(_doc([_ev([["6", 22, 22, "0.0.0.0/0"]], t=NOW - 2 * 86400)], []), NOW) == []
    (gone,) = drift_findings(_doc([_ev([["6", 22, 22, "0.0.0.0/0"]])], []), NOW)
    assert gone["sev"] == "low" and not gone["still"] and gone["cli"] == ""


def test_ipv6_and_modify_by_rule_id():
    (v6,) = drift_findings(_doc([_ev([["6", 22, 22, "::/0"]], key="added6")], [_rule("::/0", v6=True)]), NOW)
    assert v6["sev"] == "critical" and "CidrIpv6=::/0" in v6["cli"]
    (m,) = drift_findings(_doc([_ev([["6", 22, 22, "0.0.0.0/0", "sgr-9"]], key="set",
                                    name="ModifySecurityGroupRules")], [_rule("0.0.0.0/0")]), NOW)
    assert m["cli"].endswith("--security-group-rule-ids sgr-9")


def test_demo_drift_tops_needs_attention_and_watch_posts_it_once():
    doc = sg_review_demo.build_doc(sg_review_demo.ACCOUNT, time.time(), 7)
    rep = sg_review.build(doc, "1w", internal=sg_review_demo.INTERNAL)
    assert rep["attention"][0]["kind"] == "drift" and rep["attention"][0]["sev"] == "critical"
    state: dict = {}
    first = sg_review.fresh_items(rep["attention"], state, time.time(), "high", 86400)
    assert any(i["kind"] == "drift" for i in first)
    again = sg_review.fresh_items(rep["attention"], state, time.time() + 3600, "high", 86400)
    assert not any(i["kind"] == "drift" for i in again)
    assert "contractor-ops opened ops-ssh" in sg_review.alert_text("1", "x", first, markdown=False)
