"""sg_review: planning, queries, rule history, the report, the page and the CLI (no AWS, no network)."""

import json
import time
from datetime import datetime, timezone

import pytest

import sg_ipintel as ipintel
import sg_review
import sg_review as sg_flows
import sg_review_demo as demo_sg
from sg_tightener import collapse_ips_to_cidrs

NOW = datetime(2026, 11, 20, 17, 30, tzinfo=timezone.utc).timestamp()


@pytest.fixture(autouse=True, scope="module")
def _data_dir(tmp_path_factory):
    old = ipintel.DATA_DIR
    ipintel.set_data_dir(tmp_path_factory.mktemp("sgtdata"))
    yield
    ipintel.set_data_dir(old)


ACCT = demo_sg.ACCOUNT


# ------------------------------------------------------------------------------------------ planning
def test_plan_slices_hourly_six_hourly_daily_and_fills_only_the_gap():
    one = sg_review.plan(NOW, 1)
    assert all(e - s == 3600 for s, e in one)
    end = sg_review.read_end(NOW)
    assert max(e for _, e in one) == end and min(s for s, _ in one) % sg_review.SIX == 0
    week = sg_review.plan(NOW, 7)
    assert {e - s for s, e in week} == {3600, sg_review.SIX}
    month = sg_review.plan(NOW, 30)
    assert sg_review.DAY in {e - s for s, e in month}
    assert min(s for s, _ in month) % sg_review.DAY == 0
    # nothing left once read; a later read plans only the hours since
    assert sg_review.plan(NOW, 30, month) == []
    later = sg_review.plan(NOW + 3 * 3600, 30, month)
    assert sum(e - s for s, e in later) == 3 * 3600
    assert later == sorted(later, reverse=True)


def test_queries_filter_inbound_and_keep_refused_internet_sources_apart():
    fmt = "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${flow-direction}"
    q = sg_flows.detail_query(fmt, ["10.0.0.0/16"])
    assert 'f_flow_direction = "ingress"' in q and "least(f_dstport, 32768)" in q and "limit 10000" in q
    assert 'f_action = "ACCEPT" or (isIpv4InSubnet(f_srcaddr, "10.0.0.0/8")' in q
    assert "least" not in sg_flows.detail_query(fmt, [], fold=False)
    p = sg_flows.public_query(None, ["10.0.0.0/16"])
    assert 'isIpv4InSubnet(f_dstaddr, "10.0.0.0/16")' in p and 'f_action = "REJECT" and not' in p
    assert sg_flows.detail_query("${version} ${srcaddr}", []) is None


def test_rule_history_event_parsing():
    ev = {"EventTime": datetime(2026, 11, 1, tzinfo=timezone.utc), "CloudTrailEvent": json.dumps({
        "eventName": "AuthorizeSecurityGroupIngress", "userIdentity": {"arn": "arn:aws:sts::1:assumed-role/r/alice"},
        "requestParameters": {"groupId": "sg-1", "ipPermissions": {"items": [
            {"ipProtocol": "tcp", "fromPort": 443, "toPort": 443, "ipRanges": {"items": [{"cidrIp": "10.0.0.0/8"}]}}]}}})}  # fmt: skip
    p = sg_flows.parse_event(ev)
    assert p["group"] == "sg-1" and p["added"] == [["6", 443, 443, "10.0.0.0/8"]] and p["who"] == "alice"
    by_id = {"EventTime": ev["EventTime"], "CloudTrailEvent": json.dumps({
        "eventName": "RevokeSecurityGroupIngress",
        "requestParameters": {"groupId": "sg-1", "securityGroupRuleIds": {"items": ["sgr-1"]}}})}  # fmt: skip
    assert sg_flows.parse_event(by_id)["unknown"]
    failed = {"CloudTrailEvent": json.dumps({"eventName": "AuthorizeSecurityGroupIngress", "errorCode": "Denied"})}
    assert sg_flows.parse_event(failed) is None


def test_state_at_works_back_through_changes():
    now = {("6", 22, 22, "10.200.0.0/16")}
    evs = [{"t": 100, "unknown": False, "added": [["6", 22, 22, "10.200.0.0/16"]], "removed": []},
           {"t": 101, "unknown": False, "added": [], "removed": [["6", 22, 22, "10.0.0.0/8"]]}]  # fmt: skip
    assert sg_review._state_at(now, evs, 200) == (now, True)
    assert sg_review._state_at(now, evs, 50) == ({("6", 22, 22, "10.0.0.0/8")}, True)
    state, known = sg_review._state_at(now, [{"t": 100, "unknown": True, "added": [], "removed": []}], 50)
    assert state == now and not known


def test_collapse_keeps_every_address_and_never_widens_public():
    out = collapse_ips_to_cidrs([f"10.0.1.{i}" for i in range(1, 250)] + ["8.8.8.8"])
    assert out == ["8.8.8.8/32", "10.0.1.0/24"]


def test_intervals():
    a = [ipintel.cidr_iv("10.0.0.0/8")]
    b = [ipintel.cidr_iv("10.1.0.0/16")]
    assert ipintel.size(ipintel.subtract(a, b)) == 2**24 - 2**16
    assert ipintel.intersect(a, b) == b


# ------------------------------------------------------------------------------------------- report
@pytest.fixture(scope="module")
def report():
    doc = demo_sg.build_doc(ACCT, time.time(), 90)
    return doc, sg_review.build(doc, "3m", "", demo_sg.INTERNAL)


def test_over_provisioned_never_counts_a_seen_address(report):
    doc, rep = report
    seen = set()
    for c in doc["chunks"]:
        seen |= {r[0] for r in c["rows"]} | {r[0] for r in c["pub"]}
    ivs = ipintel.merge([(n, n) for n in map(sg_review._ip, seen)])
    for r in rep["rules"]:
        allowed = ipintel.merge([ipintel.cidr_iv(r["source"])])
        assert r["never"] == ipintel.size(ipintel.subtract(allowed, ivs))
    assert rep["summary"]["over_now"] > 0
    assert all(v >= 0 for s in rep["series"]["over"].values() for v in s)


def test_rule_changes_move_the_over_provisioned_line(report):
    _, rep = report
    total = [sum(rep["series"]["over"][k][i] for k in sg_review.CATS) for i in range(len(rep["bins"]))]
    assert len(set(total)) >= 3  # the revoke, the tightening, then the wide batch rule added back
    assert {m["event"] for m in rep["markers"]} >= {"AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress"}


def test_rules_statuses_and_suggestions(report):
    _, rep = report
    by = {(r["gname"], r["source"]): r for r in rep["rules"]}
    assert by[("public-alb", "0.0.0.0/0")]["status"] == "open"
    assert by[("payments-db", "172.16.0.0/12")]["status"] == "unused"
    db = next(r for (g, s), r in by.items() if g == "payments-db" and s != "172.16.0.0/12")
    assert db["status"] == "tighten" and db["suggest"]
    # the suggestion keeps every address seen on the group, the DR replica included
    sugg = ipintel.merge([ipintel.cidr_iv(c) for c in db["suggest"]])
    for x in db["top"]:
        n = sg_review._ip(x["src"])
        assert any(a <= n <= b for a, b in sugg)
    assert by[("partner-sftp", "203.0.113.0/24")]["status"] == "tighten"


def test_sources_are_labelled_and_dr_shows_apart(report):
    _, rep = report
    cats = {x["cat"] for x in rep["refused"]}
    assert {"datacentre", "aws", "saas", "internet"} <= cats
    acl = next(x for x in rep["refused"] if x["src"] == "10.200.9.9")
    assert acl["name"] == "Behind VPN Johannesburg DC" and acl["targets"][0]["by"].startswith("Network ACL")
    assert any(x["cat"] == "aws" and "Route 53" in x["name"] for x in rep["refused"])
    assert any(x["sweep"] for x in rep["refused"])
    assert rep["suggestions"] and rep["suggestions"][0]["cidrs"]
    older = [x for x in rep["active"] if not x["today"]]
    assert older and any(x["days"] <= 3 for x in older)
    assert sum(rep["series"]["active_older"]["internal"]) > 0
    # replies to the account's own connections never count as active
    assert not any(x["src"] == "52.95.110.1" for x in rep["active"])


def test_short_evidence_is_never_called_unused():
    doc = demo_sg.build_doc(ACCT, time.time(), 1)
    rep = sg_review.build(doc, "24h", "")
    assert not any(r["status"] in ("unused", "tighten") for r in rep["rules"])
    assert rep["summary"]["watch"] > 0


def test_approved_json_is_sg_tightener_v2(report):
    doc, _ = report
    region = next(iter(doc["regions"]))
    a = sg_review.approved(doc, region)
    assert a["schema"] == "sg-tightener.approved/v2" and a["ips"] and a["flows"]
    assert all(f["dstport"] < 32768 for f in a["flows"])


# ----------------------------------------------------------------------------------- page and CLI
def test_page_has_every_range_read_and_cannot_be_broken_out_of(tmp_path):
    doc = demo_sg.build_doc(ACCT, time.time(), 30)
    g = doc["regions"][demo_sg.REGION]["snapshot"]["groups"]["sg-0app0000000000001"]
    g["name"] = "</script><script>alert(1)</script>"
    data = sg_review.page_data(doc, "", demo_sg.INTERNAL)
    assert list(data["ranges"]) == ["24h", "1w", "1m"] and data["default"] == "1m"
    assert data["approved"][demo_sg.REGION]["schema"] == "sg-tightener.approved/v2"
    page = sg_review.render_page(data)
    assert page.count("</script>") == 3  # the data, the chart library and the page's own script
    assert "alert(1)</script>" not in page and "Chart.js v4" in page
    assert "{{DATA}}" not in page and "{{CHART_JS}}" not in page
    body = page.split('<script type="application/json" id="data">', 1)[1].split("</script>", 1)[0]
    assert json.loads(body)["ranges"]["1m"]["rules"]


def test_cli_demo_report_approved_and_forget(tmp_path, monkeypatch):
    out = tmp_path / "demo.html"
    assert sg_review.main(["--data-dir", str(tmp_path / "d"), "demo", "--offline", "--out", str(out)]) == 0
    assert "Security Group Review" in out.read_text()
    sg_review.save(demo_sg.build_doc(ACCT, time.time(), 7))
    page = tmp_path / "r.html"
    assert sg_review.main(["--data-dir", str(ipintel.DATA_DIR), "report", "--offline", "--out", str(page)]) == 0
    assert ACCT in page.read_text()
    ap = tmp_path / "approved.json"
    assert sg_review.main(["--data-dir", str(ipintel.DATA_DIR), "approved", "--region", demo_sg.REGION,
                           "--out", str(ap)]) == 0  # fmt: skip
    assert json.loads(ap.read_text())["flows"]
    assert sg_review.main(["--data-dir", str(ipintel.DATA_DIR), "forget", "--account", ACCT]) == 0
    assert sg_review.load(ACCT) is None
    with pytest.raises(SystemExit):
        sg_review.main(["--data-dir", str(ipintel.DATA_DIR), "report", "--offline"])


def test_estimate_from_earlier_reads():
    doc = demo_sg.build_doc(ACCT, time.time(), 7)
    est = sg_review.estimate(doc, ACCT, [demo_sg.REGION])
    assert est["rate"] > 0 and est["ranges"][1]["missing_hours"] == 0 and est["ranges"][2]["cost"] > 0
    empty = sg_review.estimate(None, ACCT, [demo_sg.REGION])
    assert empty["rate"] is None and empty["ranges"][0]["missing_hours"] > 0


class _FakeLogs:
    """Logs Insights stand-in: a slice longer than an hour fills the row limit; an hour does not."""

    def __init__(self):
        self.q = {}
        self.calls = []

    def start_query(self, **kw):
        qid = f"q{len(self.q)}"
        self.q[qid] = kw
        self.calls.append((kw["endTime"] + 1 - kw["startTime"], "stats count(*) as flows, sum" in kw["queryString"]))
        return {"queryId": qid}

    def get_query_results(self, queryId):
        kw = self.q[queryId]
        span = kw["endTime"] + 1 - kw["startTime"]
        detail = "sum(f_bytes)" in kw["queryString"]
        n = sg_flows.ROWS if detail and span > 3600 else 2
        row = [{"field": "src", "value": "10.0.0.5"}, {"field": "dst", "value": "10.0.1.1"},
               {"field": "eni", "value": "eni-1"}, {"field": "proto", "value": "6"},
               {"field": "dport", "value": "443"}, {"field": "port", "value": "443"},
               {"field": "action", "value": "ACCEPT"}, {"field": "flows", "value": "3"}]  # fmt: skip
        return {"status": "Complete", "statistics": {"bytesScanned": 1000.0}, "results": [row] * n}


def test_read_chunk_splits_a_full_slice_down_to_hours():
    logs = _FakeLogs()
    start = 1_790_000_000 // 3600 * 3600
    out = sg_review.read_chunk(logs, "eu-west-1", start, start + 4 * 3600, [{"format": None, "groups": ["g"]}], [])
    assert sorted(c["e"] - c["s"] for c in out) == [3600] * 4
    assert all(c["st"] == "ok" and len(c["rows"]) == 2 for c in out)
    assert sum(c["b"] for c in out) > 0


# ------------------------------------------------------------------ port classes, attribution, extract data
def test_port_class_names_common_ports_and_ranges():
    assert sg_review.port_class("6", 22)["cls"] == "admin" and sg_review.port_class("6", 22)["risky"]
    assert sg_review.port_class("6", 443) == {"cls": "web", "name": "Web", "svc": "HTTPS", "risky": False}
    assert sg_review.port_class("17", 53)["svc"] == "DNS"
    assert sg_review.port_class("6", 5432)["cls"] == "database"
    assert sg_review.port_class("6", 445)["cls"] == "windows"
    assert sg_review.port_class("6", 31000)["cls"] == "containers"  # Kubernetes NodePort range
    assert sg_review.port_class("6", 40000)["cls"] == "high"
    assert sg_review.port_class("6", 7)["cls"] == "low"
    assert sg_review.port_class("6", 1500)["cls"] == "registered"
    assert sg_review.port_class("1", 0)["cls"] == "network"
    assert sg_review.rule_port_class({"proto": "-1", "from": 0, "to": 65535})["cls"] == "all"
    rng = sg_review.rule_port_class({"proto": "6", "from": 20, "to": 450})
    assert rng["cls"] == "range" and rng["risky"] and "SSH, SFTP (22)" in rng["svc"]
    assert all(c in sg_review.PORT_CLASSES for c in {v[0] for v in sg_review.PORT_SERVICES.values()})


def test_build_attributes_sources_and_classifies_ports(report):
    _doc, rep = report
    by_src = {x["src"]: x for x in rep["refused"]}
    scanner = next(x for x in rep["refused"] if x["src"].startswith("162.142.125."))
    assert scanner["cat"] == "internet" and scanner["as_num"] == 398324 and scanner["cc"] == "US"
    assert scanner["net"] == f"internet|{scanner['name']}"
    hc = by_src["54.228.16.8"]
    assert hc["cat"] == "aws" and hc["service"] == "ROUTE53_HEALTHCHECKS" and hc["range"]
    dc = by_src["10.200.4.30"]
    assert dc["cat"] == "datacentre" and dc["range"] == "10.200.0.0/16"
    t = dc["targets"][0]
    assert t["port"] == 9092 and t["pc"]["cls"] == "messaging" and t["region"] == demo_sg.REGION and t["vpc"]
    assert rep["groups"]["sg-0bat0000000000005"]["name"] == "batch-workers"
    # the class series count each refused source once per class and period, and add up with the kind series
    cls = rep["series"]["by_class"]["refused"]
    assert "admin|internet" in cls and "messaging|datacentre" in cls
    nets = rep["series"]["by_net"]["refused"]
    assert sum(n["sources"] for n in nets) == rep["summary"]["refused"]
    for i in range(len(rep["bins"])):
        assert sum(n["data"][i] for n in nets) == sum(rep["series"]["refused"][c][i] for c in sg_review.CATS)
    ports = {(p["proto"], p["port"]): p for p in rep["ports"]}
    assert ports[("6", 3389)]["refused"].get("internet") and ports[("6", 3389)]["risky"]
    assert ports[("6", 443)]["active"]
    assert all("pc" in r for r in rep["rules"])


def test_page_carries_the_port_classes_and_extract_dialog(tmp_path):
    doc = demo_sg.build_doc(ACCT, time.time(), 7)
    data = sg_review.page_data(doc, "", demo_sg.INTERNAL)
    assert {c["key"] for c in data["port_classes"]} == set(sg_review.PORT_CLASSES)
    page = sg_review.render_page(data)
    assert 'id="btnExtract"' in page and 'id="xr"' in page and 'id="chPortsRefused"' in page
