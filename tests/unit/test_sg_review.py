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
    ivs = ipintel.merge([(n, n) for n in map(sg_review._ip, seen) if n is not None])
    for r in rep["rules"]:
        if r.get("v6"):  # IPv6 ranges are counted in /64 subnets, tested separately
            continue
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


def test_cli_demo_report_approved_and_forget(tmp_path, monkeypatch, capsys):
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
    assert sg_review.main(["--data-dir", str(ipintel.DATA_DIR), "reach", "10.200.4.21", "--account", ACCT]) == 0
    assert "can reach" in capsys.readouterr().out
    assert sg_review.main(["--data-dir", str(ipintel.DATA_DIR), "reach", "10.200.4.21", "--account", ACCT, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["groups"] > 0
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
    assert scanner["group"] == "scanner" and scanner["provider"] == "Censys" and scanner["name"] == "Censys"
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
    groups = rep["series"]["by_group"]["refused"]
    assert "scanner" in groups and "internal" in groups
    for i in range(len(rep["bins"])):
        assert sum(d[i] for d in groups.values()) == sum(rep["series"]["refused"][c][i] for c in sg_review.CATS)
    assert all(n["group"] for n in nets if not n["key"].endswith("|*"))
    ports = {(p["proto"], p["port"]): p for p in rep["ports"]}
    assert ports[("6", 3389)]["refused"].get("internet") and ports[("6", 3389)]["risky"]
    assert ports[("6", 443)]["active"]
    assert all("pc" in r for r in rep["rules"])


def test_page_carries_the_port_classes_and_extract_dialog(tmp_path):
    doc = demo_sg.build_doc(ACCT, time.time(), 7)
    data = sg_review.page_data(doc, "", demo_sg.INTERNAL)
    assert {c["key"] for c in data["port_classes"]} == set(sg_review.PORT_CLASSES)
    types = {t["key"]: t for t in data["source_types"]}
    assert set(types) == set(sg_review.SOURCE_TYPES) and types["security"]["kind"] == "saas" and types["security"]["note"]
    page = sg_review.render_page(data)
    assert 'id="btnExtract"' in page and 'id="xr"' in page and 'id="chPortsRefused"' in page


# ------------------------------------------------------------------------------------- source types
@pytest.mark.parametrize("asn,owner,want", [
    (398324, "CENSYS-ARIN-01 - Censys, Inc.", ("Censys", "scanner")),
    (None, "SHODAN-SCAN Shodan LLC", ("Shodan", "scanner")),
    (53813, "ZSCALER-INC", ("Zscaler", "security")),
    (1, "ZSCALER-EMEA Zscaler Switzerland GmbH", ("Zscaler", "security")),
    (1, "TORSERVERS-NET Stiftung Erneuerbare Freiheit", ("Tor exit", "anon")),
    (1, "DIGITALOCEAN-ASN - DigitalOcean, LLC", ("DigitalOcean", "hosting")),
    (1, "CLOUDFLARENET - Cloudflare, Inc.", ("Cloudflare", "cdn")),
    (1, "GITHUB - GitHub, Inc.", ("GitHub", "saas")),
    (1, "INT-NETWORK IP Volume inc", ("IP Volume", "hosting")),
    (1, "GOOGLE-CLOUD-PLATFORM - Google LLC", ("Google Cloud", "hosting")),
    (1, "GOOGLE - Google LLC", ("Google", "saas")),
])  # fmt: skip
def test_org_of_names_common_providers(asn, owner, want):
    org = ipintel.org_of(asn, owner)
    assert org and org[:2] == want and org[2]


@pytest.mark.parametrize("owner", ["COMCAST-7922 - Comcast Cable", "Zoomtel Networks", "Constant Contact",
                                   "Umbrella Telecom Ltd", "Palo Alto Unified School District", ""])
def test_org_of_leaves_unknown_and_lookalike_networks_alone(owner):
    assert ipintel.org_of(64512, owner) is None


def test_feed_group_and_every_group_has_a_kind_and_note():
    assert ipintel.feed_group("Cloudflare") == "cdn" and ipintel.feed_group("GitHub (hooks)") == "saas"
    assert ipintel.feed_group("Google Cloud (a customer's server)") == "hosting"
    for g, (name, kind) in ipintel.GROUPS.items():
        assert name and kind in ("saas", "internet") and ipintel.GROUP_NOTE[g]
    for provider, group, what in ipintel.ORG_ASNS.values():
        assert provider and group in ipintel.GROUPS and what
    assert all(g in ipintel.GROUPS for _rx, _p, g, _w in ipintel.ORG_NAMES)


def test_label_gives_the_source_type_and_hosting_feeds_are_internet():
    intel = ipintel.Intel([], [("192.0.2.0/24", "Cloudflare"), ("198.51.100.0/24", "Google Cloud (a customer's server)")],
                          [("203.0.113.0", "203.0.113.255", 398324, "US", "CENSYS-ARIN-01 - Censys, Inc."),
                           ("100.64.0.0", "100.64.0.255", 64512, "GB", "Some ISP")])  # fmt: skip
    cf = intel.label("192.0.2.9")
    assert (cf["kind"], cf["group"], cf["provider"]) == ("saas", "cdn", "Cloudflare")
    gc = intel.label("198.51.100.9")
    assert (gc["kind"], gc["group"]) == ("internet", "hosting")
    sc = intel.label("203.0.113.9")
    assert (sc["kind"], sc["group"], sc["name"]) == ("internet", "scanner", "Censys") and sc["what"]
    isp = intel.label("100.64.0.9")
    assert (isp["kind"], isp["group"]) == ("internet", "other") and isp["name"].startswith("AS64512")
    # the saas share of over-provisioned holds the provider's own ranges, not anyone's hosting
    assert intel.saas_intervals() == [(ipintel.cidr_iv("192.0.2.0/24"))]


# ------------------------------------------------------------------------------- Tor list, names file
def test_tor_exit_list_is_parsed_and_wins_over_the_network_owner():
    assert ipintel.parse_tor(b"# list\n171.25.193.25\n\nnot an ip\n2001:DB8::1\n80.67.167.81\n") == [
        "171.25.193.25", "2001:db8::1", "80.67.167.81"]  # fmt: skip
    intel = ipintel.Intel([("171.25.193.0/24", "EC2", "eu-north-1")], [],
                          [("171.25.193.0", "171.25.193.255", 198093, "SE", "DFRI-AS Foreningen")],
                          ["171.25.193.25"])  # fmt: skip
    tor = intel.label("171.25.193.25")
    assert (tor["kind"], tor["group"], tor["name"], tor["asn"]) == ("internet", "anon", "Tor exit", 198093)
    assert intel.label("171.25.193.26")["kind"] == "aws" and intel.counts["tor"] == 1


def test_refresh_keeps_the_tor_list_and_get_reads_it(monkeypatch):
    monkeypatch.setattr(ipintel, "_get", lambda url, timeout=30: b"192.0.2.77\n" if url == ipintel.TOR_URL else b"x")
    got = ipintel.refresh(force=True)
    assert got.get("tor") == 1
    assert ipintel.get().label("192.0.2.77")["group"] == "anon"


def test_names_file_is_checked():
    names = sg_review.parse_names([
        {"name": "Acme payroll", "ranges": ["203.0.113.0/24"], "asn": ["AS64500", 64501], "note": "SFTP"},
        {"name": "Cape Town DC", "type": "datacentre", "ranges": ["10.90.0.0/16"]},
    ])  # fmt: skip
    assert names[0]["type"] == "partner" and names[0]["asn"] == [64500, 64501] and str(names[0]["ranges"][0]) == "203.0.113.0/24"
    assert sg_review.parse_names({"names": []}) == [] and sg_review.parse_names(None) == []
    for bad in ([{"ranges": ["1.2.3.0/24"]}], [{"name": "x"}], [{"name": "x", "type": "friend", "asn": [1]}],
                [{"name": "x", "ranges": ["nope"]}], [{"name": "x", "type": "internal", "asn": [1]}], {"names": "x"}):  # fmt: skip
        with pytest.raises((ValueError, TypeError)):
            sg_review.parse_names(bad)


def test_names_file_names_ranges_and_as_numbers(report, tmp_path):
    doc, _rep = report
    (tmp_path / "names.yaml").write_text(
        "- name: Acme payroll\n  ranges: [203.0.113.0/24]\n  note: SFTP drop\n"
        "- name: Censys, allowed to scan\n  type: scanner\n  asn: [398324]\n"
        "- name: Cape Town DC\n  type: datacentre\n  ranges: [10.90.0.0/16]\n"
    )
    names = sg_review.load_names(tmp_path / "names.yaml")
    lab = sg_review.Labeller(doc, "", demo_sg.INTERNAL, names)
    acme = lab("203.0.113.10")
    assert (acme["cat"], acme["group"], acme["name"], acme["what"], acme["named"]) == ("saas", "partner", "Acme payroll", "SFTP drop", True)
    cz = lab("162.142.125.10")
    assert (cz["cat"], cz["group"], cz["name"], cz["as_num"]) == ("internet", "scanner", "Censys, allowed to scan", 398324)
    dc = lab("10.90.1.1")
    assert (dc["cat"], dc["name"]) == ("datacentre", "Cape Town DC")
    # the partner range moves into the SaaS and partners share of the address space
    iv = ipintel.cidr_iv("203.0.113.0/24")
    assert ipintel.size(ipintel.intersect([iv], lab.cat_iv["saas"])) == 256
    assert sum(ipintel.size(v) for v in lab.cat_iv.values()) == 2**32
    rep = sg_review.build(doc, "3m", "", demo_sg.INTERNAL, names)
    assert any(x["name"] == "Acme payroll" for x in rep["active"])


def test_names_cli_writes_an_example_then_checks_it(tmp_path):
    p = tmp_path / "names.yaml"
    assert sg_review.main(["names", "--out", str(p)]) == 0 and "Acme payroll" in p.read_text()
    assert sg_review.main(["names", "--out", str(p)]) == 0
    assert sg_review.load_names(p)[0]["asn"] == [64500]
    with pytest.raises(SystemExit):
        sg_review.load_names(tmp_path / "missing.yaml")
    (tmp_path / "broken.yaml").write_text("- name: [unclosed\n")
    with pytest.raises(SystemExit, match="broken.yaml"):
        sg_review.load_names(tmp_path / "broken.yaml")


# ----------------------------------------------------------------------------------- tighten panel
def test_fit_model_gives_each_rule_its_sources_once_for_the_page():
    doc = demo_sg.build_doc(ACCT, time.time(), 30)
    data = sg_review.page_data(doc, "", demo_sg.INTERNAL)
    fit = data["fit"]
    assert fit["cap"] == sg_review.FIT_CAP and all("fit" not in r for r in data["ranges"].values())
    rules = {(r["group"], r["from"], r["source"]): r for r in fit["rules"]}
    wide = rules[("sg-0app0000000000001", 443, "10.0.0.0/8")]
    assert wide["status"] == "tighten" and wide["allowed"] == 2**24 and len(wide["srcs"]) == 14
    assert all(src in fit["labels"] for src, _ in wide["srcs"]), "every kept source carries its attribution"
    assert {r["kind"] for r in fit["rules"] if r["source"] == "0.0.0.0/0"} == {"open"}
    assert all(not r["srcs"] for r in fit["rules"] if r["status"] == "unused")
    assert all(not any(k in r for k in ("keep_src", "fit_ok")) for r in fit["rules"])
    cat, _typ, name, rng = fit["labels"]["10.40.3.10"]
    assert cat == "internal" and name.startswith("Payments prod") and rng == "10.40.0.0/16"


def test_page_carries_the_tighten_panel_and_its_plan_goes_through_propose():
    import sg_db

    doc = demo_sg.build_doc(ACCT, time.time(), 7)
    page = sg_review.render_page(sg_review.page_data(doc, "", demo_sg.INTERNAL))
    for needle in ('id="fitWrap"', 'id="fitKinds"', 'id="fitRecent"', 'id="fitRules"', "sg-tightener.plan/v1",
                   "/api/propose", "Refused sources"):
        assert needle in page, needle
    # The plan the page writes (fitPlans): revoke the rule as it is, authorise the fitted ranges.
    perm = lambda cidrs: {"IpProtocol": "6", "FromPort": 443, "ToPort": 443,
                          "IpRanges": [{"CidrIp": c, "Description": "callers"} for c in cidrs]}
    plan = {"schema": "sg-tightener.plan/v1", "account": ACCT, "region": demo_sg.REGION,
            "groups": [{"group_id": "sg-0app0000000000001", "group_name": "app",
                        "revoke": [perm(["10.0.0.0/8"])], "authorise": [perm(["10.20.1.0/24", "10.40.3.0/24"])]}]}
    got = sg_db.plan_changes(plan, ACCT)
    assert [(op, r[4]) for _, op, r, _ in got] == [("remove", "10.0.0.0/8"), ("add", "10.20.1.0/24"), ("add", "10.40.3.0/24")]
    assert {r[:4] for _, _, r, _ in got} == {(sg_db.IN, "tcp", 443, 443)}


# ----------------------------------------------------------------------------------- blast radius
def test_reach_lists_what_one_address_can_reach_by_range_and_by_group():
    doc = demo_sg.build_doc(ACCT, time.time(), 7)
    model = sg_review.reach_model(doc)
    dc = sg_review.reach(model, "10.200.4.21")  # a data centre host, over the VPN
    by = {(x["gname"], x["ports"]): x for x in dc["rows"]}
    assert by[("ops-ssh", "tcp 22")]["risky"] and by[("app-servers", "tcp 443")]["via"] == "10.0.0.0/8"
    assert len(by[("app-servers", "tcp 443")]["assets"]) == 3
    assert dc["rows"][0]["risky"], "risky ports first"
    assert dc["summary"]["open_to_all"] == 3 and dc["groups_in"] == []
    app = sg_review.reach(model, "10.20.2.11")  # an app server: its own group is known
    assert app["groups_in"] == ["sg-0app0000000000001"]
    assert ("payments-db", "tcp 5432") in {(x["gname"], x["ports"]) for x in app["rows"]}
    anyone = sg_review.reach(model, "198.51.100.200")
    assert {x["via"] for x in anyone["rows"]} == {"0.0.0.0/0"}
    v6 = sg_review.reach(model, "2001:db8:acce:10::25")
    assert [x["gname"] for x in v6["rows"]] == ["partner-sftp"]
    with pytest.raises(SystemExit):
        sg_review.reach(model, "not-an-ip")


def test_page_carries_the_blast_radius_panel():
    doc = demo_sg.build_doc(ACCT, time.time(), 7)
    data = sg_review.page_data(doc, "", demo_sg.INTERNAL)
    assert data["reach"]["rules"] and "sg-0app0000000000001" in data["reach"]["assets"]
    page = sg_review.render_page(data)
    for needle in ('id="reachWrap"', 'id="reachIp"', 'id="reachRules"', "function reachOf"):
        assert needle in page, needle


# ------------------------------------------------------------------------------------------ threat lists
def test_threat_lists_parse_spamhaus_json_and_plain_lists():
    raw = (b'{"cidr":"1.10.16.0/20","sblid":"SBL1","rir":"apnic"}\n{"type":"metadata","records":1}\n'
           b"# Feodo Tracker\n162.243.103.246\n10.0.0.1\n0.0.0.0/0\n2001:678:254::/48 ; SBL2\nnot an address\n")  # fmt: skip
    assert ipintel.parse_threat(raw) == ["1.10.16.0/20", "162.243.103.246/32", "2001:678:254::/48"]


def test_threat_list_names_an_address_but_not_a_providers_shared_one():
    intel = ipintel.Intel(ipintel.SEED_AWS, ipintel.SEED_SAAS, ipintel.SEED_ASN, (), (), [
        ("162.243.103.246", "Feodo Tracker botnet C2"), ("104.20.22.42", "blocklist.de attacker"),
        ("13.244.1.1", "blocklist.de attacker"), ("1.10.16.0/20", "Spamhaus DROP")])  # fmt: skip
    c2 = intel.label("162.243.103.246")
    assert (c2["group"], c2["name"], c2["kind"]) == ("threat", "Feodo Tracker botnet C2", "internet")
    assert "command and control" in c2["what"]
    assert intel.label("1.10.17.5")["group"] == "threat"  # inside a Spamhaus DROP netblock
    assert intel.label("13.244.1.1")["group"] == "threat"  # anyone's server on EC2 is still named
    cf = intel.label("104.20.22.42")  # a CDN address carries everyone's traffic: the provider's name stays
    assert (cf["group"], cf["threat"]) == ("cdn", "blocklist.de attacker")
    assert intel.counts["threat"] == 4


def test_refresh_keeps_the_threat_lists_and_a_failed_read_keeps_the_old_copy(monkeypatch):
    feeds = {url: name for name, url in ipintel.THREAT_FEEDS}

    def fake(url, timeout=30):
        if feeds.get(url) == "Feodo Tracker botnet C2":
            return b"# C2\n162.243.103.246\n"
        if url in feeds:
            raise OSError("down")
        return b"x"

    monkeypatch.setattr(ipintel, "_get", fake)
    assert ipintel.refresh(force=True).get("threat") == 1
    assert ipintel.get().label("162.243.103.246")["name"] == "Feodo Tracker botnet C2"
    monkeypatch.setattr(ipintel, "_get", lambda url, timeout=30: (_ for _ in ()).throw(OSError("offline")))
    ipintel.refresh(force=True)
    assert ipintel.get().label("162.243.103.246")["group"] == "threat"


def test_known_malicious_sources_are_flagged_in_and_out():
    doc = demo_sg.build_doc(ACCT, time.time(), 30)
    doc["egress"] = True
    rep = sg_review.build(doc, "1m", "", demo_sg.INTERNAL, names=sg_review.parse_names(demo_sg.NAMES))
    let_in = [a for a in rep["attention"] if a.get("label") == "Known malicious let in"]
    assert let_in and let_in[0]["sev"] == "critical" and "198.51.100.66" in json.dumps(let_in[0])
    out = [p for p in rep["posture"] if p["label"] == "Outbound to a known malicious address"]
    assert out and out[0]["sev"] == "critical" and out[0]["name"] == "eni-0app2"
    assert "198.51.100.99 (Feodo Tracker botnet C2)" in out[0]["reason"]
    refused = next(r for r in rep["refused"] if r["src"] == "198.51.100.66")
    assert refused["verdict"]["title"] == "Known malicious address refused"
    rows = sg_review.refused_rows(ACCT, "demo", rep)
    assert next(r for r in rows if r["src"] == "198.51.100.66")["threat"]
    assert not next(r for r in rows if r["src"] == "198.51.100.66")["tor"]


def test_watch_always_posts_known_malicious_items():
    items = [{"kind": "refused", "label": "Refused"}, {"kind": "active", "label": "Known malicious let in"},
             {"kind": "posture", "label": "Outbound to a known malicious address"},
             {"kind": "active", "label": "Scan got in"}, {"kind": "drift", "label": "Opened wide"}]  # fmt: skip
    assert [i["label"] for i in sg_review.alert_items(items)] == [
        "Refused", "Known malicious let in", "Outbound to a known malicious address"]  # fmt: skip
    assert len(sg_review.alert_items(items, "all")) == 5
