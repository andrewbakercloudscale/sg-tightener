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
    assert 'f_flow_direction = "ingress"' in q and "limit 10000" in q
    assert "least(f_dstport + least(1, floor(f_dstport / 1024)) * (f_srcport < f_dstport) * (32768 - f_dstport), 32768)" in q
    assert "least(f_dstport, 32768)" in sg_flows.detail_query(fmt, [], fold="high")
    assert "least(f_dstport, 32768)" in sg_flows.detail_query(fmt.replace(" ${srcport}", ""), [])
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


def test_one_day_of_evidence_is_acted_on_the_person_decides_when():
    """Owner's decision: a day of flow logs is enough to tighten and to call a rule unused. What runs less often
    is refused, shows on Rejected traffic, and Propose allowing opens it again."""
    doc = demo_sg.build_doc(ACCT, time.time(), 1)
    rep = sg_review.build(doc, "24h", "")
    assert any(r["status"] in ("unused", "tighten") for r in rep["rules"])
    assert rep["summary"]["watch"] == 0


def test_approved_json_is_sg_tightener_v2(report):
    doc, _ = report
    region = next(iter(doc["regions"]))
    a = sg_review.approved(doc, region)
    assert a["schema"] == "sg-tightener.approved/v2" and a["ips"] and a["flows"]
    assert all(f["dstport"] < 32768 for f in a["flows"])


# ----------------------------------------------------------------------------------- page and CLI
def test_page_has_every_window_and_cannot_be_broken_out_of(tmp_path):
    doc = demo_sg.build_doc(ACCT, time.time(), 30)
    g = doc["regions"][demo_sg.REGION]["snapshot"]["groups"]["sg-0app0000000000001"]
    g["name"] = "</script><script>alert(1)</script>"
    data = sg_review.page_data(doc, "", demo_sg.INTERNAL)
    assert list(data["ranges"]) == list(sg_review.RANGES) and data["default"] == "1m"  # every window, read or not
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
        n = sg_flows.ROWS if detail and span > getattr(self, "fits", 3600) else 2
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


def test_a_busy_hour_is_split_below_an_hour_until_it_fits():
    """Two thirds of the slices of 112 accounts hit 10,000 rows at an hour (busy EKS VPCs) and were kept cut,
    which left every rule there 'not safe to act on'. Five minutes of one fitted in 4,588 rows."""
    logs = _FakeLogs()
    logs.fits = 600  # only ten minutes or less fit
    start = 1_790_000_000 // 3600 * 3600
    out = sg_review.read_chunk(logs, "eu-west-1", start, start + 3600, [{"format": None, "groups": ["g"]}], [])
    assert all(c["st"] == "ok" for c in out) and max(c["e"] - c["s"] for c in out) <= 600
    assert sorted((c["s"], c["e"]) for c in out)[0][0] == start and max(c["e"] for c in out) == start + 3600
    assert sum(c["e"] - c["s"] for c in out) == 3600


def test_an_hour_read_cut_before_is_read_again_split_and_replaced_and_the_next_read_starts_split():
    logs = _FakeLogs()
    logs.fits = 900
    start = 1_790_000_000 // 3600 * 3600
    qs = [{"format": None, "groups": ["g"]}]
    old = {"r": "eu-west-1", "s": start, "e": start + 3600, "st": "cut", "b": 5, "rows": [], "pub": [], "pc": False, "err": ""}
    doc = sg_review.new_doc("111122223333", "")
    doc["regions"]["eu-west-1"] = {"query_sets": qs}
    doc["chunks"] = [old]
    assert sg_review.coarse_cut(old)

    class Sess:
        def client(self, *_a, **_k):
            return logs

    saved = []
    orig = sg_review.save
    sg_review.save = lambda d: saved.append(1)
    try:
        sg_review.run_read(Sess(), doc, [("eu-west-1", start, start + 3600, qs, [])], 1, start + 7200)
    finally:
        sg_review.save = orig
    assert old not in doc["chunks"], "the cut hour is replaced"
    assert all(c["st"] == "ok" for c in doc["chunks"]) and sum(c["e"] - c["s"] for c in doc["chunks"]) == 3600
    assert doc["regions"]["eu-west-1"]["slice"] == 900
    assert sg_review._pieces(start, start + 3600, 900) == [(start + i * 900, start + (i + 1) * 900) for i in range(4)]
    assert sg_review._pieces(start, start + 3600, None) == [(start, start + 3600)]
    assert sg_review.cut_tasks(doc) == [], "nothing cut is left to read again"
    doc["chunks"].append({**old, "s": start - 3600, "e": start})
    assert [(t[1], t[2]) for t in sg_review.cut_tasks(doc)] == [(start - 3600 + i * 900, start - 3600 + (i + 1) * 900) for i in range(4)]
    assert sg_review.cut_tasks(doc, first_only=True) == [], "the slice length is already known"


def test_slices_of_one_read_share_the_split_that_fits_and_report_progress_within_a_slice():
    """A 7-day read showed '0 of 53' for minutes: every 3-hour slice re-queried itself whole, then in halves,
    down to the size that fits (each throwaway query billed), and progress only moved when a slice finished."""
    qs = [{"format": None, "groups": ["g"]}]
    start = 1_790_000_000 // 3600 * 3600
    slices = [(start + i * 4 * 3600, start + (i + 1) * 4 * 3600) for i in range(6)]

    def read(hint):
        logs, ticks = _FakeLogs(), []
        logs.fits = 900
        for s, e in slices:
            sg_review.read_chunk(logs, "eu-west-1", s, e, qs, [], tick=lambda b, secs: ticks.append(secs), hint=hint)
        return len(logs.calls), ticks

    alone, _ = read(None)
    shared, ticks = read({})
    assert shared < alone * 0.75 and shared <= 6 * 16 * 2 + 6, (shared, alone)  # only the first slice probes
    assert sum(ticks) == 6 * 4 * 3600 and len([t for t in ticks if t]) == 6 * 16, "progress moves per piece read"


def test_stop_cancels_the_running_queries_and_keeps_only_whole_slices():
    """Stop let the 8 running slices finish every split before stopping; now each query is cancelled."""
    logs = _FakeLogs()
    logs.fits = 900
    start = 1_790_000_000 // 3600 * 3600
    qs = [{"format": None, "groups": ["g"]}]
    stop = {"n": 0}

    def cancelled():
        stop["n"] += 1
        return stop["n"] > 6

    out = sg_review.read_chunk(logs, "eu-west-1", start, start + 4 * 3600, qs, [], cancelled, hint={})
    assert len(logs.calls) < 8, "no further queries once stopped"
    assert all(c["st"] != "failed" for c in out), "an unfinished piece is not recorded as read or failed"
    assert sg_review.read_chunk(logs, "eu-west-1", start, start + 3600, qs, [], lambda: True) == []


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
    out = [p for p in rep["posture"] if p["label"] == "Outbound to a known malicious IP address"]
    assert out and out[0]["sev"] == "critical" and out[0]["name"] == "eni-0app2"
    assert "198.51.100.99 (Feodo Tracker botnet C2)" in out[0]["reason"]
    refused = next(r for r in rep["refused"] if r["src"] == "198.51.100.66")
    assert refused["verdict"]["title"] == "Known malicious IP address refused"
    rows = sg_review.refused_rows(ACCT, "demo", rep)
    assert next(r for r in rows if r["src"] == "198.51.100.66")["threat"]
    assert not next(r for r in rows if r["src"] == "198.51.100.66")["tor"]


def test_watch_always_posts_known_malicious_items():
    items = [{"kind": "refused", "label": "Refused"}, {"kind": "active", "label": "Known malicious let in"},
             {"kind": "posture", "label": "Outbound to a known malicious IP address"},
             {"kind": "active", "label": "Scan got in"}, {"kind": "drift", "label": "Opened wide"}]  # fmt: skip
    assert [i["label"] for i in sg_review.alert_items(items)] == [
        "Refused", "Known malicious let in", "Outbound to a known malicious IP address"]  # fmt: skip
    assert len(sg_review.alert_items(items, "all")) == 5


# ------------------------------------------------------------------------------------------ extract rule
def test_hosts_name_each_address_down_to_the_instance_and_its_os():
    doc = demo_sg.build_doc(ACCT, time.time(), 3)
    h = sg_review.hosts_model(doc)
    eni = h["by_ip"]["10.20.6.50"]
    kind, inst, name, os_, _typ, groups, region, _desc = h["enis"][eni]
    assert (eni, kind, name, os_, region) == ("eni-0bat1", "EC2 instance", "batch-worker-1", "Red Hat Enterprise Linux", demo_sg.REGION)
    assert inst.startswith("i-") and "batch-workers" in groups
    assert h["by_ip"]["198.51.100.9"] == "eni-0leg1" and h["enis"]["eni-0leg1"][3] == "Windows"  # by public address too


def test_instances_are_read_with_name_and_os():
    class Ec2:
        def describe_instances(self, InstanceIds):
            return {"Reservations": [{"Instances": [
                {"InstanceId": "i-1", "Tags": [{"Key": "Name", "Value": "web-1"}], "PlatformDetails": "Windows",
                 "InstanceType": "t3.small", "ImageId": "ami-1"},
                {"InstanceId": "i-2", "InstanceType": "t3.micro"}]}]}  # fmt: skip

    errors: list = []
    got = sg_review._instances(Ec2(), ["i-1", "i-2"], errors)
    assert got["i-1"]["name"] == "web-1" and got["i-1"]["os"] == "Windows" and got["i-2"]["os"] == "Linux/UNIX"
    assert not errors


def test_page_extract_rule_shows_what_we_know_and_splits_by_destination(tmp_path):
    doc = demo_sg.build_doc(ACCT, time.time(), 7)
    data = sg_review.page_data(doc, "", demo_sg.INTERNAL, names=sg_review.parse_names(demo_sg.NAMES))
    assert data["hosts"]["by_ip"]["10.20.2.12"] == "eni-0app2"
    page = tmp_path / "p.html"
    sg_review.write_page(data, str(page))
    html = page.read_text()
    for needle in ("What we know", "data-xr-split", "destination IP address", "Copy this rule's command",
                   "Propose this one in the console", "Already let in", "Already allowed by", "Your interface"):
        assert needle in html, needle


def test_a_year_read_offers_a_year_a_bar_a_week_but_opens_on_six_months():
    doc = demo_sg.build_doc(ACCT, time.time(), 365)
    data = sg_review.page_data(doc, "", demo_sg.INTERNAL)
    assert list(data["ranges"]) == ["24h", "1w", "1m", "3m", "6m", "1y"] and data["default"] == "6m"
    year = data["ranges"]["1y"]
    assert year["step"] == 7 * sg_review.DAY and 52 <= len(year["bins"]) <= 54
    assert 365 in sg_review.READ_DAYS


def test_page_has_a_time_window_dropdown_on_each_timeline(tmp_path):
    doc = demo_sg.build_doc(ACCT, time.time(), 7)
    page = tmp_path / "p.html"
    sg_review.write_page(sg_review.page_data(doc, "", demo_sg.INTERNAL), str(page))
    html = page.read_text()
    assert html.count('class="range-sel"') == 8 and 'id="range"' in html and '"1y": "Last year"' in html


def test_covered_is_the_share_of_each_bin_read():
    D = sg_review.DAY
    chunks = [{"s": 2 * D, "e": 3 * D}, {"s": 3 * D, "e": 3 * D + D // 2}, {"s": 5 * D, "e": 6 * D}]
    assert sg_review._covered(chunks, [0, D, 2 * D, 3 * D, 4 * D, 5 * D], D, 6 * D) == [0, 0, 1.0, 0.5, 0, 1.0]


def test_every_window_is_built_and_one_longer_than_the_read_says_where_there_is_no_data(tmp_path):
    doc = demo_sg.build_doc(ACCT, time.time(), 7)
    data = sg_review.page_data(doc, "", demo_sg.INTERNAL)
    assert list(data["ranges"]) == list(sg_review.RANGES) and data["default"] == "1w"
    year = data["ranges"]["1y"]["covered"]
    assert year[0] == 0 and year[-1] == 1.0 and sum(1 for v in year if v > 0) <= 3
    assert all(v == 1.0 for v in data["ranges"]["24h"]["covered"])
    page = tmp_path / "p.html"
    sg_review.write_page(data, str(page))
    html = page.read_text()
    assert html.count('class="range-sel"') == 8 and html.count('class="gap-note small"') >= 5
    assert "No data before" in html and "not read, not quiet" in html and "unreadShade" in html


# ------------------------------------------------------------------------------------- networks, accounts, PrivateLink
def test_every_account_read_names_its_vpcs_in_the_others_reviews():
    other = demo_sg.build_doc("111122223333", time.time(), 1)
    other.update(mode="live", name="payments-prod")
    other["regions"][demo_sg.REGION]["snapshot"]["vpcs"] = [{"id": "vpc-0pay", "name": "main",
                                                              "cidrs": ["10.40.0.0/16"], "cidrs6": []}]  # fmt: skip
    sg_review.save(other)
    assert sg_review.vpc_index()["111122223333"]["name"] == "payments-prod"
    doc = demo_sg.build_doc(ACCT, time.time(), 1)
    doc["mode"] = "live"
    lab = sg_review.Labeller(doc)
    got = lab("10.40.3.4")
    assert (got["cat"], got["name"], got["range"], got["account"]) == (
        "internal", "payments-prod (111122223333), main", "10.40.0.0/16", "111122223333")
    assert sg_review.Labeller(doc, internal="10.40.0.0/16 Payments")("10.40.3.4")["name"] == "Payments"  # named wins


def test_networks_list_each_source_network_with_its_cidr_blocks():
    doc = demo_sg.build_doc(ACCT, time.time(), 30)
    rep = sg_review.build(doc, "1m", "", "", sg_review.parse_names(demo_sg.NAMES))
    nets = {n["name"]: n for n in rep["networks"]}
    assert nets["payments-prod (111122223333), main"]["blocks"] == ["10.40.0.0/16"]
    assert nets["Behind VPN Johannesburg DC"]["cat"] == "datacentre" and "10.200.0.0/16" in nets["Behind VPN Johannesburg DC"]["blocks"]
    sf = nets["Salesforce"]
    assert sf["cat"] == "saas" and sf["in"] == 3 and sf["ports_in"] == ["tcp 443"]
    assert all("-" not in b for n in rep["networks"] for b in n["blocks"])  # announced ranges as CIDR blocks
    lam = next(n for n in rep["networks"] if n["service"] == "EC2" and n["region"] == "af-south-1")
    assert "Lambda" in lam["name"] and lam["in"] == 24
    assert [n["cat"] for n in rep["networks"]] == sorted((n["cat"] for n in rep["networks"]), key=sg_review.CATS.index)
    assert sg_review._cidrs_of("165.225.0.0-165.225.13.255") == ["165.225.0.0/21", "165.225.8.0/22", "165.225.12.0/23"]


def test_privatelink_inventory_lists_every_service_and_endpoint_with_its_traffic():
    doc = demo_sg.build_doc(ACCT, time.time(), 7)
    inv = sg_review.build(doc, "1w")["pl_inventory"]
    assert inv["read"] and [s["name"] for s in inv["services"]] == ["payments-api"]
    assert inv["services"][0]["principals"] == ["*"] and inv["services"][0]["nlbs"][0]["enforce"] == "off"
    ep = inv["endpoints"][0]
    assert ep["name"] == "secrets-manager" and ep["sources"] == 3 and ep["flows"] > 0 and ep["ports"] == ["tcp 443"]
    assert ep["networks"][0][0] == "This account, main"


def test_page_has_tabs_and_the_networks_table(tmp_path):
    doc = demo_sg.build_doc(ACCT, time.time(), 7)
    data = sg_review.page_data(doc, "", "")
    assert data["accounts"] == {"111122223333": "payments-prod"}
    page = tmp_path / "p.html"
    sg_review.write_page(data, str(page))
    html = page.read_text()
    for needle in ('data-tab="privatelink"', 'data-tab-of="posture"', 'id="networks"', 'id="plEndpoints"',
                   "Where traffic comes from", 'id="netQ"'):
        assert needle in html, needle


# ------------------------------------------------------------------------------------- 5.7.1 fixes
def _acc(acct, name, *vpcs):
    return {"account": acct, "name": name, "vpcs": [["eu-west-1", vid, vn, [c], []] for vid, vn, c in vpcs]}


def test_a_range_in_several_accounts_is_not_pinned_on_the_first_one_read():
    doc = demo_sg.build_doc(ACCT, time.time(), 1)
    lab = sg_review.Labeller(doc, accounts=[_acc("111111111111", "a", ("vpc-a", "default", "172.31.0.0/16")),
                                            _acc("222222222222", "b", ("vpc-b", "default", "172.31.0.0/16"),
                                                 ("vpc-c", "core", "10.9.0.0/16"))])  # fmt: skip
    shared = lab("172.31.5.5")
    assert shared["cat"] == "internal" and shared["account"] == ""
    assert shared["name"] == "One of 2 accounts (a (111111111111), b (222222222222))"
    assert shared["accounts"] == ["111111111111", "222222222222"]
    assert lab("10.9.1.1")["account"] == "222222222222"


def test_names_file_and_onprem_win_over_automatic_account_naming():
    doc = demo_sg.build_doc(ACCT, time.time(), 1)
    names = sg_review.parse_names([{"name": "Payments platform", "type": "internal", "ranges": ["10.40.0.0/16"]},
                                   {"name": "Zurich DC", "type": "datacentre", "ranges": ["10.41.0.0/16"]}])  # fmt: skip
    acc = [_acc("111111111111", "a", ("vpc-a", "main", "10.40.0.0/16"), ("vpc-z", "z", "10.41.0.0/16"),
                ("vpc-j", "j", "10.42.0.0/16"), ("vpc-q", "q", "10.43.0.0/16"))]  # fmt: skip
    lab = sg_review.Labeller(doc, "10.42.0.0/16 Joburg", "", names, accounts=acc)
    assert lab("10.40.1.1")["name"] == "Payments platform"
    assert (lab("10.41.1.1")["name"], lab("10.41.1.1")["cat"]) == ("Zurich DC", "datacentre")
    assert (lab("10.42.1.1")["name"], lab("10.42.1.1")["cat"]) == ("Joburg", "datacentre")
    assert lab("10.43.1.1")["name"] == "a (111111111111), q"


def test_forgetting_an_account_stops_it_naming_sources_and_stale_entries_are_dropped():
    other = demo_sg.build_doc("333344445555", time.time(), 1)
    other.update(mode="live", name="gone-soon")
    other["regions"][demo_sg.REGION]["snapshot"]["vpcs"] = [{"id": "vpc-0g", "name": "main",
                                                              "cidrs": ["10.77.0.0/16"], "cidrs6": []}]  # fmt: skip
    sg_review.save(other)
    doc = demo_sg.build_doc(ACCT, time.time(), 1)
    doc["mode"] = "live"
    assert sg_review.Labeller(doc)("10.77.1.1")["name"] == "gone-soon (333344445555), main"
    assert sg_review.forget("333344445555")
    assert "333344445555" not in sg_review.vpc_index()
    assert sg_review.Labeller(doc)("10.77.1.1")["name"] != "gone-soon (333344445555), main"
    idx = sg_review.vpc_index(build_missing=False)  # a read deleted by hand
    idx["999988887777"] = {"name": "deleted", "vpcs": []}
    sg_review._save_index(idx)
    assert "999988887777" not in sg_review.vpc_index()


def test_unattributed_sources_show_their_own_address_as_the_block():
    doc = demo_sg.build_doc(ACCT, time.time(), 30)
    rep = sg_review.build(doc, "1m", "", "", sg_review.parse_names(demo_sg.NAMES))
    unknown = next(n for n in rep["networks"] if n["name"] == "Unknown network")
    assert unknown["blocks"] and all(b.endswith(("/32", "/128")) for b in unknown["blocks"])
    assert all(n["blocks"] for n in rep["networks"])


def test_aws_catch_all_range_is_not_named_aws_aws():
    intel = ipintel.Intel([("52.95.0.0/20", "AMAZON", "us-east-2")], [], [])
    got = intel.label("52.95.1.1")
    assert got["kind"] == "aws" and "AWS AWS" not in got["name"] and got["name"] == "AWS (any AWS service), us-east-2"


def test_over_provisioning_is_attributed_by_source_type_and_network_over_time(tmp_path):
    doc = demo_sg.build_doc(ACCT, time.time(), 90)
    rep = sg_review.build(doc, "3m", "", "", sg_review.parse_names(demo_sg.NAMES))
    se, nb = rep["series"], len(rep["bins"])
    total = [sum(se["over"][k][i] for k in sg_review.CATS) for i in range(nb)]
    assert [sum(n["data"][i] for n in se["over_by_net"]) for i in range(nb)] == total  # every address attributed once
    assert [sum(d[i] for d in se["over_by_group"].values()) for i in range(nb)] == total
    names = {n["name"]: n for n in se["over_by_net"]}
    for want in ("This account, main", "payments-prod (111122223333), main", "Behind VPN Johannesburg DC", "Salesforce"):
        assert want in names, want
    assert names["Behind VPN Johannesburg DC"]["cat"] == "datacentre"
    assert sum(1 for n in se["over_by_net"] if n["cat"] == "aws" and not n["key"].endswith("|*")) <= sg_review.OVER_NETS
    assert all("networks networks" not in n["name"] for n in se["over_by_net"])
    page = tmp_path / "p.html"
    pd = sg_review.page_data(doc, "", "")
    assert pd["port_services"]["tcp 5432"] == ["database", "PostgreSQL, Aurora PostgreSQL"]
    sg_review.write_page(pd, str(page))
    text = page.read_text()
    assert 'id="overBy"' in text and 'id="overScale"' in text and 'overScale: "stack"' in text
    assert "port-look" in text and "Look up" in text
    # refused timeline: counter, zoom, high-risk line; Extract rule holds back high-risk and external sources
    for needle in ('id="refusedCount"', 'id="refusedZoom"', "data-zoom-out", "High risk: scanning ports",
                   "add high risk", "data-xr-confirm", "data-xr-bulk", "xr-steps", "exceptions approved"):
        assert needle in text, needle


def test_port_lookup_catalogue_uses_table_labels():
    """The page's port lookup is keyed by the same labels the networks table shows ("tcp 5432")."""
    cat = {sg_review._port_label(p, n): [c, s] for (p, n), (c, s) in sg_review.PORT_SERVICES.items()}
    assert cat["tcp 5432"] == ["database", "PostgreSQL, Aurora PostgreSQL"]
    assert cat["tcp 445"][0] == "windows" and cat["udp 53"][1] == "DNS" and cat["tcp 443"][1] == "HTTPS"


def test_asset_rag_thresholds():
    assert sg_review.asset_rag(0) == "green" and sg_review.asset_rag(sg_review.RAG_GREEN_MAX) == "green"
    assert sg_review.asset_rag(sg_review.RAG_GREEN_MAX + 1) == "amber"
    assert sg_review.asset_rag(sg_review.RAG_AMBER_MAX) == "amber" and sg_review.asset_rag(sg_review.RAG_AMBER_MAX + 1) == "red"
    assert sg_review.asset_rag(0, open_risky=True) == "red"


def test_a_read_timeout_is_retried_like_throttling():
    from botocore.exceptions import ReadTimeoutError

    calls, waits = [], []

    def fn():
        calls.append(1)
        if len(calls) < 3:
            raise ReadTimeoutError(endpoint_url="https://logs.af-south-1.amazonaws.com/")
        return "ok"

    assert sg_review.with_backoff(fn, sleep=waits.append) == "ok" and len(waits) == 2


def test_a_slice_out_of_reach_is_recorded_failed_and_the_rest_of_the_account_is_still_read():
    from botocore.exceptions import ReadTimeoutError

    start = 1_790_000_000 // 3600 * 3600
    qs = [{"format": None, "groups": ["g"]}]
    good = _FakeLogs()

    class Dead:
        def start_query(self, **_k):
            raise ReadTimeoutError(endpoint_url="https://logs.af-south-1.amazonaws.com/")

    class Sess:
        def client(self, _svc, region_name=None, **_k):
            return Dead() if region_name == "af-south-1" else good

    doc = sg_review.new_doc("111122223333", "")
    doc["regions"] = {"eu-west-1": {"query_sets": qs}, "af-south-1": {"query_sets": qs}}
    orig, slept = sg_review.save, sg_review.time.sleep
    sg_review.save, sg_review.time.sleep = (lambda d: None), (lambda s: None)
    try:
        sg_review.run_read(Sess(), doc, [("af-south-1", start, start + 3600, qs, []),
                                         ("eu-west-1", start, start + 3600, qs, [])], 1, start + 7200)  # fmt: skip
    finally:
        sg_review.save, sg_review.time.sleep = orig, slept
    st = {c["r"]: c["st"] for c in doc["chunks"]}
    assert st == {"af-south-1": "failed", "eu-west-1": "ok"}
    assert "ReadTimeoutError" in next(c["err"] for c in doc["chunks"] if c["r"] == "af-south-1")


def test_replies_are_folded_in_the_query_with_tcp_flags():
    fmt = "${account-id} ${interface-id} ${pkt-srcaddr} ${srcport} ${pkt-dstaddr} ${dstport} ${tcp-flags} ${protocol} ${packets} ${bytes} ${action} ${flow-direction} ${start} ${end}"
    port = sg_review.reply_port(sg_review.fields_of(fmt))
    assert "floor(f_tcp_flags / 16) % 2" in port and "(1 - floor(f_tcp_flags / 2) % 2)" in port

    def value(srcport, dstport, flags):  # the expression, evaluated as Logs Insights would
        expr = port.replace("f_srcport", str(srcport)).replace("f_dstport", str(dstport)).replace("f_tcp_flags", str(flags))
        return int(eval(expr, {"least": min, "greatest": max, "floor": lambda x: int(x // 1)}))  # noqa: S307

    assert value(32163, 26085, 19) == 32768, "a NodePort's SYN-ACK to a client's random port is a reply"
    assert value(32163, 9247, 0) == 9247 and value(32163, 40000, 0) == 32768
    assert value(40000, 9092, 3) == 9092 and value(1500, 9092, 2) == 9092, "a SYN to a service port is kept"
    assert value(443, 123, 0) == 123 and value(55000, 443, 0) == 443, "ports under 1024 are never folded"
    assert value(40000, 50000, 2) == 32768, "from EPHEMERAL up is folded as before"


def test_reads_saved_before_replies_were_folded_are_folded_once():
    doc = sg_review.new_doc("111122223333", "")
    assert doc["replies_folded"] == 1
    del doc["replies_folded"]
    doc["regions"]["eu-west-1"] = {"slice": 60}
    rows = [["100.64.0.1", "10.0.0.5", "eni-1", "6", p, "ACCEPT", 1] for p in range(2000, 2030)]
    rows += [["100.64.0.1", "10.0.0.5", "eni-1", "6", 8080, "ACCEPT", 4], ["10.0.0.9", "10.0.0.5", "eni-1", "6", 5432, "ACCEPT", 2],
             ["10.0.0.9", "10.0.0.5", "eni-1", "6", 2001, "ACCEPT", 1]]  # fmt: skip
    doc["chunks"] = [{"r": "eu-west-1", "s": 0, "e": 60, "st": "ok", "rows": rows, "k": 7}]
    assert sg_review.fold_replies(doc) == 30
    got = sorted(tuple(r) for r in doc["chunks"][0]["rows"])
    assert ("100.64.0.1", "10.0.0.5", "eni-1", "6", 32768, "ACCEPT", 34) in got
    assert ("100.64.0.1", "10.0.0.5", "eni-1", "6", 8080, "ACCEPT", 4) not in got, "8080 is one of its many ports"
    assert ("10.0.0.9", "10.0.0.5", "eni-1", "6", 2001, "ACCEPT", 1) in got, "a source with few ports keeps them"
    assert "k" not in doc["chunks"][0] and "slice" not in doc["regions"]["eu-west-1"]
    assert sg_review.fold_replies(doc) == 0


def test_hours_cut_at_the_row_limit_still_narrow_the_rule():
    """Owner, 2026-11-25: Remediate shows the least exposure the evidence allows. Hours cut at 10,000 rows used to
    turn every rule in the region into "incomplete" and leave it as it was (891M addresses kept in aws-prd-plrdoc).
    Now the rule narrows to the sources read, and is marked cut so the page says so."""
    doc = demo_sg.build_doc(ACCT, time.time(), 90)
    for c in doc["chunks"]:
        c["st"] = "cut"
    rep = sg_review.build(doc, "3m", "", demo_sg.INTERNAL)
    assert not any(r["status"] == "incomplete" for r in rep["rules"])
    by = {(r["gname"], r["source"]): r for r in rep["rules"]}
    sftp = by[("partner-sftp", "203.0.113.0/24")]
    assert sftp["status"] == "tighten" and sftp["suggest"] and sftp["cut"] and "10,000" in sftp["note"]
    assert by[("payments-db", "172.16.0.0/12")]["status"] == "unused"


def test_open_to_everyone_narrows_except_on_a_public_load_balancers_web_ports(report):
    """Owner, 2026-11-25: 0.0.0.0/0 narrows to the sources seen, like any public range, except on an internet-facing
    load balancer's 80/443, whose users cannot be listed (aws-prd-plrdoc's VPC endpoint group was left open)."""
    _, rep = report
    by = {(r["gname"], r["source"]): r for r in rep["rules"]}
    assert by[("public-alb", "0.0.0.0/0")]["status"] == "open"
    rdp = by[("legacy-admin", "0.0.0.0/0")]
    assert rdp["status"] in ("tighten", "unused") and "0.0.0.0/0" not in rdp["suggest"]
    assert sg_review.serves_web({"proto": "6", "from": 443, "to": 443}) and sg_review.serves_web({"proto": "-1"})
    assert not sg_review.serves_web({"proto": "6", "from": 22, "to": 22})
    snap = {"enis": {"e1": {"kind": "load balancer", "public": ""}, "e2": {"kind": "load balancer", "public": "1.2.3.4"}}}
    assert not sg_review.public_lb({"enis": ["e1"]}, snap)  # an internal load balancer
    assert sg_review.public_lb({"enis": ["e1", "e2"]}, snap)


def test_needed_against_permitted_follows_what_remediate_leaves():
    """Owner, 2026-11-25: the Risk overview shows IP addresses needed (estimate) against permitted."""
    rules = [{"allowed": 16777216, "status": "tighten", "suggest_size": 4},
             {"allowed": 65536, "status": "unused"},
             {"allowed": 256, "status": "used"},
             {"allowed": 4294967296, "status": "open"}]
    assert sg_review.permitted_ips(rules) == 16777216 + 65536 + 256 + 4294967296
    assert sg_review.needed_ips(rules) == 4 + 256 + 4294967296


def test_the_macro_row_carries_needed_and_permitted(report):
    _, rep = report
    row = sg_review.macro_row(ACCT, "demo", rep)
    assert 0 < row["needed"] < row["permitted"]
