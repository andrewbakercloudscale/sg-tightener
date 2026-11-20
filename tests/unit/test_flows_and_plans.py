"""Insights splitting, region handling, record parsing, sg_viz and plan properties."""

from __future__ import annotations

import datetime as dt
import ipaddress
import random

import pytest

import sg_tightener
import sg_viz
from sg_tightener import (
    DEFAULT_LOG_FORMAT_FIELDS,
    AnalyseConfig,
    build_flow_stats_query,
    build_plan,
    flow_records,
    resolve_apply_region,
    run_insights_query,
)
from tests.fixtures.flowgen import (
    RECOMMENDED_FIELDS,
    FakeLogs,
    Talker,
    Topology,
    build_sample,
    format_lines,
    generate_records,
    sample_topology,
    sample_window,
)

UTC = dt.timezone.utc
T0 = dt.datetime(2026, 11, 1, tzinfo=UTC)


def _records(n_sources: int, hours: int = 24, every: float = 1.0):
    sources = [f"10.{8 + i // 250}.{i % 250}.1" for i in range(n_sources)]
    topo = Topology("eu-west-1", [], [], [Talker(sources, "10.4.1.20", 5432, every=every)])
    return generate_records(topo, T0, T0 + dt.timedelta(hours=hours))


# --------------------------------------------------------------------------- #
# run_insights_query
# --------------------------------------------------------------------------- #

class TestRunInsightsQuery:
    def test_under_the_limit_is_one_query(self):
        logs = FakeLogs(_records(20), DEFAULT_LOG_FORMAT_FIELDS)
        q, col = sg_tightener.build_cloudwatch_query(DEFAULT_LOG_FORMAT_FIELDS)
        rows = run_insights_query(logs, "lg", q, T0, T0 + dt.timedelta(days=1))
        assert len({r[col] for r in rows}) == 20
        assert len(logs.queries) == 1

    def test_at_the_limit_splits_until_complete(self, monkeypatch):
        monkeypatch.setattr(sg_tightener, "INSIGHTS_ROW_LIMIT", 50)
        records = _records(180, every=0.3)
        logs = FakeLogs(records, DEFAULT_LOG_FORMAT_FIELDS)
        q, col = sg_tightener.build_cloudwatch_query(DEFAULT_LOG_FORMAT_FIELDS)
        assert "limit 50" in q
        rows = run_insights_query(logs, "lg", q, T0, T0 + dt.timedelta(days=1))
        assert {r[col] for r in rows} == {r["src"] for r in records}
        # The halves never overlap: no second is read twice.
        spans = sorted((s, e) for _q, s, e in logs.queries[1:])
        leaves = [s for s in spans if not any(o != s and o[0] >= s[0] and o[1] <= s[1] for o in spans)]
        for (s1, e1), (s2, _e2) in zip(leaves, leaves[1:]):
            assert e1 < s2

    def test_refuses_when_even_the_smallest_window_is_full(self):
        logs = FakeLogs(_records(30, hours=1), DEFAULT_LOG_FORMAT_FIELDS)
        q, _ = sg_tightener.build_cloudwatch_query(DEFAULT_LOG_FORMAT_FIELDS)
        with pytest.raises(RuntimeError, match="truncated"):
            run_insights_query(logs, "lg", q, T0, T0 + dt.timedelta(hours=1), limit=5,
                               min_window=dt.timedelta(hours=2))

    def test_failed_query_raises_instead_of_returning_nothing(self):
        class Failed:
            def start_query(self, **kw):
                return {"queryId": "q"}

            def get_query_results(self, queryId):  # noqa: N803
                return {"status": "Failed", "results": []}

        with pytest.raises(RuntimeError, match="Failed"):
            run_insights_query(Failed(), "lg", "q", T0, T0 + dt.timedelta(hours=1))

    def test_polls_with_a_pause(self):
        """Regression: analyse spun on get_query_results with no sleep."""
        class Slow:
            calls = 0

            def start_query(self, **kw):
                return {"queryId": "q"}

            def get_query_results(self, queryId):  # noqa: N803
                self.calls += 1
                return {"status": "Complete" if self.calls > 3 else "Running", "results": []}

        sleeps = []
        run_insights_query(Slow(), "lg", "q", T0, T0 + dt.timedelta(hours=1), sleep=sleeps.append)
        assert sleeps == [1.0, 1.0, 1.0]


# --------------------------------------------------------------------------- #
# Region and window
# --------------------------------------------------------------------------- #

class TestApplyRegion:
    def test_plan_region_wins_over_the_environment(self):
        assert resolve_apply_region({"region": "eu-west-1"}, None, {"AWS_REGION": "us-east-1"}) == "eu-west-1"

    def test_mismatching_flag_is_refused(self):
        with pytest.raises(SystemExit, match="built in eu-west-1"):
            resolve_apply_region({"region": "eu-west-1"}, "us-east-1", {})

    def test_old_plan_falls_back_to_flag_then_environment(self):
        assert resolve_apply_region({}, "ap-south-1", {"AWS_REGION": "us-east-1"}) == "ap-south-1"
        assert resolve_apply_region({}, None, {"AWS_DEFAULT_REGION": "us-east-1"}) == "us-east-1"
        with pytest.raises(SystemExit, match="does not record its region"):
            resolve_apply_region({}, None, {})

    def test_plan_records_its_region(self):
        sg = {"GroupId": "sg-1", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 1, "ToPort": 1, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}
        assert build_plan([sg], ["10.1.1.1"], region="eu-west-1")["region"] == "eu-west-1"


def test_analyse_window_uses_hours_when_given():
    now = dt.datetime(2026, 11, 17, 12, tzinfo=UTC)
    cfg = AnalyseConfig("r", days=1, log_group="lg", s3_bucket=None, s3_prefix=None, out_path="x", hours=2)
    start, end = cfg.window(now)
    assert end - start == dt.timedelta(hours=2)
    cfg.hours = None
    start, end = cfg.window(now)
    assert end - start == dt.timedelta(days=1)


# --------------------------------------------------------------------------- #
# Record parsing and query building
# --------------------------------------------------------------------------- #

class TestFlowRecords:
    def test_recommended_format_round_trip(self):
        topo = sample_topology()
        start, end = sample_window()
        records = generate_records(topo, start, start + dt.timedelta(hours=12))
        parsed = list(flow_records(format_lines(records, RECOMMENDED_FIELDS), RECOMMENDED_FIELDS))
        assert len(parsed) == len(records)
        for got, want in zip(parsed, records):
            for k in ("src", "dst", "dstport", "protocol", "action", "packets", "bytes", "start", "interface"):
                assert got[k] == want[k], k
        # Through the transit gateway the true client is kept, not the hop.
        assert "10.4.250.9" not in {r["src"] for r in parsed}

    def test_default_format_has_no_direction_and_uses_srcaddr(self):
        records = generate_records(sample_topology(), *sample_window())[:50]
        parsed = list(flow_records(format_lines(records, DEFAULT_LOG_FORMAT_FIELDS), DEFAULT_LOG_FORMAT_FIELDS))
        assert all(r["direction"] is None for r in parsed)
        assert {r["src"] for r in parsed} == {r.get("srcaddr", r["src"]) for r in records}

    def test_nodata_records_are_skipped(self):
        line = "2 123456789012 eni-1 - - - - - - - 1418530010 1418530070 - NODATA"
        assert list(flow_records([line], DEFAULT_LOG_FORMAT_FIELDS)) == []


class TestFlowStatsQuery:
    def test_default_format_uses_discovered_names(self):
        q, cols = build_flow_stats_query(DEFAULT_LOG_FORMAT_FIELDS, by=("src", "dst", "dstport"),
                                         action="REJECT")
        assert "parse @message" not in q
        assert 'filter action = "REJECT"' in q
        assert cols["src"] == "srcAddr" and cols["dst"] == "dstAddr" and cols["dstport"] == "dstPort"
        assert q.endswith(f"limit {sg_tightener.INSIGHTS_ROW_LIMIT}")

    def test_custom_format_prefers_packet_addresses_and_drops_egress(self):
        q, cols = build_flow_stats_query(RECOMMENDED_FIELDS, by=("src", "dst"), bin_seconds=3600)
        assert cols["src"] == f"f{RECOMMENDED_FIELDS.index('pkt-srcaddr')}"
        assert cols["dst"] == f"f{RECOMMENDED_FIELDS.index('pkt-dstaddr')}"
        assert f'filter f{RECOMMENDED_FIELDS.index("flow-direction")} = "ingress"' in q
        assert cols["bucket"] == "bin(3600s)"

    def test_missing_field_is_an_error(self):
        with pytest.raises(ValueError, match="dstport"):
            build_flow_stats_query(["srcaddr", "action"], by=("src", "dstport"))


# --------------------------------------------------------------------------- #
# sg_viz
# --------------------------------------------------------------------------- #

class TestSgViz:
    def test_cloudwatch_and_s3_paths_agree(self):
        """The Insights aggregation and the S3 line parser must produce the same flows."""
        start, end = sample_window()
        end = start + dt.timedelta(days=2)
        records = generate_records(sample_topology(), start, end)
        from_s3 = sg_viz.aggregate_records(
            flow_records(format_lines(records, RECOMMENDED_FIELDS), RECOMMENDED_FIELDS), 3600)

        logs = FakeLogs(records, RECOMMENDED_FIELDS)
        q, cols = build_flow_stats_query(RECOMMENDED_FIELDS, by=("src", "dst", "dstport", "protocol", "action"),
                                         bin_seconds=3600)
        rows = run_insights_query(logs, "lg", q, start, end)
        from_cw = sg_viz.flows_from_insights_rows(rows, cols)
        assert from_cw == from_s3

    def test_split_windows_are_merged(self):
        cols = {"src": "s", "dst": "d", "dstport": "p", "protocol": "pr", "action": "a",
                "bucket": "b", "records": "n", "packets": "pk", "bytes": "by"}
        row = {"s": "10.0.0.1", "d": "10.0.0.2", "p": "443", "pr": "6", "a": "ACCEPT",
               "b": "2026-11-01 10:00:00.000", "n": "2", "pk": "10", "by": "100"}
        flows = sg_viz.flows_from_insights_rows([row, dict(row)], cols)
        assert len(flows) == 1 and flows[0]["records"] == 4 and flows[0]["proto"] == "tcp"

    def test_sample_explains_who_allowed_what(self):
        data = build_sample()
        by_key = {(c["src"], c["dst"], c["port"]): c for c in data["connections"]}
        db = by_key[("10.4.2.10", "10.4.1.20", 5432)]
        assert db["status"] == "accepted"
        assert db["allowed_by"] == ["sg-0db0000000000001: tcp 5432 from 10.0.0.0/8"]
        scan = by_key[("10.66.1.2", "10.4.1.20", 3306)]
        assert scan["status"] == "rejected" and scan["allowed_by"] == []
        # Every flow row points at a real connection and a bucket in the window.
        n = data["window"]["buckets"]
        assert all(0 <= f[0] < len(data["connections"]) and 0 <= f[1] < n for f in data["flows"])

    def test_plan_overlay_marks_the_batch_job_the_plan_would_cut_off(self):
        data = build_sample()
        blocked = [(c["src"], c["port"]) for c in data["connections"] if c["plan_impact"] == "blocked"]
        assert blocked == [("10.9.7.3", 5432)]
        assert data["plan"]["blocked_connections"] == 1
        kept = next(c for c in data["connections"] if c["src"] == "10.4.2.10" and c["port"] == 5432)
        assert kept["plan_impact"] == "kept"

    def test_rejected_connections_are_never_marked(self):
        data = build_sample()
        assert all(c["plan_impact"] is None for c in data["connections"] if c["status"] == "rejected")

    def test_security_group_reference_rules_match_by_source_interface(self):
        perms = {"sg-db": [{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [],
                            "UserIdGroupPairs": [{"GroupId": "sg-app"}]}]}
        ip_groups = {"10.0.0.5": {"sg-app"}}
        assert sg_viz.rules_covering(perms, ["sg-db"], "10.0.0.5", 5432, "tcp", ip_groups) == [
            "sg-db: tcp 5432 from sg-app"]
        assert sg_viz.rules_covering(perms, ["sg-db"], "10.0.0.6", 5432, "tcp", ip_groups) == []

    def test_all_traffic_rule_covers_any_port(self):
        perms = {"sg": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}
        assert sg_viz.rules_covering(perms, ["sg"], "10.1.1.1", 9999, "udp", {}) == [
            "sg: all traffic from 10.0.0.0/8"]

    def test_default_bucket_grows_with_the_window(self):
        assert sg_viz.default_bucket_seconds(T0, T0 + dt.timedelta(days=2)) == 3600
        assert sg_viz.default_bucket_seconds(T0, T0 + dt.timedelta(days=30)) == 6 * 3600
        assert sg_viz.default_bucket_seconds(T0, T0 + dt.timedelta(days=90)) == 86400


# --------------------------------------------------------------------------- #
# Plan property: narrow, never widen
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("seed", range(25))
def test_plan_never_grants_outside_the_rule_it_replaces(seed):
    rng = random.Random(seed)
    blocks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    sgs = []
    for g in range(rng.randint(1, 4)):
        perms = []
        for _ in range(rng.randint(1, 4)):
            base = ipaddress.ip_network(rng.choice(blocks))
            prefix = rng.randint(base.prefixlen, 23)
            sub = list(base.subnets(new_prefix=prefix)) if prefix - base.prefixlen < 10 else [base]
            net = rng.choice(sub)
            port = rng.choice([22, 443, 5432])
            perms.append({"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                          "IpRanges": [{"CidrIp": str(net)}]})
        sgs.append({"GroupId": f"sg-{g}", "IpPermissions": perms})
    ips = []
    for _ in range(rng.randint(0, 300)):
        net = ipaddress.ip_network(rng.choice(blocks + ["0.0.0.0/0"]))
        ips.append(str(net.network_address + rng.randrange(net.num_addresses)))

    plan = build_plan(sgs, ips, max_rules=rng.choice([5, 20, 60]), tolerance=rng.random())
    for g in plan["groups"]:
        revoked = [(p["FromPort"], ipaddress.ip_network(r["CidrIp"])) for p in g["revoke"] for r in p["IpRanges"]]
        for p in g["authorise"]:
            for r in p["IpRanges"]:
                net = ipaddress.ip_network(r["CidrIp"])
                assert any(port == p["FromPort"] and net.subnet_of(o) for port, o in revoked), (seed, net)


# --------------------------------------------------------------------------- #
# Per-group plans from approved/v2 flows
# --------------------------------------------------------------------------- #

def _rule(port, cidr, proto="tcp", to_port=None):
    return {"IpProtocol": proto, "FromPort": port, "ToPort": to_port or port,
            "IpRanges": [{"CidrIp": cidr}]}


def _group(gid, *perms):
    return {"GroupId": gid, "GroupName": gid, "VpcId": "vpc-1", "IpPermissions": list(perms)}


def _eni(ip, *gids, prefixes=()):
    return {"PrivateIpAddress": ip, "PrivateIpAddresses": [{"PrivateIpAddress": ip}],
            "Groups": [{"GroupId": g} for g in gids],
            "Ipv4Prefixes": [{"Ipv4Prefix": p} for p in prefixes]}


def _flow(src, dst, port, proto="6"):
    return {"src": src, "dst": dst, "dstport": port, "protocol": proto}


def _granted(plan, gid):
    g = next(g for g in plan["groups"] if g["group_id"] == gid)
    return {(p["FromPort"], r["CidrIp"]) for p in g["authorise"] for r in p["IpRanges"]}


class TestFlowMatchesRule:
    @pytest.mark.parametrize("flow, rule, expected", [
        (_flow("a", "b", 443), ("tcp", 443, 443), True),
        (_flow("a", "b", 444), ("tcp", 443, 443), False),
        (_flow("a", "b", 8080), ("tcp", 8000, 8999), True),
        (_flow("a", "b", 443), ("6", 443, 443), True),          # numeric protocol
        (_flow("a", "b", 53, "17"), ("tcp", 53, 53), False),    # udp flow, tcp rule
        (_flow("a", "b", 53, "17"), ("udp", 53, 53), True),
        (_flow("a", "b", 5432), ("-1", None, None), True),      # all traffic
        (_flow("a", "b", 0, "1"), ("icmp", 8, 0), True),        # icmp: type/code not ports
        (_flow("a", "b", 0, "1"), ("tcp", 0, 65535), False),
        ({"src": "a"}, ("tcp", 443, 443), True),                # no port/protocol recorded
    ])
    def test_cases(self, flow, rule, expected):
        assert sg_tightener.flow_matches_rule(flow, *rule) is expected


class TestPerGroupPlan:
    def test_each_group_gets_only_the_sources_that_reached_it(self):
        sgs = [_group("sg-db", _rule(5432, "10.0.0.0/8")), _group("sg-api", _rule(443, "10.0.0.0/8"))]
        enis = [_eni("10.4.1.20", "sg-db"), _eni("10.4.2.10", "sg-api")]
        flows = [_flow("10.4.2.10", "10.4.1.20", 5432), _flow("10.20.33.11", "10.4.2.10", 443)]
        plan = build_plan(sgs, ["10.4.2.10", "10.20.33.11"], flows=flows, interfaces=enis)
        assert plan["attribution"] == "per-group"
        assert _granted(plan, "sg-db") == {(5432, "10.4.2.10/32")}
        assert _granted(plan, "sg-api") == {(443, "10.20.33.11/32")}

    def test_port_must_match_the_rule(self):
        sgs = [_group("sg-api", _rule(443, "10.0.0.0/8"), _rule(9100, "10.4.0.0/16"))]
        enis = [_eni("10.4.2.10", "sg-api")]
        flows = [_flow("10.4.9.50", "10.4.2.10", 9100), _flow("10.4.9.51", "10.4.2.10", 443)]
        plan = build_plan(sgs, ["10.4.9.50", "10.4.9.51"], flows=flows, interfaces=enis)
        assert _granted(plan, "sg-api") == {(9100, "10.4.9.50/32"), (443, "10.4.9.51/32")}

    def test_a_rule_reached_on_no_matching_port_is_removed_without_evidence(self):
        sgs = [_group("sg-api", _rule(443, "10.0.0.0/8"), _rule(22, "10.0.0.0/8"))]
        plan = build_plan(sgs, ["10.1.1.1"], flows=[_flow("10.1.1.1", "10.4.2.10", 443)],
                          interfaces=[_eni("10.4.2.10", "sg-api")])
        g = plan["groups"][0]
        assert _granted(plan, "sg-api") == {(443, "10.1.1.1/32")}
        assert [(r["from_port"], r["cidr"]) for r in g["removed_without_evidence"]] == [(22, "10.0.0.0/8")]

    def test_every_group_on_the_interface_gets_the_source(self):
        sgs = [_group("sg-a", _rule(443, "10.0.0.0/8")), _group("sg-b", _rule(443, "10.0.0.0/8"))]
        plan = build_plan(sgs, ["10.1.1.1"], flows=[_flow("10.1.1.1", "10.4.2.10", 443)],
                          interfaces=[_eni("10.4.2.10", "sg-a", "sg-b")])
        assert _granted(plan, "sg-a") == _granted(plan, "sg-b") == {(443, "10.1.1.1/32")}

    def test_unknown_destination_is_kept_on_every_admitting_rule_and_reported(self):
        sgs = [_group("sg-db", _rule(5432, "10.0.0.0/8")), _group("sg-api", _rule(443, "10.0.0.0/8"))]
        plan = build_plan(sgs, ["10.1.1.1"], flows=[_flow("10.1.1.1", "10.9.9.9", 5432)],
                          interfaces=[_eni("10.4.1.20", "sg-db")])
        assert plan["unattributed_destinations"] == ["10.9.9.9"]
        assert _granted(plan, "sg-db") == {(5432, "10.1.1.1/32")}
        assert _granted(plan, "sg-api") == set()  # port 5432 is not 443

    def test_missing_destination_counts_as_unknown(self):
        sgs = [_group("sg-db", _rule(5432, "10.0.0.0/8"))]
        plan = build_plan(sgs, ["10.1.1.1"], flows=[{"src": "10.1.1.1", "dst": None,
                                                     "dstport": 5432, "protocol": "6"}],
                          interfaces=[])
        assert plan["unattributed_destinations"] == ["-"]
        assert _granted(plan, "sg-db") == {(5432, "10.1.1.1/32")}

    def test_hand_added_ip_without_a_flow_is_kept_per_rule(self):
        sgs = [_group("sg-db", _rule(5432, "10.0.0.0/8")), _group("sg-api", _rule(443, "10.0.0.0/8"))]
        enis = [_eni("10.4.1.20", "sg-db"), _eni("10.4.2.10", "sg-api")]
        plan = build_plan(sgs, ["10.4.2.10", "10.7.7.7"],
                          flows=[_flow("10.4.2.10", "10.4.1.20", 5432)], interfaces=enis)
        assert plan["sources_without_flows"] == ["10.7.7.7"]
        assert _granted(plan, "sg-api") == {(443, "10.7.7.7/32")}
        assert (5432, "10.7.7.7/32") in _granted(plan, "sg-db")

    def test_delegated_prefix_maps_pod_addresses_to_the_node_groups(self):
        sgs = [_group("sg-pods", _rule(8080, "10.0.0.0/8"))]
        enis = [_eni("10.4.3.5", "sg-pods", prefixes=["10.4.3.16/28"])]
        plan = build_plan(sgs, ["10.1.1.1"], flows=[_flow("10.1.1.1", "10.4.3.20", 8080)],
                          interfaces=enis)
        assert plan["unattributed_destinations"] == []
        assert _granted(plan, "sg-pods") == {(8080, "10.1.1.1/32")}

    def test_without_flows_the_plan_is_per_rule(self):
        sgs = [_group("sg-db", _rule(5432, "10.0.0.0/8"))]
        plan = build_plan(sgs, ["10.1.1.1"])
        assert plan["attribution"] == "per-rule"
        assert _granted(plan, "sg-db") == {(5432, "10.1.1.1/32")}

    def test_public_sources_in_flows_never_reach_private_rules(self):
        sgs = [_group("sg-api", _rule(443, "10.0.0.0/8"))]
        plan = build_plan(sgs, ["8.8.8.8"], flows=[_flow("8.8.8.8", "10.4.2.10", 443)],
                          interfaces=[_eni("10.4.2.10", "sg-api")])
        assert _granted(plan, "sg-api") == set()


class TestFlowKeys:
    def test_default_and_recommended_formats_record_destinations(self):
        assert sg_tightener.flow_keys_for(DEFAULT_LOG_FORMAT_FIELDS) == ("src", "dst", "dstport", "protocol")
        assert sg_tightener.flow_keys_for(RECOMMENDED_FIELDS) == ("src", "dst", "dstport", "protocol")

    def test_protocol_is_optional_destination_is_not(self):
        assert sg_tightener.flow_keys_for(["srcaddr", "dstaddr", "dstport", "action"]) == ("src", "dst", "dstport")
        assert sg_tightener.flow_keys_for(["srcaddr", "dstaddr", "action"]) is None
        assert sg_tightener.flow_keys_for(["srcaddr", "dstport", "action"]) is None


def test_version_flag_prints_the_version(capsys):
    import pytest

    import sg_tightener

    with pytest.raises(SystemExit) as exc:
        sg_tightener.main(["--version"])
    assert exc.value.code == 0
    assert sg_tightener.__version__ in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# Rules apply can execute, flow-log coverage, PrivateLink
# --------------------------------------------------------------------------- #

class TestPlanIsExecutable:
    def test_all_traffic_rule_sends_no_null_ports(self):
        """Regression: "-1" rules have no ports and the plan sent FromPort/ToPort
        of None, which boto3 rejects, so apply halted on every such group."""
        sgs = [_group("sg-a", {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.0.0.0/8"}]})]
        plan = build_plan(sgs, ["10.1.1.1"], flows=[_flow("10.1.1.1", "10.4.2.10", 22)],
                          interfaces=[_eni("10.4.2.10", "sg-a")])
        g = plan["groups"][0]
        for perm in g["revoke"] + g["restore"] + g["authorise"]:
            assert "FromPort" not in perm and "ToPort" not in perm, perm
        assert g["authorise"][0]["IpRanges"][0]["CidrIp"] == "10.1.1.1/32"

    def test_old_plans_with_null_ports_are_cleaned_before_sending(self):
        perms = [{"IpProtocol": "-1", "FromPort": None, "ToPort": None, "IpRanges": []},
                 {"IpProtocol": "tcp", "FromPort": 0, "ToPort": 0, "IpRanges": []}]
        assert sg_tightener._clean_permissions(perms) == [
            {"IpProtocol": "-1", "IpRanges": []},
            {"IpProtocol": "tcp", "FromPort": 0, "ToPort": 0, "IpRanges": []}]

    def test_replacement_already_kept_by_a_narrow_rule_is_not_authorised_again(self):
        """Regression: the /32 already existed as an untouched rule, so the
        authorise failed as a duplicate AFTER the broad rule was revoked."""
        sgs = [_group("sg-a", _rule(443, "10.0.0.0/8"), _rule(443, "10.1.2.3/32"))]
        plan = build_plan(sgs, ["10.1.2.3", "10.9.0.1"],
                          flows=[_flow("10.1.2.3", "10.4.2.10", 443), _flow("10.9.0.1", "10.4.2.10", 443)],
                          interfaces=[_eni("10.4.2.10", "sg-a")])
        assert _granted(plan, "sg-a") == {(443, "10.9.0.1/32")}
        assert plan["groups"][0]["removed_without_evidence"] == []

    def test_kept_rule_on_another_port_does_not_count(self):
        sgs = [_group("sg-a", _rule(443, "10.0.0.0/8"), _rule(22, "10.1.2.3/32"))]
        plan = build_plan(sgs, ["10.1.2.3"], flows=[_flow("10.1.2.3", "10.4.2.10", 443)],
                          interfaces=[_eni("10.4.2.10", "sg-a")])
        assert _granted(plan, "sg-a") == {(443, "10.1.2.3/32")}


def _vpc_group(gid, vpc):
    return {"GroupId": gid, "GroupName": gid, "VpcId": vpc, "IpPermissions": [_rule(443, "10.0.0.0/8")]}


def _placed_eni(eni_id, subnet, *gids, ip="10.4.2.10", **extra):
    return {"NetworkInterfaceId": eni_id, "SubnetId": subnet, "PrivateIpAddress": ip,
            "Groups": [{"GroupId": g} for g in gids], **extra}


class TestFlowLogCoverage:
    def test_check_records_the_resources_the_flow_logs_capture(self):
        logs = [{"FlowLogId": "fl-1", "FlowLogStatus": "ACTIVE", "TrafficType": "ALL",
                 "ResourceId": "vpc-1", "LogFormat": ""},
                {"FlowLogId": "fl-2", "FlowLogStatus": "ACTIVE", "TrafficType": "ALL",
                 "ResourceId": "subnet-9", "LogFormat": ""}]
        assert sg_tightener.check_flow_log_config(logs).resources == ["subnet-9", "vpc-1"]
        assert sg_tightener.check_flow_log_config([]).resources is None

    def test_group_in_an_unlogged_vpc_is_skipped(self):
        sgs = [_vpc_group("sg-in", "vpc-1"), _vpc_group("sg-out", "vpc-2")]
        skip = sg_tightener.groups_outside_flow_log_coverage(sgs, [], ["vpc-1"])
        assert list(skip) == ["sg-out"]

    def test_subnet_and_interface_logs_cover_a_group_only_when_every_interface_is_covered(self):
        sgs = [_vpc_group("sg-sub", "vpc-2"), _vpc_group("sg-eni", "vpc-2"),
               _vpc_group("sg-part", "vpc-2"), _vpc_group("sg-none", "vpc-2")]
        enis = [_placed_eni("eni-1", "subnet-a", "sg-sub", "sg-part"),
                _placed_eni("eni-2", "subnet-b", "sg-eni"),
                _placed_eni("eni-3", "subnet-b", "sg-part")]
        skip = sg_tightener.groups_outside_flow_log_coverage(sgs, enis, ["subnet-a", "eni-2"])
        assert sorted(skip) == ["sg-none", "sg-part"]

    def test_unknown_coverage_skips_nothing(self):
        assert sg_tightener.groups_outside_flow_log_coverage([_vpc_group("sg", "vpc-2")], [], None) == {}

    def test_skipped_groups_are_left_alone_and_listed(self):
        sgs = [_vpc_group("sg-in", "vpc-1"), _vpc_group("sg-out", "vpc-2")]
        plan = build_plan(sgs, ["10.1.1.1"], skip={"sg-out": "not logged"})
        assert [g["group_id"] for g in plan["groups"]] == ["sg-in"]
        assert plan["skipped_groups"] == [{"group_id": "sg-out", "group_name": "sg-out",
                                           "reason": "not logged"}]


NLB_ARN = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/net/orders/50dc6c495c0c9188"


def _nlb_eni(eni_id, *gids):
    return _placed_eni(eni_id, "subnet-a", *gids, ip="10.4.5.5", InterfaceType="network_load_balancer",
                       RequesterManaged=True, Description="ELB net/orders/50dc6c495c0c9188")


def _endpoint_service():
    return [{"ServiceId": "vpce-svc-0abc", "NetworkLoadBalancerArns": [NLB_ARN]}]


class TestPrivateLink:
    def test_provider_nlb_group_is_never_planned(self):
        """Flow logs miss endpoint-to-NLB traffic, so the NLB group would show
        no evidence and lose every consumer."""
        lbs = [{"LoadBalancerArn": NLB_ARN, "SecurityGroups": ["sg-nlb"],
                "EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic": "on"}]
        skip = sg_tightener.privatelink_provider_groups([_nlb_eni("eni-n", "sg-nlb")],
                                                        _endpoint_service(), lbs)
        assert list(skip) == ["sg-nlb"]
        assert "vpce-svc-0abc" in skip["sg-nlb"] and "orders" in skip["sg-nlb"]

    def test_enforcement_off_means_the_rules_do_not_see_privatelink_traffic(self):
        lbs = [{"LoadBalancerArn": NLB_ARN, "SecurityGroups": ["sg-nlb"],
                "EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic": "off"}]
        assert sg_tightener.privatelink_provider_groups([], _endpoint_service(), lbs) == {}

    def test_without_the_nlb_description_the_interface_groups_are_used_and_enforcement_assumed(self):
        skip = sg_tightener.privatelink_provider_groups([_nlb_eni("eni-n", "sg-nlb")],
                                                        _endpoint_service(), None)
        assert list(skip) == ["sg-nlb"]

    def test_unlisted_endpoint_services_hold_back_every_load_balancer_group(self):
        enis = [_nlb_eni("eni-n", "sg-nlb"), _placed_eni("eni-i", "subnet-a", "sg-app")]
        assert list(sg_tightener.privatelink_provider_groups(enis, None, None)) == ["sg-nlb"]

    def test_nlb_without_an_endpoint_service_is_planned_as_usual(self):
        assert sg_tightener.privatelink_provider_groups([_nlb_eni("eni-n", "sg-nlb")], [], []) == {}

    def test_interface_endpoint_group_is_tightened_to_the_clients_that_used_it(self):
        """Consumer side: an interface endpoint's ENI carries its group and
        flow logs record client-to-endpoint traffic, so it plans like any
        other interface."""
        sgs = [_group("sg-vpce", _rule(443, "10.0.0.0/8")), _group("sg-app", _rule(443, "10.0.0.0/8"))]
        enis = [_placed_eni("eni-e", "subnet-a", "sg-vpce", ip="10.4.8.8", InterfaceType="vpc_endpoint",
                            RequesterManaged=True, Description="VPC Endpoint Interface vpce-0123"),
                _placed_eni("eni-a", "subnet-a", "sg-app", ip="10.4.2.10")]
        flows = [_flow("10.4.2.10", "10.4.8.8", 443), _flow("10.20.0.7", "10.4.2.10", 443)]
        plan = build_plan(sgs, ["10.4.2.10", "10.20.0.7"], flows=flows, interfaces=enis)
        assert _granted(plan, "sg-vpce") == {(443, "10.4.2.10/32")}
        assert _granted(plan, "sg-app") == {(443, "10.20.0.7/32")}
        assert plan["unattributed_destinations"] == []
