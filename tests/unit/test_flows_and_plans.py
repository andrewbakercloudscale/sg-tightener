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
