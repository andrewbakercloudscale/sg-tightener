"""analyse -> plan -> apply -> revert against a moto estate."""

from __future__ import annotations

import ipaddress
import json
from unittest import mock

import pytest

import sg_extend
import sg_tightener
from sg_tightener import AnalyseConfig, DEFAULT_LOG_FORMAT_FIELDS
from tests.fixtures.flowgen import RECOMMENDED_FIELDS, Talker, generate_records, put_s3_objects
from tests.integration.conftest import LOG_GROUP, REGION, add_cloudwatch_flow_log, window


def _talkers():
    return [
        Talker(["10.4.2.10", "10.4.2.11"], "10.4.1.20", 5432),
        Talker(["10.20.33.11", "10.20.33.12"], "10.4.2.10", 443, via="10.4.250.9"),
        Talker(["172.16.5.10"], "10.4.2.11", 443),
        Talker(["10.4.9.50"], "10.4.2.10", 9100),
        Talker(["10.66.1.2"], "10.4.1.20", 3306, action="REJECT"),
    ]


def _analyse(tmp_fields=RECOMMENDED_FIELDS, hours=48):
    cfg = AnalyseConfig(region=REGION, days=2, hours=hours, log_group=LOG_GROUP,
                        s3_bucket=None, s3_prefix=None, out_path="approved.json")
    return sg_tightener.run_analyse(cfg)


def _plan(approved):
    sgs = sg_tightener._list_security_groups(REGION)
    plan = sg_tightener.build_plan(sgs, approved["ips"], region=REGION)
    with open("plan.json", "w") as fh:
        json.dump(plan, fh)
    return plan


@pytest.fixture
def observed(estate):
    start, end = window()
    records = generate_records(estate.topology(_talkers()), start, end)
    add_cloudwatch_flow_log(estate, RECOMMENDED_FIELDS, records)
    return records


def test_round_trip_restores_the_exact_original_rules(estate, observed):
    before = estate.snapshot()
    approved = _analyse()
    # pkt-srcaddr: the real office clients, never the transit gateway hop.
    assert "10.20.33.11" in approved["ips"] and "10.4.250.9" not in approved["ips"]
    assert "10.66.1.2" not in approved["ips"]  # rejected only

    plan = _plan(approved)
    assert plan["region"] == REGION
    sg_tightener.apply_plan(plan, REGION, manifest_path="manifest.json")
    tightened = estate.snapshot()
    assert tightened != before
    db = {r[3] for r in tightened[estate.groups["db"]]}
    assert "10.4.2.10/32" in db or "10.4.2.10/31" in db

    manifest = json.load(open("manifest.json"))
    assert manifest["complete"] is True
    sg_tightener.revert_from_manifest("manifest.json")
    assert estate.snapshot() == before  # descriptions included


@pytest.mark.xfail(strict=True, reason=(
    "known gap: approved.json holds source IPs only, with no destination or port, "
    "so every group's rule is rebuilt from every observed source inside it. The "
    "database on 5432 is granted the office clients that only ever called the API "
    "on 443. Narrower than 10.0.0.0/8, but not what the evidence shows."))
def test_a_group_only_gets_sources_that_reached_it(estate, observed):
    _plan(_analyse())
    plan = json.load(open("plan.json"))
    db = next(g for g in plan["groups"] if g["group_id"] == estate.groups["db"])
    granted = {ipaddress.ip_network(r["CidrIp"]) for p in db["authorise"] for r in p["IpRanges"]}
    assert not any(ipaddress.ip_address("10.20.33.11") in n for n in granted)


def test_every_authorised_cidr_sits_inside_a_revoked_one(estate, observed):
    plan = _plan(_analyse())
    for g in plan["groups"]:
        revoked = {(p["FromPort"], ipaddress.ip_network(r["CidrIp"]))
                   for p in g["revoke"] for r in p["IpRanges"]}
        for p in g["authorise"]:
            for r in p["IpRanges"]:
                net = ipaddress.ip_network(r["CidrIp"])
                assert any(port == p["FromPort"] and net.subnet_of(o) for port, o in revoked), net


def test_apply_refuses_a_plan_when_rules_changed_since(estate, observed):
    plan = _plan(_analyse())
    estate.ec2.authorize_security_group_ingress(
        GroupId=estate.groups["db"],
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                        "IpRanges": [{"CidrIp": "10.1.0.0/16"}]}])
    before = estate.snapshot()
    with pytest.raises(RuntimeError, match="stale"):
        sg_tightener.apply_plan(plan, REGION, manifest_path="manifest.json")
    assert estate.snapshot() == before


def test_failure_mid_apply_records_only_what_was_done_and_reverts_cleanly(estate, observed):
    """Regression: the manifest recorded the whole group as done even when
    the authorise after a successful revoke failed, so revert then tried to
    remove rules that were never added."""
    before = estate.snapshot()
    plan = _plan(_analyse())
    assert len(plan["groups"]) == 2

    real_client = sg_tightener._client

    class FailingSecondAuthorise:
        def __init__(self, inner):
            self.inner, self.authorises = inner, 0

        def __getattr__(self, name):
            return getattr(self.inner, name)

        def authorize_security_group_ingress(self, **kw):
            self.authorises += 1
            if self.authorises == 2:
                raise sg_tightener.botocore.exceptions.ClientError(
                    {"Error": {"Code": "RulesPerSecurityGroupLimitExceeded", "Message": "limit"}},
                    "AuthorizeSecurityGroupIngress")
            return self.inner.authorize_security_group_ingress(**kw)

    wrapped = FailingSecondAuthorise(real_client("ec2", REGION))
    with mock.patch.object(sg_tightener, "_client",
                           lambda s, r=None: wrapped if s == "ec2" else real_client(s, r)):
        with pytest.raises(SystemExit, match="HALTED"):
            sg_tightener.apply_plan(plan, REGION, manifest_path="manifest.json")

    manifest = json.load(open("manifest.json"))
    assert manifest["complete"] is False
    first, second = manifest["groups"]
    assert first["revoked"] and first["authorised"]
    assert second["revoked"] and second["authorised"] == []  # revoke done, authorise failed

    sg_tightener.revert_from_manifest("manifest.json")
    assert estate.snapshot() == before


def test_cli_apply_uses_the_plan_region_and_refuses_a_different_one(estate, observed, monkeypatch):
    _plan(_analyse())
    monkeypatch.setenv("AWS_REGION", "us-east-1")  # ambient region must not matter
    assert sg_tightener.main(["apply", "--plan", "plan.json", "--yes"]) == 0
    with pytest.raises(SystemExit, match="built in eu-west-1"):
        sg_tightener.main(["apply", "--plan", "plan.json", "--region", "us-east-1", "--yes"])


def test_truncated_insights_answer_is_split_not_trusted(estate, monkeypatch):
    """Regression: analyse took the first 10,000 Insights rows as the whole
    answer; the plan then revoked access for every source cut off."""
    start, end = window(hours=24)
    sources = [f"10.{8 + i // 250}.{i % 250}.1" for i in range(300)]
    records = generate_records(estate.topology([Talker(sources, "10.4.1.20", 5432, every=0.5)]), start, end)
    add_cloudwatch_flow_log(estate, DEFAULT_LOG_FORMAT_FIELDS, records)
    monkeypatch.setattr(sg_tightener, "INSIGHTS_ROW_LIMIT", 100)

    approved = _analyse(hours=24)
    assert set(approved["ips"]) == {r["src"] for r in records}
    assert len(approved["ips"]) > 100
    assert len(estate.logs.queries) > 1


def test_s3_reader_handles_gzip_headers_prefixes_and_pkt_srcaddr(estate):
    s3 = sg_tightener._client("s3", REGION)
    s3.create_bucket(Bucket="flowlogs", CreateBucketConfiguration={"LocationConstraint": REGION})
    estate.ec2.create_flow_logs(
        ResourceIds=[estate.vpc_id], ResourceType="VPC", TrafficType="ALL",
        LogDestinationType="s3", LogDestination="arn:aws:s3:::flowlogs",  # moto refuses a /prefix
        LogFormat=" ".join("${%s}" % f for f in RECOMMENDED_FIELDS))
    start, end = window(hours=6)
    records = generate_records(estate.topology(_talkers()), start, end)
    put_s3_objects(s3, "flowlogs", records, RECOMMENDED_FIELDS, prefix="AWSLogs", per_object=20)
    put_s3_objects(s3, "flowlogs", records[:5], RECOMMENDED_FIELDS, prefix="other", gz=False)

    cfg = AnalyseConfig(region=REGION, days=1, hours=6, log_group=None, s3_bucket="flowlogs",
                        s3_prefix="AWSLogs/", out_path="approved.json")
    approved = sg_tightener.run_analyse(cfg)
    expected = {r["src"] for r in records if r["action"] == "ACCEPT"}
    assert set(approved["ips"]) == expected
    assert "10.4.250.9" not in approved["ips"]
    assert approved["flow_log_check"]["verified"] is True


def test_sg_extend_only_ever_adds_rules(estate, monkeypatch):
    start, end = window(hours=6)
    records = generate_records(estate.topology([
        Talker(["10.4.5.7"], "10.4.2.10", 8443, action="REJECT"),
        Talker(["10.4.2.10"], "10.4.1.20", 5432),
    ]), start, end)
    add_cloudwatch_flow_log(estate, RECOMMENDED_FIELDS, records)
    real_client = sg_extend._client
    calls = []

    class Recorder:
        def __init__(self, inner):
            self.inner = inner

        def __getattr__(self, name):
            calls.append(name)
            return getattr(self.inner, name)

    monkeypatch.setattr(sg_extend, "_client",
                        lambda s, r=None: Recorder(real_client(s, r)) if s == "ec2" else real_client(s, r))
    before = estate.snapshot()
    rc = sg_extend.main(["--region", REGION, "--log-group", LOG_GROUP, "--hours", "6", "--yes"])
    assert rc in (0, None)
    assert "authorize_security_group_ingress" in calls
    assert not any(c.startswith("revoke") for c in calls)
    after = estate.snapshot()
    api = estate.groups["api"]
    added = set(after[api]) - set(before[api])
    assert [(r[2], r[3]) for r in added] == [(8443, "10.4.5.7/32")]
    for gid in before:
        assert set(before[gid]) <= set(after[gid])


def test_sg_diagnose_reads_exactly_the_requested_hours(estate, monkeypatch):
    """Regression: --hours was turned into whole days, so --hours 2 read 24."""
    import sg_diagnose
    add_cloudwatch_flow_log(estate, RECOMMENDED_FIELDS, [])
    monkeypatch.setattr("builtins.input", lambda _prompt="": "n")
    sg_diagnose.main(["--region", REGION, "--log-group", LOG_GROUP, "--hours", "2"])
    (_query, qstart, qend), = estate.logs.queries
    assert qend - qstart == 2 * 3600
