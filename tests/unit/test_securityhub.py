"""Security Hub export: ASFF shape, stable ids, and archiving what is no longer open."""

import time

import pytest

import sg_ipintel as ipintel
import sg_review
import sg_store
import sg_review_demo
import sg_securityhub as hub

NOW = "2026-11-21T10:00:00.000Z"


def test_asff_has_the_required_fields_and_limits():
    f = hub.to_asff("123456789012", "eu-west-1", "k", "critical", "t" * 300, "d" * 2000, generator="g",
                    recommendation="r" * 600, group="sg-1", now=NOW)
    for k in ("SchemaVersion", "Id", "ProductArn", "GeneratorId", "AwsAccountId", "Types", "CreatedAt", "UpdatedAt",
              "Severity", "Title", "Description", "Resources"):
        assert k in f
    assert f["ProductArn"] == "arn:aws:securityhub:eu-west-1:123456789012:product/123456789012/default"
    assert f["Severity"] == {"Label": "CRITICAL"} and len(f["Title"]) == 256 and len(f["Description"]) == 1024
    assert len(f["Remediation"]["Recommendation"]["Text"]) == 512
    assert f["Resources"][0] == {"Type": "AwsEc2SecurityGroup", "Region": "eu-west-1", "Partition": "aws",
                                 "Id": "arn:aws:ec2:eu-west-1:123456789012:security-group/sg-1"}
    assert hub.to_asff("1", "cn-north-1", "k", "low", "t", "d", generator="g")["ProductArn"].startswith("arn:aws-cn:")


def test_same_key_same_id_and_other_resources():
    a = hub.finding_id("1", "eu-west-1", "x")
    assert a == hub.finding_id("1", "eu-west-1", "x") != hub.finding_id("1", "eu-west-1", "y")
    assert hub.resource("1", "eu-west-1", name="vpce-svc-0abc")["Type"] == "AwsEc2VpcEndpointService"
    assert hub.resource("1", "eu-west-1", name="eni-1")["Type"] == "Other"


def test_plan_archives_findings_that_are_gone_and_only_once():
    state: dict = {}
    f1 = hub.to_asff("1", "eu-west-1", "a", "high", "A", "a", generator="g", now=NOW)
    f2 = hub.to_asff("1", "eu-west-1", "b", "high", "B", "b", generator="g", now=NOW)
    assert [f["Id"] for f in hub.plan([f1, f2], state, "1/eu-west-1", NOW)] == [f1["Id"], f2["Id"]]
    second = hub.plan([f1], state, "1/eu-west-1", NOW)
    assert [(f["Id"], f["RecordState"]) for f in second] == [(f1["Id"], "ACTIVE"), (f2["Id"], "ARCHIVED")]
    assert second[1]["Workflow"] == {"Status": "RESOLVED"} and second[1]["Title"] == "B"
    assert [f["Id"] for f in hub.plan([f1], state, "1/eu-west-1", NOW)] == [f1["Id"]]

@pytest.fixture
def tor_list(tmp_path):
    """The demo's Tor relay on the Tor exit list, whatever lists this computer has downloaded."""
    old = ipintel.DATA_DIR
    ipintel.set_data_dir(tmp_path)
    sg_store.File(tmp_path / "ipintel" / "tor.json").write_text('["185.220.101.33"]')
    yield
    ipintel.set_data_dir(old)


def test_review_findings_from_the_demo(tor_list):
    rep = sg_review.build(sg_review_demo.build_doc(sg_review_demo.ACCOUNT, time.time(), 7), "1w",
                          internal=sg_review_demo.INTERNAL)
    fs = sg_review.hub_findings(sg_review_demo.ACCOUNT, rep, NOW)
    assert len({f["Id"] for f in fs}) == len(fs)
    labels = {f["Severity"]["Label"] for f in fs}
    assert {"CRITICAL", "HIGH", "MEDIUM", "LOW"} <= labels and "INFORMATIONAL" not in labels
    drift = next(f for f in fs if f["ProductFields"].get("sg-tightener/kind") == "drift")
    assert "Unusual Behaviors/User" in drift["Types"] and "revoke-security-group-ingress" in drift["Remediation"]["Recommendation"]["Text"]
    c2 = next(f for f in fs if f["ProductFields"].get("sg-tightener/key") == "egress-bad")
    assert "TTPs/Command and Control" in c2["Types"]
    assert sg_review.hub_findings(sg_review_demo.ACCOUNT, rep, NOW) == fs  # stable from one run to the next


def test_ou_findings():
    f = hub.from_ou_finding({"account_id": "111122223333", "account_name": "a", "region": "eu-west-1",
                             "resource_type": "SG", "resource_id": "sg-9", "cidr": "0.0.0.0/0",
                             "port_range": "22", "severity": "HIGH"}, NOW)
    assert f["AwsAccountId"] == "111122223333" and f["Severity"]["Label"] == "HIGH"
    assert f["Resources"][0]["Id"].endswith("security-group/sg-9")
