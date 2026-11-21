"""Sending to Security Hub, against moto: findings land, and the ones gone are archived on the next send."""

from __future__ import annotations

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

import sg_ou_report
import sg_review
import sg_securityhub as hub

REGION = "eu-west-1"


def test_push_hub_sends_then_archives(aws, tmp_path, monkeypatch):
    monkeypatch.setattr(sg_review, "_dir", lambda: tmp_path)
    acct = boto3.client("sts").get_caller_identity()["Account"]
    sess = boto3.Session()
    a = hub.to_asff(acct, REGION, "a", "high", "A", "a", generator="g")
    b = hub.to_asff(acct, REGION, "b", "medium", "B", "b", generator="g")
    assert sg_review.push_hub(sess, acct, [a, b])["sent"] == 2
    res = sg_review.push_hub(sess, acct, [a])
    assert res["archived"] == 1
    got = {f["Id"]: f for f in boto3.client("securityhub", region_name=REGION).get_findings()["Findings"]}
    assert got[b["Id"]]["RecordState"] == "ARCHIVED" and got[a["Id"]]["RecordState"] == "ACTIVE"


def test_ou_report_sends_each_accounts_findings_with_its_session(aws, tmp_path):
    acct = boto3.client("sts").get_caller_identity()["Account"]
    rows = [{"account_id": acct, "account_name": "x", "region": REGION, "resource_type": "SG", "resource_id": "sg-1",
             "cidr": "0.0.0.0/0", "port_range": "22", "severity": "HIGH"}]
    res = sg_ou_report.send_to_securityhub(rows, {acct: boto3.Session()}, str(tmp_path / "s.json"), [REGION])
    assert res["sent"] == 1
    assert (tmp_path / "s.json").exists()
