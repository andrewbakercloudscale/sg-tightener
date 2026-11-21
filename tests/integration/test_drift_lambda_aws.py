"""sg_drift_lambda against moto: SNS, Security Hub with sg_review's finding id, and a real revoke."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

import sg_drift_lambda as dl

REGION = "eu-west-1"
EVENT = json.loads((Path(__file__).parents[1] / "fixtures" / "events" / "authorize-ssh-world.json").read_text())


def test_alert_lands_in_sns_and_security_hub_and_the_rule_is_revoked(aws, monkeypatch):
    acct = boto3.client("sts").get_caller_identity()["Account"]
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    gid = ec2.create_security_group(GroupName="ops-ssh", Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    sns = boto3.client("sns", region_name=REGION)
    topic = sns.create_topic(Name="sg-drift")["TopicArn"]
    sqs = boto3.client("sqs", region_name=REGION)
    q = sqs.create_queue(QueueName="inbox")["QueueUrl"]
    qarn = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=qarn)
    for k, v in {"SNS_TOPIC_ARN": topic, "SECURITY_HUB": "true", "AUTO_REVOKE": "critical"}.items():
        monkeypatch.setenv(k, v)

    ev = copy.deepcopy(EVENT)
    ev["account"] = ev["detail"]["recipientAccountId"] = acct
    ev["detail"]["requestParameters"]["groupId"] = gid
    ev["detail"]["requestParameters"]["ipPermissions"]["items"][0].pop("ipv6Ranges")
    out = dl.handler(ev)

    assert out["sent"] == ["sns", "securityhub"] and len(out["revoked"]) == 1
    rules = ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]["IpPermissions"]
    assert not any(r.get("IpRanges") for r in rules)  # taken back out
    msg = json.loads(sqs.receive_message(QueueUrl=q)["Messages"][0]["Body"])
    assert "contractor-ops opened ops-ssh to 0.0.0.0/0" in msg["Message"] and "Revoked automatically" in msg["Message"]
    found = boto3.client("securityhub", region_name=REGION).get_findings()["Findings"]
    assert len(found) == 1 and found[0]["Severity"]["Label"] == "CRITICAL"
    assert found[0]["AwsAccountId"] == acct
