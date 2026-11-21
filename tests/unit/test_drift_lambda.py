"""sg_drift_lambda without AWS: which events alert, and how."""

import copy
import json
from pathlib import Path

import pytest

import sg_drift_lambda as dl

EVENT = json.loads((Path(__file__).parents[1] / "fixtures" / "events" / "authorize-ssh-world.json").read_text())


def _event(**req):
    ev = copy.deepcopy(EVENT)
    ev["detail"]["requestParameters"]["groupId"] = "sg-0abc"
    ev["detail"]["requestParameters"].update(req)
    return ev


class EC2:
    def __init__(self, perms=None, tags=None, fail=False):
        self.perms, self.tags, self.fail, self.revoked = perms, tags or [], fail, []

    def describe_security_groups(self, GroupIds):
        if self.fail:
            raise RuntimeError("AccessDenied")
        return {"SecurityGroups": [{"GroupId": GroupIds[0], "GroupName": "ops-ssh", "Tags": self.tags,
                                    "IpPermissions": self.perms if self.perms is not None else [
                                        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                         "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]}]}

    def revoke_security_group_ingress(self, **kw):
        self.revoked.append(kw)


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("MIN_SEVERITY", "AUTO_REVOKE", "SNS_TOPIC_ARN", "SLACK_SECRET_ARN", "SECURITY_HUB", "ACCOUNT_NAME"):
        monkeypatch.delenv(k, raising=False)


def test_ssh_to_the_world_on_v4_and_v6_is_two_critical_items_naming_who_and_where():
    items, meta = dl.findings(_event(), EC2())
    assert meta == {"account": "111122223333", "region": "eu-west-1", "exempt": False}
    assert [(i["sev"], i["rule"]["cidr"]) for i in items] == [("critical", "0.0.0.0/0"), ("critical", "::/0")]
    assert "contractor-ops" in items[0]["title"] and "41.13.7.200" in items[0]["reason"]
    assert items[0]["group"] == "sg-0abc" and "ops-ssh" in items[0]["title"]


def test_unreadable_group_is_judged_from_the_event_not_called_removed():
    items, _ = dl.findings(_event(), EC2(fail=True))
    assert items and all(i["still"] and i["sev"] == "critical" for i in items)


def test_rule_already_gone_by_the_time_it_is_read_is_low_and_not_alerted():
    ec2 = EC2(perms=[])
    items, _ = dl.findings(_event(), ec2)
    assert {i["sev"] for i in items} == {"low"}
    assert dl.handler(_event(), ec2=ec2)["found"] == 0


def test_narrow_rules_failed_calls_and_other_events_raise_nothing():
    narrow = {"ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
                                           "ipRanges": {"items": [{"cidrIp": "203.0.113.7/32"}]}}]}}
    assert dl.findings(_event(**narrow), EC2(perms=[]))[0] == []
    failed = _event()
    failed["detail"]["errorCode"] = "UnauthorizedOperation"
    assert dl.findings(failed, EC2())[0] == []
    other = _event()
    other["detail"]["eventName"] = "RevokeSecurityGroupIngress"
    assert dl.findings(other, EC2())[0] == []


def test_auto_revoke_takes_critical_rules_back_out_unless_the_group_is_tagged(monkeypatch):
    monkeypatch.setenv("AUTO_REVOKE", "critical")
    ec2 = EC2()
    out = dl.handler(_event(), ec2=ec2)
    assert out["found"] == 2 and len(out["revoked"]) == 2
    assert ec2.revoked[0] == {"GroupId": "sg-0abc", "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
    assert ec2.revoked[1]["IpPermissions"][0]["Ipv6Ranges"] == [{"CidrIpv6": "::/0"}]

    tagged = EC2(tags=[{"Key": "sg-tightener-allow-wide", "Value": "true"}])
    assert dl.handler(_event(), ec2=tagged)["revoked"] == [] and tagged.revoked == []


def test_modify_by_rule_id_is_revoked_by_that_id(monkeypatch):
    monkeypatch.setenv("AUTO_REVOKE", "high")
    ev = _event()
    ev["detail"]["eventName"] = "ModifySecurityGroupRules"
    ev["detail"]["requestParameters"] = {"ModifySecurityGroupRulesRequest": {"GroupId": "sg-0abc", "SecurityGroupRule": {
        "SecurityGroupRuleId": "sgr-0123", "SecurityGroupRule": {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
                                                                "CidrIpv4": "0.0.0.0/0"}}}}
    ec2 = EC2(perms=[{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    dl.handler(ev, ec2=ec2)
    assert ec2.revoked == [{"GroupId": "sg-0abc", "SecurityGroupRuleIds": ["sgr-0123"]}]


def test_min_severity_and_bad_settings(monkeypatch):
    web = {"ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 443, "toPort": 443,
                                        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}
    ec2 = EC2(perms=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    assert dl.handler(_event(**web), ec2=ec2)["found"] == 0  # medium, below the default high
    monkeypatch.setenv("MIN_SEVERITY", "medium")
    assert dl.handler(_event(**web), ec2=ec2)["found"] == 1
    monkeypatch.setenv("AUTO_REVOKE", "everything")
    with pytest.raises(ValueError, match="AUTO_REVOKE"):
        dl.handler(_event(), ec2=EC2())


def test_slack_failure_alone_raises_but_a_working_channel_keeps_it_quiet(monkeypatch):
    monkeypatch.setenv("SLACK_SECRET_ARN", "arn:aws:secretsmanager:eu-west-1:1:secret:s")
    monkeypatch.setattr(dl, "_slack_url", lambda arn: "https://hooks.slack.com/x")
    posted = []
    monkeypatch.setattr(dl.sg_review, "post_slack", lambda url, text: posted.append(text))
    assert dl.handler(_event(), ec2=EC2())["sent"] == ["slack"] and "CRITICAL" in posted[0]

    def boom(url, text):
        raise OSError("timeout")

    monkeypatch.setattr(dl.sg_review, "post_slack", boom)
    with pytest.raises(RuntimeError, match="every channel failed"):
        dl.handler(_event(), ec2=EC2())


def test_cli_prints_the_alert_for_a_saved_event(tmp_path, capsys):
    p = tmp_path / "e.json"
    p.write_text(json.dumps(EVENT["detail"]))  # a bare CloudTrail record works too
    assert dl.main([str(p)]) == 1
    assert "CRITICAL" in capsys.readouterr().out
