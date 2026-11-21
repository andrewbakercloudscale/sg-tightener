"""Surveillance and enforce modes, the DryRun permission check, and one asset tightened on its own: a group of
its own from its own flows, two-person approval, the swap, the asset's audit trail, an outside change found by
reconcile, and the revert. Auto scaling instances are refused."""

from __future__ import annotations

import json
import os

import boto3
import pytest

import sg_assets
import sg_db
from tests.integration.conftest import REGION


def _db():
    return sg_db.Store(os.environ["SG_TIGHTENER_DB"])


def _eni_groups(ec2, eni):
    return sorted(g["GroupId"] for g in ec2.describe_network_interfaces(NetworkInterfaceIds=[eni])["NetworkInterfaces"][0]["Groups"])


def _ingress(ec2, gid):
    sg = ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]
    return {(p["IpProtocol"], p.get("FromPort"), r["CidrIp"]) for p in sg["IpPermissions"] for r in p.get("IpRanges", [])}


class _Who:
    def __init__(self, monkeypatch):
        self.arn = "arn:aws:sts::123456789012:assumed-role/Ops/alice@example.com"
        monkeypatch.setattr(sg_db, "account_of", lambda session=None: ("123456789012", self.arn))
        monkeypatch.setattr(sg_db.sg_tightener, "caller_arn", lambda: self.arn)

    def be(self, name):
        self.arn = f"arn:aws:sts::123456789012:assumed-role/Ops/{name}@example.com"


def _approved(estate, path="approved.json"):
    api_a = estate.enis["10.4.2.10"]
    flows = [{"src": "10.20.33.11", "dst": "10.4.2.10", "dstport": 443, "protocol": "6", "interface": api_a},
             {"src": "10.20.33.12", "dst": "10.4.2.10", "dstport": 443, "protocol": "6", "interface": api_a},
             {"src": "10.4.9.50", "dst": "10.4.2.11", "dstport": 9100, "protocol": "6", "interface": estate.enis["10.4.2.11"]}]
    doc = {"schema": "sg-tightener.approved/v2", "ips": sorted({f["src"] for f in flows}), "flows": flows}
    with open(path, "w") as fh:
        json.dump(doc, fh)
    return path


def test_surveillance_is_the_default_and_refuses_every_write(estate, capsys):
    ec2, db = estate.ec2, estate.groups["db"]
    store = _db()
    with store:
        store.set_mode("*", "surveillance", "test", "report only")
    assert sg_db.main(["import", "--regions", REGION]) == 0
    assert sg_db.main(["add", "--region", REGION, "--group", db, "--proto", "tcp", "--port", "5432",
                       "--source", "10.4.1.0/24", "--reason", "app subnet"]) == 0  # proposing is reporting
    with pytest.raises(SystemExit, match="surveillance mode"):
        sg_db.main(["apply", "--region", REGION, "--yes"])
    assert ("tcp", 5432, "10.4.1.0/24") not in _ingress(ec2, db)
    with pytest.raises(SystemExit, match="surveillance mode"):
        sg_db.main(["create-group", "--region", REGION, "--vpc", estate.vpc_id, "--name", "x", "--description", "x",
                    "--reason", "x"])
    with pytest.raises(SystemExit, match="surveillance mode"):
        sg_db.track(ec2, REGION, "sg_tightener apply")
    sg_db.track(ec2, REGION, "sg_tightener revert", strict=False)  # an undo is always allowed

    account = store.regions()[0][0]
    with pytest.raises(SystemExit, match="check the permissions first"):
        sg_db.main(["mode", "enforce", "--account", account, "--reason", "ready"])
    assert sg_db.main(["check", "--regions", REGION, "--assets"]) == 0
    assert "can change all 4 group(s) checked and swap an asset's groups" in capsys.readouterr().out
    assert store.permissions(account)[0]["ok"]
    assert sg_db.main(["mode", "enforce", "--account", account, "--reason", "ready"]) == 0
    assert store.mode(account) == "enforce" and store.mode("999999999999") == "surveillance"
    assert sg_db.main(["apply", "--region", REGION, "--yes"]) == 0
    assert ("tcp", 5432, "10.4.1.0/24") in _ingress(ec2, db)
    actions = [e["action"] for e in store.log()]
    assert "permissions-checked" in actions and "mode-enforce" in actions


def test_apply_changes_nothing_when_the_dry_run_is_denied(estate, monkeypatch):
    ec2, db = estate.ec2, estate.groups["db"]
    sg_db.main(["import", "--regions", REGION])
    sg_db.main(["add", "--region", REGION, "--group", db, "--proto", "tcp", "--port", "5432",
                "--source", "10.4.1.0/24", "--reason", "app subnet"])
    real = sg_db._dry

    def deny_revoke(call, **kw):
        if call.__name__ == "revoke_security_group_ingress":
            return "denied"
        return real(call, **kw)

    monkeypatch.setattr(sg_db, "_dry", deny_revoke)
    with pytest.raises(SystemExit, match="(?s)cannot make every change.*not allowed revoke_security_group_ingress"):
        sg_db.main(["apply", "--region", REGION, "--yes"])
    assert ("tcp", 5432, "10.4.1.0/24") not in _ingress(ec2, db)
    assert not _db().permissions()[0]["ok"]


def test_one_asset_gets_a_group_of_its_own_with_approval_audit_and_revert(estate, monkeypatch, capsys):
    ec2, api = estate.ec2, estate.groups["api"]
    eni = estate.enis["10.4.2.10"]
    who = _Who(monkeypatch)
    assert sg_db.main(["import", "--regions", REGION]) == 0
    store = _db()
    with store:
        store.set_approvals(True, "test", "two people")
    assert [a["groups"] for a in sg_assets.list_assets(store, "123456789012", REGION) if a["eni"] == eni] == [[api]]

    assert sg_db.main(["asset-plan", "--region", REGION, "--eni", eni, "--approved", _approved(estate),
                       "--out", "asset-plan.json"]) == 0
    with open("asset-plan.json") as fh:
        plan = json.load(fh)
    srcs = {r["source"] for r in plan["ingress"]}
    assert "10.0.0.0/8" not in srcs and "172.16.0.0/12" not in srcs, "the wide private ranges are narrowed"
    assert any(r["from"] == 443 and r["source"].startswith("10.20.33.") for r in plan["ingress"])
    assert not any(r["from"] == 9100 for r in plan["ingress"]), "9100 only ever reached the other interface"
    assert plan["integrity"]["sha256"]
    assert _eni_groups(ec2, eni) == [api], "planning changes nothing"

    assert sg_db.main(["asset-propose", "--plan", "asset-plan.json", "--reason", "isolate api-a", "--ticket", "CHG-5"]) == 0
    (req,) = store.requests("pending")
    assert req["kind"] == "asset"
    with pytest.raises(SystemExit, match="different person"):
        sg_db.main(["approve", str(req["id"])])
    who.be("bob")
    assert sg_db.main(["approve", str(req["id"]), "--note", "flows checked"]) == 0
    assert "asset-apply" in capsys.readouterr().out
    assert sg_db.main(["asset-apply", str(req["id"]), "--yes"]) == 0
    (new,) = _eni_groups(ec2, eni)
    assert new != api and _eni_groups(ec2, estate.enis["10.4.2.11"]) == [api], "the other interface is untouched"
    assert ("tcp", 443, "10.0.0.0/8") not in _ingress(ec2, new)
    assert new in store.groups("123456789012", REGION), "the new group is in the database"
    assert store._request(req["id"])["status"] == "applied"

    # someone puts it back on the shared group by hand: reconcile records it against the asset
    ec2.modify_network_interface_attribute(NetworkInterfaceId=eni, Groups=[api])
    assert sg_db.main(["reconcile", "--regions", REGION, "--no-cloudtrail"]) == 1
    assert f"asset {eni}" in capsys.readouterr().out
    ec2.modify_network_interface_attribute(NetworkInterfaceId=eni, Groups=[new])
    sg_db.main(["reconcile", "--regions", REGION, "--no-cloudtrail"])

    assert sg_db.main(["asset-revert", "--region", REGION, "--eni", eni, "--reason", "rollback test"]) == 0
    assert _eni_groups(ec2, eni) == [api]
    capsys.readouterr()
    assert sg_db.main(["asset-log", "--eni", eni]) == 0
    log = capsys.readouterr().out
    for action in ("assets-imported", "asset-request-proposed", "request-approved", "asset-swapped",
                   "asset-groups-changed", "asset-reverted"):
        assert action in log, action
    assert store.verify()[0]


def test_an_auto_scaling_instance_is_refused_and_pointed_at_its_groups(estate):
    ec2 = estate.ec2
    sub = ec2.describe_subnets()["Subnets"][0]["SubnetId"]
    inst = ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1, SubnetId=sub,
                             SecurityGroupIds=[estate.groups["api"]],
                             TagSpecifications=[{"ResourceType": "instance",
                                                 "Tags": [{"Key": "aws:autoscaling:groupName", "Value": "web-asg"}]}])["Instances"][0]
    with pytest.raises(sg_db.Refused, match="auto scaling group web-asg.*launch template"):
        sg_assets.plan_asset(ec2, "123456789012", REGION, {"flows": [], "ips": []}, instance=inst["InstanceId"])
    assets = {a["instance"]: a for a in sg_assets.describe_assets(boto3.client("ec2", region_name=REGION))}
    assert assets[inst["InstanceId"]]["asg"] == "web-asg"
