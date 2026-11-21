"""sg_db against moto: import, an out-of-band change found by reconcile, apply putting it back, exec,
create-group, and the write tools (sg_tightener apply) recording what they did."""

from __future__ import annotations

import json
import os

import boto3
import pytest

import sg_db
from tests.integration.conftest import REGION


def _db():
    return sg_db.Store(os.environ["SG_TIGHTENER_DB"])


def _ssh_world(_gid):
    return {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}


def _ingress(ec2, gid):
    sg = ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]
    return {(p["IpProtocol"], p.get("FromPort"), r["CidrIp"]) for p in sg["IpPermissions"] for r in p.get("IpRanges", [])}


def test_reconcile_records_console_change_and_apply_reverts_it(estate, capsys):
    ec2, db = estate.ec2, estate.groups["db"]
    assert sg_db.main(["import", "--regions", REGION]) == 0
    assert sg_db.main(["reconcile", "--regions", REGION, "--no-cloudtrail"]) == 0
    assert "AWS matches the database" in capsys.readouterr().out

    ec2.authorize_security_group_ingress(GroupId=db, IpPermissions=[_ssh_world(db)])  # someone in the console
    assert sg_db.main(["reconcile", "--regions", REGION, "--no-cloudtrail"]) == 1
    out = capsys.readouterr().out
    assert "changed outside sg-tightener" in out and "+ inbound tcp 22 from 0.0.0.0/0" in out
    assert "sg_db.py apply" in out and "sg_db.py adopt" in out

    assert sg_db.main(["apply", "--region", REGION, "--yes", "--reason", "revert console change"]) == 0
    assert ("tcp", 22, "0.0.0.0/0") not in _ingress(ec2, db)
    store = _db()
    actions = [(e["origin"], e["action"]) for e in store.log()]
    assert ("external", "rules-changed") in actions and actions[-1] == ("apply", "applied")
    assert store.verify()[0] and store.pending(boto3.client("sts").get_caller_identity()["Account"], REGION) == []


def test_apply_refuses_when_aws_changed_since_last_read(estate):
    ec2, db = estate.ec2, estate.groups["db"]
    sg_db.main(["import", "--regions", REGION])
    sg_db.main(["add", "--region", REGION, "--group", db, "--proto", "tcp", "--port", "5432",
                "--source", "10.4.1.0/24", "--reason", "app subnet", "--ticket", "CHG-7"])
    ec2.authorize_security_group_ingress(GroupId=db, IpPermissions=[_ssh_world(db)])
    with pytest.raises(SystemExit, match="outside this tool"):
        sg_db.main(["apply", "--region", REGION, "--yes"])
    assert ("tcp", 5432, "10.4.1.0/24") not in _ingress(ec2, db)
    # a person has now seen it; apply makes the wanted rule and takes the console one away
    assert sg_db.main(["apply", "--region", REGION, "--yes"]) == 0
    assert ("tcp", 5432, "10.4.1.0/24") in _ingress(ec2, db) and ("tcp", 22, "0.0.0.0/0") not in _ingress(ec2, db)


def test_exec_runs_a_printed_fix_through_the_database(estate, capsys):
    ec2, api = estate.ec2, estate.groups["api"]
    cmd = (f"aws ec2 revoke-security-group-ingress --region {REGION} --group-id {api} "
           "--ip-permissions 'IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=172.16.0.0/12}]'")
    with pytest.raises(SystemExit):
        sg_db.main(["exec", "--", *cmd.split()[:3]])  # no --reason
    assert sg_db.main(["exec", "--reason", "nothing from 172.16 in 90 days", cmd]) == 0
    assert ("tcp", 443, "172.16.0.0/12") not in _ingress(ec2, api)
    e = _db().log()[-2]
    assert e["action"] == "desired-changed" and e["reason"] == "nothing from 172.16 in 90 days"


def test_create_group_lands_in_aws_and_the_database(estate, capsys):
    sg_db.main(["import", "--regions", REGION])
    assert sg_db.main(["create-group", "--region", REGION, "--vpc", estate.vpc_id, "--name", "cache",
                       "--description", "redis", "--reason", "new cache tier"]) == 0
    gid = capsys.readouterr().out.strip().splitlines()[-1]
    acct = boto3.client("sts").get_caller_identity()["Account"]
    assert gid in _db().groups(acct, REGION)
    assert sg_db.main(["reconcile", "--regions", REGION, "--no-cloudtrail"]) == 0


def test_log_and_verify_commands(estate, capsys):
    sg_db.main(["import", "--regions", REGION])
    assert sg_db.main(["verify"]) == 0
    assert "audit trail intact" in capsys.readouterr().out
    assert sg_db.main(["log", "--since", "1h", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows and all(r["action"] == "group-imported" for r in rows)


def test_tracked_client_records_tool_changes_and_refuses_unreviewed_drift(estate):
    ec2, db = estate.ec2, estate.groups["db"]
    t = sg_db.track(ec2, REGION, "sg_tightener apply", reason="plan")  # first use imports
    t.revoke_security_group_ingress(GroupId=db, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}])
    store = _db()
    last = store.log()[-1]
    assert (last["origin"], last["action"]) == ("sg_tightener apply", "revoke-security-group-ingress")
    acct = boto3.client("sts").get_caller_identity()["Account"]
    assert store.pending(acct, REGION) == []
    ec2.authorize_security_group_ingress(GroupId=db, IpPermissions=[_ssh_world(db)])
    with pytest.raises(SystemExit, match="changed outside sg-tightener"):
        sg_db.track(ec2, REGION, "sg_tightener apply")
    sg_db.track(ec2, REGION, "sg_extend", strict=False)  # break-glass goes ahead, the change is on record
