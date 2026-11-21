"""sg_db against moto: import, an out-of-band change found by reconcile, apply putting it back, exec,
create-group, and the write tools (sg_tightener apply) recording what they did."""

from __future__ import annotations

import json
import os
import shlex

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
    (e,) = [x for x in _db().log() if x["action"] == "request-proposed"]
    assert e["reason"] == "nothing from 172.16 in 90 days"


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
    assert rows and {r["action"] for r in rows} == {"approvals-off", "group-imported"}


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


def test_a_fix_printed_by_sg_review_runs_as_printed(estate):
    import sg_review

    ec2, api = estate.ec2, estate.groups["api"]
    rule = {"proto": "6", "from": 443, "to": 443}
    line = sg_review._revoke_cli(REGION, api, rule, "172.16.0.0/12")
    argv = shlex.split(line)
    assert argv[:3] == ["python", "sg_db.py", "exec"]
    assert sg_db.main(argv[2:]) == 0
    assert ("tcp", 443, "172.16.0.0/12") not in _ingress(ec2, api)
    (e,) = [x for x in _db().log() if x["action"] == "request-proposed"]
    assert e["reason"].startswith("sg_review: remove")


class _Who:
    """Two people: sg_db names the caller from STS, so the tests switch who STS says is calling."""

    def __init__(self, monkeypatch):
        self.arn = "arn:aws:sts::123456789012:assumed-role/Ops/alice@example.com"
        monkeypatch.setattr(sg_db, "account_of", lambda session=None: ("123456789012", self.arn))
        monkeypatch.setattr(sg_db.sg_tightener, "caller_arn", lambda: self.arn)

    def be(self, name):
        self.arn = f"arn:aws:sts::123456789012:assumed-role/Ops/{name}@example.com"


def test_two_person_approval_from_proposal_to_aws(estate, monkeypatch, capsys):
    ec2, db = estate.ec2, estate.groups["db"]
    who = _Who(monkeypatch)
    sg_db.main(["import", "--regions", REGION])
    store = _db()
    with store:
        store.set_approvals(True, "test", "two-person from now on")
    assert sg_db.main(["add", "--region", REGION, "--group", db, "--proto", "tcp", "--port", "5432",
                       "--source", "10.4.1.0/24", "--reason", "app subnet", "--ticket", "CHG-9"]) == 0
    assert "waiting for a second person" in capsys.readouterr().out
    (req,) = store.requests("pending")
    assert sg_db.main(["apply", "--region", REGION, "--yes"]) == 0  # nothing approved: nothing to apply
    assert ("tcp", 5432, "10.4.1.0/24") not in _ingress(ec2, db)
    with pytest.raises(SystemExit, match="a different person must approve"):
        sg_db.main(["approve", str(req["id"])])
    who.be("bob")
    with pytest.raises(SystemExit, match="only .*alice.* can cancel"):
        sg_db.main(["cancel", str(req["id"])])
    assert sg_db.main(["approve", str(req["id"]), "--note", "checked flow logs"]) == 0
    assert sg_db.main(["apply", "--region", REGION, "--yes"]) == 0
    assert ("tcp", 5432, "10.4.1.0/24") in _ingress(ec2, db)
    assert store.requests(rid=req["id"])[0]["status"] == "applied"
    trail = [(e["action"], sg_db.principal(e["actor"]).rsplit("/", 1)[-1]) for e in store.log()]
    assert ("request-proposed", "alice@example.com") in trail and ("request-approved", "bob@example.com") in trail
    assert store.verify()[0]


def test_reject_needs_a_note_and_write_tools_refuse_while_approvals_are_on(estate, monkeypatch):
    ec2, db = estate.ec2, estate.groups["db"]
    _Who(monkeypatch)
    sg_db.main(["import", "--regions", REGION])
    store = _db()
    with store:
        store.set_approvals(True, "test", "on")
    sg_db.main(["remove", "--region", REGION, "--group", db, "--all", "--reason", "decommission"])
    (req,) = store.requests("pending")
    with pytest.raises(SystemExit, match="say why"):
        sg_db.main(["reject", str(req["id"])])
    assert sg_db.main(["reject", str(req["id"]), "--note", "still in use"]) == 0
    assert store.requests(rid=req["id"])[0]["status"] == "rejected"
    with pytest.raises(SystemExit, match="two-person approval is on"):
        sg_db.track(ec2, REGION, "sg_tightener apply")
    sg_db.track(ec2, REGION, "sg_extend", strict=False)  # break-glass is never held for approval


def test_a_plan_becomes_one_change_request(estate, monkeypatch, tmp_path):
    ec2, api = estate.ec2, estate.groups["api"]
    _Who(monkeypatch)
    plan = {"schema": "sg-tightener.plan/v1", "region": REGION, "groups": [{
        "group_id": api,
        "revoke": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}],
        "authorise": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                       "IpRanges": [{"CidrIp": "10.4.0.0/24", "Description": "fitted"}]}]}]}
    (tmp_path / "plan.json").write_text(json.dumps(plan))
    assert sg_db.main(["propose", "--plan", str(tmp_path / "plan.json"), "--reason", "90 days of flow logs"]) == 0
    (req,) = _db().requests()
    assert req["status"] == "approved"  # approvals are off in this test
    assert {(c["op"], c["rule"]["source"]) for c in req["changes"]} == {("remove", "10.0.0.0/8"), ("add", "10.4.0.0/24")}
    sg_db.main(["apply", "--region", REGION, "--yes"])
    assert ("tcp", 443, "10.4.0.0/24") in _ingress(ec2, api) and ("tcp", 443, "10.0.0.0/8") not in _ingress(ec2, api)
