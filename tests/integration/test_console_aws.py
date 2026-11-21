"""sg_console against moto: a change proposed and approved in the console reaches AWS on apply, and
reconcile in the console finds a change made outside the tool."""

from __future__ import annotations

import os

import sg_console
import sg_db
from tests.integration.conftest import REGION


def _ingress(ec2, gid):
    sg = ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]
    return {(p["IpProtocol"], p.get("FromPort"), r["CidrIp"]) for p in sg["IpPermissions"] for r in p.get("IpRanges", [])}


def test_console_propose_approve_apply_and_reconcile(estate, monkeypatch):
    ec2, db = estate.ec2, estate.groups["db"]
    assert sg_db.main(["import", "--regions", REGION]) == 0
    store = sg_db.Store(os.environ["SG_TIGHTENER_DB"])
    with store:
        store.set_approvals(True, "tests", "two people from here")
    account = store.regions()[0][0]
    store.close()

    con = sg_console.Console(os.environ["SG_TIGHTENER_DB"])
    me = con.targets().actor
    rule = {"direction": "in", "proto": "tcp", "from": 5432, "to": 5432, "source": "10.4.9.0/24", "description": "etl"}
    res = con.propose({"account": account, "region": REGION, "reason": "etl reads", "ticket": "CHG-1",
                       "changes": [{"group": db, "op": "add", "rule": rule}]})
    assert res["status"] == "pending"

    other = sg_db.Targets.__new__(sg_db.Targets)
    other.__dict__.update(con.targets().__dict__, actor=f"arn:aws:sts::{account}:assumed-role/Admin/bob")
    con._targets, con._fixed = other, True
    assert con.decide({"id": res["id"], "action": "approve", "note": "fine"})["status"] == "approved"

    chk = con.check({"account": account, "region": REGION})
    assert chk["ok"] and chk["checked"] >= 2 and chk["mode"] == "enforce"
    out = con.apply({"account": account, "region": REGION})
    assert out["done"] == 1 and out["failed"] == [] and out["settled"] == [res["id"]]
    assert ("tcp", 5432, "10.4.9.0/24") in _ingress(ec2, db)

    ec2.authorize_security_group_ingress(GroupId=db, IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                                                     "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    got = con.reconcile({"account": account, "region": REGION, "cloudtrail": False})
    assert len(got["changes"]) == 1 and got["pending"] == 1, "the outside rule is wanted gone"
    assert me != other.actor
    assets = con.assets(account, REGION)
    assert len(assets) == 3 and all(a["groups"] for a in assets)
    assert con.asset_history(estate.enis["10.4.1.20"])[-1]["action"] == "assets-imported"
