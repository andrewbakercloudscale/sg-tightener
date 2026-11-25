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


def test_apply_previews_its_impact_then_a_refused_source_is_fixed_end_to_end(estate, monkeypatch):
    """Tighten the database's 10.0.0.0/8 to one subnet: the preview names the group, its interface, the request and
    the source the flow logs saw that it cuts off; apply makes exactly that in AWS. That source's Fix then finds
    the change that cut it off, recommends putting it back on the same group for it alone, and once proposed and
    applied AWS lets it in again."""
    ec2, db = estate.ec2, estate.groups["db"]
    assert sg_db.main(["import", "--regions", REGION]) == 0
    store = sg_db.Store(os.environ["SG_TIGHTENER_DB"])
    account = store.regions()[0][0]
    store.close()
    con = sg_console.Console(os.environ["SG_TIGHTENER_DB"])
    con.assets(account, REGION)  # interfaces were read with the import
    old = {"direction": "in", "proto": "tcp", "from": 5432, "to": 5432, "source": "10.0.0.0/8"}
    new = {**old, "source": "10.4.2.0/24", "description": "api subnet"}
    req = con.propose({"account": account, "region": REGION, "reason": "only the API subnet", "ticket": "CHG-5",
                       "changes": [{"group": db, "op": "remove", "rule": old}, {"group": db, "op": "add", "rule": new}]})
    assert req["status"] == "approved"  # approvals are off in these tests
    monkeypatch.setattr(con, "verdicts", lambda a, r="": {"rules": [
        {"key": f"{REGION}|{db}|tcp|5432|5432|10.0.0.0/8", "top": ["10.4.2.10", "10.7.0.5"], "seen": 2, "days": 30,
         "action": "tighten"}]})

    p = con.apply_preview({"account": account, "region": REGION})
    assert p["summary"]["add"] == 1 and p["summary"]["remove"] == 1 and p["summary"]["interfaces"] == 1
    rm = next(c for c in p["changes"] if c["op"] == "remove")
    assert rm["requests"][0]["id"] == req["id"] and rm["evidence"]["lost"] == ["10.7.0.5"]
    assert ("tcp", 5432, "10.0.0.0/8") in _ingress(ec2, db), "a preview changes nothing"

    out = con.apply({"account": account, "region": REGION})
    assert out["done"] == 2 and out["settled"] == [req["id"]]
    assert ("tcp", 5432, "10.4.2.0/24") in _ingress(ec2, db) and ("tcp", 5432, "10.0.0.0/8") not in _ingress(ec2, db)

    db_eni = estate.enis["10.4.1.20"]
    f = con.fix_refused({"account": account, "region": REGION, "eni": db_eni, "src": "10.7.0.5", "proto": "6",
                         "port": 5432, "internal": True})
    assert f["broken_by"] and f["broken_by"][0]["requests"][0] == {**f["broken_by"][0]["requests"][0], "id": req["id"],
                                                                    "ticket": "CHG-5"}, "names the request that cut it off"
    assert f["recommend"] == {**f["recommend"], "kind": "add", "group": db}
    assert f["rule"]["source"] == "10.7.0.5/32"
    fix = con.propose({"account": account, "region": REGION, "reason": "the reporting host still needs it",
                       "changes": [{"group": f["recommend"]["group"], "op": "add", "rule": f["rule"]}]})
    assert con.apply_preview({"account": account, "region": REGION})["changes"][0]["requests"][0]["id"] == fix["id"]
    con.apply({"account": account, "region": REGION})
    assert ("tcp", 5432, "10.7.0.5/32") in _ingress(ec2, db)
    assert con.fix_refused({"account": account, "region": REGION, "eni": db_eni, "src": "10.7.0.5", "proto": "6",
                            "port": 5432})["recommend"]["kind"] == "done"
