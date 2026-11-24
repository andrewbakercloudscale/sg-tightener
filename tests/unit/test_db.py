"""sg_db: the security group database, its desired/synced model and the hash-chained audit trail."""

from __future__ import annotations

import psycopg
import pytest

import sg_db
from sg_db import IN, OUT, Refused, Store

ACCT, REGION = "111122223333", "eu-west-1"
SSH_WORLD = (IN, "tcp", 22, 22, "0.0.0.0/0")
HTTPS_VPC = (IN, "tcp", 443, 443, "10.0.0.0/16")
ALL_OUT = (OUT, "-1", -1, -1, "0.0.0.0/0")


def group(rules, name="web", vpc="vpc-1"):
    return {"name": name, "vpc": vpc, "description": name, "rules": dict(rules)}


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "sg.db")
    with s:
        s.import_region(ACCT, REGION, {"sg-1": group({HTTPS_VPC: "vpc https", ALL_OUT: ""})}, "alice")
    yield s
    s.close()


def test_import_takes_every_rule_as_desired_and_synced(store):
    assert store.imported(ACCT, REGION)
    assert store.rules(ACCT, REGION, "sg-1", "desired") == store.rules(ACCT, REGION, "sg-1", "synced")
    assert store.pending(ACCT, REGION) == []
    with store, pytest.raises(Refused):
        store.import_region(ACCT, REGION, {}, "alice")


def test_each_location_is_its_own_database(tmp_path):
    a, b = Store(tmp_path / "a" / "sg.db"), Store(tmp_path / "b" / "sg.db")
    with a:
        a.import_region(ACCT, REGION, {"sg-1": group({HTTPS_VPC: ""})}, "alice")
    assert a.imported(ACCT, REGION) and not b.imported(ACCT, REGION)
    assert Store(tmp_path / "a" / "sg.db").imported(ACCT, REGION)  # the same location is the same data
    a.close()
    b.close()


def test_external_rule_is_recorded_and_apply_would_put_it_back(store):
    live = {"sg-1": group({HTTPS_VPC: "vpc https", ALL_OUT: "", SSH_WORLD: "temp"})}
    with store:
        ch = store.observe(ACCT, REGION, live, "reconciler", who=lambda g: "bob (console)")
    assert len(ch) == 1 and ch[0]["change"] == "rules changed" and ch[0]["changed_by"] == "bob (console)"
    assert store.pending(ACCT, REGION) == [("sg-1", "remove", SSH_WORLD, "temp")]
    last = store.log()[-1]
    assert (last["origin"], last["action"]) == ("external", "rules-changed")
    # seen once: reading AWS again records nothing new
    with store:
        assert store.observe(ACCT, REGION, live, "reconciler") == []


def test_adopt_keeps_the_external_change(store):
    live = {"sg-1": group({HTTPS_VPC: "vpc https", ALL_OUT: "", SSH_WORLD: ""})}
    with store:
        store.observe(ACCT, REGION, live, "r")
        with pytest.raises(Refused):
            store.adopt(ACCT, REGION, "carol", "")
        assert store.adopt(ACCT, REGION, "carol", "approved in CHG-9") == 1
    assert store.pending(ACCT, REGION) == []


def test_groups_created_and_deleted_outside(store):
    live = {"sg-2": group({}, name="new")}
    with store:
        ch = store.observe(ACCT, REGION, live, "r")
    assert {c["change"] for c in ch} == {"group created", "group deleted"}
    assert list(store.groups(ACCT, REGION)) == ["sg-2"]


def test_desire_needs_a_reason_and_a_known_group(store):
    with store:
        with pytest.raises(Refused):
            store.desire(ACCT, REGION, "sg-1", "alice", "  ", add={SSH_WORLD: ""})
        with pytest.raises(Refused):
            store.desire(ACCT, REGION, "sg-9", "alice", "why", add={SSH_WORLD: ""})
        d = store.desire(ACCT, REGION, "sg-1", "alice", "least privilege", "CHG-1", remove=[HTTPS_VPC],
                         add={(IN, "tcp", 443, 443, "10.0.1.0/24"): "api"})
    assert len(d["added"]) == 1 and len(d["removed"]) == 1
    assert [(op, r) for _, op, r, _ in store.pending(ACCT, REGION)] == [
        ("remove", HTTPS_VPC), ("add", (IN, "tcp", 443, 443, "10.0.1.0/24"))]
    assert store.log()[-1]["ticket"] == "CHG-1"


def test_failed_transaction_leaves_no_trace(store):
    before = len(store.log())
    with pytest.raises(RuntimeError), store:
        store.desire(ACCT, REGION, "sg-1", "alice", "why", add={SSH_WORLD: ""})
        raise RuntimeError("boom")
    assert len(store.log()) == before and store.pending(ACCT, REGION) == []


def test_audit_trail_is_append_only_and_hash_chained(store, tmp_path):
    with store:
        store.desire(ACCT, REGION, "sg-1", "alice", "why", add={SSH_WORLD: ""})
    assert store.verify() == (True, 2, "")
    for sql in ("UPDATE audit SET actor = 'mallory'", "DELETE FROM audit WHERE seq = 1"):
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            store.db.execute(sql)
    # someone who drops the trigger to edit an entry is still caught by the chain
    store.db.execute("DROP TRIGGER audit_append_only_u ON audit")
    store.db.execute("UPDATE audit SET reason = 'nothing to see' WHERE seq = 2")
    ok, _, why = store.verify()
    assert not ok and "changed after it was written" in why


def test_removed_entry_breaks_the_chain(store):
    with store:
        store.desire(ACCT, REGION, "sg-1", "alice", "one", add={SSH_WORLD: ""})
        store.desire(ACCT, REGION, "sg-1", "alice", "two", remove=[SSH_WORLD])
    store.db.execute("DROP TRIGGER audit_append_only_d ON audit")
    store.db.execute("DELETE FROM audit WHERE seq = 2")
    ok, _, why = store.verify()
    assert not ok and "removed or reordered" in why


def test_rules_from_permissions_covers_every_source_kind():
    perms = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
              "IpRanges": [{"CidrIp": "10.0.0.0/8", "Description": "ops"}],
              "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
              "PrefixListIds": [{"PrefixListId": "pl-1"}],
              "UserIdGroupPairs": [{"GroupId": "sg-a", "UserId": ACCT}, {"GroupId": "sg-b", "UserId": "999"}]},
             {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    rules = sg_db.rules_from_permissions(perms, IN, ACCT)
    assert set(rules) == {(IN, "tcp", 22, 22, s) for s in ("10.0.0.0/8", "::/0", "pl-1", "sg-a", "999/sg-b")} | {
        (IN, "-1", -1, -1, "0.0.0.0/0")}
    assert rules[(IN, "tcp", 22, 22, "10.0.0.0/8")] == "ops"
    # and back again
    assert sg_db.to_permission((IN, "tcp", 22, 22, "999/sg-b")) == {
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "UserIdGroupPairs": [{"GroupId": "sg-b", "UserId": "999"}]}
    assert "FromPort" not in sg_db.to_permission(ALL_OUT)


@pytest.mark.parametrize("argv, want", [
    (["aws", "ec2", "revoke-security-group-ingress", "--region", "eu-west-1", "--group-id", "sg-1",
      "--ip-permissions", "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0},{CidrIp=10.0.0.0/8}]"],
     ("revoke", IN, "eu-west-1", {(IN, "tcp", 22, 22, "0.0.0.0/0"), (IN, "tcp", 22, 22, "10.0.0.0/8")})),
    (["authorize-security-group-egress", "--group-id", "sg-1", "--ip-permissions",
      '[{"IpProtocol":"tcp","FromPort":443,"ToPort":443,"IpRanges":[{"CidrIp":"52.1.0.0/16"}]}]'],
     ("authorize", OUT, "", {(OUT, "tcp", 443, 443, "52.1.0.0/16")})),
    (["aws", "ec2", "authorize-security-group-ingress", "--group-id", "sg-1", "--protocol", "tcp",
      "--port", "8000-8100", "--cidr", "10.1.0.0/16"],
     ("authorize", IN, "", {(IN, "tcp", 8000, 8100, "10.1.0.0/16")})),
])
def test_parse_command(argv, want):
    c = sg_db.parse_command(argv)
    assert (c["verb"], c["direction"], c["region"], set(sg_db.rules_from_permissions(c["perms"], c["direction"]))) == want


def test_parse_command_rule_ids_and_refusals():
    c = sg_db.parse_command(["aws", "ec2", "revoke-security-group-ingress", "--group-id", "sg-1",
                             "--security-group-rule-ids", "sgr-1", "sgr-2"])
    assert c["rule_ids"] == ["sgr-1", "sgr-2"] and c["perms"] == []
    for bad in (["aws", "ec2", "delete-security-group", "--group-id", "sg-1"],
                ["revoke-security-group-ingress", "--group-id", "sg-1"],
                ["revoke-security-group-ingress", "--protocol", "tcp", "--port", "22", "--cidr", "1.2.3.4/32"]):
        with pytest.raises(ValueError):
            sg_db.parse_command(bad)
