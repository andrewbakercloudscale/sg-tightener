"""IPv6 against moto's EC2: sg_review reads the VPC's IPv6 block and each interface's IPv6 addresses, and plan
narrows a unique local IPv6 rule to the /64s seen, leaving ::/0 alone; apply and revert round-trip it."""

from __future__ import annotations

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

import sg_review
import sg_tightener
from tests.integration.conftest import REGION


def _v6_rules(ec2, gid: str) -> set:
    sg = ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]
    return {(p["IpProtocol"], p.get("FromPort"), r["CidrIpv6"], r.get("Description")) for p in sg["IpPermissions"]
            for r in p.get("Ipv6Ranges", [])}


@pytest.fixture
def v6estate(estate):
    ec2 = estate.ec2
    assoc = ec2.associate_vpc_cidr_block(VpcId=estate.vpc_id, AmazonProvidedIpv6CidrBlock=True)
    block = assoc["Ipv6CidrBlockAssociation"]["Ipv6CidrBlock"]
    gid = estate.groups["db"]
    ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
         "Ipv6Ranges": [{"CidrIpv6": "fd00::/16", "Description": "data centre ULA"}]},
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
    eni = estate.enis["10.4.1.20"]
    subnet = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni])["NetworkInterfaces"][0]["SubnetId"]
    ec2.associate_subnet_cidr_block(SubnetId=subnet, Ipv6CidrBlock=block.replace("::/56", "::/64"))
    addr = ec2.assign_ipv6_addresses(NetworkInterfaceId=eni, Ipv6AddressCount=1)["AssignedIpv6Addresses"][0]
    return estate, block, gid, eni, addr


def test_review_snapshot_reads_vpc_and_interface_ipv6(v6estate):
    est, block, gid, eni, addr = v6estate
    snap = sg_review.snapshot(boto3.Session(region_name=REGION), REGION)
    vpc = next(v for v in snap["vpcs"] if v["id"] == est.vpc_id)
    assert vpc["cidrs6"] == [block]
    assert addr in snap["enis"][eni]["ipv6"]
    assert block in sg_review._vpc_ranges(snap)
    assert {c for r in snap["groups"][gid]["rules"] for c in r["cidrs6"]} == {"fd00::/16", "::/0"}


def test_plan_narrows_a_ula_rule_to_the_64s_seen_and_round_trips(v6estate):
    est, _block, gid, eni, addr = v6estate
    srcs = ["fd00:1:2:3::10", "fd00:1:2:3::11", "fd00:1:2:9::5"]
    approved = {"schema": sg_tightener.APPROVED_SCHEMA_V2, "ips": srcs + ["10.9.0.1"],
                "flow_log_check": {"resources": [est.vpc_id]},
                "flows": [{"src": s, "dst": addr, "dstport": 5432, "protocol": "6", "interface": eni} for s in srcs]
                + [{"src": "10.9.0.1", "dst": "10.4.1.20", "dstport": 5432, "protocol": "6", "interface": eni}]}
    plan = sg_tightener.plan_from_approved(approved, REGION)
    g = next(x for x in plan["groups"] if x["group_id"] == gid)
    revoked6 = {r["CidrIpv6"] for p in g["revoke"] for r in p.get("Ipv6Ranges", [])}
    granted6 = {r["CidrIpv6"] for p in g["authorise"] for r in p.get("Ipv6Ranges", [])}
    assert revoked6 == {"fd00::/16"}  # ::/0 is out of scope, as 0.0.0.0/0 is
    assert granted6 == {"fd00:1:2:3::/64", "fd00:1:2:9::/64"}
    before = _v6_rules(est.ec2, gid)
    sg_tightener.apply_plan(plan, REGION, manifest_path="manifest.json")
    after = {c for _p, _f, c, _d in _v6_rules(est.ec2, gid)}
    assert after == {"::/0", "fd00:1:2:3::/64", "fd00:1:2:9::/64"}
    sg_tightener.revert_from_manifest("manifest.json")
    assert _v6_rules(est.ec2, gid) == before  # descriptions included
