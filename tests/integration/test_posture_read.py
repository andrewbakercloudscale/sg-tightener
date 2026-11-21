"""What the exposure and hygiene checks read, against moto: route tables, IPv6 rules and addresses, outbound
rules and cross-account references."""

from __future__ import annotations

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

import sg_review

REGION = "eu-west-1"


def test_snapshot_reads_what_exposure_and_hygiene_need(aws):
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.1.0.0/16", AmazonProvidedIpv6CidrBlock=True)["Vpc"]["VpcId"]
    sub = ec2.create_subnet(VpcId=vpc, CidrBlock="10.1.1.0/24")["Subnet"]["SubnetId"]
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    rtb = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    ec2.associate_route_table(RouteTableId=rtb, SubnetId=sub)
    sg = ec2.create_security_group(GroupName="sftp", Description="s", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
         "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
    ec2.create_network_interface(SubnetId=sub, Groups=[sg])

    snap = sg_review.snapshot(boto3.Session(), REGION)
    assert snap["routes"]["read"] and snap["routes"]["subnets"][sub]["igw4"]
    g = snap["groups"][sg]
    (r,) = g["rules"]
    assert r["cidrs"] == ["0.0.0.0/0"] and r["cidrs6"] == ["::/0"] and r["any6"]
    assert any(e["proto"] == "-1" and "0.0.0.0/0" in e["cidrs"] for e in g["egress"])
    assert g["owner"] and snap["stale"] == []
    assert all("ipv6" in e for e in snap["enis"].values())
    doc = {"account": g["owner"], "regions": {REGION: {"snapshot": snap}}}
    found = {(i["key"], i["sev"]) for i in sg_review.posture_findings(doc)}
    assert ("latent-open", "low") in found  # open to the world, but the interface has no public address
