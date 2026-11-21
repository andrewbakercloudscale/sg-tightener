"""sg_ou_report across two moto accounts in an organization."""

from __future__ import annotations

import json

import boto3
import pytest

import sg_ou_report

REGION = "eu-west-1"


@pytest.fixture
def org(aws):
    orgs = boto3.client("organizations", region_name="us-east-1")
    orgs.create_organization(FeatureSet="ALL")
    ids = []
    for name in ("payments-prod", "payments-dev"):
        status = orgs.create_account(AccountName=name, Email=f"{name}@example.com")["CreateAccountStatus"]
        ids.append(status["AccountId"])
    return ids


def _session_for(account_id):
    # moto ties assumed-role credentials to the account in the role ARN.
    return sg_ou_report._assume(f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole", "test")


def _open_rule(account_id, port, cidr):
    ec2 = _session_for(account_id).client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    gid = ec2.create_security_group(GroupName=f"g{port}", Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "IpRanges": [{"CidrIp": cidr}]}])


def test_findings_are_attributed_per_account_and_critical_fails_the_run(org, monkeypatch, tmp_path):
    prod, dev = org
    _open_rule(prod, 22, "0.0.0.0/0")      # SSH open to the world
    _open_rule(dev, 443, "10.0.0.0/8")

    out = tmp_path / "report.json"
    rc = sg_ou_report.main(["--regions", REGION, "--accounts", f"{prod},{dev}",
                            "--json", str(out), "--out", str(tmp_path / "r.xlsx")])
    report = json.loads(out.read_text())
    sg = {(f["account_id"], f["cidr"], f["severity"]) for f in report["findings"] if f["resource_type"] == "SG"}
    assert (prod, "0.0.0.0/0", "CRITICAL") in sg
    assert (dev, "10.0.0.0/8", "HIGH") in sg            # broad private rule: the tool's target
    assert not any(a == dev and s == "CRITICAL" for a, _c, s in sg)
    summary = {r["account_id"]: r for r in report["summary"]}
    assert summary[prod]["risk_score"] > summary[dev]["risk_score"]
    assert rc == 1


def test_lists_accounts_from_the_organization(org):
    listed = {a["Id"] for a in sg_ou_report._list_org_accounts(None)}
    assert set(org) <= listed


def test_an_account_that_cannot_be_scanned_is_reported_and_fails_the_gate(org, monkeypatch, tmp_path):
    prod, dev = org
    _open_rule(prod, 443, "10.0.0.0/8")
    real = sg_ou_report._assume

    def assume(role_arn, name):
        if dev in role_arn:
            raise RuntimeError("AccessDenied")
        return real(role_arn, name)

    monkeypatch.setattr(sg_ou_report, "_assume", assume)
    out = tmp_path / "report.json"
    rc = sg_ou_report.main(["--regions", REGION, "--accounts", f"{prod},{dev}",
                            "--json", str(out), "--out", str(tmp_path / "r.xlsx")])
    report = json.loads(out.read_text())
    status = {r["account_id"]: r["scan_status"] for r in report["summary"]}
    assert status == {prod: "ok", dev: "failed"}
    assert report["complete"] is False and report["errors"][0]["stage"] == "assume-role"
    assert rc == 2


def test_ipv6_open_rule_is_critical(org, tmp_path):
    prod, dev = org
    ec2 = _session_for(prod).client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    gid = ec2.create_security_group(GroupName="v6", Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
    out = tmp_path / "report.json"
    rc = sg_ou_report.main(["--regions", REGION, "--accounts", prod,
                            "--json", str(out), "--out", str(tmp_path / "r.xlsx")])
    report = json.loads(out.read_text())
    assert any(f["cidr"] == "::/0" and f["severity"] == "CRITICAL" for f in report["findings"])
    assert rc == 1


def test_reachability_note_wide_ipv6_and_default_group(org, tmp_path):
    prod, _dev = org
    ec2 = _session_for(prod).client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    pub = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    priv = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.2.0/24")["Subnet"]["SubnetId"]
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    rtb = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    ec2.associate_route_table(RouteTableId=rtb, SubnetId=pub)

    def group(name, **perm):
        gid = ec2.create_security_group(GroupName=name, Description="d", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, **perm}])
        return gid

    exposed = group("exposed", IpRanges=[{"CidrIp": "0.0.0.0/0"}])
    hidden = group("hidden", IpRanges=[{"CidrIp": "0.0.0.0/0"}])
    group("widev6", Ipv6Ranges=[{"CidrIpv6": "2c0f:fb50::/32"}])
    eni = ec2.create_network_interface(SubnetId=pub, Groups=[exposed])["NetworkInterface"]["NetworkInterfaceId"]
    alloc = ec2.allocate_address(Domain="vpc")["AllocationId"]
    ec2.associate_address(AllocationId=alloc, NetworkInterfaceId=eni)
    ec2.create_network_interface(SubnetId=priv, Groups=[hidden])
    default = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc]},
                                                    {"Name": "group-name", "Values": ["default"]}])
    dflt = default["SecurityGroups"][0]["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=dflt, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}])
    ec2.create_network_interface(SubnetId=priv, Groups=[dflt])

    out = tmp_path / "report.json"
    sg_ou_report.main(["--regions", REGION, "--accounts", prod, "--json", str(out), "--out", str(tmp_path / "r.xlsx")])
    report = json.loads(out.read_text())
    by = {(f["resource_type"], f["resource_id"], f["cidr"]): f for f in report["findings"]}
    assert by[("SG", exposed, "0.0.0.0/0")]["note"].startswith("reachable from the internet: 1 of 1")
    assert by[("SG", hidden, "0.0.0.0/0")]["note"].startswith("not reachable today")
    assert any(f["cidr"] == "2c0f:fb50::/32" and f["severity"] == "HIGH" for f in report["findings"])
    assert ("SG (default, in use)", dflt, "default group") in by
