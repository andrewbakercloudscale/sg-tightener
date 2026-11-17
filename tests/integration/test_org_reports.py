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
