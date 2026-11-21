"""PrivateLink that is too open, on both sides, against moto's EC2 and ELBv2."""

from __future__ import annotations

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

import sg_ou_report
import sg_review

REGION = "eu-west-1"


@pytest.fixture
def estate(aws):
    ec2, elb = boto3.client("ec2", region_name=REGION), boto3.client("elbv2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]
    sub = ec2.create_subnet(VpcId=vpc, CidrBlock="10.1.1.0/24")["Subnet"]["SubnetId"]
    sg = ec2.create_security_group(GroupName="secrets-endpoint", Description="e", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}])
    lb = elb.create_load_balancer(Name="payments-api", Subnets=[sub], Type="network", Scheme="internal")
    open_svc = ec2.create_vpc_endpoint_service_configuration(
        NetworkLoadBalancerArns=[lb["LoadBalancers"][0]["LoadBalancerArn"]], AcceptanceRequired=False)
    sid = open_svc["ServiceConfiguration"]["ServiceId"]
    ec2.modify_vpc_endpoint_service_permissions(ServiceId=sid, AddAllowedPrincipals=["*"])
    vpce = ec2.create_vpc_endpoint(VpcEndpointType="Interface", VpcId=vpc, SubnetIds=[sub], SecurityGroupIds=[sg],
                                   ServiceName=f"com.amazonaws.{REGION}.secretsmanager")["VpcEndpoint"]["VpcEndpointId"]
    return {"sid": sid, "sg": sg, "vpce": vpce}


def test_ou_report_flags_an_open_endpoint_service_and_names_endpoint_groups(estate):
    found, errors = sg_ou_report._scan_region(boto3.Session(), "123456789012", "a", REGION)
    by = {(f.resource_type, f.severity) for f in found}
    assert ("PrivateLink service", "CRITICAL") in by  # any account, accepted without review
    assert ("PrivateLink NLB", "MEDIUM") in by  # no security group on the load balancer
    ep = [f for f in found if f.resource_type == "SG (PrivateLink endpoint)"]
    assert ep and estate["vpce"] in ep[0].resource_id and ep[0].cidr == "10.0.0.0/8"
    assert not any(f.resource_type == "SG" and f.resource_id == estate["sg"] for f in found)  # not counted twice
    assert not [e for e in errors if not e.get("optional")]


def test_classify_endpoint_service():
    assert sg_ou_report.classify_endpoint_service(["*"], False) == "CRITICAL"
    assert sg_ou_report.classify_endpoint_service(["*"], True) == "HIGH"
    assert sg_ou_report.classify_endpoint_service(["arn:aws:iam::111122223333:root"], False) == "LOW"
    assert sg_ou_report.classify_endpoint_service(["arn:aws:iam::111122223333:root"], True) is None
    assert sg_ou_report.classify_endpoint_service([], False) is None


def test_a_missing_privatelink_permission_does_not_make_an_account_incomplete():
    errs = [{"account_id": "1", "region": REGION, "stage": "privatelink-services", "error": "denied",
             "optional": True}]
    assert sg_ou_report.account_status([{"Id": "1"}], errs) == {"1": "ok"}


def test_sg_review_snapshot_reads_both_sides(estate, monkeypatch):
    from botocore.exceptions import ClientError

    real = sg_review._pages

    def pages(client, op, key, **kw):  # moto has no DescribeVpcEndpointConnections: answer as a refusal would
        if op == "describe_vpc_endpoint_connections":
            raise ClientError({"Error": {"Code": "UnauthorizedOperation", "Message": "no"}}, op)
        return real(client, op, key, **kw)

    monkeypatch.setattr(sg_review, "_pages", pages)
    snap = sg_review.snapshot(boto3.Session(), REGION)
    pl = snap["privatelink"]
    (svc,) = pl["services"]
    assert any("connections to" in e for e in snap["errors"])
    assert svc["id"] == estate["sid"] and svc["principals"] == ["*"] and not svc["acceptance"]
    assert svc["nlbs"][0]["name"] == "payments-api" and svc["nlbs"][0]["groups"] == []
    (ep,) = pl["endpoints"]
    assert ep["id"] == estate["vpce"] and ep["groups"] == [estate["sg"]]
    doc = {"regions": {REGION: {"snapshot": snap}}}
    got = {it["key"]: it for it in sg_review.privatelink_findings(doc, [])}
    assert got["pl-service-anyone"]["sev"] == "critical"
    assert "--acceptance-required" in got["pl-service-anyone"]["cli"]
    assert got["pl-nlb-no-sg"]["sev"] == "medium" and not got["pl-nlb-no-sg"]["cli"]
    assert got["pl-endpoint-open"]["sev"] == "medium" and "10.0.0.0/8" in got["pl-endpoint-open"]["title"]
