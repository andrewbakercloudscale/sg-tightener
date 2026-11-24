"""sg_review read against moto's EC2 (real API shapes), with stand-ins for Logs Insights and CloudTrail."""

from __future__ import annotations

import time

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

import sg_ipintel  # noqa: E402
import sg_review  # noqa: E402

REGION = "eu-west-1"


class _Logs:
    """Answers the detail query with one accepted and one refused private connection, the public query with
    one refused internet source."""

    def __init__(self, dst, eni):
        self.dst, self.eni, self.q = dst, eni, {}

    def start_query(self, **kw):
        qid = f"q{len(self.q)}"
        self.q[qid] = kw["queryString"]
        return {"queryId": qid}

    def get_query_results(self, queryId):
        if "sum(f_bytes)" in self.q[queryId]:
            rows = [("10.1.2.3", "ACCEPT"), ("10.9.9.9", "REJECT")]
            res = [[{"field": "src", "value": s}, {"field": "dst", "value": self.dst},
                    {"field": "eni", "value": self.eni}, {"field": "proto", "value": "6"},
                    {"field": "dport", "value": "5432"}, {"field": "action", "value": a},
                    {"field": "flows", "value": "4"}] for s, a in rows]  # fmt: skip
        else:
            res = [[{"field": "src", "value": "198.51.100.9"}, {"field": "flows", "value": "2"},
                    {"field": "ports", "value": "1"}, {"field": "dsts", "value": "1"},
                    {"field": "dst", "value": self.dst}, {"field": "eni", "value": self.eni},
                    {"field": "port", "value": "22"}, {"field": "proto", "value": "6"}]]  # fmt: skip
        return {"status": "Complete", "statistics": {"bytesScanned": 5000.0}, "results": res}


class _CloudTrail:
    """moto has no LookupEvents: no rule changes in the window."""

    def lookup_events(self, **kw):
        return {"Events": []}


class _Session:
    def __init__(self, real, logs):
        self.real, self.logs = real, logs

    def client(self, name, **kw):
        if name == "logs":
            return self.logs
        if name == "cloudtrail":
            return _CloudTrail()
        return self.real.client(name, **kw)


@pytest.fixture
def estate(monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    old = sg_ipintel.DATA_DIR
    sg_ipintel.set_data_dir(tmp_path)
    with moto.mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]
        sub = ec2.create_subnet(VpcId=vpc, CidrBlock="10.1.2.0/24")["Subnet"]["SubnetId"]
        sg = ec2.create_security_group(GroupName="db", Description="db", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}])
        eni = ec2.create_network_interface(SubnetId=sub, Groups=[sg], PrivateIpAddress="10.1.2.50")
        eni_id = eni["NetworkInterface"]["NetworkInterfaceId"]
        ec2.create_flow_logs(ResourceIds=[vpc], ResourceType="VPC", TrafficType="ALL", LogGroupName="vpc-flow-logs",
                             DeliverLogsPermissionArn="arn:aws:iam::123456789012:role/fl")  # fmt: skip
        yield _Session(boto3.Session(region_name=REGION), _Logs("10.1.2.50", eni_id)), sg
    sg_ipintel.set_data_dir(old)


def test_read_then_report(estate):
    sess, sg = estate
    doc = sg_review.new_doc("123456789012", "test")
    now = time.time()
    tasks = sg_review.plan_read(sess, doc, [REGION], 1, now)
    snap = doc["regions"][REGION]["snapshot"]
    assert snap["groups"][sg]["rules"][0]["cidrs"] == ["10.0.0.0/8"]
    assert doc["regions"][REGION]["query_sets"] == [{"format": sg_review.DEFAULT_FORMAT, "groups": ["vpc-flow-logs"]}]
    assert len(tasks) >= 24
    state = sg_review.run_read(sess, doc, tasks, 1, now)
    assert state["done"] == len(tasks) and state["bytes"] > 0
    rep = sg_review.build(doc, "24h")
    rule = next(r for r in rep["rules"] if r["group"] == sg)
    assert rule["here"] == 1 and rule["status"] == "tighten"  # one day of evidence is acted on (owner's decision)
    assert {x["src"] for x in rep["refused"]} == {"10.9.9.9", "198.51.100.9"}
    assert sg_review.approved(doc, REGION)["ips"] == ["10.1.2.3"]
