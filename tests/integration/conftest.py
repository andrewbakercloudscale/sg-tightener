"""A moto-backed AWS estate for the end-to-end tests.

EC2, S3, STS and Organizations come from moto. Logs Insights is barely
emulated by moto, so ``logs`` clients are a FakeLogs (tests/fixtures) that
answers the queries this project builds from synthetic flow records.
"""

from __future__ import annotations

import dataclasses
import datetime as dt

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

import sg_extend  # noqa: E402
import sg_tightener  # noqa: E402
from tests.fixtures.flowgen import FakeLogs, Talker, Topology, Interface, generate_records  # noqa: E402

REGION = "eu-west-1"
LOG_GROUP = "vpc-flow-logs"


@dataclasses.dataclass
class Estate:
    ec2: object
    vpc_id: str
    groups: dict[str, str]          # name -> group id
    enis: dict[str, str]            # ip -> eni id
    logs: FakeLogs | None = None

    def snapshot(self) -> dict[str, list]:
        """Every group's ingress rules, in a comparable form."""
        out = {}
        for sg in self.ec2.describe_security_groups(GroupIds=list(self.groups.values()))["SecurityGroups"]:
            rules = set()
            for p in sg["IpPermissions"]:
                for r in p.get("IpRanges", []):
                    rules.add((p["IpProtocol"], p.get("FromPort"), p.get("ToPort"),
                               r["CidrIp"], r.get("Description") or None))
            out[sg["GroupId"]] = sorted(rules, key=str)
        return out

    def topology(self, talkers: list[Talker]) -> Topology:
        interfaces = [Interface(eni, ip, []) for ip, eni in self.enis.items()]
        return Topology(REGION, interfaces, [], talkers)


@pytest.fixture
def aws(monkeypatch, tmp_path):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.setenv("SG_TIGHTENER_DB", str(tmp_path / "sg.db"))  # every change lands in a test database
    import sg_db

    store = sg_db.Store(tmp_path / "sg.db")  # one test identity: approvals off unless a test turns them on
    with store:
        store.set_approvals(False, "tests", "the tests act as one person")
    store.close()
    monkeypatch.chdir(tmp_path)  # manifests land here
    with moto.mock_aws():
        yield


def _perm(port, *cidrs, desc="legacy broad rule"):
    return {"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
            "IpRanges": [{"CidrIp": c, "Description": desc} for c in cidrs]}


@pytest.fixture
def estate(aws, monkeypatch):
    """A VPC with a database, two API servers and broad legacy rules."""
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.4.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.4.0.0/20")["Subnet"]["SubnetId"]
    groups = {}
    for name, perms in {
        "db": [_perm(5432, "10.0.0.0/8")],
        "api": [_perm(443, "10.0.0.0/8", "172.16.0.0/12"), _perm(9100, "10.4.0.0/16", desc="")],
    }.items():
        gid = ec2.create_security_group(GroupName=name, Description=name, VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=perms)
        groups[name] = gid
    enis = {}
    for ip, group in {"10.4.1.20": "db", "10.4.2.10": "api", "10.4.2.11": "api"}.items():
        eni = ec2.create_network_interface(SubnetId=subnet, PrivateIpAddress=ip, Groups=[groups[group]])
        enis[ip] = eni["NetworkInterface"]["NetworkInterfaceId"]

    est = Estate(ec2, vpc, groups, enis)

    def fake_client(service, region=None):
        if service == "logs":
            assert est.logs is not None, "test did not set up flow logs"
            return est.logs
        return boto3.client(service, region_name=region or REGION)

    monkeypatch.setattr(sg_tightener, "_client", fake_client)
    monkeypatch.setattr(sg_extend, "_client", fake_client)
    return est


def add_cloudwatch_flow_log(est: Estate, fields: list[str], records: list[dict]) -> None:
    """Register a flow log on the VPC and back the log group with ``records``."""
    fmt = " ".join("${%s}" % f for f in fields)
    est.ec2.create_flow_logs(
        ResourceIds=[est.vpc_id], ResourceType="VPC", TrafficType="ALL",
        LogGroupName=LOG_GROUP, DeliverLogsPermissionArn="arn:aws:iam::123456789012:role/flowlogs",
        LogFormat=fmt,
    )
    est.logs = FakeLogs(records, fields)


def window(hours: int = 48) -> tuple[dt.datetime, dt.datetime]:
    end = dt.datetime.now(dt.timezone.utc).replace(minute=0, second=0, microsecond=0)
    return end - dt.timedelta(hours=hours), end


__all__ = ["Estate", "REGION", "LOG_GROUP", "add_cloudwatch_flow_log", "window", "generate_records"]


@pytest.fixture(autouse=True)
def _moto_gaps(monkeypatch):
    """moto has no DescribeStaleSecurityGroups: answer as an account with no stale references would."""
    import sg_review

    real = sg_review._pages

    def pages(client, op, key, **kw):
        if op == "describe_stale_security_groups":
            return []
        return real(client, op, key, **kw)

    monkeypatch.setattr(sg_review, "_pages", pages)
