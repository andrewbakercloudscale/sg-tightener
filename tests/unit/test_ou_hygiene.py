"""sg_ou_report: wide IPv6 ranges, and rules trusting another account's group (moto cannot hold those)."""

import sg_ou_report
from sg_ou_report import Finding, classify_sg_rule, scan_reach_and_hygiene


class _Pager:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **_):
        return self.pages


class FakeEC2:
    def __init__(self, enis=(), tables=()):
        self.data = {"describe_network_interfaces": [{"NetworkInterfaces": list(enis)}],
                     "describe_route_tables": [{"RouteTables": list(tables)}]}

    def get_paginator(self, op):
        return _Pager(self.data[op])


def test_wide_global_ipv6_is_rated_but_ula_and_narrow_are_not():
    assert classify_sg_rule("2c0f:fb50::/32", 22, 22) == "HIGH"
    assert classify_sg_rule("2c0f:fb50::/32", 8080, 8080) == "MEDIUM"
    assert classify_sg_rule("2c0f:fb50::/48", 22, 22) is None
    assert classify_sg_rule("fd00::/8", 22, 22) is None
    assert classify_sg_rule("::/0", 22, 22) == "CRITICAL"


def test_cross_account_reference_and_main_table_routing():
    sg = {"GroupId": "sg-1", "GroupName": "db", "OwnerId": "111", "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
         "UserIdGroupPairs": [{"GroupId": "sg-x", "UserId": "222"}, {"GroupId": "sg-y", "UserId": "111"}]}]}
    open_ = Finding("111", "a", "eu-west-1", "SG", "sg-2", "0.0.0.0/0", "22", "CRITICAL")
    enis = [{"Groups": [{"GroupId": "sg-2"}], "SubnetId": "subnet-nomap", "VpcId": "vpc-1",
             "Association": {"PublicIp": "1.2.3.4"}}]
    tables = [{"VpcId": "vpc-1", "Routes": [{"GatewayId": "igw-1", "DestinationCidrBlock": "0.0.0.0/0"}],
               "Associations": [{"Main": True}]}]
    out, errors = scan_reach_and_hygiene(FakeEC2(enis, tables), [sg], [open_], "111", "a", "eu-west-1")
    assert errors == []
    assert [(f.resource_type, f.cidr, f.severity) for f in out] == [
        ("SG (cross-account reference)", "sg-x (account 222)", "MEDIUM")]
    assert open_.note.startswith("reachable from the internet")  # via the VPC's main route table


def test_unreadable_reachability_is_an_optional_error():
    class Broken:
        def get_paginator(self, op):
            raise RuntimeError("UnauthorizedOperation")

    out, errors = scan_reach_and_hygiene(Broken(), [], [], "111", "a", "eu-west-1")
    assert out == [] and errors[0]["optional"] is True
    assert sg_ou_report.account_status([{"Id": "111"}], errors) == {"111": "ok"}
