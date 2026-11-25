"""sg_profile: the account at a glance, against stand-ins for Cost Explorer, EC2, RDS, S3 and CloudWatch."""

from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

pytest.importorskip("botocore")
from botocore.exceptions import ClientError  # noqa: E402

import sg_profile  # noqa: E402


class _CE:
    def __init__(self):
        self.calls = []

    def get_cost_and_usage(self, **kw):
        self.calls.append(kw)
        if "GroupBy" in kw:
            groups = [{"Keys": [f"svc{i}"], "Metrics": {"UnblendedCost": {"Amount": str(100 - i)}}} for i in range(12)]
            groups.append({"Keys": ["dust"], "Metrics": {"UnblendedCost": {"Amount": "0.001"}}})
            return {"ResultsByTime": [{"Groups": groups}]}
        return {"ResultsByTime": [{"Total": {"UnblendedCost": {"Amount": "42.5"}}}]}


def test_last_month_spend_its_top_ten_services_and_this_month_so_far():
    ce = _CE()
    got = sg_profile.costs(ce, "111122223333", date(2026, 11, 25))
    assert got["month"] == "2026-10" and got["this_month"] == 42.5
    assert ce.calls[0]["TimePeriod"] == {"Start": "2026-10-01", "End": "2026-11-01"}
    assert ce.calls[0]["Filter"]["And"][0] == {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": ["111122223333"]}}
    assert [t["service"] for t in got["top"]] == [f"svc{i}" for i in range(10)]
    assert got["total"] == round(sum(100 - i for i in range(12)) + 0.001, 2)
    assert sg_profile.last_month(date(2026, 1, 3)) == ("2025-12-01", "2026-01-01")


class _Pager:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **_k):
        return iter(self.pages)


class _Client:
    def __init__(self, pages=None, fail=()):
        self.pages, self.fail = pages or {}, fail

    def get_paginator(self, op):
        if op in self.fail:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, op)
        return _Pager(self.pages.get(op, [{}]))


class _Sess:
    def __init__(self, deny_rds_in=""):
        self.deny = deny_rds_in

    def client(self, svc, region_name=None, config=None):
        if svc == "ec2":
            return _Client({"describe_instances": [{"Reservations": [{"Instances": [
                {"State": {"Name": "running"}}, {"State": {"Name": "stopped"}}, {"State": {"Name": "terminated"}}]}]}],
                "describe_vpc_endpoints": [{"VpcEndpoints": [{"VpcEndpointType": "Interface"},
                                                             {"VpcEndpointType": "Gateway"}]}],
                "describe_vpcs": [{"Vpcs": [{}]}]})  # fmt: skip
        if svc == "rds":
            return _Client({"describe_db_instances": [{"DBInstances": [{}, {}]}]},
                           fail=("describe_db_instances",) if region_name == self.deny else ())  # fmt: skip
        if svc == "s3":
            return _S3()
        if svc == "cloudwatch":
            return _CW()
        return _Client()


class _S3:
    def list_buckets(self, **_k):
        return {"Buckets": [{"Name": "a", "BucketRegion": "af-south-1"}, {"Name": "b"}]}

    def get_bucket_location(self, Bucket):
        return {"LocationConstraint": "EU"}


class _CW:
    def get_metric_data(self, MetricDataQueries, **_k):
        out = []
        for q in MetricDataQueries:
            m = q["MetricStat"]["Metric"]
            st = m["Dimensions"][1]["Value"]
            v = 1000.0 if st in ("StandardStorage", "GlacierStorage") else 7.0 if st == "AllStorageTypes" else None
            out.append({"Id": q["Id"], "Values": [v, 1.0] if v is not None else []})
        return {"MetricDataResults": out}


def test_a_refused_part_is_not_known_where_refused_never_zero():
    prof = sg_profile.read(_Sess(deny_rds_in="eu-west-1"), "111122223333", ["af-south-1", "eu-west-1"], _CE())
    t = prof["totals"]
    assert t["ec2"]["n"] == 4 and t["ec2_running"]["n"] == 2, "terminated instances are left out"
    assert t["rds"]["n"] == 2 and t["rds"]["missing"] == ["eu-west-1: AccessDenied"]
    assert t["privatelink"]["n"] == 2 and t["gateway_endpoints"]["n"] == 2 and t["vpcs"]["n"] == 2
    s3 = prof["s3"]
    assert s3["buckets"] == 2 and s3["regions"] == {"af-south-1": 1, "eu-west-1": 1}, "EU is eu-west-1"
    assert s3["bytes"] == 4000 and s3["objects"] == 14, "newest value of every storage type, both buckets"
    assert prof["spend"]["total"] > 0


def test_the_profile_is_kept_and_read_back(monkeypatch):
    saved = {}

    class F:
        def __init__(self, key):
            self.key = key

        def write_text(self, t):
            saved[self.key] = t

        def read_text(self):
            if self.key not in saved:
                raise FileNotFoundError(self.key)
            return saved[self.key]

    monkeypatch.setattr(sg_profile, "_file", lambda a: F(a))
    assert sg_profile.cached("111122223333") is None
    sg_profile.save("111122223333", {"at": datetime(2026, 11, 25, tzinfo=timezone.utc).timestamp()})
    assert sg_profile.cached("111122223333")["at"] > 0
