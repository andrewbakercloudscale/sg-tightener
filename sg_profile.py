"""One account at a glance: last month's spend and its ten biggest services, and what runs in it (EC2, RDS, S3
buckets and their size, PrivateLink endpoints, load balancers, Lambda, EKS). Read only: every call is a
Describe, List or Get. Kept a day in the database; the page can read it again.

Each part is read on its own, so one refused permission or one unreachable region costs that number only:
it shows as not known, with why, never as zero."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone

import sg_ipintel
import sg_store

KEEP = 86400  # a profile is read again after a day
S3_TYPES = ("StandardStorage", "IntelligentTieringFAStorage", "IntelligentTieringIAStorage",
            "IntelligentTieringAIAStorage", "StandardIAStorage", "OneZoneIAStorage", "ReducedRedundancyStorage",
            "GlacierInstantRetrievalStorage", "GlacierStorage", "DeepArchiveStorage")  # fmt: skip
TOP = 10


def _file(account: str) -> sg_store.File:
    return sg_store.File(sg_ipintel.DATA_DIR / "profiles" / f"{account}.json")


def cached(account: str) -> dict | None:
    try:
        return json.loads(_file(account).read_text())
    except FileNotFoundError:
        return None


def save(account: str, prof: dict) -> None:
    _file(account).write_text(json.dumps(prof))


def _why(exc: BaseException) -> str:
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "") if hasattr(exc, "response") else ""
    return code or type(exc).__name__


def _pages(client, op: str, key: str, **kw) -> list:
    out = []
    for page in client.get_paginator(op).paginate(**kw):
        out += page.get(key) or []
    return out


# ------------------------------------------------------------------------------------------- spend
def last_month(today: date) -> tuple[str, str]:
    first = today.replace(day=1)
    return (first - timedelta(days=1)).replace(day=1).isoformat(), first.isoformat()


def costs(ce, account: str, today: date | None = None) -> dict:
    """Last full month's spend of one account and its TOP services, and this month so far (credits and
    refunds left out). Two Cost Explorer calls: US$0.02."""
    today = today or datetime.now(timezone.utc).date()
    start, end = last_month(today)
    flt = {"And": [{"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [account]}},
                   {"Not": {"Dimensions": {"Key": "RECORD_TYPE", "Values": ["Credit", "Refund"]}}}]}  # fmt: skip
    r = ce.get_cost_and_usage(TimePeriod={"Start": start, "End": end}, Granularity="MONTHLY",
                              Metrics=["UnblendedCost"], Filter=flt,
                              GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}])  # fmt: skip
    by: dict[str, float] = {}
    for period in r.get("ResultsByTime") or []:
        for g in period.get("Groups") or []:
            by[g["Keys"][0]] = by.get(g["Keys"][0], 0.0) + float(g["Metrics"]["UnblendedCost"]["Amount"])
    total = sum(by.values())
    top = sorted(((k, v) for k, v in by.items() if v >= 0.005), key=lambda x: -x[1])[:TOP]
    out = {"month": start[:7], "total": round(total, 2),
           "top": [{"service": k, "cost": round(v, 2), "share": round(v / total, 4) if total else 0} for k, v in top]}
    if today.day > 1:
        r = ce.get_cost_and_usage(TimePeriod={"Start": today.replace(day=1).isoformat(), "End": today.isoformat()},
                                  Granularity="MONTHLY", Metrics=["UnblendedCost"], Filter=flt)  # fmt: skip
        out["this_month"] = round(sum(float(p["Total"]["UnblendedCost"]["Amount"]) for p in r.get("ResultsByTime") or []), 2)
    return out


# ------------------------------------------------------------------------------------------- what runs there
def region_counts(sess, region: str, config=None) -> dict:
    """What runs in one region. A part that fails is ``{"error": why}``."""
    out: dict = {}

    def part(name, fn):
        try:
            out[name] = fn()
        except Exception as exc:  # noqa: BLE001 - one refused call costs that number only
            out[name] = {"error": _why(exc)}

    ec2 = sess.client("ec2", region_name=region, config=config)

    def instances():
        res = _pages(ec2, "describe_instances", "Reservations")
        ins = [i for r in res for i in r.get("Instances") or [] if i.get("State", {}).get("Name") != "terminated"]
        eks = [i for i in ins if _eks_node(i)]
        return {"total": len(ins), "running": sum(1 for i in ins if i.get("State", {}).get("Name") == "running"),
                "eks": len(eks), "eks_running": sum(1 for i in eks if i.get("State", {}).get("Name") == "running")}  # fmt: skip

    def endpoints():
        eps = _pages(ec2, "describe_vpc_endpoints", "VpcEndpoints")
        kinds: dict = {}
        for e in eps:
            kinds[e.get("VpcEndpointType", "")] = kinds.get(e.get("VpcEndpointType", ""), 0) + 1
        return {"interface": kinds.get("Interface", 0) + kinds.get("GatewayLoadBalancer", 0)
                + kinds.get("Resource", 0) + kinds.get("ServiceNetwork", 0),
                "gateway": kinds.get("Gateway", 0), "total": len(eps)}  # fmt: skip

    def services():
        return len(_pages(ec2, "describe_vpc_endpoint_service_configurations", "ServiceConfigurations"))

    part("ec2", instances)
    part("endpoints", endpoints)
    part("endpoint_services", services)
    part("vpcs", lambda: len(_pages(ec2, "describe_vpcs", "Vpcs")))
    rds = sess.client("rds", region_name=region, config=config)
    part("rds", lambda: {"instances": len(_pages(rds, "describe_db_instances", "DBInstances")),
                         "clusters": len(_pages(rds, "describe_db_clusters", "DBClusters"))})  # fmt: skip
    elb = sess.client("elbv2", region_name=region, config=config)
    part("load_balancers", lambda: len(_pages(elb, "describe_load_balancers", "LoadBalancers")))
    lam = sess.client("lambda", region_name=region, config=config)
    part("lambda", lambda: len(_pages(lam, "list_functions", "Functions")))
    eks = sess.client("eks", region_name=region, config=config)
    part("eks", lambda: len(_pages(eks, "list_clusters", "clusters")))
    kafka = sess.client("kafka", region_name=region, config=config)
    part("msk", lambda: len(_pages(kafka, "list_clusters_v2", "ClusterInfoList")))
    return out


def s3(sess, config=None, now: datetime | None = None) -> dict:
    """Buckets, and their size and objects from CloudWatch's daily storage metrics (the last two days: S3
    publishes them once a day), by the bucket's region."""
    s3c = sess.client("s3", region_name="us-east-1", config=config)
    buckets = []
    kw: dict = {}
    while True:
        r = s3c.list_buckets(**kw)
        buckets += r.get("Buckets") or []
        if not r.get("ContinuationToken"):
            break
        kw["ContinuationToken"] = r["ContinuationToken"]
    def where(b):
        if b.get("BucketRegion"):
            return b["BucketRegion"]
        try:
            loc = s3c.get_bucket_location(Bucket=b["Name"]).get("LocationConstraint")
        except Exception:  # noqa: BLE001 - its region not known: its size is not counted
            return ""
        return {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}.get(loc, loc)

    by_region: dict = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        for b, region in zip(buckets, pool.map(where, buckets)):
            by_region.setdefault(region, []).append(b["Name"])
    lost = by_region.pop("", [])
    now = now or datetime.now(timezone.utc)
    size, objects, unknown = 0, 0, ([f"{len(lost)} bucket(s) whose region could not be read"] if lost else [])
    for region, names in by_region.items():
        try:
            cw = sess.client("cloudwatch", region_name=region, config=config)
            queries = []
            for i, name in enumerate(names):
                for j, st in enumerate(S3_TYPES):
                    queries.append(("b", f"s{i}_{j}", name, "BucketSizeBytes", st))
                queries.append(("o", f"o{i}", name, "NumberOfObjects", "AllStorageTypes"))
            for k in range(0, len(queries), 500):
                chunk = queries[k:k + 500]
                got = cw.get_metric_data(MetricDataQueries=[{"Id": q[1], "MetricStat": {"Metric": {
                    "Namespace": "AWS/S3", "MetricName": q[3], "Dimensions": [
                        {"Name": "BucketName", "Value": q[2]}, {"Name": "StorageType", "Value": q[4]}]},
                    "Period": 86400, "Stat": "Average"}} for q in chunk],
                    StartTime=now - timedelta(days=3), EndTime=now)  # fmt: skip
                kinds = {q[1]: q[0] for q in chunk}
                for res in got.get("MetricDataResults") or []:
                    if res.get("Values"):
                        v = res["Values"][0]  # newest first
                        if kinds[res["Id"]] == "b":
                            size += int(v)
                        else:
                            objects += int(v)
        except Exception as exc:  # noqa: BLE001
            unknown.append(f"{region}: {_why(exc)}")
    return {"buckets": len(buckets), "bytes": size, "objects": objects, "unknown": unknown,
            "regions": {r: len(n) for r, n in by_region.items()}}


REGION_WORKERS = 10  # regions read at once: each makes a handful of List/Describe calls


def read(sess, account: str, regions: list[str], ce=None, config=None) -> dict:
    """The account's profile: its regions (REGION_WORKERS at a time), S3 and spend from ``ce`` (Cost Explorer in
    the management account, when given) all read at once. A part that fails is noted, never the whole."""
    prof: dict = {"account": account, "at": time.time(), "regions": {}, "errors": []}

    def guarded(fn):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - shown on the tile, the rest still read
            return {"error": _why(exc)}

    with ThreadPoolExecutor(max_workers=2) as side:
        s3_f = side.submit(guarded, lambda: s3(sess, config))
        ce_f = side.submit(guarded, lambda: costs(ce, account)) if ce is not None else None
        with ThreadPoolExecutor(max_workers=REGION_WORKERS) as pool:
            for region, got in zip(regions, pool.map(lambda r: guarded(lambda: region_counts(sess, r, config)), regions)):
                prof["regions"][region] = got
        prof["s3"] = s3_f.result()
        if ce_f is not None:
            prof["spend"] = ce_f.result()
    prof["totals"] = totals(prof)
    return prof


def _eks_node(instance: dict) -> bool:
    """An EC2 instance that is an EKS worker node: managed node groups, self-managed nodes and Karpenter all
    tag it with the cluster's name."""
    for t in instance.get("Tags") or []:
        k = t.get("Key", "")
        if k in ("eks:cluster-name", "aws:eks:cluster-name", "eks:nodegroup-name", "karpenter.sh/nodepool",
                 "karpenter.sh/provisioner-name") or k.startswith("kubernetes.io/cluster/"):  # fmt: skip
            return True
    return False


def totals(prof: dict) -> dict:
    """Each number summed over the regions, with the regions it could not be read in."""
    out: dict = {}

    def add(key, value, region):
        t = out.setdefault(key, {"n": 0, "missing": []})
        if isinstance(value, dict) and "error" in value:
            t["missing"].append(f"{region}: {value['error']}")
        else:
            t["n"] += value

    for region, r in prof.get("regions", {}).items():
        e = r.get("ec2", {})
        add("ec2", e if "error" in e else e.get("total", 0), region)
        add("ec2_running", e if "error" in e else e.get("running", 0), region)
        if "error" in e or "eks" in e:  # summaries read before EKS nodes were told apart have none: not zero
            add("ec2_eks", e if "error" in e else e["eks"], region)
            add("ec2_eks_running", e if "error" in e else e["eks_running"], region)
        d = r.get("rds", {})
        add("rds", d if "error" in d else d.get("instances", 0), region)
        add("rds_clusters", d if "error" in d else d.get("clusters", 0), region)
        p = r.get("endpoints", {})
        add("privatelink", p if "error" in p else p.get("interface", 0), region)
        add("gateway_endpoints", p if "error" in p else p.get("gateway", 0), region)
        for key in ("endpoint_services", "vpcs", "load_balancers", "lambda", "eks"):
            add(key, r.get(key, 0), region)
        if "msk" in r:  # summaries read before MSK was counted have none: shown as not read, never as zero
            add("msk", r["msk"], region)
    return out
