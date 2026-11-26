"""sg_athena.py — read VPC flow logs kept in S3, through Amazon Athena, the way Logs Insights reads CloudWatch Logs.

The recommended layout (docs/flow-logs-s3.md): every account's flow logs delivered to ONE bucket in the
organisation's Log Archive account, in Parquet, with Hive-compatible, per-hour partitions:

    s3://BUCKET[/PREFIX]/AWSLogs/aws-account-id=ACCOUNT/aws-service=vpcflowlogs/aws-region=REGION/
        year=YYYY/month=MM/day=DD/hour=HH/…parquet

One Athena table over that prefix (``ddl``) uses partition projection, so no crawler and no partitions to
add: a query names the account, the region and the hours it wants, and Athena reads only those folders.
Plain-text delivery (``AWSLogs/ACCOUNT/vpcflowlogs/REGION/YYYY/MM/DD/``) works too, with a table per log format.

Athena runs in the account that holds the table (usually Log Archive, or a security tooling account that
may read the bucket): the console reaches it with the same sign-in, the role chosen for every account.
Each query returns the same columns as sg_review's Logs Insights detail query, so everything after the read
(reports, Tighten, Rejected traffic) is the same whichever store the flow logs came from.

The settings are kept in ``athena.json`` in the data folder (the console's Settings tab writes it).
"""

from __future__ import annotations

import json
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

FILE = "athena.json"
FIELDS_PARQUET = {  # AWS's Parquet column names and types for VPC flow logs (version 2 to 5 fields)
    "version": "int", "account_id": "string", "interface_id": "string", "srcaddr": "string", "dstaddr": "string",
    "srcport": "int", "dstport": "int", "protocol": "bigint", "packets": "bigint", "bytes": "bigint",
    "start": "bigint", "end": "bigint", "action": "string", "log_status": "string", "vpc_id": "string",
    "subnet_id": "string", "instance_id": "string", "tcp_flags": "int", "type": "string", "pkt_srcaddr": "string",
    "pkt_dstaddr": "string", "region": "string", "az_id": "string", "sublocation_type": "string",
    "sublocation_id": "string", "pkt_src_aws_service": "string", "pkt_dst_aws_service": "string",
    "flow_direction": "string", "traffic_path": "int",
}  # fmt: skip
ROW_CAP = 50_000  # rows one slice's query may return (Logs Insights stops at 10,000; Athena has no such limit)
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_lock = threading.Lock()
_session_factory = None  # (account) -> boto3 Session: set by the console to its sign-in


class AthenaError(Exception):
    pass


# ------------------------------------------------------------------------------------------- settings
def path() -> Path:
    import sg_ipintel

    return Path(sg_ipintel.DATA_DIR) / FILE


_cache: dict = {}


def load(every: bool = False) -> dict:
    """The settings, or {} when flow logs in S3 are not set up (``every``: the settings even when switched off).
    Read again only when the file changes: a report asks for each flow log it looks at."""
    p = path()
    try:
        key = (str(p), p.stat().st_mtime_ns)
    except OSError:
        return {}
    if _cache.get("key") != key:
        try:
            cfg = json.loads(p.read_text())
        except (OSError, ValueError):
            cfg = {}
        _cache.update(key=key, cfg=cfg if isinstance(cfg, dict) else {})
    cfg = dict(_cache["cfg"])
    return cfg if every or cfg.get("on") else {}


def save(cfg: dict) -> dict:
    """Check and keep the settings: {on, account, region, database, table, workgroup, output, bucket, prefix,
    layout ("hive" or "plain"), hourly}."""
    clean = {
        "on": bool(cfg.get("on")),
        "account": str(cfg.get("account") or "").strip(),
        "region": str(cfg.get("region") or "").strip(),
        "database": str(cfg.get("database") or "vpc_flow_logs").strip(),
        "table": str(cfg.get("table") or "flow_logs").strip(),
        "workgroup": str(cfg.get("workgroup") or "primary").strip(),
        "output": str(cfg.get("output") or "").strip(),
        "bucket": str(cfg.get("bucket") or "").strip().removeprefix("s3://").strip("/"),
        "prefix": str(cfg.get("prefix") or "").strip().strip("/"),
        "layout": "plain" if cfg.get("layout") == "plain" else "hive",
        "hourly": bool(cfg.get("hourly", True)),
    }
    if clean["on"]:
        if not re.fullmatch(r"\d{12}", clean["account"]):
            raise AthenaError("the account that runs Athena is a 12-digit account id (usually Log Archive)")
        if not re.fullmatch(r"[a-z]{2}(-[a-z]+)+-\d", clean["region"]):
            raise AthenaError("the region is where the bucket and the Athena table are, for example eu-west-1")
        for k in ("database", "table"):
            if not _NAME.fullmatch(clean[k]):
                raise AthenaError(f"the {k} name is letters, digits and _")
        if not clean["bucket"] or "/" in clean["bucket"]:
            raise AthenaError("the bucket is its name alone (a prefix inside it goes in Prefix)")
        if clean["output"] and not clean["output"].startswith("s3://"):
            raise AthenaError("query results go to an s3:// address (or leave it empty when the workgroup sets one)")
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(clean, indent=2))
    return clean


def set_session_factory(fn) -> None:
    """How to reach an account: ``fn(account)`` returns a boto3 Session (the console passes its sign-in)."""
    global _session_factory
    _session_factory = fn


def _client(cfg: dict):
    import boto3
    from botocore.config import Config

    sess = _session_factory(cfg["account"]) if _session_factory else boto3.Session()
    return sess.client("athena", region_name=cfg["region"],
                       config=Config(retries={"max_attempts": 10, "mode": "adaptive"}, read_timeout=60))  # fmt: skip


# ------------------------------------------------------------------------------------------- matching
def bucket_of(destination: str) -> tuple[str, str]:
    """(bucket, prefix) of a flow log's S3 destination ARN (arn:aws:s3:::bucket/prefix)."""
    rest = destination.split(":::", 1)[-1] if destination.startswith("arn:") else destination.removeprefix("s3://")
    bucket, _, prefix = rest.partition("/")
    return bucket, prefix.strip("/")


def covers(cfg: dict, flow_log: dict) -> bool:
    """This flow log is delivered where the table reads: the same bucket and prefix, in the layout set up."""
    if not cfg or flow_log.get("dest") != "s3":
        return False
    bucket, prefix = bucket_of(flow_log.get("s3") or "")
    if bucket != cfg["bucket"] or prefix != cfg.get("prefix", ""):
        return False
    if cfg["layout"] == "hive":
        return (flow_log.get("file") or "parquet") == "parquet" and flow_log.get("hive", True) is not False
    return (flow_log.get("file") or "plain-text") == "plain-text"


# ------------------------------------------------------------------------------------------- the table
def location(cfg: dict) -> str:
    return f"s3://{cfg['bucket']}/{cfg['prefix'] + '/' if cfg.get('prefix') else ''}AWSLogs/"


def ddl(cfg: dict, log_format: str | None = None) -> str:
    """CREATE EXTERNAL TABLE for the bucket, with partition projection: run it once in Athena (in the account
    and region set up). Parquet: every field AWS writes, by name, whatever format each account's flow log
    uses. Plain text: the columns of ``log_format``, in its order (one table per format)."""
    import sg_review

    db, table = cfg["database"], cfg["table"]
    hourly = cfg.get("hourly", True)
    if cfg["layout"] == "hive":
        cols = ",\n  ".join(f"`{k}` {v}" for k, v in FIELDS_PARQUET.items())
        tmpl = (location(cfg) + "aws-account-id=${aws_account_id}/aws-service=vpcflowlogs/aws-region=${aws_region}/"
                "year=${year}/month=${month}/day=${day}" + ("/hour=${hour}" if hourly else ""))  # fmt: skip
        stored = "STORED AS PARQUET"
    else:
        fields = sg_review.fields_of(log_format)
        cols = ",\n  ".join(f"`{f}` {FIELDS_PARQUET.get(f, 'string')}" for f in fields)
        tmpl = (location(cfg) + "${aws_account_id}/vpcflowlogs/${aws_region}/${year}/${month}/${day}"
                + ("/${hour}" if hourly else ""))  # fmt: skip
        stored = "ROW FORMAT DELIMITED FIELDS TERMINATED BY ' '\nSTORED AS TEXTFILE"
    parts = "aws_account_id string, aws_region string, year string, month string, day string" + (", hour string" if hourly else "")
    props = {
        "projection.enabled": "true",
        "projection.aws_account_id.type": "injected",
        "projection.aws_region.type": "injected",
        "projection.year.type": "integer", "projection.year.range": "2020,2099",
        "projection.month.type": "integer", "projection.month.range": "1,12", "projection.month.digits": "2",
        "projection.day.type": "integer", "projection.day.range": "1,31", "projection.day.digits": "2",
        "storage.location.template": tmpl,
    }  # fmt: skip
    if hourly:
        props.update({"projection.hour.type": "integer", "projection.hour.range": "0,23", "projection.hour.digits": "2"})
    if cfg["layout"] != "hive":
        props["skip.header.line.count"] = "1"
    tp = ",\n  ".join(f"'{k}' = '{v}'" for k, v in props.items())
    return (f"CREATE DATABASE IF NOT EXISTS `{db}`;\n\n"
            f"CREATE EXTERNAL TABLE IF NOT EXISTS `{db}`.`{table}` (\n  {cols}\n)\nPARTITIONED BY ({parts})\n{stored}\n"
            f"LOCATION '{location(cfg)}'\nTBLPROPERTIES (\n  {tp}\n);")  # fmt: skip


# ------------------------------------------------------------------------------------------- queries
def _q(v: str) -> str:
    return "'" + str(v).replace("'", "''") + "'"


def _partitions(cfg: dict, s: int, e: int) -> str:
    """The partition filter for [s, e): the days (and hours) touched, so Athena opens only those folders.
    Flow records are filed by the hour their capture window ended in, so one hour either side is included."""
    t0 = datetime.fromtimestamp(s - 3600, timezone.utc).replace(minute=0, second=0, microsecond=0)
    t1 = datetime.fromtimestamp(e + 3600, timezone.utc)
    if cfg.get("hourly", True) and (t1 - t0) <= timedelta(hours=48):
        hours, t = [], t0
        while t < t1:
            hours.append(f"(year = '{t:%Y}' AND month = '{t:%m}' AND day = '{t:%d}' AND hour = '{t:%H}')")
            t += timedelta(hours=1)
        return "(" + " OR ".join(hours) + ")"
    days, d = [], t0.date()
    while d <= t1.date():
        days.append(f"(year = '{d:%Y}' AND month = '{d:%m}' AND day = '{d:%d}')")
        d += timedelta(days=1)
    return "(" + " OR ".join(days) + ")"


def _in_any(col: str, cidrs: list[str]) -> str:
    return "(" + " OR ".join(f"contains({_q(c)}, {col})" for c in cidrs) + ")"


def detail_sql(cfg: dict, account: str, region: str, log_format: str | None, vpc_ranges: list[str], s: int, e: int,
               fold: bool | str = True) -> str | None:  # fmt: skip
    """The Athena twin of sg_review.detail_query: the same rows, by source, target, interface, protocol,
    port (replies folded) and action, with flows, bytes, resets and (with flow-direction) the direction."""
    import sg_review

    fields = sg_review.fields_of(log_format)
    if not sg_review._has_needed(fields):
        return None
    pkt = cfg["layout"] == "hive"  # Parquet has every column: the packet address wins whenever it is there
    src = ("COALESCE(NULLIF(pkt_srcaddr, '-'), NULLIF(srcaddr, '-'))" if pkt or "pkt_srcaddr" in fields
           else "NULLIF(srcaddr, '-')")  # fmt: skip
    dst = ("COALESCE(NULLIF(pkt_dstaddr, '-'), NULLIF(dstaddr, '-'))" if pkt or "pkt_dstaddr" in fields
           else "NULLIF(dstaddr, '-')")  # fmt: skip
    if cfg["layout"] != "hive":  # text columns are strings: numbers are read as numbers
        num = lambda c: f"TRY_CAST(NULLIF({c}, '-') AS BIGINT)"  # noqa: E731
    else:
        num = lambda c: f"CAST({c} AS BIGINT)"  # noqa: E731
    dport, sport = num("dstport"), num("srcport")
    flags = f"COALESCE({num('tcp_flags')}, 0)" if "tcp_flags" in fields else "0"
    E = sg_review.EPHEMERAL
    if fold is True and "srcport" in fields:
        lower = f"CASE WHEN {sport} < {dport} THEN 1 ELSE 0 END"
        reply = (f"GREATEST(({flags} / 16) % 2, (1 - ({flags} / 2) % 2) * {lower})" if "tcp_flags" in fields else lower)
        port = f"CASE WHEN {dport} >= 1024 AND {reply} = 1 THEN {E} ELSE LEAST({dport}, {E}) END"
    elif fold:
        port = f"LEAST({dport}, {E})"
    else:
        port = dport
    rst = f"(({flags} / 4) % 2)"
    by_dir = "flow_direction" in fields
    where = [f"aws_account_id = {_q(account)}", f"aws_region = {_q(region)}", _partitions(cfg, s, e),
             f"{num('start')} >= {int(s)}", f"{num('start')} < {int(e)}"]  # fmt: skip
    if by_dir:
        where.append(f"(flow_direction = 'ingress' OR (flow_direction = 'egress' AND {rst} = 1))" if "tcp_flags" in fields
                     else "flow_direction = 'ingress'")  # fmt: skip
    elif vpc_ranges and len(vpc_ranges) <= sg_review.VPC_FILTER_MAX:
        where.append(_in_any(f"TRY_CAST({dst} AS IPADDRESS)", vpc_ranges))
    dir_col = ", flow_direction AS dir" if by_dir and "tcp_flags" in fields else ""
    group_dir = ", 7" if dir_col else ""
    return (f"SELECT {src} AS src, {dst} AS dst, interface_id AS eni, CAST({num('protocol')} AS VARCHAR) AS proto,"
            f" {port} AS dport, action{dir_col}, COUNT(*) AS flows, SUM({num('bytes')}) AS bytes,"
            f" SUM({rst}) AS resets"
            f" FROM `{cfg['database']}`.`{cfg['table']}`"
            f" WHERE {' AND '.join(where)} AND {src} IS NOT NULL AND {dst} IS NOT NULL"
            f" GROUP BY 1, 2, 3, 4, 5, 6{group_dir} ORDER BY flows DESC LIMIT {ROW_CAP}")  # fmt: skip


def egress_sql(cfg: dict, account: str, region: str, log_format: str | None, vpc_ranges: list[str], s: int,
               e: int) -> str | None:  # fmt: skip
    """The Athena twin of sg_review.egress_query: accepted outbound connections."""
    import sg_review

    fields = sg_review.fields_of(log_format)
    if not sg_review._has_needed(fields):
        return None
    pkt = cfg["layout"] == "hive"
    src = "COALESCE(NULLIF(pkt_srcaddr, '-'), NULLIF(srcaddr, '-'))" if pkt or "pkt_srcaddr" in fields else "NULLIF(srcaddr, '-')"
    dst = "COALESCE(NULLIF(pkt_dstaddr, '-'), NULLIF(dstaddr, '-'))" if pkt or "pkt_dstaddr" in fields else "NULLIF(dstaddr, '-')"
    num = (lambda c: f"TRY_CAST(NULLIF({c}, '-') AS BIGINT)") if cfg["layout"] != "hive" else (lambda c: f"CAST({c} AS BIGINT)")
    where = [f"aws_account_id = {_q(account)}", f"aws_region = {_q(region)}", _partitions(cfg, s, e),
             f"{num('start')} >= {int(s)}", f"{num('start')} < {int(e)}", "action = 'ACCEPT'",
             f"{num('dstport')} < {sg_review.EPHEMERAL}"]  # fmt: skip
    if "flow_direction" in fields:
        where.append("flow_direction = 'egress'")
    elif vpc_ranges and len(vpc_ranges) <= sg_review.VPC_FILTER_MAX:
        where.append(_in_any(f"TRY_CAST({src} AS IPADDRESS)", vpc_ranges))
    else:
        return None
    return (f"SELECT {src} AS src, {dst} AS dst, interface_id AS eni, CAST({num('protocol')} AS VARCHAR) AS proto,"
            f" {num('dstport')} AS dport, COUNT(*) AS flows FROM `{cfg['database']}`.`{cfg['table']}`"
            f" WHERE {' AND '.join(where)} AND {src} IS NOT NULL AND {dst} IS NOT NULL"
            f" GROUP BY 1, 2, 3, 4, 5 LIMIT {ROW_CAP}")  # fmt: skip


def run(cfg: dict, sql: str, wait: float = 900, cancelled=lambda: False, client=None) -> tuple[list[dict] | None, int, str]:
    """(rows or None, bytes scanned, status) of one Athena query, as sg_review.run_query gives Logs Insights'."""
    athena = client or _client(cfg)
    args = {"QueryString": sql, "WorkGroup": cfg.get("workgroup") or "primary",
            "QueryExecutionContext": {"Database": cfg["database"]}}  # fmt: skip
    if cfg.get("output"):
        args["ResultConfiguration"] = {"OutputLocation": cfg["output"]}
    qid = athena.start_query_execution(**args)["QueryExecutionId"]
    waited, pause = 0.0, 0.5
    while True:
        x = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = x["Status"]["State"]
        scanned = int((x.get("Statistics") or {}).get("DataScannedInBytes") or 0)
        if state == "SUCCEEDED":
            break
        if state in ("FAILED", "CANCELLED"):
            why = x["Status"].get("StateChangeReason", "")
            if state == "FAILED" and ("does not exist" in why or "NoSuchKey" in why):
                return [], scanned, "Complete"  # nothing delivered for these hours yet
            return None, scanned, f"{state.title()}: {why}"[:300]
        if cancelled() or waited >= wait:
            athena.stop_query_execution(QueryExecutionId=qid)
            return None, scanned, "Cancelled" if cancelled() else "Timeout"
        time.sleep(pause)
        waited += pause
        pause = min(pause * 1.5, 5)
    rows, cols, token = [], None, None
    while True:
        kw = {"QueryExecutionId": qid, "MaxResults": 1000}
        if token:
            kw["NextToken"] = token
        page = athena.get_query_results(**kw)
        data = page["ResultSet"]["Rows"]
        if cols is None:
            cols = [c["Name"] for c in page["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]]
            data = data[1:]  # the first row of the first page is the header
        rows += [{c: d.get("VarCharValue") for c, d in zip(cols, r["Data"])} for r in data]
        token = page.get("NextToken")
        if not token:
            break
    return rows, scanned, "Complete"


def test(cfg: dict, account: str = "", region: str = "") -> dict:
    """A cheap query that proves Athena, the table and the bucket answer: the flows in the newest hour of one
    account (the Athena account itself when none is named). {"ok", "rows", "bytes", "seconds", "error"}."""
    t0 = time.time()
    now = int(time.time()) // 3600 * 3600
    acct, reg = account or cfg["account"], region or cfg["region"]
    sql = (f"SELECT COUNT(*) AS flows FROM `{cfg['database']}`.`{cfg['table']}` WHERE aws_account_id = {_q(acct)}"
           f" AND aws_region = {_q(reg)} AND {_partitions(cfg, now - 3600, now)}")  # fmt: skip
    try:
        rows, nbytes, status = run(cfg, sql, wait=120)
    except Exception as exc:  # noqa: BLE001 - said on the page
        return {"ok": False, "error": str(exc)[:400], "seconds": round(time.time() - t0, 1)}
    if rows is None:
        return {"ok": False, "error": status, "seconds": round(time.time() - t0, 1)}
    return {"ok": True, "flows": int((rows[0] if rows else {}).get("flows") or 0), "bytes": nbytes,
            "account": acct, "region": reg, "seconds": round(time.time() - t0, 1)}  # fmt: skip
