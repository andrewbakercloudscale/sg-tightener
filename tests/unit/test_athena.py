"""Flow logs in S3, read through Athena: the settings, the table, the queries, and a read that uses S3 from when
its flow log was created and CloudWatch Logs before, never both."""

from __future__ import annotations

import os

import pytest

import sg_athena
import sg_ipintel as ipintel
import sg_review

CFG = {"on": True, "account": "999988887777", "region": "eu-west-1", "database": "vpc_flow_logs", "table": "flow_logs",
       "workgroup": "primary", "output": "s3://athena-results/sgt/", "bucket": "org-flow-logs", "prefix": "", "layout": "hive",
       "hourly": True}  # fmt: skip
FMT = sg_review.DEFAULT_FORMAT + " ${tcp-flags} ${flow-direction}"


@pytest.fixture
def data(tmp_path):
    old = ipintel.DATA_DIR
    ipintel.set_data_dir(tmp_path / "data")
    yield tmp_path
    ipintel.set_data_dir(old)


def test_settings_are_checked_and_kept(data):
    assert sg_athena.load() == {}
    with pytest.raises(sg_athena.AthenaError, match="12-digit"):
        sg_athena.save({**CFG, "account": "log-archive"})
    with pytest.raises(sg_athena.AthenaError, match="bucket is its name alone"):
        sg_athena.save({**CFG, "bucket": "org-flow-logs/AWSLogs"})
    saved = sg_athena.save({**CFG, "bucket": "s3://org-flow-logs/"})
    assert saved["bucket"] == "org-flow-logs" and sg_athena.load() == saved
    sg_athena.save({**CFG, "on": False})
    assert sg_athena.load() == {} and sg_athena.load(every=True)["bucket"] == "org-flow-logs"


def test_a_save_is_read_back_even_when_the_file_keeps_its_mtime(data):
    """Two saves in one clock tick leave the file's mtime unchanged (most saves back to back on Windows, now and
    then on Linux): load() must still return what was saved last, not what it read before."""
    sg_athena.save(CFG)
    assert sg_athena.load()["on"]
    before = sg_athena.path().stat().st_mtime_ns
    sg_athena.save({**CFG, "on": False})
    os.utime(sg_athena.path(), ns=(before, before))
    assert sg_athena.load() == {}


def test_the_table_uses_partition_projection_over_every_account():
    ddl = sg_athena.ddl(CFG)
    assert "STORED AS PARQUET" in ddl and "`end` bigint" in ddl and "`tcp_flags` int" in ddl
    assert ("s3://org-flow-logs/AWSLogs/aws-account-id=${aws_account_id}/aws-service=vpcflowlogs/aws-region=${aws_region}/"
            "year=${year}/month=${month}/day=${day}/hour=${hour}") in ddl
    assert "'projection.aws_account_id.type' = 'injected'" in ddl
    plain = sg_athena.ddl({**CFG, "layout": "plain", "hourly": False, "prefix": "flow"}, sg_review.DEFAULT_FORMAT)
    assert "FIELDS TERMINATED BY ' '" in plain and "s3://org-flow-logs/flow/AWSLogs/${aws_account_id}/vpcflowlogs/" in plain
    assert "hour" not in plain.split("PARTITIONED BY")[1].split(")")[0]


def test_a_flow_log_counts_only_when_it_goes_where_the_table_reads():
    s3 = {"dest": "s3", "s3": "arn:aws:s3:::org-flow-logs", "file": "parquet", "hive": True}
    assert sg_athena.covers(CFG, s3)
    assert not sg_athena.covers(CFG, {**s3, "s3": "arn:aws:s3:::other-bucket"})
    assert not sg_athena.covers(CFG, {**s3, "file": "plain-text"})
    assert not sg_athena.covers({}, s3) and not sg_athena.covers(CFG, {"dest": "cloud-watch-logs"})
    assert sg_athena.bucket_of("arn:aws:s3:::b/some/prefix/") == ("b", "some/prefix")


def test_the_query_reads_only_the_hours_asked_and_folds_replies_like_insights():
    s, e = 1795413600, 1795417200  # one hour
    sql = sg_athena.detail_sql(CFG, "222233334444", "eu-west-1", FMT, ["10.0.0.0/16"], s, e)
    assert "aws_account_id = '222233334444'" in sql and "aws_region = 'eu-west-1'" in sql
    assert sql.count("hour = ") == 3, "the hour, and one either side for records filed late or early"
    assert f">= {s}" in sql and f"< {e}" in sql and "THEN 32768" in sql and "flow_direction = 'egress'" in sql
    assert "GROUP BY 1, 2, 3, 4, 5, 6, 7" in sql
    week = sg_athena.detail_sql(CFG, "222233334444", "eu-west-1", sg_review.DEFAULT_FORMAT, ["10.0.0.0/16"], s, s + 7 * 86400)
    assert "hour = " not in week and week.count("day = ") >= 7, "long spans filter by day"
    assert "contains('10.0.0.0/16', TRY_CAST(" in week, "no flow direction: inbound is a target inside the VPCs"
    assert sg_athena.detail_sql(CFG, "1", "r", "${version} ${srcaddr}", [], s, e) is None


class FakeAthena:
    def __init__(self, rows, state="SUCCEEDED"):
        self.rows, self.state, self.sql = rows, state, []

    def start_query_execution(self, **kw):
        self.sql.append(kw["QueryString"])
        assert kw["WorkGroup"] == "primary" and kw["ResultConfiguration"]["OutputLocation"] == CFG["output"]
        return {"QueryExecutionId": "q1"}

    def get_query_execution(self, QueryExecutionId):
        return {"QueryExecution": {"Status": {"State": self.state, "StateChangeReason": "boom"},
                                   "Statistics": {"DataScannedInBytes": 12345}}}  # fmt: skip

    def get_query_results(self, QueryExecutionId, MaxResults, NextToken=None):
        cols = list(self.rows[0]) if self.rows else ["flows"]
        head = [{"Data": [{"VarCharValue": c} for c in cols]}]
        body = [{"Data": [{"VarCharValue": str(r[c])} for c in cols]} for r in self.rows]
        if NextToken is None:  # two pages: the header comes only on the first
            return {"ResultSet": {"Rows": head + body[:1], "ResultSetMetadata": {"ColumnInfo": [{"Name": c} for c in cols]}},
                    "NextToken": "p2"}  # fmt: skip
        return {"ResultSet": {"Rows": body[1:], "ResultSetMetadata": {"ColumnInfo": [{"Name": c} for c in cols]}}}


def test_results_are_paged_and_a_failure_is_said():
    rows = [{"src": "10.0.0.5", "flows": 3}, {"src": "10.0.0.6", "flows": 1}]
    got, nbytes, status = sg_athena.run(CFG, "SELECT 1", client=FakeAthena(rows))
    assert got == [{"src": "10.0.0.5", "flows": "3"}, {"src": "10.0.0.6", "flows": "1"}] and nbytes == 12345
    got, _, status = sg_athena.run(CFG, "SELECT 1", client=FakeAthena([], "FAILED"))
    assert got is None and status == "Failed: boom"


def test_a_read_uses_s3_from_its_flow_log_on_and_cloudwatch_before(data, monkeypatch):
    sg_athena.save(CFG)
    since = 1795413600
    snap = {"flow_logs": [
        {"id": "fl-cw", "dest": "cloud-watch-logs", "group": "/vpc/flow", "format": FMT, "status": "ACTIVE", "created": 1.0},
        {"id": "fl-s3", "dest": "s3", "group": "", "format": FMT, "status": "ACTIVE", "created": float(since),
         "s3": "arn:aws:s3:::org-flow-logs", "file": "parquet", "hive": True, "hourly": True},
    ]}  # fmt: skip
    qsets = sg_review.query_sets(snap, "222233334444")
    assert qsets == [{"format": FMT, "groups": ["/vpc/flow"]}, {"format": FMT, "s3": "222233334444", "since": float(since)}]
    assert sg_review.query_sets(snap) == qsets[:1], "no account, no S3 (an old caller)"
    assert [q.get("s3", "cw") for q in sg_review.slice_sets(qsets, since - 3600)] == ["cw"]
    assert [q.get("s3", "cw") for q in sg_review.slice_sets(qsets, since)] == ["222233334444"]

    fake = FakeAthena([{"src": "10.1.0.9", "dst": "10.0.0.5", "eni": "eni-1", "proto": "6", "dport": "443",
                        "action": "ACCEPT", "dir": "ingress", "flows": 7, "bytes": 900, "resets": 0}] * 2)  # fmt: skip
    monkeypatch.setattr(sg_athena, "_client", lambda cfg: fake)
    monkeypatch.setattr(sg_review, "run_query", lambda *a, **k: pytest.fail("CloudWatch Logs read for an S3 hour"))
    (chunk,) = sg_review.read_chunk(object(), "eu-west-1", since, since + 3600, qsets, ["10.0.0.0/16"])
    assert chunk["st"] == "ok" and chunk["b"] == 12345 and len(fake.sql) == 1
    assert chunk["rows"][0][:6] == ["10.1.0.9", "10.0.0.5", "eni-1", "6", 443, "ACCEPT"]
