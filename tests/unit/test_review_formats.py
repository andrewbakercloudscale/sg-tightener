"""Custom flow-log formats that log only the packet addresses (pkt-srcaddr, pkt-dstaddr) are read."""

from __future__ import annotations

import sg_review

PKT_ONLY = ("${account-id} ${interface-id} ${pkt-srcaddr} ${srcport} ${pkt-dstaddr} ${dstport} ${tcp-flags} "
            "${log-status} ${protocol} ${packets} ${bytes} ${action} ${flow-direction} ${traffic-path} ${start} ${end}")


def test_packet_address_only_format_is_readable():
    assert sg_review.readable(PKT_ONLY)
    head = sg_review._base(PKT_ONLY, ["10.0.0.0/16"])[0]
    assert 'f_pkt_srcaddr != "-"' in head and "f_srcaddr" not in head


def test_packet_address_only_format_is_queried():
    snap = {"flow_logs": [{"dest": "cloud-watch-logs", "group": "vpc-flow", "status": "ACTIVE", "format": PKT_ONLY}]}
    assert sg_review.query_sets(snap) == [{"format": PKT_ONLY, "groups": ["vpc-flow"]}]


def test_a_format_without_any_source_address_is_not_readable():
    assert not sg_review.readable("${interface-id} ${dstport} ${protocol} ${action} ${pkt-dstaddr}")


def test_a_slice_older_than_the_log_group_is_empty_not_an_error():
    from botocore.exceptions import ClientError

    class Logs:
        def start_query(self, **_):
            raise ClientError({"Error": {"Code": "MalformedQueryException", "Message": "Query's end date and time is "
                               "either before the log groups creation time or exceeds the log groups log retention "
                               "settings ([0,88])"}}, "StartQuery")  # fmt: skip

    assert sg_review.run_query(Logs(), ["g"], "q", 0, 3600) == ([], 0, "Complete")


def test_other_malformed_queries_still_raise():
    import pytest
    from botocore.exceptions import ClientError

    class Logs:
        def start_query(self, **_):
            raise ClientError({"Error": {"Code": "MalformedQueryException", "Message": "unexpected symbol"}}, "StartQuery")

    with pytest.raises(ClientError):
        sg_review.run_query(Logs(), ["g"], "q", 0, 3600)


def test_reading_an_ou_again_keeps_to_the_regions_with_flow_logs(monkeypatch):
    import sg_console

    doc = {"regions": {"af-south-1": {"query_sets": [{"format": "x", "groups": ["g"]}]}, "us-east-1": {"query_sets": []}}}
    monkeypatch.setattr(sg_review, "cached_accounts", lambda: ["111111111111"])
    monkeypatch.setattr(sg_review, "load", lambda a: doc)
    assert sg_console.Console._flow_regions("111111111111", "all") == ["af-south-1"]
    assert sg_console.Console._flow_regions("222222222222", "all") == "all", "never read: every region"
    assert sg_console.Console._flow_regions("111111111111", "eu-west-1") == "eu-west-1", "a choice is kept"
