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
