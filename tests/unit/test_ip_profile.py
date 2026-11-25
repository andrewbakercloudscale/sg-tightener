"""The estate's address book: before an address is let in, everything known about it across every account is one
lookup away. Who owns it, our instance and its operating system, where it was let in or refused and on which
ports, whether it scanned, when first and last seen, and what the port it asks for is."""

from __future__ import annotations

from pathlib import Path

import pytest

import sg_console
import sg_ipintel
import sg_review
from tests.unit.test_apply_and_fix import ACCOUNT, REGION, WEB, con  # noqa: F401 - the fixture

OTHER, THIRD = "444455556666", "777788889999"
DAY = 86400


def _doc():
    rows = [
        ("10.1.0.10", "10.2.0.5", "eni-a", 6, 5432, "ACCEPT", 900),  # let in on postgres
        ("10.1.0.10", "10.2.0.5", "eni-a", 6, 443, "REJECT", 7),  # refused on 443
        ("52.1.2.3", "10.2.0.5", "eni-a", 6, 50000, "ACCEPT", 40),  # answering our own connection
        ("", "10.2.0.5", "eni-a", 6, 22, "REJECT", 1),  # no source: ignored
    ]
    pub = [("198.51.100.7", 300, 120, 30, "10.2.0.5", "eni-a", 22, 6)]  # a sweep, folded by the read
    return {"name": "payments", "chunks": [
        {"r": REGION, "s": 10 * DAY, "e": 11 * DAY, "st": "ok", "rows": rows, "pub": pub},
        {"r": "af-south-1", "s": 2 * DAY, "e": 3 * DAY, "st": "ok", "rows": [rows[0]], "pub": []},
        {"r": REGION, "s": 1 * DAY, "e": 2 * DAY, "st": "failed", "rows": [rows[1]], "pub": []},  # not read: not counted
    ], "regions": {REGION: {"snapshot": {
        "groups": {"sg-db": {"name": "db"}},
        "instances": {"i-db": {"name": "pg-primary", "os": "Red Hat Enterprise Linux", "type": "r6i.large"}},
        "enis": {"eni-a": {"ips": ["10.2.0.5"], "instance": "i-db", "groups": ["sg-db"], "kind": "EC2 instance",
                           "desc": ""}}}}}}


def test_sightings_count_let_in_refused_and_replies_with_ports_regions_and_dates():
    got = sg_review.sightings(_doc())
    x = got["seen"]["10.1.0.10"]
    assert x[:5] == [1800, 7, 0, 2 * DAY, 11 * DAY]
    assert x[7] == ["af-south-1", REGION]
    assert x[5] == 1 and x[9] == 1  # one port refused, one let in
    assert x[8][0] == ["6", 5432, 1800, 0]
    assert got["seen"]["52.1.2.3"][2] == 40 and got["seen"]["52.1.2.3"][8] == []  # replies are not ports it asked for
    sweep = got["seen"]["198.51.100.7"]
    assert sweep[1] == 300 and sweep[5] == 120 and sweep[6] == 30
    assert "" not in got["seen"]
    assert got["own"]["eni-a"][3] == "Red Hat Enterprise Linux" and got["own"]["eni-a"][8] == ["10.2.0.5"]


def test_sightings_keep_every_private_source_and_only_the_busiest_public_ones(monkeypatch):
    monkeypatch.setattr(sg_review, "SEEN_PUBLIC", 1)
    got = sg_review.sightings(_doc())
    assert "10.1.0.10" in got["seen"] and "198.51.100.7" in got["seen"] and "52.1.2.3" not in got["seen"]


def _rows():
    a = sg_review.sightings(_doc())
    other = {"name": "lending", "own": {}, "seen": {
        "10.1.0.10": [50, 0, 0, 5 * DAY, 12 * DAY, 0, 1, [REGION], [["6", 5432, 50, 0]], 1],
        "198.51.100.7": [0, 80, 0, 4 * DAY, 4 * DAY, 2, 1, [REGION], [["6", 22, 0, 80]], 0]}}
    return {ACCOUNT: a, OTHER: other, THIRD: None}


@pytest.fixture
def book(con, monkeypatch):  # noqa: F811
    rows = _rows()
    monkeypatch.setattr(con, "_reports_soon", lambda kind, rk, names: (rows, 0) if (kind, rk) == ("seen", "all") else ({}, 0))
    return con


def _answer(p, q):
    return next(x for x in p["answers"] if x["q"] == q)


def test_our_own_address_names_the_instance_its_operating_system_and_groups(book):
    p = book.ip_profile("10.2.0.5")
    assert p["ours"][0]["instance"] == "i-db" and p["ours"][0]["os"] == "Red Hat Enterprise Linux"
    assert "pg-primary" in _answer(p, "Whose is it?")["a"] and _answer(p, "Whose is it?")["tone"] == "good"
    assert "Red Hat" in _answer(p, "What operating system?")["a"]


def test_an_address_let_in_elsewhere_says_where_and_on_which_port(book):
    p = book.ip_profile("10.1.0.10", "tcp", 5432, account=ACCOUNT)
    assert [r["account"] for r in p["seen"]] == [ACCOUNT, OTHER]
    assert "lending" in _answer(p, "Is it already let in elsewhere?")["a"] and "5432" in _answer(p, "Is it already let in elsewhere?")["a"]
    port = _answer(p, "What port is it asking for?")
    assert "PostgreSQL" in port["a"] and "database port" in port["a"] and p["port"]["database"]
    assert "first 1970-01-03" in _answer(p, "Have we seen it before?")["a"]
    assert "Unknown" in _answer(p, "What operating system?")["a"]  # not one of ours: nothing is probed
    assert "none of the interfaces" in _answer(p, "Whose is it?")["a"]


def test_a_scanner_is_called_out_with_the_ports_and_addresses_it_tried(book):
    p = book.ip_profile("198.51.100.7", "tcp", 22)
    s = _answer(p, "Has it scanned?")
    assert s["tone"] == "bad" and "120 ports" in s["a"] and "30 addresses" in s["a"]
    assert _answer(p, "Is it already let in elsewhere?")["tone"] == "warn"
    assert "AS" in _answer(p, "Whose is it?")["a"] or "Unknown network" in _answer(p, "Whose is it?")["a"]


def test_a_never_seen_address_says_so(book):
    p = book.ip_profile("203.0.113.9")
    assert p["seen"] == [] and _answer(p, "Have we seen it before?")["a"].startswith("Never")
    assert p["accounts_indexed"] == 2


def test_threat_lists_and_aws_owners_are_named(book, monkeypatch):
    class Fake:
        def label(self, ip):
            return ({"kind": "internet", "name": "Spamhaus DROP", "group": "threat", "threat": "Spamhaus DROP",
                     "what": "On Spamhaus DROP"} if ip.startswith("203.")
                    else {"kind": "aws", "name": "AWS EC2, eu-west-1", "service": "EC2", "prefix": "54.0.0.0/8"})

    monkeypatch.setattr(sg_ipintel, "get", lambda: Fake())
    assert _answer(book.ip_profile("203.0.113.9"), "Is it on a threat list or Tor?")["tone"] == "bad"
    assert "AWS EC2" in _answer(book.ip_profile("54.1.1.1"), "Whose is it?")["a"]


def test_not_an_ip_address_is_refused(book):
    with pytest.raises(sg_console.ConsoleError):
        book.ip_profile("not-an-ip")


def test_the_index_is_rebuilt_only_when_an_accounts_sightings_change(book, monkeypatch):
    first, _ = book._ip_index()
    assert book._ip_index()[0] is first
    rows = _rows()
    monkeypatch.setattr(book, "_reports_soon", lambda *a: (rows, 0))
    assert book._ip_index()[0] is not first


def test_the_apply_preview_says_who_each_added_source_is(book):
    book.propose({"account": ACCOUNT, "region": REGION, "reason": "partner", "changes": [
        {"group": WEB, "op": "add", "rule": {"direction": "in", "proto": "tcp", "from": 22, "to": 22, "source": "198.51.100.7/32"}},
        {"group": WEB, "op": "add", "rule": {"direction": "in", "proto": "tcp", "from": 443, "to": 443, "source": "10.50.0.0/16"}}]})
    book.verdicts = lambda a, r="": {"rules": []}
    p = book.apply_preview({"account": ACCOUNT, "region": REGION})
    one = next(c for c in p["changes"] if c["rule"]["source"] == "198.51.100.7/32")
    assert one["who"]["ip"] == "198.51.100.7" and any(x["tone"] == "bad" and "ports" in x["a"] for x in one["who"]["answers"])
    wide = next(c for c in p["changes"] if c["rule"]["source"] == "10.50.0.0/16")
    assert wide["who"]["addresses"] == 65536 and wide["who"]["answers"][0]["tone"] == "warn"


def test_the_page_looks_up_addresses_and_shows_them_before_a_fix_and_an_apply():
    page = (Path(sg_console.__file__).parent / "assets" / "sg_console.html").read_text()
    assert 'id="ipQ"' in page and "/api/ip?ip=" in page and 'id="fixWho"' in page
    assert "c.who?.answers" in page
    assert ("seen", "all") in sg_console.WARM
