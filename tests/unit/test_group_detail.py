"""A security group's details: every source let in through its rules, whether the new rules keep it, the new
ranges and who is in them, and its traffic over time (no AWS, no network)."""

import pytest

import sg_ipintel as ipintel
import sg_review


@pytest.fixture(autouse=True, scope="module")
def _data_dir(tmp_path_factory):
    old = ipintel.DATA_DIR
    ipintel.set_data_dir(tmp_path_factory.mktemp("sgtdata"))
    yield
    ipintel.set_data_dir(old)


T0 = 1_790_000_000 - 1_790_000_000 % 86400


def _doc():
    enis = {"eni-db": {"kind": "instance", "desc": "", "subnet": "subnet-1", "vpc": "vpc-1", "groups": ["sg-db", "sg-ops"],
                       "ips": ["10.0.0.5"]},
            "eni-x": {"kind": "instance", "desc": "", "subnet": "subnet-1", "vpc": "vpc-1", "groups": ["sg-other"], "ips": ["10.0.0.9"]}}  # fmt: skip
    rows1 = [["10.1.0.7", "10.0.0.5", "eni-db", "6", 5432, "ACCEPT", 30],
             ["10.2.0.9", "10.0.0.5", "eni-db", "6", 5432, "ACCEPT", 5],
             ["203.0.113.4", "10.0.0.5", "eni-db", "6", 22, "REJECT", 3],
             ["10.1.0.7", "10.0.0.9", "eni-x", "6", 5432, "ACCEPT", 99],  # another group's interface
             ["10.0.0.5", "10.0.0.5", "eni-db", "6", 5432, "ACCEPT", 1],  # its own record
             ["192.0.2.1", "10.0.0.5", "eni-db", "6", 40000, "ACCEPT", 7]]  # a reply: no rule needed  # fmt: skip
    rows2 = [["10.1.0.7", "10.0.0.5", "eni-db", "6", 5432, "ACCEPT", 10]]
    chunks = [{"r": "eu-west-1", "s": T0, "e": T0 + 3600, "st": "ok", "rows": rows1, "pub": []},
              {"r": "eu-west-1", "s": T0 + 86400, "e": T0 + 86400 + 3600, "st": "ok", "rows": rows2, "pub": []}]  # fmt: skip
    groups = {"sg-db": {"name": "db", "vpc": "vpc-1", "rules": []}, "sg-ops": {"name": "ops", "vpc": "vpc-1", "rules": []}}
    ev = {"t": T0 + 100, "group": "sg-db", "name": "AuthorizeSecurityGroupIngress", "who": "alice",
          "added": [["in", "6", 5432, "10.0.0.0/8"]], "removed": [], "unknown": False}  # fmt: skip
    return {"account": "111122223333", "name": "t", "chunks": chunks,
            "regions": {"eu-west-1": {"snapshot": {"enis": enis, "groups": groups, "vpcs": [{"id": "vpc-1", "cidrs": ["10.0.0.0/16"]}]},
                                      "history": {"events": [ev]}}}}  # fmt: skip


RULES = [{"proto": "6", "from": 5432, "to": 5432, "source": "10.0.0.0/8", "action": "tighten",
          "new": [{"proto": "6", "from": 5432, "to": 5432, "source": "10.1.0.0/24"}]},
         {"proto": "6", "from": 22, "to": 22, "source": "0.0.0.0/0", "action": "remove", "new": []}]  # fmt: skip


def test_every_source_is_listed_with_whether_the_new_rules_still_let_it_in():
    d = sg_review.group_detail(_doc(), "eu-west-1", "sg-db", RULES, T0, T0 + 2 * 86400)
    by = {s["src"]: s for s in d["sources"]}
    assert set(by) == {"10.1.0.7", "10.2.0.9"}, "not its own record, a reply, or another group's interface"
    assert by["10.1.0.7"]["kept"] and by["10.1.0.7"]["flows"] == 40 and by["10.1.0.7"]["active"] == 2
    assert not by["10.2.0.9"]["kept"]
    assert d["sources"][0]["src"] == "10.2.0.9", "the ones the new rules would refuse come first"
    assert d["total"]["lost"] == 1 and d["total"]["refused"] == 3
    assert any("would be refused" in h for h in d["hints"])


def test_the_new_ranges_say_who_is_in_them_and_the_timeline_has_every_day():
    d = sg_review.group_detail(_doc(), "eu-west-1", "sg-db", RULES, T0, T0 + 2 * 86400)
    (rng,) = d["rules"][0]["ranges"]
    assert rng["source"] == "10.1.0.0/24" and rng["size"] == 256 and rng["sources"] == 1 and rng["examples"] == ["10.1.0.7"]
    assert d["rules"][1]["sources"] == 0, "nothing used the rule being removed"
    tl = [t["flows"] for t in d["timeline"]]
    assert d["step"] == 3600 and len(tl) == 48 and tl[0] == 35 and tl[24] == 10 and sum(tl) == 45, "hours, gaps as 0"
    assert d["events"][0]["who"] == "alice" and d["enis"][0]["others"] == ["ops"]
