"""Connection resets: the query counts them in the one scan, slices keep them apart, the account summary says
which sources to block (no AWS, no network)."""

import pytest

import sg_ipintel as ipintel
import sg_review

FMT = ("${account-id} ${interface-id} ${pkt-srcaddr} ${srcport} ${pkt-dstaddr} ${dstport} ${tcp-flags} ${log-status}"
       " ${protocol} ${packets} ${bytes} ${action} ${flow-direction} ${traffic-path} ${start} ${end}")  # fmt: skip


@pytest.fixture(autouse=True, scope="module")
def _data_dir(tmp_path_factory):
    old = ipintel.DATA_DIR
    ipintel.set_data_dir(tmp_path_factory.mktemp("sgtdata"))
    yield
    ipintel.set_data_dir(old)


def test_the_query_counts_resets_in_the_same_scan_and_only_with_tcp_flags():
    q = sg_review.detail_query(FMT, ["10.0.0.0/16"])
    assert "sum(rst) as resets" in q and "floor(f_tcp_flags / 4) % 2" in q
    assert 'f_flow_direction = "egress" and floor(f_tcp_flags / 4) % 2 = 1' in q, "resets the interface sent"
    assert "f_flow_direction as dir" in q
    plain = sg_review.detail_query(FMT.replace(" ${tcp-flags}", ""), ["10.0.0.0/16"])
    assert "rst" not in plain and "dir" not in plain.split("by")[-1]


def test_a_slice_keeps_resets_apart_from_the_connections(monkeypatch):
    def fake(logs, groups, query, s, e, cancelled=None, **kw):
        return [{"src": "198.51.100.9", "dst": "10.0.0.5", "eni": "eni-lb", "proto": "6", "dport": "443",
                 "action": "ACCEPT", "flows": "10", "resets": "8", "dir": "ingress"},
                {"src": "10.0.0.5", "dst": "198.51.100.9", "eni": "eni-lb", "proto": "6", "dport": "51000",
                 "action": "ACCEPT", "flows": "4", "resets": "4", "dir": "egress"},
                {"src": "10.0.0.5", "dst": "203.0.113.50", "eni": "eni-app", "proto": "6", "dport": "443",
                 "action": "ACCEPT", "flows": "2", "resets": "2", "dir": "egress"}], 10, "Complete"  # fmt: skip

    monkeypatch.setattr(sg_review, "run_query", fake)
    (c,) = sg_review.read_chunk(None, "eu-west-1", 0, 3600, [{"format": FMT, "groups": ["g"]}], ["10.0.0.0/16"])
    assert [r[0] for r in c["rows"]] == ["198.51.100.9"], "outbound rows are not connections in"
    assert c["rst"] == [["198.51.100.9", "10.0.0.5", "eni-lb", "6", 443, 8, "in"],
                        ["198.51.100.9", "10.0.0.5", "eni-lb", "6", None, 4, "out"]]  # fmt: skip
    plain = FMT.replace(" ${tcp-flags}", "")
    (c,) = sg_review.read_chunk(None, "eu-west-1", 0, 3600, [{"format": plain, "groups": ["g"]}], ["10.0.0.0/16"])
    assert "rst" not in c, "a slice without tcp-flags was not read for resets"


def _doc(rst, rows):
    enis = {"eni-lb": {"kind": "load balancer", "desc": "ELB net/edge/abc123", "subnet": "subnet-1", "vpc": "vpc-1",
                       "public": True, "groups": [], "ips": ["10.0.0.5"]},
            "eni-app": {"kind": "instance", "desc": "", "subnet": "subnet-2", "vpc": "vpc-1", "groups": [], "ips": ["10.0.1.5"]}}  # fmt: skip
    chunk = {"r": "eu-west-1", "s": 1_790_000_000, "e": 1_790_003_600, "st": "ok", "b": 0, "rows": rows, "pub": [],
             "pc": False, "rst": rst}  # fmt: skip
    return {"account": "111122223333", "name": "t", "chunks": [chunk],
            "regions": {"eu-west-1": {"snapshot": {"enis": enis, "groups": {}, "vpcs": [{"id": "vpc-1", "cidrs": ["10.0.0.0/16"]}]}}}}  # fmt: skip


def test_the_summary_says_which_sources_to_block_and_which_to_investigate():
    rst = [["198.51.100.9", "10.0.0.5", "eni-lb", "6", 443, 80, "in"],
           ["198.51.100.9", "10.0.0.5", "eni-lb", "6", None, 10, "out"],
           ["203.0.113.7", "10.0.0.5", "eni-lb", "6", 443, 2, "in"],
           ["10.9.9.9", "10.0.0.5", "eni-lb", "6", 443, 30, "in"],
           ["10.8.8.8", "10.0.1.5", "eni-app", "6", 5432, 30, "in"]]  # fmt: skip
    rows = [["198.51.100.9", "10.0.0.5", "eni-lb", "6", 443, "ACCEPT", 100],
            ["203.0.113.7", "10.0.0.5", "eni-lb", "6", 443, "ACCEPT", 500],
            ["10.9.9.9", "10.0.0.5", "eni-lb", "6", 443, "ACCEPT", 40]]  # fmt: skip
    got = sg_review.resets_summary(_doc(rst, rows), "1m")
    by = {r["src"]: r for r in got["sources"]}
    assert "10.8.8.8" not in by, "resets between the account's own services are not listed"
    assert by["198.51.100.9"]["action"] == "block" and by["198.51.100.9"]["resets"] == 90
    assert by["198.51.100.9"]["share"] == 0.9 and by["198.51.100.9"]["lbs"] == ["net/edge/abc123"]
    assert by["198.51.100.9"]["subnet"] == "subnet-1" and by["198.51.100.9"]["port"] == 443
    assert by["203.0.113.7"]["action"] == "watch", "a few resets, as any client has"
    assert by["10.9.9.9"]["action"] == "investigate" and by["10.9.9.9"]["internal"]
    assert got["sources"][0]["src"] == "198.51.100.9" and got["block"] == 1
    (lb,) = got["lbs"]
    assert lb["name"] == "edge" and lb["type"] == "net" and lb["in"] == 112 and lb["out"] == 10 and lb["srcs"] == 3
    assert got["read"] == 1 and sum(got["series"]["in"]) == 112


def test_no_resets_read_says_so():
    doc = _doc([], [])
    del doc["chunks"][0]["rst"]
    got = sg_review.resets_summary(doc, "1m")
    assert got["read"] == 0 and got["slices"] == 1 and "sources" in got


# ------------------------------------------------------------------------------------------ blocking
class _Ec2:
    def __init__(self, entries):
        self.entries, self.added = entries, []

    def describe_network_acls(self, Filters):
        subs = Filters[0]["Values"]
        return {"NetworkAcls": [{"NetworkAclId": "acl-1", "Entries": self.entries,
                                 "Associations": [{"SubnetId": s} for s in subs]}]}  # fmt: skip

    def create_network_acl_entry(self, **kw):
        self.added.append(kw)
        self.entries.append({**kw, "RuleAction": kw["RuleAction"]})


def test_a_block_is_a_change_request_and_applies_a_deny_ahead_of_the_allows(tmp_path):
    import sg_db
    import sg_remediate

    alice, bob = "arn:aws:sts::1:assumed-role/A/alice", "arn:aws:sts::1:assumed-role/A/bob"
    st = sg_db.Store(tmp_path / "sg.db")
    with pytest.raises(sg_remediate.RemediateError, match="inside your network"):
        sg_remediate.propose_block(st, "111122223333", "eu-west-1", "10.9.9.9", ["subnet-1"], alice)
    r = sg_remediate.propose_block(st, "111122223333", "eu-west-1", "198.51.100.9", ["subnet-1", "subnet-2"], alice,
                                   detail={"why": "90% reset", "lbs": ["net/edge/abc"]})  # fmt: skip
    assert r["cidr"] == "198.51.100.9/32" and r["status"] == "pending"
    with pytest.raises(sg_remediate.RemediateError, match="already blocks"):
        sg_remediate.propose_block(st, "111122223333", "eu-west-1", "198.51.100.9", ["subnet-1"], alice)
    ec2 = _Ec2([{"RuleNumber": 100, "RuleAction": "allow", "Egress": False, "CidrBlock": "0.0.0.0/0"},
                {"RuleNumber": 1, "RuleAction": "deny", "Egress": False, "CidrBlock": "203.0.113.1/32"},
                {"RuleNumber": 32767, "RuleAction": "deny", "Egress": False, "CidrBlock": "0.0.0.0/0"}])  # fmt: skip
    with pytest.raises(sg_remediate.RemediateError, match="approved"):
        sg_remediate.apply_block(st, ec2, "111122223333", r["id"], alice)
    st.decide(r["id"], bob, True)
    with st:
        st.set_mode("111122223333", "enforce", bob, "ready")
    got = sg_remediate.apply_block(st, ec2, "111122223333", r["id"], bob)
    assert ec2.added == [{"NetworkAclId": "acl-1", "RuleNumber": 2, "Protocol": "-1", "RuleAction": "deny",
                          "Egress": False, "CidrBlock": "198.51.100.9/32"}]  # fmt: skip
    assert got["added"][0]["subnets"] == ["subnet-1", "subnet-2"]
    assert st._request(r["id"])["status"] == "applied"
    assert sg_remediate._free_rule_number([{"RuleNumber": 1, "RuleAction": "allow"}]) is None
