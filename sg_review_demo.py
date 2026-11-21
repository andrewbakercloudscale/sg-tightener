#!/usr/bin/env python3
"""sg_review_demo.py — a made-up Security Group Review read: no AWS calls.

Builds the same cache document ``sg_review.py read`` does (security groups, interfaces, network ACL, VPN
routes, flow log, rule history and flow-log slices), so the report runs on the real code path. Used by
``sg_review.py demo`` and the tests. The story it tells: a database group open to a whole /12 nobody uses,
a DR source seen on one day, a batch rule added three weeks ago, a public load balancer used through
CloudFront, a partner whose new address is being refused, scanners, a probe, and a data centre host turned
away by a network ACL.
"""

from __future__ import annotations

import ipaddress
import random

import sg_review
from sg_review import DAY, HOUR

ACCOUNT = "123456789012"
NAME = "payments-demo"
REGION = "eu-west-1"
VPC = "10.20.0.0/16"
VPC6 = "2a05:d018:abc:c00::/56"  # the VPC's IPv6 block (Amazon-provided)
ONPREM6 = "fd12:3456::/48"  # the data centre's unique local IPv6 range, over the VPN
OTHER = ("Payments prod (111122223333)", "10.40.0.0/16")
INTERNAL = f"{OTHER[1]} {OTHER[0]}"
# the demo's names file: the partner behind the SFTP rule, and a network they say is theirs
NAMES = [{"name": "Acme payroll", "type": "partner", "ranges": ["203.0.113.0/24", "2001:db8:acce::/48"],
          "note": "SFTP drop for payroll files"}]  # fmt: skip

DEMO_BYTES_PER_HOUR = 150_000_000  # what the made-up flow logs "scan" per hour, for the cost estimate


def _host(cidr: str, offset: int) -> str:
    return str(ipaddress.IPv4Network(cidr, strict=False).network_address + offset)


def snapshot(region: str, vpc: str, now: float) -> dict:
    h = lambda o: _host(vpc, o)
    sub = {"app": "subnet-0a11", "db": "subnet-0b22", "pub": "subnet-0c33", "ops": "subnet-0d44"}

    def rule(proto, lo, hi, cidrs, descs=None, v6=(), refs=(), xrefs=()):
        return {"proto": proto, "from": lo, "to": hi, "cidrs": cidrs, "descs": descs or {}, "pls": [],
                "refs": list(refs), "any6": "::/0" in v6, "cidrs6": list(v6), "xrefs": list(xrefs)}  # fmt: skip

    out_all = [rule("-1", 0, 65535, ["0.0.0.0/0"])]  # every group's outbound: the AWS default

    groups = {
        "sg-0app0000000000001": {"name": "app-servers", "vpc": "vpc-0demo", "tag": "",
                                 "rules": [rule("6", 443, 443, ["10.0.0.0/8"], {"10.0.0.0/8": "internal callers"},
                                                v6=[ONPREM6]),
                                           rule("6", 9100, 9100, [_host(vpc, 7 * 256) + "/24"],
                                                {_host(vpc, 7 * 256) + "/24": "monitoring"})]},
        "sg-0db00000000000002": {"name": "payments-db", "vpc": "vpc-0demo", "tag": "",
                                 "rules": [rule("6", 5432, 5432, [vpc, "172.16.0.0/12"]),
                                           rule("6", 5432, 5432, [], refs=["sg-0rep0000000000077"],
                                                xrefs=[{"group": "sg-0rep0000000000077", "account": "444455556666",
                                                        "peering": "pcx-0demo"}])]},
        "sg-0alb0000000000003": {"name": "public-alb", "vpc": "vpc-0demo", "tag": "",
                                 "rules": [rule("6", 443, 443, ["0.0.0.0/0"])]},
        "sg-0sftp000000000004": {"name": "partner-sftp", "vpc": "vpc-0demo", "tag": "",
                                 "rules": [rule("6", 22, 22, ["203.0.113.0/24"], {"203.0.113.0/24": "partner"},
                                                v6=["::/0"])]},
        "sg-0bat0000000000005": {"name": "batch-workers", "vpc": "vpc-0demo", "tag": "",
                                 "rules": [rule("6", 8080, 8080, ["10.0.0.0/8"])]},
        "sg-0leg0000000000008": {"name": "legacy-admin", "vpc": "vpc-0demo", "tag": "",
                                 "rules": [rule("6", 3389, 3389, ["0.0.0.0/0"], {"0.0.0.0/0": "temporary, vendor support"})]},
        "sg-0vpce000000000009": {"name": "secrets-endpoint", "vpc": "vpc-0demo", "tag": "",
                                 "rules": [rule("6", 443, 443, ["10.0.0.0/8"], {"10.0.0.0/8": "default from module"})]},
        "sg-0nlb0000000000010": {"name": "payments-api-nlb", "vpc": "vpc-0demo", "tag": "",
                                 "rules": [rule("6", 443, 443, ["10.0.0.0/8"])]},
        "sg-0ops0000000000006": {"name": "ops-ssh", "vpc": "vpc-0demo", "tag": "",
                                 "rules": [rule("6", 22, 22, ["10.200.0.0/16"], v6=["2c0f:fb50::/32"]),
                                           rule("6", 22, 22, ["0.0.0.0/0"], {"0.0.0.0/0": "debug, remove after"})]},
        "sg-0old0000000000007": {"name": "unused-sg", "vpc": "vpc-0demo", "tag": "",
                                 "rules": [rule("-1", 0, 65535, ["10.0.0.0/8"])]},
        "sg-0def000000000011": {"name": "default", "vpc": "vpc-0demo", "tag": "",
                                "rules": [rule("-1", 0, 65535, [], refs=["sg-0def000000000011"]),
                                          rule("6", 22, 22, ["10.0.0.0/8"])]},
    }  # fmt: skip
    for g in groups.values():
        g["owner"] = ACCOUNT
        g["egress"] = out_all

    def eni(ip, groups_, subnet, kind="EC2 instance", desc="", public=""):
        return {"ips": [ip], "prefixes": [], "groups": groups_, "subnet": subnet, "vpc": "vpc-0demo", "kind": kind,
                "desc": desc, "instance": "", "public": public}  # fmt: skip

    enis = {
        "eni-0app1": eni(h(2 * 256 + 11), ["sg-0app0000000000001"], sub["app"]),
        "eni-0app2": eni(h(2 * 256 + 12), ["sg-0app0000000000001"], sub["app"]),
        "eni-0app3": eni(h(2 * 256 + 13), ["sg-0app0000000000001", "sg-0ops0000000000006"], sub["app"]),
        "eni-0db01": eni(h(4 * 256 + 20), ["sg-0db00000000000002"], sub["db"], "RDS database", "RDSNetworkInterface"),
        "eni-0alb1": eni(h(1 * 256 + 30), ["sg-0alb0000000000003"], sub["pub"], "Load balancer", "ELB app/public"),
        "eni-0sftp": eni(h(1 * 256 + 40), ["sg-0sftp000000000004"], sub["pub"], public="198.51.100.7"),
        "eni-0bat1": eni(h(6 * 256 + 50), ["sg-0bat0000000000005", "sg-0def000000000011"], sub["app"]),
        "eni-0leg1": eni(h(1 * 256 + 60), ["sg-0leg0000000000008"], sub["pub"], public="198.51.100.9"),
        "eni-0nat1": eni(h(1 * 256 + 5), [], sub["pub"], "NAT gateway", "Interface for NAT Gateway"),
        "eni-0vpce1": eni(h(2 * 256 + 90), ["sg-0vpce000000000009"], sub["app"], "VPC endpoint",
                          "VPC Endpoint Interface vpce-0secrets"),
    }
    enis["eni-0sftp"]["ipv6"] = ["2a05:d018:abc:c33::40"]
    enis["eni-0app1"]["ipv6"] = ["2a05:d018:abc:c11::11"]
    enis["eni-0db01"]["groups"].append("sg-0bat0000000000005")  # the batch group, reused on the database
    nacl = {"id": "acl-0demo", "entries": [
        {"n": 90, "proto": "6", "allow": False, "cidr": "10.200.9.0/24", "from": 22, "to": 22},
        {"n": 100, "proto": "-1", "allow": True, "cidr": "0.0.0.0/0", "from": 0, "to": 65535},
    ]}  # fmt: skip
    return {
        "errors": [],
        "vpcs": [{"id": "vpc-0demo", "name": "main", "cidrs": [vpc], "cidrs6": [VPC6]}],
        "groups": groups,
        "enis": enis,
        "prefix_lists": {},
        "nacls": {s: nacl for s in sub.values()},
        "vpns": [{"name": "Johannesburg DC", "routes": ["10.200.0.0/16", ONPREM6]}],
        "routes": {"read": True, "subnets": {sub["pub"]: {"igw4": True, "igw6": True, "table": "rtb-0pub"}},
                   "main": {"vpc-0demo": {"igw4": False, "igw6": False, "table": "rtb-0main"}}},
        "stale": [{"group": "sg-0app0000000000001", "name": "app-servers", "vpc": "vpc-0demo", "direction": "in",
                   "proto": "6", "from": 8443, "to": 8443, "ref": "sg-0gone000000000099", "account": ACCOUNT,
                   "peering": ""}],
        "privatelink": {
            "read": True,
            "services": [{
                "id": "vpce-svc-0demo00000000001", "name": "payments-api", "service":
                "com.amazonaws.vpce.eu-west-1.vpce-svc-0demo00000000001", "state": "Available", "acceptance": False,
                "principals": ["*"],
                "connections": [{"id": "vpce-0c0n1", "owner": "111122223333", "state": "available"},
                                {"id": "vpce-0c0n2", "owner": "444455556666", "state": "available"}],
                "nlbs": [{"arn": "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/net/payments-api/0d"
                          "emo", "name": "payments-api", "groups": ["sg-0nlb0000000000010"], "enforce": "off",
                          "scheme": "internal"}],
                "gwlbs": []}],
            "endpoints": [{"id": "vpce-0secrets", "service": "com.amazonaws.eu-west-1.secretsmanager",
                           "vpc": "vpc-0demo", "name": "secrets-manager", "state": "available",
                           "groups": ["sg-0vpce000000000009"], "enis": ["eni-0vpce1"]}],
        },
        "flow_logs": [
            {
                "id": "fl-0demo",
                "resource": "vpc-0demo",
                "traffic": "ALL",
                "dest": "cloud-watch-logs",
                "group": "/vpc/flow-logs",
                "format": sg_review.DEFAULT_FORMAT,
                "status": "ACTIVE",
                "created": now - 400 * DAY,
            }
        ],  # fmt: skip
    }


def history(now: float) -> dict:
    return {
        "read": True,
        "whole_since": now - 90 * DAY,
        "events": [
            {"t": now - 40 * DAY, "name": "RevokeSecurityGroupIngress", "who": "network-team", "group":
             "sg-0db00000000000002", "added": [], "removed": [["6", 5432, 5432, "192.168.0.0/16"]], "unknown": False},
            {"t": now - 30 * DAY, "name": "AuthorizeSecurityGroupIngress", "who": "network-team", "group":
             "sg-0ops0000000000006", "added": [["6", 22, 22, "10.200.0.0/16"]], "removed": [], "unknown": False},
            {"t": now - 30 * DAY + 60, "name": "RevokeSecurityGroupIngress", "who": "network-team", "group":
             "sg-0ops0000000000006", "added": [], "removed": [["6", 22, 22, "10.0.0.0/8"]], "unknown": False},
            {"t": now - 20 * DAY, "name": "AuthorizeSecurityGroupIngress", "who": "batch-pipeline", "group":
             "sg-0bat0000000000005", "added": [["6", 8080, 8080, "10.0.0.0/8"]], "removed": [], "unknown": False},
            {"t": now - 4 * DAY - 5 * HOUR, "name": "RevokeSecurityGroupIngress", "who": "jsmith", "group":
             "sg-0app0000000000001", "added": [], "removed": [["6", 8443, 8443, "10.40.0.0/16"]], "unknown": False},
            {"t": now - 2 * HOUR, "name": "AuthorizeSecurityGroupIngress", "who": "contractor-ops", "ip": "41.13.7.200",
             "group": "sg-0ops0000000000006", "added": [["6", 22, 22, "0.0.0.0/0"]], "removed": [], "unknown": False},
        ],
    }  # fmt: skip


def _patterns(vpc: str, other: tuple | None) -> list[dict]:
    """Who talks to whom: (source, target interface and address, port, accepted?, when active)."""
    h = lambda o: _host(vpc, o)
    o = (lambda n: _host(other[1], n)) if other else (lambda n: _host("10.99.0.0/16", n))
    app = [("eni-0app1", h(2 * 256 + 11)), ("eni-0app2", h(2 * 256 + 12)), ("eni-0app3", h(2 * 256 + 13))]
    db = ("eni-0db01", h(4 * 256 + 20))
    alb = ("eni-0alb1", h(256 + 30))
    sftp = ("eni-0sftp", h(256 + 40))
    bat = ("eni-0bat1", h(6 * 256 + 50))
    leg = ("eni-0leg1", h(256 + 60))
    pats = []
    # internal callers of the app servers: this VPC's load balancer and another account
    for i in range(6):
        pats.append({"src": h(256 + 100 + i), "to": app[i % 3], "port": 443, "ok": True, "p": 1.0, "rate": 60})
    for i in range(4):
        pats.append({"src": o(3 * 256 + 10 + i), "to": app[i % 3], "port": 443, "ok": True, "p": 0.9, "rate": 20})
    # the data centre, over the VPN
    for i in range(3):
        pats.append({"src": _host("10.200.4.0/24", 21 + i), "to": app[0], "port": 443, "ok": True, "p": 0.7, "rate": 8})
    pats.append({"src": "10.200.4.21", "to": app[2], "port": 22, "ok": True, "p": 0.3, "rate": 2})
    # app servers to the database
    for ip in app:
        pats.append({"src": ip[1], "to": db, "port": 5432, "ok": True, "p": 1.0, "rate": 200})
    # the DR replica in this VPC: seen on one day, 45 days ago, then on a failover test 9 days ago
    pats.append({"src": h(9 * 256 + 5), "to": db, "port": 5432, "ok": True, "only": [45, 9], "rate": 900})
    # monthly reconciliation from the data centre: the first of each month
    pats.append({"src": "10.200.7.15", "to": app[1], "port": 443, "ok": True, "monthly": True, "rate": 300})
    # batch workers, since the rule was added 20 days ago
    for i in range(3):
        pats.append({"src": h(5 * 256 + 60 + i), "to": bat, "port": 8080, "ok": True, "p": 0.8, "rate": 30,
                     "after": 19})  # fmt: skip
    # the public load balancer: CloudFront and the internet
    for i in range(8):
        pats.append({"src": _host("130.176.0.0/16", 7 * 256 + i), "to": alb, "port": 443, "ok": True, "p": 1.0,
                     "rate": 500})  # fmt: skip
    for i in range(5):
        pats.append({"src": _host("41.0.0.0/11", 1000 + 97 * i), "to": alb, "port": 443, "ok": True, "p": 0.4,
                     "rate": 5})  # fmt: skip
    # the partner: two addresses used, and their new one (a Zscaler egress) refused for the last 6 days
    pats.append({"src": "203.0.113.10", "to": sftp, "port": 22, "ok": True, "p": 0.6, "rate": 6, "before": 6})
    pats.append({"src": "203.0.113.11", "to": sftp, "port": 22, "ok": True, "p": 0.2, "rate": 3})
    pats.append({"src": "165.225.12.40", "to": sftp, "port": 22, "ok": False, "p": 0.6, "rate": 6, "after": 6})
    # a rule change that broke something: jsmith revoked 8443 from Payments prod four days ago, which its two
    # settlement callers still use
    for i in range(2):
        pats.append({"src": o(3 * 256 + 20 + i), "to": app[0], "port": 8443, "ok": True, "p": 0.9, "rate": 25,
                     "before": 4})  # fmt: skip
        pats.append({"src": o(3 * 256 + 20 + i), "to": app[0], "port": 8443, "ok": False, "p": 0.9, "rate": 25,
                     "after": 4})  # fmt: skip
    # a host inside the VPC sweeping ports on its neighbours for the last two days
    for i, port in enumerate((22, 23, 445, 3389, 6379, 9200, 27017, 2375, 10250, 1433, 5900, 11211)):
        pats.append({"src": h(3 * 256 + 77), "to": (app[0], app[1], bat)[i % 3], "port": port, "ok": False,
                     "p": 0.6, "rate": 3, "after": 2})  # fmt: skip
    # a vendor-support rule left open to the internet: scanners and a Tor exit found it
    for i in range(3):
        pats.append({"src": _host("162.142.125.0/24", 10 + 17 * i), "to": leg, "port": 3389, "ok": True, "p": 0.3,
                     "rate": 2})  # fmt: skip
    pats.append({"src": "185.220.101.33", "to": leg, "port": 3389, "ok": True, "p": 0.15, "rate": 3})
    # refused inside: a new service in another account trying the database, and a data centre host the ACL turns away
    pats.append({"src": o(4 * 256 + 44), "to": db, "port": 5432, "ok": False, "p": 0.9, "rate": 40, "after": 3})
    pats.append({"src": "10.200.9.9", "to": app[0], "port": 22, "ok": False, "p": 0.5, "rate": 4})
    # refused from the internet: health checks to a closed port, webhooks, scanners
    for i in range(3):
        pats.append({"src": _host("54.228.16.0/26", 8 + i), "to": alb, "port": 80, "ok": False, "p": 1.0,
                     "rate": 30})  # fmt: skip
    pats.append({"src": "140.82.112.5", "to": sftp, "port": 8443, "ok": False, "p": 0.3, "rate": 3})
    for i in range(12):
        pats.append({"src": _host("162.142.125.0/24", 10 + 17 * i), "to": sftp, "port": 3389, "ok": False,
                     "p": 0.25, "rate": 2, "sweep": True})  # fmt: skip
    pats.append({"src": "185.220.101.33", "to": alb, "port": 3389, "ok": False, "p": 0.2, "rate": 1, "sweep": True})
    # more ports: batch workers trying a cache on an app server, a data centre producer trying the batch workers'
    # Kafka port, the internal Prometheus scraping node exporters, and scanners on the ports they always try
    pats.append({"src": h(5 * 256 + 61), "to": app[1], "port": 6379, "ok": False, "p": 0.7, "rate": 15, "after": 10})
    pats.append({"src": "10.200.4.30", "to": bat, "port": 9092, "ok": False, "p": 0.5, "rate": 10, "after": 25})
    for ip in app:
        pats.append({"src": h(7 * 256 + 9), "to": ip, "port": 9100, "ok": True, "p": 1.0, "rate": 120})
    for port, net, n in ((445, "89.248.165.0/24", 6), (23, "71.6.199.0/24", 3), (5900, "193.163.125.0/24", 4),
                         (6379, "64.62.197.0/24", 3), (9200, "198.235.24.0/24", 3)):
        for i in range(n):
            pats.append({"src": _host(net, 20 + 11 * i), "to": alb if i % 2 else sftp, "port": port, "ok": False,
                         "p": 0.03, "rate": 1, "sweep": True})  # fmt: skip
    # a probe twelve days ago: seventy hosts of one network try SSH on the load balancer, all refused
    for i in range(70):
        pats.append({"src": _host("45.155.205.0/24", 2 + i), "to": alb, "port": 22, "ok": False, "p": 1.0, "rate": 2,
                     "only": [12], "sweep": True})  # fmt: skip
    # the app servers reading secrets through the Secrets Manager interface endpoint
    # IPv6: the partner's office reaching SFTP over IPv6, data centre hosts calling the app over the VPN's
    # unique local range, and a scanner's IPv6 address trying RDP on the SFTP server since two days ago
    sftp6, app6 = ("eni-0sftp", "2a05:d018:abc:c33::40"), ("eni-0app1", "2a05:d018:abc:c11::11")
    pats.append({"src": "2001:db8:acce:10::25", "to": sftp6, "port": 22, "ok": True, "p": 0.5, "rate": 4})
    for i in range(2):
        pats.append({"src": f"fd12:3456:0:4::{21 + i:x}", "to": app6, "port": 443, "ok": True, "p": 0.7, "rate": 6})
    pats.append({"src": "2602:80d:1003::17", "to": sftp6, "port": 3389, "ok": False, "p": 0.8, "rate": 2,
                 "after": 2, "sweep": True})  # fmt: skip
    vpce = ("eni-0vpce1", h(2 * 256 + 90))
    for ip in app:
        pats.append({"src": ip[1], "to": vpce, "port": 443, "ok": True, "p": 1.0, "rate": 40})
    return pats


def _active(p: dict, s: float, e: float, now: float, rnd: random.Random) -> bool:
    age_s, age_e = (now - e) / DAY, (now - s) / DAY
    if "only" in p:
        return any(age_s <= d < age_e or (age_e - age_s < 1 and int(age_s) == d) for d in p["only"])
    if p.get("monthly"):
        import datetime as dt

        t = s
        while t < e:
            if dt.datetime.fromtimestamp(t, dt.timezone.utc).day == 1:
                return True
            t += HOUR
        return False
    if "after" in p and age_e > p["after"] + (e - s) / DAY:
        return False
    if "before" in p and age_s < p["before"]:
        return False
    span = (e - s) / HOUR
    return rnd.random() < 1 - (1 - p["p"]) ** max(1.0, span / 6)


def chunk(region: str, s: int, e: int, pats: list, now: float, rnd: random.Random) -> dict:
    rows, pub = [], []
    hours = (e - s) / HOUR
    for p in pats:
        if not _active(p, s, e, now, rnd):
            continue
        eni, dst = p["to"]
        flows = max(1, int(p["rate"] * hours * rnd.uniform(0.6, 1.4)))
        private = ipaddress.ip_address(p["src"]).is_private
        if p["ok"] or private:
            rows.append([p["src"], dst, eni, "6", p["port"], "ACCEPT" if p["ok"] else "REJECT", flows])
        else:
            ports = rnd.randint(12, 40) if p.get("sweep") else 1
            pub.append([p["src"], flows * ports, ports, 3 if p.get("sweep") else 1, dst, eni, p["port"], "6"])
    # replies to the account's own connections land on high ports: kept out of the report
    eni, dst = pats[0]["to"]
    rows.append(["52.95.110.1", dst, eni, "6", 32768, "ACCEPT", max(1, int(50 * hours))])
    return {"r": region, "s": s, "e": e, "st": "ok", "b": int(DEMO_BYTES_PER_HOUR * hours), "rows": rows, "pub": pub,
            "pc": False, "err": "", "egr": _egress(s, e, now, rnd)}  # fmt: skip


def _egress(s: int, e: int, now: float, rnd: random.Random) -> list:
    """Outbound connections (read with --egress): the app servers call the database, Secrets Manager through
    its endpoint, S3 and a payments API; and a batch worker has been calling a Tor relay for the last three days."""
    h = lambda o: _host(VPC, o)
    hours = (e - s) / HOUR
    app = [("eni-0app1", h(2 * 256 + 11)), ("eni-0app2", h(2 * 256 + 12)), ("eni-0app3", h(2 * 256 + 13))]
    out = []
    for eni, ip in app:
        for dst, port, rate in ((h(4 * 256 + 20), 5432, 200), (h(2 * 256 + 90), 443, 40), ("52.218.48.10", 443, 30),
                                ("52.218.52.77", 443, 20), ("203.0.113.80", 443, 6)):
            out.append([ip, dst, eni, "6", port, max(1, int(rate * hours * rnd.uniform(0.6, 1.4)))])
    if now - e < 3 * DAY:
        out.append([h(6 * 256 + 50), "185.220.101.33", "eni-0bat1", "6", 9001, max(1, int(4 * hours))])
    return out


def build_doc(account: str, now: float, days: int, existing: dict | None = None) -> dict:
    doc = existing if existing and existing.get("mode") == "demo" else sg_review.new_doc(account, NAME, "demo")
    doc["egress"] = True
    qsets = [{"format": sg_review.DEFAULT_FORMAT, "groups": ["/vpc/flow-logs"]}]
    doc["regions"][REGION] = {"snapshot": snapshot(REGION, VPC, now), "history": history(now), "taken": now,
                              "query_sets": qsets}  # fmt: skip
    rnd = random.Random(int(account) if account.isdigit() else 7)
    pats = _patterns(VPC, OTHER)
    have = [(c["s"], c["e"]) for c in doc["chunks"] if c["r"] == REGION]
    todo = sg_review.plan(now, days, have)
    for s, e in todo:
        doc["chunks"].append(chunk(REGION, s, e, pats, now, rnd))
    nbytes = sum(int(DEMO_BYTES_PER_HOUR * (e - s) / HOUR) for s, e in todo)
    doc["reads"].append({"at": now, "days": days, "bytes": nbytes, "slices": len(todo)})
    return doc
