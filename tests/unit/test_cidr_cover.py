"""The exact minimum-waste CIDR cover (2.3.0) against brute force and 2.2.0.

``waste`` is the number of addresses a set of CIDRs grants that were never
observed. The new code must be optimal on small cases, never waste more than
2.2.0 did (tests/fixtures/legacy_collapse.py), and stay fast on large ones.
"""

from __future__ import annotations

import bisect
import ipaddress
import itertools
import logging
import random
import time
import unittest

import sg_tightener as sg
from tests.fixtures import legacy_collapse as legacy

N = ipaddress.ip_network
RFC1918 = [N("10.0.0.0/8"), N("172.16.0.0/12"), N("192.168.0.0/16")]


def waste(cidrs, ips) -> int:
    nets = list(ipaddress.collapse_addresses(N(str(c)) for c in cidrs))
    return sum(n.num_addresses for n in nets) - len(set(ips))


def covers(cidrs, ips) -> bool:
    nets = [N(str(c)) for c in cidrs]
    return all(any(ipaddress.ip_address(ip) in n for n in nets) for ip in ips)


def clustered(seed: int, n: int, prefix: str = "10") -> list[str]:
    r = random.Random(seed)
    return [f"{prefix}.{r.choice([1, 1, 1, 2, 9])}.{r.choice([4, 5, 6, 40, 200])}.{r.randint(0, 255)}"
            for _ in range(n)]


def optimal_waste(ips: list[str], k: int, root: ipaddress.IPv4Network) -> int:
    """Brute-force-style oracle: min-plus over the full (uncompressed) binary tree under ``root``."""
    xs = sorted({int(ipaddress.ip_address(i)) for i in ips})

    def solve(base: int, plen: int) -> list:
        size = 1 << (32 - plen)
        c = bisect.bisect_left(xs, base + size) - bisect.bisect_left(xs, base)
        if c == 0:
            return [0] * (k + 1)
        if plen == 32:
            return [float("inf")] + [0] * k
        left, right = solve(base, plen + 1), solve(base + size // 2, plen + 1)
        best = [float("inf")] * (k + 1)
        for i in range(k + 1):
            for j in range(k + 1 - i):
                best[i + j] = min(best[i + j], left[i] + right[j])
        for i in range(1, k + 1):
            best[i] = min(best[i], size - c, best[i - 1])
        return best

    return solve(int(root.network_address), root.prefixlen)[k]


class CoverIsOptimal(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.WARNING)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_matches_brute_force_at_zero_tolerance(self):
        root = N("10.0.0.0/22")
        for seed in range(40):
            r = random.Random(seed)
            ips = [str(ipaddress.ip_address(int(root.network_address) + r.randrange(1024)))
                   for _ in range(r.randint(2, 40))]
            for k in (1, 2, 3, 5, 8):
                got = sg.collapse_ips_to_cidrs(ips, max_rules=k, tolerance=0.0)
                self.assertLessEqual(len(got), k)
                self.assertTrue(covers(got, ips))
                # A /22 root is inside 10/8, so the oracle's tree is a subtree of the real one;
                # with k >= 1 the best cover never needs to leave the smallest block around the set.
                self.assertEqual(waste(got, ips), optimal_waste(ips, k, root), (seed, k, got))

    def test_split_budget_matches_brute_force(self):
        r = random.Random(7)
        for _ in range(60):
            n = r.randint(1, 4)
            curves = []
            for _ in range(n):
                vals = sorted((r.randint(0, 500) for _ in range(r.randint(1, 5))), reverse=True)
                curves.append([float("inf")] + vals)
            budget = r.randint(n, 12)
            fns = [lambda k, c=c: c[min(k, len(c) - 1)] for c in curves]
            got = sg._split_budget(fns, [len(c) - 1 for c in curves], budget)
            self.assertLessEqual(sum(got), budget)
            self.assertTrue(all(k >= 1 for k in got))
            best = min(sum(f(k) for f, k in zip(fns, ks))
                       for ks in itertools.product(range(1, budget + 1), repeat=n) if sum(ks) <= budget)
            self.assertEqual(sum(f(k) for f, k in zip(fns, got)), best)

    def test_split_budget_gives_one_each_when_over(self):
        fns = [lambda k: 10 - k] * 3
        self.assertEqual(sg._split_budget(fns, [5, 5, 5], 2), [1, 1, 1])


class NeverWiderThan220(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.WARNING)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_collapse_never_wastes_more(self):
        cases = 0
        for seed in range(12):
            r = random.Random(seed)
            ips = clustered(seed, r.choice([30, 80, 150]))
            ips += [f"172.16.{r.randint(0, 15)}.{r.randint(0, 255)}" for _ in range(r.randint(0, 40))]
            for k in (3, 10, 40):
                for t in (0.0, 0.3, 0.6):
                    new = sg.collapse_ips_to_cidrs(ips, max_rules=k, tolerance=t)
                    old = legacy.collapse_ips_to_cidrs(ips, max_rules=k, tolerance=t)
                    self.assertTrue(covers(new, ips))
                    self.assertLessEqual(len(new), k)
                    self.assertTrue(all(any(N(c).subnet_of(b) for b in RFC1918) for c in new), new)
                    self.assertLessEqual(waste(new, ips), waste(old, ips), (seed, k, t))
                    cases += 1
        self.assertEqual(cases, 108)

    def test_identical_when_tolerance_already_fits(self):
        for seed in range(10):
            ips = clustered(seed, 50)
            self.assertEqual(sg.collapse_ips_to_cidrs(ips, max_rules=500),
                             legacy.collapse_ips_to_cidrs(ips, max_rules=500))

    def test_public_addresses_are_never_merged(self):
        ips = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "10.0.0.1", "10.0.0.200"]
        got = sg.collapse_ips_to_cidrs(ips, max_rules=4, tolerance=0.0)
        self.assertIn("8.8.8.8/32", got)
        self.assertIn("8.8.4.4/32", got)
        self.assertIn("1.1.1.1/32", got)
        self.assertIn("10.0.0.0/24", got)

    def test_plan_grants_no_more_than_220(self):
        """Whole plans: the exact budget split versus 2.2.0's proportional one."""
        for seed in range(12):
            r = random.Random(seed)
            rules = ["10.4.0.0/16", "10.8.0.0/20", "10.9.0.0/16", "172.16.0.0/14"]
            ips = clustered(seed, 200, "10")
            ips += [f"10.4.{r.randint(0, 255)}.{r.randint(0, 255)}" for _ in range(60)]
            ips += [f"10.8.{r.randint(0, 15)}.{r.randint(0, 255)}" for _ in range(40)]
            ips += [f"172.17.{r.randint(0, 3)}.{r.randint(0, 255)}" for _ in range(30)]
            group = {"GroupId": "sg-a", "GroupName": "a", "VpcId": "vpc-1", "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": c} for c in rules]}]}
            for budget, t in ((6, 0.0), (12, 0.3), (40, 0.3)):
                plan = sg.build_plan([group], ips, max_rules=budget, tolerance=t)
                granted = [c["CidrIp"] for p in plan["groups"][0]["authorise"] for c in p["IpRanges"]]
                self.assertLessEqual(len(granted), budget)
                self.assertTrue(covers(granted, [ip for ip in ips if any(ipaddress.ip_address(ip) in N(c)
                                                                         for c in rules)]))
                per_rule = [sorted({ip for ip in ips if ipaddress.ip_address(ip) in N(c)}) for c in rules]
                needs = [len(legacy._replacements_within(N(c), u, 10**9, t)) if u else 0
                         for c, u in zip(rules, per_rule)]
                slots = legacy._allocate_budget(needs, budget)
                old = [n for c, u, s in zip(rules, per_rule, slots) if u
                       for n in legacy._replacements_within(N(c), u, s, t)]
                self.assertLessEqual(waste(granted, ips), waste(old, ips), (seed, budget, t))

    def test_slots_go_where_they_save_most(self):
        """30 hosts that merge almost free should not starve a rule where one slot saves a /16."""
        ips = [f"10.4.0.{i}" for i in range(0, 60, 2)] + ["10.8.0.1", "10.8.255.1"]
        group = {"GroupId": "sg-a", "GroupName": "a", "VpcId": "vpc-1", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
             "IpRanges": [{"CidrIp": "10.4.0.0/16"}, {"CidrIp": "10.8.0.0/16"}]}]}
        plan = sg.build_plan([group], ips, max_rules=4, tolerance=0.0)
        granted = {c["CidrIp"] for p in plan["groups"][0]["authorise"] for c in p["IpRanges"]}
        self.assertIn("10.8.0.1/32", granted)
        self.assertIn("10.8.255.1/32", granted)


class FastEnough(unittest.TestCase):
    def test_two_thousand_addresses(self):
        logging.disable(logging.WARNING)
        try:
            r = random.Random(1)
            ips = [f"10.{r.randint(0, 3)}.{r.randint(0, 255)}.{r.randint(0, 255)}" for _ in range(2000)]
            start = time.monotonic()
            got = sg.collapse_ips_to_cidrs(ips)
            self.assertLess(time.monotonic() - start, 5.0)  # 2.2.0 took about 28 s
            self.assertLessEqual(len(got), sg.DEFAULT_MAX_RULES)
            self.assertTrue(covers(got, ips))
        finally:
            logging.disable(logging.NOTSET)


if __name__ == "__main__":
    unittest.main()
