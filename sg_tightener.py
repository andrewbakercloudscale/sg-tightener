#!/usr/bin/env python3
"""sg_tightener.py — Evidence-based security group CIDR tightening.

Replaces broad RFC 1918 ingress rules on AWS security groups with the
tightest covering CIDR blocks empirically observed in VPC flow logs.

Modes:
  analyse  Read flow logs (CloudWatch Logs or S3) and emit an
           approved JSON file: the observed source IPs and, for
           each, the destination address and port it reached.
           Before reading, the flow logs
           feeding the destination are checked with
           ec2:DescribeFlowLogs: the parse layout is derived from
           the configured log format, and a warning is raised when
           the format lacks pkt-srcaddr — without it, traffic that
           arrives through a transit gateway or NAT gateway is
           recorded under the intermediate interface's IP (the next
           hop), not the true source.
  plan     Read the approved file, the current SG inventory and the
           network interfaces, and emit a plan.json describing rules
           to revoke and rules to authorise. Each group keeps only
           the sources that reached an interface carrying it. Plans are signed with a state hash so
           apply refuses to run against a stale snapshot.
  apply    Execute a plan. Halts immediately on any single-group
           failure and prints the revert command.
  revert   Restore the exact pre-apply state from the manifest
           written by the most recent apply.

This module also exposes a pure-Python CIDR collapse function
(``collapse_ips_to_cidrs``) used by the test suite. It is part of
the CloudToRepo project: https://cloudtorepo.com

Usage:
  sg_tightener.py analyse  --region <r> [--days 90] [--out approved.json]
                           [--log-group <name> | --s3-bucket <b> --s3-prefix <p>]
  sg_tightener.py plan     --region <r> --approved approved.json
                           [--max-rules 60] [--tolerance 0.30]
                           [--prefix-threshold 24] [--out plan.json]
  sg_tightener.py apply    --plan plan.json [--region <r>] [--yes]
  sg_tightener.py revert   --manifest manifest-<ts>.json [--yes]
"""

from __future__ import annotations

__version__ = "5.33.1"

import argparse
import bisect
import dataclasses
import datetime as dt
import gzip
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import sys
import time
from typing import Callable, Iterable, Iterator, Sequence

try:
    import boto3
    import botocore
    from botocore.config import Config as BotoConfig
except ImportError:
    boto3 = None
    botocore = None
    BotoConfig = None

LOG = logging.getLogger("sg_tightener")

# --------------------------------------------------------------------------- #
# Credentials: profiles, IAM Identity Center (SSO), and friendly login errors
# --------------------------------------------------------------------------- #

# botocore exception class names that mean "not logged in" rather than "denied".
_LOGIN_ERRORS = {
    "SSOTokenLoadError": "the SSO login has expired or was never made",
    "UnauthorizedSSOTokenError": "the SSO login has expired",
    "TokenRetrievalError": "the SSO login has expired",
    "SSOError": "the SSO login failed",
    "NoCredentialsError": "no AWS credentials were found",
    "PartialCredentialsError": "the AWS credentials are incomplete",
    "ProfileNotFound": "that AWS profile does not exist",
    "NoRegionError": "no region is set",
}
# Error codes AWS returns when credentials have expired or are not recognised.
_LOGIN_CODES = {"ExpiredToken", "ExpiredTokenException", "RequestExpired", "InvalidClientTokenId",
                "UnrecognizedClientException", "AuthFailure"}
_PROFILE: list = [None]


def add_profile_arg(parser: argparse.ArgumentParser) -> None:
    """Add --profile, which works for SSO (IAM Identity Center), role and key profiles alike."""
    parser.add_argument(
        "--profile",
        help="AWS profile to use, for example one set up with `aws configure sso` "
             "(default: the usual credential chain, including AWS_PROFILE)",
    )


def use_profile(profile: str | None) -> None:
    """Make every boto3 client in this process use `profile`. No-op for None."""
    _PROFILE[0] = profile or os.environ.get("AWS_PROFILE")
    if profile:
        _require_boto3()
        boto3.setup_default_session(profile_name=profile)


def login_hint(exc: BaseException, profile: str | None = None) -> str | None:
    """A plain message, with the command that fixes it, when `exc` means
    "you are not logged in"; None for every other error."""
    profile = profile or _PROFILE[0] or os.environ.get("AWS_PROFILE")
    flag = f" --profile {profile}" if profile else ""
    seen: set = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        names = {k.__name__ for k in type(exc).__mro__}
        for name, why in _LOGIN_ERRORS.items():
            if name in names:
                if name == "ProfileNotFound":
                    return (f"{why} ({exc}). List profiles with `aws configure list-profiles`, "
                            f"or create an SSO one with `aws configure sso`.")
                if name == "NoRegionError":
                    return f"{why}: pass --region (or --regions), or set AWS_REGION."
                if name.startswith(("SSO", "Unauthorized", "Token")):
                    return f"{why}. Log in again with: aws sso login{flag}"
                return (f"{why}. Log in with `aws sso login{flag}` (IAM Identity Center), "
                        f"or set AWS_PROFILE / pass --profile.")
        resp = getattr(exc, "response", None)
        code = (resp or {}).get("Error", {}).get("Code") if isinstance(resp, dict) else None
        if code in _LOGIN_CODES:
            return (f"AWS did not accept the credentials ({code}): they have probably expired. "
                    f"If you use SSO, log in again with: aws sso login{flag}")
        exc = exc.__cause__ or exc.__context__
    return None


def friendly_login_errors(main_fn: Callable) -> Callable:
    """Wrap a script's main(): a "not logged in" error becomes one line with the
    fix and exit code 1, instead of a traceback. Other errors pass through."""
    import functools

    @functools.wraps(main_fn)
    def wrapper(*a, **kw):
        try:
            return main_fn(*a, **kw)
        except SystemExit:
            raise
        except Exception as exc:  # re-raised unless it is a login error
            hint = login_hint(exc)
            if hint is None:
                raise
            LOG.error("%s", hint)
            return 1

    return wrapper

RFC1918_BLOCKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

DEFAULT_PREFIX_THRESHOLD = 24
# IPv6: a client is kept as its /64, the size of one subnet. Its own address changes within that /64 every
# day or so (temporary addresses, RFC 8981), so a /128 rule would break it. An IPv6 rule wider than a /64 is
# in scope when it is unique local (fc00::/7) or inside one of the account's own VPC IPv6 ranges: the IPv6
# counterparts of 10.0.0.0/8 rules. Public IPv6 ranges and ::/0 are left alone, as public IPv4 ranges are.
V6_SUBNET = 64
DEFAULT_V6_PREFIX_THRESHOLD = 64
ULA = ipaddress.ip_network("fc00::/7")
DEFAULT_TOLERANCE = 0.30
DEFAULT_MAX_RULES = 60
DEFAULT_DAYS = 90

# approved.json: v1 holds source IPs only; v2 adds ``flows``, the destination
# (address, port, protocol) each source reached. plan reads either.
APPROVED_SCHEMA_V1 = "sg-tightener.approved/v1"
APPROVED_SCHEMA_V2 = "sg-tightener.approved/v2"

# CloudWatch Logs Insights returns at most this many rows per query. A query
# that returns exactly this many has been cut off; see run_insights_query.
INSIGHTS_ROW_LIMIT = 10000


# --------------------------------------------------------------------------- #
# CIDR collapsing
# --------------------------------------------------------------------------- #

def _is_strict_rfc1918(net: ipaddress.IPv4Network) -> bool:
    return any(net.subnet_of(b) for b in RFC1918_BLOCKS)


def _normalise_ips(ips: Iterable[str]) -> list[ipaddress.IPv4Address]:
    out: list[ipaddress.IPv4Address] = []
    seen: set[ipaddress.IPv4Address] = set()
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip.strip())
        except (ValueError, AttributeError):
            continue
        if not isinstance(addr, ipaddress.IPv4Address):
            continue
        if addr not in seen:
            seen.add(addr)
            out.append(addr)
    return out


def _normalise_ips6(ips: Iterable[str]) -> list[ipaddress.IPv6Address]:
    out: list[ipaddress.IPv6Address] = []
    seen: set[ipaddress.IPv6Address] = set()
    for ip in ips:
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            continue
        if isinstance(addr, ipaddress.IPv6Address) and addr not in seen:
            seen.add(addr)
            out.append(addr)
    return out


def _home_of(base: int, plen: int) -> int:
    """Index of the RFC 1918 block holding (base, plen), or -1 for any other address."""
    for i, b in enumerate(RFC1918_BLOCKS):
        if plen >= b.prefixlen and (base >> (32 - b.prefixlen)) == (int(b.network_address) >> (32 - b.prefixlen)):
            return i
    return -1


def _count_in(xs: list[int], base: int, size: int) -> int:
    """How many of the sorted addresses ``xs`` fall in [base, base + size)."""
    return bisect.bisect_left(xs, base + size) - bisect.bisect_left(xs, base)


def _widest_block_for(
    addr: ipaddress.IPv4Address,
    observed: set[ipaddress.IPv4Address] | None,
    tolerance: float,
    xs: list[int] | None = None,
) -> ipaddress.IPv4Network:
    """Widest containing CIDR where (block_size - observed_in_block)/block_size <= tolerance.

    Always returns at least the /32 host route, and never widens past the
    RFC 1918 block the address belongs to. ``xs`` (the observed addresses as
    sorted integers) makes each count a binary search instead of a scan.
    """
    home_block = next((b for b in RFC1918_BLOCKS if addr in b), None)
    if home_block is None:
        return ipaddress.ip_network(f"{addr}/32")
    if xs is None:
        xs = sorted(int(o) for o in observed or ())
    a = int(addr)
    best = 32
    for prefix in range(31, home_block.prefixlen - 1, -1):
        size = 1 << (32 - prefix)
        in_block = _count_in(xs, a & ~(size - 1), size)
        if (size - in_block) / size <= tolerance:
            best = prefix
        else:
            break
    return ipaddress.ip_network((a & ~((1 << (32 - best)) - 1), best))


def _tolerance_blocks(
    xs: list[int],
    tolerance: float,
    within: ipaddress.IPv4Network | None = None,
) -> list[tuple[int, int, int]]:
    """Layer 1: every address widened as far as ``tolerance`` allows, merged.

    Returns disjoint (base, prefix length, observed count) blocks in address
    order. With ``within``, a block that grew past it is clipped back to it.
    These blocks are the finest cover sg-tightener will ever grant: their
    headroom is what ``--tolerance`` buys.
    """
    nets = set()
    for a in xs:
        n = _widest_block_for(ipaddress.IPv4Address(a), None, tolerance, xs)
        if within is not None and not n.subnet_of(within):
            n = within
        nets.add(n)
    out = []
    for n in ipaddress.collapse_addresses(nets):
        base = int(n.network_address)
        out.append((base, n.prefixlen, _count_in(xs, base, n.num_addresses)))
    return out


_INF = float("inf")


class _Node:
    __slots__ = ("base", "cost", "left", "plen", "right", "waste")


class _Cover:
    """The least wasteful way to cover a set of blocks with at most k CIDRs.

    ``leaves`` are disjoint (base, prefix length, observed count) blocks that
    must all be covered, and only whole: a leaf is never split. A covering
    CIDR is only ever the smallest one around some of the leaves, so the
    candidates are the nodes of the compressed binary tree over them, and for
    each node the cheapest cover with k CIDRs follows from its two children
    (cost = addresses granted that were never observed). ``curve[k]`` is that
    cost for the whole set; ``blocks(k)`` returns the CIDRs, fewest first on a
    tie. Exact, and O(leaves x kmax) rather than exponential.
    """

    def __init__(self, leaves: list[tuple[int, int, int]], kmax: int, bits: int = 32):
        self.kmax = max(1, kmax)
        self.bits = bits  # 32: IPv4 addresses; 64: IPv6 /64 subnets (an address's top 64 bits)
        self.root = self._build(leaves, 0, len(leaves))
        self.curve = self.root.cost

    def _build(self, leaves, lo: int, hi: int) -> _Node:
        node = _Node()
        node.left = node.right = None
        bits = self.bits
        if hi - lo == 1:
            node.base, node.plen, count = leaves[lo]
            node.waste = (1 << (bits - node.plen)) - count
            node.cost = [_INF, node.waste]
            return node
        first = leaves[lo][0]
        last_base, last_plen, _ = leaves[hi - 1]
        last = last_base + (1 << (bits - last_plen)) - 1
        node.plen = bits - (first ^ last).bit_length()
        node.base = first & ~((1 << (bits - node.plen)) - 1)
        mid = node.base + (1 << (bits - 1 - node.plen))
        split = bisect.bisect_left(leaves, (mid,), lo, hi)
        node.left = self._build(leaves, lo, split)
        node.right = self._build(leaves, split, hi)
        size = 1 << (bits - node.plen)
        node.waste = size - sum(c for _b, _p, c in leaves[lo:hi])
        left, right = node.left.cost, node.right.cost
        cap = min(self.kmax, len(left) - 1 + len(right) - 1)
        cost = [_INF] * (cap + 1)
        for i in range(1, len(left)):
            li = left[i]
            for j in range(1, min(len(right), cap - i + 1)):
                v = li + right[j]
                if v < cost[i + j]:  # noqa: PLR1730 (hot loop; min() is slower)
                    cost[i + j] = v
        cost[1] = node.waste
        for k in range(2, cap + 1):
            cost[k] = min(cost[k], node.waste, cost[k - 1])
        node.cost = cost
        return node

    def cost(self, k: int) -> float:
        return self.curve[min(k, len(self.curve) - 1)] if k >= 1 else _INF

    def blocks(self, k: int) -> list[ipaddress.IPv4Network]:
        out: list[ipaddress.IPv4Network] = []
        self._pick(self.root, k, out)
        return sorted(out, key=lambda n: (int(n.network_address), n.prefixlen))

    def _pick(self, node: _Node, k: int, out: list) -> None:
        cost = node.cost
        k = min(max(k, 1), len(cost) - 1)
        while k > 1 and cost[k] == cost[k - 1]:
            k -= 1
        if cost[k] == node.waste or node.left is None:
            out.append(ipaddress.ip_network((node.base, node.plen)) if self.bits == 32
                       else ipaddress.IPv6Network((node.base << (128 - self.bits), node.plen)))
            return
        left, right = node.left.cost, node.right.cost
        for i in range(max(1, k - len(right) + 1), min(len(left) - 1, k - 1) + 1):
            if left[i] + right[k - i] == cost[k]:
                self._pick(node.left, i, out)
                self._pick(node.right, k - i, out)
                return
        raise AssertionError("cover reconstruction failed")  # pragma: no cover


def _split_budget(curves: list[Callable[[int], float]], sizes: list[int], budget: int) -> list[int]:
    """Slots per cover that minimise the total waste, at least one each.

    ``curves[i](k)`` is cover i's waste with k CIDRs, flat beyond ``sizes[i]``.
    Exact (a knapsack over the covers), and the fewest slots on a tie. When
    the covers outnumber the budget, each gets one and the result is over it.
    """
    n = len(curves)
    if n == 0:
        return []
    if budget <= n:
        return [1] * n
    # best[b]: least waste of the covers so far using exactly b slots.
    best = [0.0] + [_INF] * budget
    choice: list[list[int]] = []
    for i, curve in enumerate(curves):
        nxt = [_INF] * (budget + 1)
        pick = [0] * (budget + 1)
        top = min(sizes[i], budget - (n - 1 - i))
        for b in range(i, budget + 1):
            if best[b] == _INF:
                continue
            for k in range(1, min(top, budget - b) + 1):
                v = best[b] + curve(k)
                if v < nxt[b + k]:
                    nxt[b + k], pick[b + k] = v, k
        best = nxt
        choice.append(pick)
    b = min(range(budget + 1), key=lambda x: (best[x], x))
    out = [0] * n
    for i in range(n - 1, -1, -1):
        out[i] = choice[i][b]
        b -= out[i]
    return out


def _smallest_covering(
    a: ipaddress.IPv4Network,
    b: ipaddress.IPv4Network,
) -> ipaddress.IPv4Network | None:
    """The smallest CIDR holding both, or None when they sit in different RFC 1918 blocks."""
    if not any(a.subnet_of(blk) and b.subnet_of(blk) for blk in RFC1918_BLOCKS):
        return None
    lo = min(int(a.network_address), int(b.network_address))
    hi = max(int(a.broadcast_address), int(b.broadcast_address))
    plen = 32 - (lo ^ hi).bit_length()
    return ipaddress.ip_network((lo & ~((1 << (32 - plen)) - 1), plen))


def collapse_ips_to_cidrs(
    ips: Sequence[str],
    max_rules: int = DEFAULT_MAX_RULES,
    tolerance: float = DEFAULT_TOLERANCE,
) -> list[str]:
    """Collapse observed IPs into a CIDR list <= max_rules in size.

    Layer 1: widen each IP to the widest block respecting ``tolerance`` (never
    past its RFC 1918 block), and merge.
    Layer 2: if that is over budget, choose the at most ``max_rules`` CIDRs
    that cover those blocks granting the fewest never-observed addresses
    (see _Cover), sharing the budget across the RFC 1918 blocks the same way.
    Public addresses are never merged with anything.

    Returns sorted ``"a.b.c.d/p"`` strings.
    """
    xs = sorted({int(a) for a in _normalise_ips(ips)})
    if not xs:
        return []
    t = max(0.0, min(1.0, tolerance))
    leaves = _tolerance_blocks(xs, t)
    if len(leaves) <= max_rules:
        return [str(ipaddress.ip_network((b, p))) for b, p, _c in leaves]

    by_home: dict[int, list] = {}
    singles = []
    for leaf in leaves:
        home = _home_of(leaf[0], leaf[1])
        if home < 0:
            singles.append([leaf])
        else:
            by_home.setdefault(home, []).append(leaf)
    covers = [_Cover(g, max_rules) for g in list(by_home.values()) + singles]
    slots = _split_budget([c.cost for c in covers], [len(c.curve) - 1 for c in covers], max_rules)
    nets = [n for c, k in zip(covers, slots) for n in c.blocks(k)]
    LOG.warning(
        "%d blocks at tolerance %.2f exceed the %d rule budget; merged into %d with the fewest "
        "extra addresses — request a quota increase from AWS Support to keep precision",
        len(leaves), t, max_rules, len(nets),
    )
    if len(nets) > max_rules:
        LOG.warning("%d public addresses cannot be merged: %d rules needed, budget %d",
                    len(singles), len(nets), max_rules)
    nets.sort(key=lambda n: (int(n.network_address), n.prefixlen))
    return [str(n) for n in nets]


# --------------------------------------------------------------------------- #
# Eligibility
# --------------------------------------------------------------------------- #

def _widen6(ids: list[int], tolerance: float, floor: int) -> list[tuple[int, int, int]]:
    """IPv6 layer 1, in /64 units: each /64 widened while at most ``tolerance`` of the block was never seen,
    never wider than a /``floor``. Disjoint (base, prefix length, /64s seen) blocks in order."""
    nets = set()
    for a in ids:
        best = V6_SUBNET
        for plen in range(V6_SUBNET - 1, floor - 1, -1):
            size = 1 << (V6_SUBNET - plen)
            if (size - _count_in(ids, a & ~(size - 1), size)) / size <= tolerance:
                best = plen
            else:
                break
        size = 1 << (V6_SUBNET - best)
        nets.add((a & ~(size - 1), best))
    out = []
    for base, plen in sorted(nets, key=lambda n: (n[0], n[1])):
        end = base + (1 << (V6_SUBNET - plen))
        if out and base < out[-1][0] + (1 << (V6_SUBNET - out[-1][1])):
            continue  # inside the block before it
        out.append((base, plen, _count_in(ids, base, end - base)))
    return out


def _rule_cover6(original: ipaddress.IPv6Network, ips: list[str], kmax: int, tolerance: float) -> _Cover:
    """The cover of the IPv6 sources inside ``original``, by /64, that never leaves it."""
    ids = sorted({int(a) >> (128 - V6_SUBNET) for a in _normalise_ips6(ips) if a in original})
    floor = min(original.prefixlen, V6_SUBNET)
    return _Cover(_widen6(ids, tolerance, floor), kmax, bits=V6_SUBNET)


def collapse_ipv6_to_cidrs(
    ips: Sequence[str],
    max_rules: int = DEFAULT_MAX_RULES,
    tolerance: float = DEFAULT_TOLERANCE,
    within: str | None = None,
) -> list[str]:
    """IPv6 sources as at most ``max_rules`` CIDRs: each source's /64, widened as ``tolerance`` allows (never
    past ``within``, or a /48 without it), then merged with the fewest unused /64s when over the budget.
    Without ``within``, sources in different /32s (different networks' allocations) are never merged.
    Sorted CIDR strings."""
    net = ipaddress.IPv6Network(within, strict=False) if within else None
    addrs = [a for a in _normalise_ips6(ips) if net is None or a in net]
    if not addrs:
        return []
    ids = sorted({int(a) >> (128 - V6_SUBNET) for a in addrs})
    t = max(0.0, min(1.0, tolerance))
    leaves = _widen6(ids, t, min(net.prefixlen, V6_SUBNET) if net else 48)
    nets = [ipaddress.IPv6Network((b << (128 - V6_SUBNET), p)) for b, p, _c in leaves]
    if len(leaves) > max_rules:
        if net is not None:
            homes = [leaves]
        else:  # one cover per /32: a merge never spans two networks' allocations
            by: dict[int, list] = {}
            for leaf in leaves:
                by.setdefault(leaf[0] >> 32, []).append(leaf)
            homes = list(by.values())
        covers = [_Cover(h, max_rules, bits=V6_SUBNET) for h in homes]
        slots = _split_budget([c.cost for c in covers], [len(c.curve) - 1 for c in covers], max_rules)
        nets = [n for c, k in zip(covers, slots) for n in c.blocks(k)]
        if net is not None:
            nets = [n if n.subnet_of(net) else net for n in nets]
    return [str(n) for n in sorted(set(ipaddress.collapse_addresses(nets)),
                                   key=lambda n: (int(n.network_address), n.prefixlen))]


def rule_is_eligible6(
    cidr: str | None,
    own: Iterable[str] = (),
    prefix_threshold: int = DEFAULT_V6_PREFIX_THRESHOLD,
) -> bool:
    """An IPv6 rule is in scope iff it is wider than ``prefix_threshold`` (a /64) and unique local or inside
    one of ``own`` (the account's VPC IPv6 ranges). ::/0 and public IPv6 ranges are left untouched."""
    if not cidr:
        return False
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    if not isinstance(net, ipaddress.IPv6Network) or not 0 < net.prefixlen < prefix_threshold:
        return False
    if net.subnet_of(ULA):
        return True
    for c in own:
        try:
            o = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if o.version == 6 and net.subnet_of(o):
            return True
    return False


def rule_is_eligible(
    cidr: str | None,
    prefix_threshold: int = DEFAULT_PREFIX_THRESHOLD,
) -> bool:
    """A rule is in-scope iff it is a strict RFC 1918 subset and shorter
    than the configured prefix threshold. Anything else — including
    0.0.0.0/0, overlapping non-private ranges, security-group references,
    IPv6, and already-tight CIDRs — is left untouched."""
    if not cidr:
        return False
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    if not isinstance(net, ipaddress.IPv4Network):
        return False
    if not _is_strict_rfc1918(net):
        return False
    return net.prefixlen < prefix_threshold


# --------------------------------------------------------------------------- #
# Port range merging
# --------------------------------------------------------------------------- #

def merge_port_ranges(
    ranges: Iterable[tuple[int, int]],
) -> list[tuple[int, int]]:
    """Merge adjacent or overlapping (from, to) ranges into smallest spanning ranges."""
    items = sorted((min(a, b), max(a, b)) for a, b in ranges)
    if not items:
        return []
    merged: list[tuple[int, int]] = [items[0]]
    for lo, hi in items[1:]:
        last_lo, last_hi = merged[-1]
        if lo <= last_hi + 1:
            merged[-1] = (last_lo, max(last_hi, hi))
        else:
            merged.append((lo, hi))
    return merged


# --------------------------------------------------------------------------- #
# Plan signing
# --------------------------------------------------------------------------- #

def state_hash(payload: object) -> str:
    blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


# --------------------------------------------------------------------------- #
# AWS helpers (only used by analyse/plan/apply/revert main entry points)
# --------------------------------------------------------------------------- #

def _require_boto3() -> None:
    if boto3 is None:
        sys.stderr.write(
            "boto3 is required. Activate the venv created by ./install.sh\n"
        )
        sys.exit(2)


def _client(service: str, region: str | None = None):
    _require_boto3()
    cfg = BotoConfig(retries={"max_attempts": 10, "mode": "adaptive"})
    return boto3.client(service, region_name=region, config=cfg)


def _list_security_groups(region: str) -> list[dict]:
    ec2 = _client("ec2", region)
    out: list[dict] = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        out.extend(page.get("SecurityGroups", []))
    return out


# --------------------------------------------------------------------------- #
# Flow-log configuration preflight
# --------------------------------------------------------------------------- #
# VPC flow logs only record the TRUE origin of traffic that reaches an
# interface through an intermediate hop — a transit gateway attachment ENI,
# a NAT gateway ENI, an EKS pod behind a node ENI — in the version-3
# ``pkt-srcaddr`` field. The DEFAULT log format stops at version 2: for such
# flows its ``srcaddr`` contains the private IP of the INTERMEDIATE interface
# (the next hop), not the client. An approved list built from default-format
# logs in a transit-gateway estate therefore contains TGW/NAT infrastructure
# addresses and misses the real client CIDRs. These checks verify the flow
# logs feeding the analysis before any list is written.

DEFAULT_LOG_FORMAT_FIELDS = [
    "version", "account-id", "interface-id", "srcaddr", "dstaddr",
    "srcport", "dstport", "protocol", "packets", "bytes",
    "start", "end", "action", "log-status",
]

# Custom format we recommend when warning: original addresses, direction,
# and everything the default format already provided.
RECOMMENDED_LOG_FORMAT = (
    "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} "
    "${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} "
    "${action} ${log-status} ${pkt-srcaddr} ${pkt-dstaddr} ${flow-direction}"
)


def parse_log_format(log_format: str) -> list[str]:
    """Ordered field names from a flow-log format string (``${field} ...``)."""
    return re.findall(r"\$\{([a-z0-9-]+)\}", log_format or "")


@dataclasses.dataclass
class FlowLogCheck:
    fields: list[str]        # ordered fields the parsers should use
    warnings: list[str]
    errors: list[str]        # fatal: the analysis output would be garbage
    verified: bool           # True when a matching flow-log config was found
    # ResourceIds (vpc-/subnet-/eni-) the matched flow logs capture, or None
    # when unknown. plan refuses to tighten groups outside them.
    resources: list[str] | None = None


def check_flow_log_config(
    flow_logs: list[dict],
    accepted_only: bool = True,
    traffic: str | None = None,
) -> FlowLogCheck:
    """Evaluates the describe_flow_logs entries that feed the analysis
    destination and returns the parse field order plus warnings/errors.

    ``traffic`` is what the caller needs: "ACCEPT", "REJECT" or "ALL". It
    defaults from ``accepted_only``. For "ALL" (the viewer export) a flow log
    that captures only one side is a warning, not an error: half the picture
    is still worth showing, as long as the reader is told.
    """
    if traffic is None:
        traffic = "ACCEPT" if accepted_only else "REJECT"
    warnings: list[str] = []
    errors: list[str] = []

    if not flow_logs:
        return FlowLogCheck(
            fields=list(DEFAULT_LOG_FORMAT_FIELDS),
            warnings=[
                "no flow log delivering to this destination was found in this "
                "account/region, so the log format cannot be verified (the logs "
                "may be delivered from another account). Analysis will assume "
                "the DEFAULT format — if these logs use a custom format the "
                "parsed columns WILL be wrong. Note the default format has no "
                "pkt-srcaddr field: traffic arriving through a transit gateway "
                "or NAT gateway is recorded with the intermediate interface's "
                "IP (the next hop), not the true source."
            ],
            errors=[],
            verified=False,
        )

    for fl in flow_logs:
        flid = fl.get("FlowLogId", "?")
        status = fl.get("FlowLogStatus", "")
        if status != "ACTIVE":
            warnings.append(f"flow log {flid} status is {status or 'unknown'}, not ACTIVE — its data may be stale or absent")
        if fl.get("DeliverLogsErrorMessage"):
            warnings.append(f"flow log {flid} reports a delivery error: {fl['DeliverLogsErrorMessage']}")
        ttype = fl.get("TrafficType", "")
        if traffic == "ACCEPT" and ttype == "REJECT":
            errors.append(f"flow log {flid} captures REJECT traffic only — an accepted-traffic analysis would observe nothing")
        if traffic == "REJECT" and ttype == "ACCEPT":
            errors.append(f"flow log {flid} captures ACCEPT traffic only — a rejected-traffic analysis would observe nothing")
        if traffic == "ALL" and ttype in ("ACCEPT", "REJECT"):
            warnings.append(f"flow log {flid} captures {ttype} traffic only — the other side will be missing from the picture")

    resources = sorted({fl["ResourceId"] for fl in flow_logs if fl.get("ResourceId")}) or None
    formats = {fl.get("LogFormat") or "" for fl in flow_logs}
    if len(formats) > 1:
        errors.append(
            "the flow logs feeding this destination use DIFFERENT log formats; "
            "records in one destination cannot be parsed positionally when the "
            "column order varies per record. Align the formats or split the "
            "destinations."
        )
        return FlowLogCheck(list(DEFAULT_LOG_FORMAT_FIELDS), warnings, errors, verified=True,
                            resources=resources)

    fields = parse_log_format(next(iter(formats)))
    if not fields:
        fields = list(DEFAULT_LOG_FORMAT_FIELDS)

    if "action" not in fields:
        errors.append("log format has no ${action} field — accepted traffic cannot be distinguished from rejected traffic")
    if "srcaddr" not in fields and "pkt-srcaddr" not in fields:
        errors.append("log format has neither ${srcaddr} nor ${pkt-srcaddr} — there is no source address to analyse")

    if "pkt-srcaddr" not in fields:
        warnings.append(
            "log format has no ${pkt-srcaddr} (v3) field. For traffic that "
            "reaches an interface through an intermediate hop — a transit "
            "gateway attachment ENI or a NAT gateway ENI — ${srcaddr} records "
            "the intermediate interface's private IP (the NEXT HOP), not the "
            "original client. Approved lists built from these logs can contain "
            "TGW/NAT infrastructure addresses and miss the real client CIDRs. "
            "Flow logs cannot be edited in place: create a replacement flow "
            f"log with a custom format such as: {RECOMMENDED_LOG_FORMAT}"
        )
    if "flow-direction" not in fields:
        warnings.append(
            "log format has no ${flow-direction} (v5) field — ingress and "
            "egress records cannot be separated, so the destinations of "
            "OUTBOUND connections also appear as observed sources and inflate "
            "the approved list."
        )

    return FlowLogCheck(fields, warnings, errors, verified=True, resources=resources)


def _describe_matching_flow_logs(region: str, log_group: str | None, s3_bucket: str | None):
    """Fetches flow-log configs that deliver to the analysis destination.
    Returns None when the API call itself fails (missing ec2:DescribeFlowLogs
    permission, endpoint issues) so the caller can degrade to a warning."""
    try:
        ec2 = _client("ec2", region)
        all_logs: list[dict] = []
        paginator = ec2.get_paginator("describe_flow_logs")
        for page in paginator.paginate():
            all_logs.extend(page.get("FlowLogs", []))
    except Exception as exc:  # noqa: BLE001 — any API failure degrades to "unverified"
        LOG.warning("could not verify flow-log configuration (ec2:DescribeFlowLogs failed: %s)", exc)
        return None

    matched = []
    for fl in all_logs:
        dest_type = fl.get("LogDestinationType", "cloud-watch-logs")
        if log_group and dest_type == "cloud-watch-logs" and fl.get("LogGroupName") == log_group:
            matched.append(fl)
        elif s3_bucket and dest_type == "s3":
            # LogDestination is arn:aws:s3:::bucket or arn:aws:s3:::bucket/prefix
            dest = fl.get("LogDestination", "")
            bucket = dest.split(":::", 1)[-1].split("/", 1)[0]
            if bucket == s3_bucket:
                matched.append(fl)
    return matched


# --------------------------------------------------------------------------- #
# Analyse
# --------------------------------------------------------------------------- #

@dataclasses.dataclass
class AnalyseConfig:
    region: str
    days: int
    log_group: str | None
    s3_bucket: str | None
    s3_prefix: str | None
    out_path: str
    accepted_only: bool = True
    # When set, the window is this many hours and ``days`` is ignored.
    hours: int | None = None
    traffic: str | None = None  # "ACCEPT" | "REJECT" | "ALL"; default from accepted_only

    def window(self, now: dt.datetime | None = None) -> tuple[dt.datetime, dt.datetime]:
        end = now or dt.datetime.now(dt.timezone.utc)
        span = dt.timedelta(hours=self.hours) if self.hours else dt.timedelta(days=self.days)
        return end - span, end


def build_cloudwatch_query(fields: list[str], accepted_only: bool = True) -> tuple[str, str]:
    """Builds the Logs Insights query for the given log format and returns
    (query, result_field_name).

    CloudWatch auto-discovers named fields (srcAddr, action, ...) ONLY for
    default-format VPC flow logs. Custom-format records must be split
    positionally out of @message, otherwise the query silently returns
    nothing — so the query is derived from the actual configured format."""
    wanted_action = "ACCEPT" if accepted_only else "REJECT"
    if fields == DEFAULT_LOG_FORMAT_FIELDS:
        query = (
            "fields srcAddr, action | "
            f"filter action = \"{wanted_action}\" | "
            "stats count() by srcAddr | "
            f"limit {INSIGHTS_ROW_LIMIT}"
        )
        return query, "srcAddr"

    idx = {f: i for i, f in enumerate(fields)}
    pattern = " ".join("*" for _ in fields)
    aliases = ", ".join(f"f{i}" for i in range(len(fields)))
    src = f"f{idx['pkt-srcaddr']}" if "pkt-srcaddr" in idx else f"f{idx['srcaddr']}"
    query = (
        f"fields @message | parse @message \"{pattern}\" as {aliases} | "
        f"filter f{idx['action']} = \"{wanted_action}\" | "
    )
    if "flow-direction" in idx:
        query += f"filter f{idx['flow-direction']} = \"ingress\" | "
    query += f"stats count() by {src} | limit {INSIGHTS_ROW_LIMIT}"
    return query, src


# Field names Logs Insights discovers on its own for DEFAULT-format flow logs.
_DISCOVERED_FIELD = {
    "version": "version", "account-id": "accountId", "interface-id": "interfaceId",
    "srcaddr": "srcAddr", "dstaddr": "dstAddr", "srcport": "srcPort",
    "dstport": "dstPort", "protocol": "protocol", "packets": "packets",
    "bytes": "bytes", "start": "start", "end": "end", "action": "action",
    "log-status": "logStatus",
}

# Logical record keys (as flow_records names them) -> flow-log fields, best first.
_LOGICAL_FIELDS = {
    "src": ("pkt-srcaddr", "srcaddr"),
    "dst": ("pkt-dstaddr", "dstaddr"),
    "srcport": ("srcport",),
    "dstport": ("dstport",),
    "protocol": ("protocol",),
    "action": ("action",),
    "packets": ("packets",),
    "bytes": ("bytes",),
    "interface": ("interface-id",),
}


def build_flow_stats_query(
    fields: list[str],
    *,
    by: Sequence[str],
    action: str | None = None,
    ingress_only: bool = True,
    bin_seconds: int | None = None,
) -> tuple[str, dict[str, str]]:
    """Logs Insights ``stats`` query over flow-log records, grouped by
    logical keys (``src``, ``dst``, ``dstport``, ``protocol``, ``action`` ...).

    Returns (query, columns) where ``columns`` maps each logical key, plus
    ``records``, ``packets``, ``bytes`` and ``bucket`` (when binned), to the
    name the result rows carry. Like build_cloudwatch_query, the query reads
    discovered field names for the default format and splits @message
    positionally for any custom one, and prefers pkt-srcaddr/pkt-dstaddr.
    """
    default = list(fields) == DEFAULT_LOG_FORMAT_FIELDS
    idx = {f: i for i, f in enumerate(fields)}

    def ref(logical: str) -> str:
        for name in _LOGICAL_FIELDS[logical]:
            if name in idx:
                return _DISCOVERED_FIELD[name] if default else f"f{idx[name]}"
        raise ValueError(f"flow-log format has no field for {logical!r}")

    if default:
        query = "fields @timestamp"
    else:
        pattern = " ".join("*" for _ in fields)
        aliases = ", ".join(f"f{i}" for i in range(len(fields)))
        query = f"fields @message | parse @message \"{pattern}\" as {aliases}"
    if action:
        query += f" | filter {ref('action')} = \"{action}\""
    if ingress_only and "flow-direction" in idx and not default:
        query += f" | filter f{idx['flow-direction']} = \"ingress\""

    columns = {key: ref(key) for key in by}
    group = [columns[key] for key in by]
    stats = ["count(*) as records"]
    columns["records"] = "records"
    for metric in ("packets", "bytes"):
        if any(n in idx for n in _LOGICAL_FIELDS[metric]):
            stats.append(f"sum({ref(metric)}) as {metric}_sum")
            columns[metric] = f"{metric}_sum"
    if bin_seconds:
        group.append(f"bin({int(bin_seconds)}s)")
        columns["bucket"] = f"bin({int(bin_seconds)}s)"
    query += f" | stats {', '.join(stats)} by {', '.join(group)} | limit {INSIGHTS_ROW_LIMIT}"
    return query, columns


def run_insights_query(
    logs,
    log_group: str,
    query: str,
    start: dt.datetime,
    end: dt.datetime,
    *,
    limit: int | None = None,
    min_window: dt.timedelta = dt.timedelta(minutes=1),
    poll_seconds: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict[str, str]]:
    """Run a Logs Insights query over [start, end] and return every row.

    Insights stops at ``limit`` rows without saying so. Returning that
    partial answer is how an approved list silently loses sources and the
    plan then revokes their access. So a result that reaches the limit is
    thrown away and the window is split in half, recursively, until every
    part fits. The caller merges the parts: every query used here is a
    ``stats ... by`` whose rows can be combined across windows.

    Raises RuntimeError when the query fails, or when a window of
    ``min_window`` still reaches the limit (refuse rather than truncate).
    Rows are returned as {field: value} dicts.
    """
    limit = INSIGHTS_ROW_LIMIT if limit is None else limit
    resp = logs.start_query(
        logGroupName=log_group,
        startTime=int(start.timestamp()),
        endTime=int(end.timestamp()),
        queryString=query,
    )
    qid = resp["queryId"]
    while True:
        result = logs.get_query_results(queryId=qid)
        status = result.get("status")
        if status in ("Complete", "Failed", "Cancelled", "Timeout"):
            break
        sleep(poll_seconds)
    if status != "Complete":
        raise RuntimeError(
            f"Logs Insights query on {log_group} ended with status {status} "
            f"for {start.isoformat()} to {end.isoformat()} — refusing to "
            "continue with a partial view"
        )
    rows = result.get("results", [])
    if len(rows) < limit:
        return [{c["field"]: c.get("value", "") for c in row} for row in rows]

    if end - start <= min_window:
        raise RuntimeError(
            f"Logs Insights returned {len(rows)} rows (its limit) even for the "
            f"{int((end - start).total_seconds())}s window starting "
            f"{start.isoformat()}; the answer would be truncated. Narrow the "
            "query (fewer interfaces, a smaller --days) rather than act on it."
        )
    mid = start + (end - start) / 2
    # Insights takes whole seconds; keep the halves from overlapping.
    mid = mid.replace(microsecond=0)
    LOG.info(
        "Logs Insights hit its %d-row limit for %s to %s; splitting the window",
        limit, start.isoformat(), end.isoformat(),
    )
    first = run_insights_query(logs, log_group, query, start, mid, limit=limit,
                               min_window=min_window, poll_seconds=poll_seconds, sleep=sleep)
    second = run_insights_query(logs, log_group, query, mid + dt.timedelta(seconds=1), end,
                                limit=limit, min_window=min_window,
                                poll_seconds=poll_seconds, sleep=sleep)
    return first + second


def _analyse_from_cloudwatch(cfg: AnalyseConfig, fields: list[str]) -> list[str]:
    logs = _client("logs", cfg.region)
    start, end = cfg.window()
    query, src_field = build_cloudwatch_query(fields, cfg.accepted_only)
    rows = run_insights_query(logs, cfg.log_group, query, start, end)
    # '-' is the flow-log placeholder for "not applicable" (e.g. pkt-srcaddr
    # on records where it could not be computed) — never a real source.
    return sorted({
        row[src_field]
        for row in rows
        if row.get(src_field) and row[src_field] != "-"
    })


# The logical keys a flow in approved.json carries: who (src) reached what
# (dst, dstport) over which protocol, logged by which interface. src, dst and
# dstport are required for per-group planning; protocol and interface are used
# when the format has them (interface makes attribution exact where VPCs reuse
# addresses).
_FLOW_KEYS = ("src", "dst", "dstport", "protocol", "interface")


def flow_keys_for(fields: list[str]) -> tuple[str, ...] | None:
    """The flow keys ``fields`` can supply, or None when the format has no
    destination address or port (then only source IPs can be recorded and
    ``plan`` falls back to per-rule evidence)."""
    keys = tuple(k for k in _FLOW_KEYS if any(n in fields for n in _LOGICAL_FIELDS[k]))
    if not {"src", "dst", "dstport"} <= set(keys):
        return None
    return keys


def _flow_entry(src: str | None, dst: str | None, dstport, protocol: str | None,
                interface: str | None = None) -> dict | None:
    """One approved.json flow, or None when there is no usable source.
    '-' (flow-log "not applicable") becomes None for dst, protocol and
    interface."""
    if not src or src == "-":
        return None
    port = dstport if isinstance(dstport, int) or dstport is None else _int_or_none(dstport)
    return {
        "src": src,
        "dst": dst if dst and dst != "-" else None,
        "dstport": port,
        "protocol": protocol if protocol and protocol != "-" else None,
        "interface": interface if interface and interface != "-" else None,
    }


def _sorted_flows(flows: Iterable[dict]) -> list[dict]:
    unique = {(f["src"], f["dst"], f["dstport"], f["protocol"], f.get("interface")): f for f in flows}
    return [unique[k] for k in sorted(
        unique, key=lambda k: (k[0], k[1] or "", -1 if k[2] is None else k[2], k[3] or "", k[4] or ""))]


def _analyse_flows_from_cloudwatch(cfg: AnalyseConfig, fields: list[str]) -> list[dict] | None:
    """Accepted ingress flows as (src, dst, dstport, protocol), or None when
    the log format records no destination (the caller falls back to IPs)."""
    keys = flow_keys_for(fields)
    if keys is None:
        return None
    logs = _client("logs", cfg.region)
    start, end = cfg.window()
    query, columns = build_flow_stats_query(
        fields, by=keys, action="ACCEPT" if cfg.accepted_only else "REJECT", ingress_only=True)
    rows = run_insights_query(logs, cfg.log_group, query, start, end)
    flows = []
    for row in rows:
        entry = _flow_entry(*(row.get(columns[k]) if k in columns else None for k in _FLOW_KEYS))
        if entry:
            flows.append(entry)
    return _sorted_flows(flows)


def _int_or_none(value: str | None) -> int | None:
    try:
        return int(value) if value not in (None, "-") else None
    except ValueError:
        return None


def flow_records(lines: Iterable[str], fields: list[str]) -> Iterator[dict]:
    """Parse space-separated flow-log records laid out per ``fields``.

    Yields one dict per record with: src, dst, srcport, dstport, protocol
    (IANA number as a string), action, packets, bytes, start, end,
    direction (None when the format has no flow-direction) and interface.

    ``src``/``dst`` prefer pkt-srcaddr/pkt-dstaddr (the ORIGINAL addresses)
    over srcaddr/dstaddr, which for traffic through a transit gateway or NAT
    gateway interface hold the intermediate hop's address. A "-" packet
    address falls back to the interface address. Header rows, short lines,
    and records with no action or no source (NODATA/SKIPDATA) are skipped.
    """
    idx = {f: i for i, f in enumerate(fields)}
    action_i = idx.get("action")
    if action_i is None or ("srcaddr" not in idx and "pkt-srcaddr" not in idx):
        return
    n = len(fields)

    def pick(parts: list[str], *names: str) -> str | None:
        for name in names:
            i = idx.get(name)
            if i is not None and parts[i] != "-":
                return parts[i]
        return None

    for line in lines:
        parts = line.split()
        if len(parts) < n:
            continue
        action = parts[action_i]
        # Also skips each file's header row: its 'action' column holds the
        # literal field name.
        if action not in ("ACCEPT", "REJECT"):
            continue
        src = pick(parts, "pkt-srcaddr", "srcaddr")
        if src is None:
            continue
        yield {
            "src": src,
            "dst": pick(parts, "pkt-dstaddr", "dstaddr"),
            "srcport": _int_or_none(pick(parts, "srcport")),
            "dstport": _int_or_none(pick(parts, "dstport")),
            "protocol": pick(parts, "protocol"),
            "action": action,
            "packets": _int_or_none(pick(parts, "packets")) or 0,
            "bytes": _int_or_none(pick(parts, "bytes")) or 0,
            "start": _int_or_none(pick(parts, "start")),
            "end": _int_or_none(pick(parts, "end")),
            "direction": pick(parts, "flow-direction"),
            "interface": pick(parts, "interface-id"),
        }


def ips_from_flow_log_lines(lines: Iterable[str], fields: list[str], accepted_only: bool = True) -> set[str]:
    """Extracts observed source addresses from space-separated flow-log
    records laid out per ``fields``. Prefers pkt-srcaddr (the ORIGINAL
    source) over srcaddr, which for traffic through a transit gateway or
    NAT gateway interface contains the intermediate hop's address."""
    wanted_action = "ACCEPT" if accepted_only else "REJECT"
    return {
        r["src"]
        for r in flow_records(lines, fields)
        if r["action"] == wanted_action and r["direction"] != "egress"
    }


def iter_s3_flow_log_lines(
    s3,
    bucket: str,
    prefix: str | None,
    start: dt.datetime,
    end: dt.datetime,
) -> Iterator[tuple[dict, list[str]]]:
    """Yield (object summary, lines) for every flow-log object in the window.

    Objects are selected by LastModified. ``.gz`` objects are decompressed.
    An object that cannot be read is logged and skipped; if more than 10% of
    the objects in the window fail, RuntimeError is raised after the last
    one, so nobody acts on a partial view.
    """
    prefix = (prefix or "").rstrip("/")
    total = 0
    failed = 0
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            if obj["LastModified"] < start or obj["LastModified"] > end:
                continue
            total += 1
            try:
                body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
                if obj["Key"].endswith(".gz"):
                    body = gzip.decompress(body)
                lines = body.decode("utf-8", errors="ignore").splitlines()
            except Exception as exc:  # noqa: BLE001 — broad on purpose, see docstring
                failed += 1
                LOG.warning("failed to read s3://%s/%s: %s", bucket, obj["Key"], exc)
                continue
            yield obj, lines
    if total and failed / total > 0.10:
        raise RuntimeError(
            f"S3 flow-log read failure ratio {failed}/{total} exceeds 10% — refusing "
            "to act on a partial view. Check IAM and bucket policies."
        )


def _analyse_from_s3(cfg: AnalyseConfig, fields: list[str]) -> list[str]:
    if not cfg.s3_bucket:
        return []
    s3 = _client("s3", cfg.region)
    start, end = cfg.window()
    ips: set[str] = set()
    for _obj, lines in iter_s3_flow_log_lines(s3, cfg.s3_bucket, cfg.s3_prefix, start, end):
        ips |= ips_from_flow_log_lines(lines, fields, cfg.accepted_only)
    return sorted(ips)


def _analyse_flows_from_s3(cfg: AnalyseConfig, fields: list[str]) -> list[dict] | None:
    """S3 counterpart of _analyse_flows_from_cloudwatch."""
    if flow_keys_for(fields) is None:
        return None
    if not cfg.s3_bucket:
        return []
    s3 = _client("s3", cfg.region)
    start, end = cfg.window()
    wanted_action = "ACCEPT" if cfg.accepted_only else "REJECT"
    flows = []
    for _obj, lines in iter_s3_flow_log_lines(s3, cfg.s3_bucket, cfg.s3_prefix, start, end):
        for r in flow_records(lines, fields):
            if r["action"] != wanted_action or r["direction"] == "egress":
                continue
            entry = _flow_entry(r["src"], r["dst"], r["dstport"], r["protocol"], r["interface"])
            if entry:
                flows.append(entry)
    return _sorted_flows(flows)


def preflight_flow_logs(cfg: AnalyseConfig) -> FlowLogCheck:
    """Verify the flow logs feeding cfg's destination and return the check.

    Logs every warning, and raises RuntimeError on a configuration that
    cannot answer the question (REJECT-only capture, no action or source
    field, mixed formats). Shared by ``analyse`` and ``sg_diagnose`` so both
    parse records with the configured log format rather than assuming one.
    """
    matched = _describe_matching_flow_logs(cfg.region, cfg.log_group, cfg.s3_bucket)
    if matched is None:
        check = FlowLogCheck(
            fields=list(DEFAULT_LOG_FORMAT_FIELDS),
            warnings=[
                "flow-log configuration could not be verified (add "
                "ec2:DescribeFlowLogs to the analysis role to enable this "
                "check) — assuming the DEFAULT log format. If these logs use "
                "a custom format the parsed columns WILL be wrong, and the "
                "default format records only the next-hop address (not the "
                "true source) for traffic through a transit gateway or NAT "
                "gateway."
            ],
            errors=[],
            verified=False,
        )
    else:
        check = check_flow_log_config(matched, cfg.accepted_only, traffic=cfg.traffic)

    for warning in check.warnings:
        LOG.warning("flow-log config: %s", warning)
    if check.errors:
        for error in check.errors:
            LOG.error("flow-log config: %s", error)
        raise RuntimeError(
            "flow-log configuration cannot support this analysis: "
            + "; ".join(check.errors)
        )
    return check


def run_analyse(cfg: AnalyseConfig) -> dict:
    if not cfg.log_group and not cfg.s3_bucket:
        raise ValueError("either --log-group or --s3-bucket is required")

    # Preflight: verify the flow logs feeding this destination can actually
    # answer "who talks to these instances" before writing any approved list.
    check = preflight_flow_logs(cfg)

    # Record which destination (address and port) each source reached, so
    # plan can give each group only the sources that reached its interfaces.
    if cfg.log_group:
        flows = _analyse_flows_from_cloudwatch(cfg, check.fields)
    else:
        flows = _analyse_flows_from_s3(cfg, check.fields)
    if flows is None:
        LOG.warning(
            "log format has no destination address or port, so approved.json "
            "will hold source IPs only and plan will grant every observed source "
            "inside a rule to every group carrying that rule (per rule, not per "
            "group). Add ${dstaddr} and ${dstport} (or ${pkt-dstaddr}) to the "
            "flow-log format for per-group plans."
        )
        if cfg.log_group:
            ips = _analyse_from_cloudwatch(cfg, check.fields)
        else:
            ips = _analyse_from_s3(cfg, check.fields)
    else:
        ips = sorted({f["src"] for f in flows})

    if not ips:
        raise RuntimeError(
            "no source IPs observed — refusing to write an empty approved list. "
            "Verify that flow logs are enabled and the analysis window contains traffic."
        )

    payload = {
        "schema": APPROVED_SCHEMA_V2 if flows is not None else APPROVED_SCHEMA_V1,
        "region": cfg.region,
        "days": cfg.days,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": "cloudwatch" if cfg.log_group else "s3",
        "flow_log_check": {
            "verified": check.verified,
            "fields": check.fields,
            "warnings": check.warnings,
            "resources": check.resources,
        },
        "ips": sorted(set(ips)),
    }
    if flows is not None:
        payload["flows"] = flows
    with open(cfg.out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    LOG.info("wrote %d observed IPs (%d flows) to %s", len(payload["ips"]),
             len(payload.get("flows", [])), cfg.out_path)
    return payload


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #

def _eligible_rules6(sg: dict, own: Iterable[str], prefix_threshold: int) -> list[dict]:
    out = []
    for perm in sg.get("IpPermissions", []):
        for ip in perm.get("Ipv6Ranges", []):
            if rule_is_eligible6(ip.get("CidrIpv6"), own, prefix_threshold):
                out.append({"cidr": ip["CidrIpv6"], "protocol": perm.get("IpProtocol"),
                            "from_port": perm.get("FromPort"), "to_port": perm.get("ToPort"),
                            "description": ip.get("Description"), "v6": True})
    return out


def _eligible_rules(sg: dict, prefix_threshold: int) -> list[dict]:
    out = []
    for perm in sg.get("IpPermissions", []):
        proto = perm.get("IpProtocol")
        from_p = perm.get("FromPort")
        to_p = perm.get("ToPort")
        for ip in perm.get("IpRanges", []):
            if rule_is_eligible(ip.get("CidrIp"), prefix_threshold):
                out.append({
                    "cidr": ip["CidrIp"],
                    "protocol": proto,
                    "from_port": from_p,
                    "to_port": to_p,
                    "description": ip.get("Description"),
                })
    return out


def _all_rule_count(sg: dict) -> int:
    n = 0
    for perm in sg.get("IpPermissions", []):
        n += len(perm.get("IpRanges", []))
        n += len(perm.get("Ipv6Ranges", []))
        n += len(perm.get("UserIdGroupPairs", []))
        n += len(perm.get("PrefixListIds", []))
    return n


def _rule_cover(
    original: ipaddress.IPv4Network,
    ips: list[str],
    kmax: int,
    tolerance: float,
) -> _Cover:
    """The cover of ``ips`` (all inside ``original``) that never leaves it.

    Layer-1 blocks that would grow past the original rule are clipped back to
    it, so a replacement can only ever narrow a rule.
    """
    xs = sorted({int(a) for a in _normalise_ips(ips)})
    return _Cover(_tolerance_blocks(xs, tolerance, within=original), kmax)


def _replacements_within(
    original: ipaddress.IPv4Network,
    ips: list[str],
    max_rules: int,
    tolerance: float,
) -> list[ipaddress.IPv4Network]:
    """Collapse ``ips`` (all inside ``original``) into at most ``max_rules`` CIDRs inside it."""
    return _rule_cover(original, ips, max_rules, tolerance).blocks(max_rules)


# Security-group protocol names -> the IANA numbers flow logs record.
_PROTOCOL_NUMBERS = {"tcp": "6", "udp": "17", "icmp": "1", "icmpv6": "58"}


def flow_matches_rule(flow: dict, protocol, from_port, to_port) -> bool:
    """Whether a rule (protocol, port range) would have admitted ``flow``.

    Protocol "-1" admits everything. Otherwise the flow's protocol must be
    the rule's, and for TCP and UDP its destination port must be inside the
    rule's range (for ICMP the rule's "ports" are type and code, which flow
    logs do not record, so only the protocol is compared). A flow with no
    protocol or no port recorded (an old or hand-edited approved.json) is
    not ruled out on that count.
    """
    proto = str(protocol).lower()
    if proto == "-1":
        return True
    wanted = _PROTOCOL_NUMBERS.get(proto, proto)
    if flow.get("protocol") is not None and str(flow["protocol"]) != wanted:
        return False
    port = flow.get("dstport")
    if wanted in ("6", "17") and port is not None and from_port is not None and to_port is not None:
        return int(from_port) <= int(port) <= int(to_port)
    return True


class InterfaceIndex:
    """Which network interface received a packet, from DescribeNetworkInterfaces.

    ``resolve(dst, iface)`` returns (interface, status):

    * ``ok``         the interface that owns ``dst``;
    * ``not-owner``  the flow record was logged by ``iface`` but ``iface``
                     does not own ``dst``: it is the SENDING side's copy of
                     the connection (an egress record in a format without
                     flow-direction) and says nothing about who received it;
    * ``unknown``    no interface owns ``dst`` (deleted, another account);
    * ``ambiguous``  no ``iface`` was recorded and interfaces in more than
                     one VPC use the address (VPCs with overlapping ranges).

    With an interface id the answer is exact even across overlapping VPCs.
    Delegated /28 prefixes (EKS prefix mode) count as owned addresses.
    """

    def __init__(self, interfaces: Iterable[dict]):
        self.by_id: dict[str, dict] = {}
        self._by_ip: dict[str, list[dict]] = {}
        self._prefixes: list[tuple[ipaddress.IPv4Network, dict]] = []
        for eni in interfaces:
            if eni.get("NetworkInterfaceId"):
                self.by_id[eni["NetworkInterfaceId"]] = eni
            for ip in self._ips(eni):
                self._by_ip.setdefault(ip, []).append(eni)
            for pfx in eni.get("Ipv4Prefixes", []) + eni.get("Ipv6Prefixes", []):
                try:
                    self._prefixes.append((ipaddress.ip_network(pfx.get("Ipv4Prefix") or pfx["Ipv6Prefix"]), eni))
                except (KeyError, ValueError):
                    continue

    @staticmethod
    def _ips(eni: dict) -> set[str]:
        ips = {eni.get("PrivateIpAddress")}
        ips |= {pa.get("PrivateIpAddress") for pa in eni.get("PrivateIpAddresses", [])}
        ips |= {str(ipaddress.ip_address(a["Ipv6Address"])) for a in eni.get("Ipv6Addresses", [])
                if a.get("Ipv6Address")}  # fmt: skip
        return ips - {None}

    def owners(self, ip: str | None) -> list[dict]:
        """Every interface owning ``ip`` (exact addresses first, then prefixes)."""
        if not ip:
            return []
        if ip in self._by_ip:
            return list(self._by_ip[ip])
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return []
        if addr.version == 6 and str(addr) in self._by_ip:  # flow logs may write it uncompressed
            return list(self._by_ip[str(addr)])
        return [eni for net, eni in self._prefixes if addr in net]

    def owns(self, eni: dict, ip: str) -> bool:
        return any(o is eni for o in self.owners(ip))

    def resolve(self, dst: str | None, iface: str | None = None,
                prefer_vpc: str | None = None) -> tuple[dict | None, str]:
        if iface and iface in self.by_id:
            eni = self.by_id[iface]
            return (eni, "ok") if dst and self.owns(eni, dst) else (None, "not-owner")
        owners = self.owners(dst)
        if not owners:
            return None, "unknown"
        vpcs = {o.get("VpcId") for o in owners}
        if len(vpcs) > 1:
            in_vpc = [o for o in owners if o.get("VpcId") == prefer_vpc] if prefer_vpc else []
            if not in_vpc:
                return None, "ambiguous"
            owners = in_vpc
        return owners[0], "ok"

    @staticmethod
    def groups(eni: dict | None) -> set[str]:
        return {g["GroupId"] for g in (eni or {}).get("Groups", []) if g.get("GroupId")}


def describe_groups(ec2, group_ids: Iterable[str]) -> dict[str, dict]:
    """{group id: group} for the ids that exist. DescribeSecurityGroups fails
    the whole call on one unknown id (a typo, a group owned by another
    account), so a failed chunk is retried one id at a time and the missing
    ids are simply absent."""
    found: dict[str, dict] = {}
    ids = list(dict.fromkeys(g for g in group_ids if g))
    for i in range(0, len(ids), 100):
        chunk = ids[i:i + 100]
        try:
            for sg in ec2.describe_security_groups(GroupIds=chunk)["SecurityGroups"]:
                found[sg["GroupId"]] = sg
        except botocore.exceptions.ClientError:
            for gid in chunk:
                try:
                    for sg in ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"]:
                        found[sg["GroupId"]] = sg
                except botocore.exceptions.ClientError as exc:
                    LOG.warning("%s: %s", gid, exc)
    return found


def _attribute_flows(
    approved_ips: list[str],
    flows: list[dict] | None,
    interfaces: list[dict] | None,
) -> tuple[dict[str, list[dict]], list[dict], dict]:
    """Split the evidence into flows per group and flows for every group.

    Returns (by_group, everywhere, report). A flow whose destination is an
    interface we know goes to that interface's groups only; when the flow
    records the interface that logged it, that interface decides (exact
    where VPCs reuse addresses), and a record logged by the sending side
    is dropped. Everything else goes to ``everywhere`` and is treated as
    before per-group evidence existed, i.e. it counts for every group whose
    rule admits it:

    * no ``flows`` at all (an approved/v1 file): every source;
    * a flow whose destination matches no interface in the region (the
      interface was deleted or replaced, as Fargate tasks and autoscaled
      instances are, or the address is in another account);
    * a flow with no interface id whose address interfaces in several VPCs
      use (``ambiguous_destinations``);
    * an address in ``ips`` that no flow mentions (added by hand or by
      sg_diagnose).

    Unattributed evidence keeps access rather than cutting it: without it,
    a service whose interfaces were replaced during the window would lose
    every source that only reached the old ones. ``report`` lists it.
    """
    if flows is None:
        return {}, [{"src": ip} for ip in approved_ips], {"attribution": "per-rule"}

    index = InterfaceIndex(interfaces or [])
    by_group: dict[str, list[dict]] = {}
    everywhere: list[dict] = []
    unknown_dst: set[str] = set()
    ambiguous: set[str] = set()
    sender_side = 0
    for f in flows:
        eni, status = index.resolve(f.get("dst"), f.get("interface"))
        if status == "not-owner":
            sender_side += 1
            continue
        gids = index.groups(eni)
        if status != "ok" or not gids:
            everywhere.append(f)
            (ambiguous if status == "ambiguous" else unknown_dst).add(f.get("dst") or "-")
            continue
        for gid in gids:
            by_group.setdefault(gid, []).append(f)

    in_flows = {f["src"] for f in flows}
    extra = sorted(set(approved_ips) - in_flows)
    everywhere.extend({"src": ip} for ip in extra)
    report = {
        "attribution": "per-group",
        "unattributed_destinations": sorted(unknown_dst),
        "ambiguous_destinations": sorted(ambiguous),
        "sources_without_flows": extra,
        "sender_side_records_ignored": sender_side,
    }
    return by_group, everywhere, report


def groups_outside_flow_log_coverage(
    sgs: list[dict],
    interfaces: list[dict],
    resources: list[str] | None,
) -> dict[str, str]:
    """Groups the analysed flow logs cannot see, as {group id: reason}.

    ``resources`` are the ResourceIds of the flow logs that fed approved.json
    (vpc-, subnet- or eni-). A group with no flow log on its traffic has no
    evidence, and planning it would revoke every eligible rule: so a group is
    covered only when its VPC is, or when every interface carrying it sits in
    a covered subnet or is itself covered. ``resources`` None (not recorded,
    e.g. logs delivered from another account) checks nothing.
    """
    if resources is None:
        return {}
    covered = set(resources)
    enis_by_group: dict[str, list[dict]] = {}
    for eni in interfaces:
        for g in eni.get("Groups", []):
            if g.get("GroupId"):
                enis_by_group.setdefault(g["GroupId"], []).append(eni)
    out = {}
    for sg in sgs:
        if sg.get("VpcId") in covered:
            continue
        enis = enis_by_group.get(sg["GroupId"], [])
        if enis and all(e.get("SubnetId") in covered or e.get("NetworkInterfaceId") in covered
                        for e in enis):
            continue
        out[sg["GroupId"]] = (
            f"no analysed flow log covers {sg.get('VpcId') or 'its VPC'} or every interface "
            "carrying this group, so there is no evidence for its rules"
        )
    return out


def privatelink_provider_groups(
    interfaces: list[dict],
    service_configs: list[dict] | None,
    load_balancers: list[dict] | None,
) -> dict[str, str]:
    """Groups on Network Load Balancers behind PrivateLink endpoint services,
    as {group id: reason}.

    Flow logs do not record traffic between an interface endpoint and the
    NLB it reaches, and when the NLB enforces its inbound rules on
    PrivateLink traffic they are evaluated against the CONSUMER's private
    address, in another VPC or account. No flow log in this account can
    show those sources, so tightening the NLB's group would cut off every
    consumer. Such groups are never planned.

    ``service_configs`` is DescribeVpcEndpointServiceConfigurations output
    (None when the call failed: then every group on any NLB interface is
    held back, since none can be cleared). ``load_balancers`` is elbv2
    DescribeLoadBalancers output for those NLBs (None when unavailable: the
    groups are then read from the NLB interfaces and enforcement is assumed,
    which is the AWS default). An NLB with enforcement "off" does not apply
    its rules to PrivateLink traffic, so its groups are planned as usual.
    """
    out: dict[str, str] = {}
    nlb_enis = [e for e in interfaces if e.get("InterfaceType") == "network_load_balancer"]
    if service_configs is None:
        for eni in nlb_enis:
            for g in eni.get("Groups", []):
                out[g["GroupId"]] = (
                    f"carried by load balancer interface {eni.get('NetworkInterfaceId', '?')}, and "
                    "endpoint services could not be listed (ec2:DescribeVpcEndpointServiceConfigurations), "
                    "so it may serve PrivateLink consumers that flow logs cannot show"
                )
        return out
    lbs = {lb.get("LoadBalancerArn"): lb for lb in (load_balancers or [])}
    for svc in service_configs:
        for arn in svc.get("NetworkLoadBalancerArns", []):
            lb = lbs.get(arn)
            if lb is not None:
                if str(lb.get("EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic", "on")).lower() == "off":
                    continue
                gids = set(lb.get("SecurityGroups", []))
            else:
                # ENI description is "ELB net/<name>/<id>"; the ARN ends ":loadbalancer/net/<name>/<id>".
                suffix = arn.split(":loadbalancer/", 1)[-1]
                gids = {g["GroupId"] for e in nlb_enis if e.get("Description") == f"ELB {suffix}"
                        for g in e.get("Groups", [])}
            for gid in gids:
                out[gid] = (
                    f"on NLB {arn.rsplit('/', 2)[-2] if '/' in arn else arn} behind PrivateLink endpoint "
                    f"service {svc.get('ServiceId', '?')}: flow logs do not record endpoint-to-NLB "
                    "traffic and its inbound rules see the consumers' own addresses, so there is no "
                    "evidence for them"
                )
    return out


def _permission(proto, from_port, to_port, ranges: list[dict], ranges6: list[dict] | None = None) -> dict:
    """An IpPermissions entry. Rules for all protocols ("-1") have no ports,
    and the EC2 API rejects FromPort/ToPort of None, so absent ports are left
    out rather than sent as null. ``ranges6`` are IPv6 ({"CidrIpv6": …})."""
    perm: dict = {"IpProtocol": proto}
    if from_port is not None:
        perm["FromPort"] = from_port
    if to_port is not None:
        perm["ToPort"] = to_port
    if ranges or not ranges6:
        perm["IpRanges"] = ranges
    if ranges6:
        perm["Ipv6Ranges"] = ranges6
    return perm


def _clean_permissions(perms: list[dict]) -> list[dict]:
    """Drop null ports from plans and manifests written before _permission."""
    return [{k: v for k, v in p.items() if not (k in ("FromPort", "ToPort") and v is None)}
            for p in perms]


def _untouched_ranges6(sg: dict, own: Iterable[str], prefix_threshold: int) -> dict[tuple, list[ipaddress.IPv6Network]]:
    """IPv6 ranges plan leaves alone, per (protocol, from, to)."""
    out: dict[tuple, list[ipaddress.IPv6Network]] = {}
    for perm in sg.get("IpPermissions", []):
        key = (perm.get("IpProtocol"), perm.get("FromPort"), perm.get("ToPort"))
        for ip in perm.get("Ipv6Ranges", []):
            cidr = ip.get("CidrIpv6")
            if not cidr or rule_is_eligible6(cidr, own, prefix_threshold):
                continue
            try:
                out.setdefault(key, []).append(ipaddress.IPv6Network(cidr, strict=False))
            except ValueError:
                continue
    return out


def _untouched_ranges(sg: dict, prefix_threshold: int) -> dict[tuple, list[ipaddress.IPv4Network]]:
    """IPv4 ranges plan leaves alone, per (protocol, from, to)."""
    out: dict[tuple, list[ipaddress.IPv4Network]] = {}
    for perm in sg.get("IpPermissions", []):
        key = (perm.get("IpProtocol"), perm.get("FromPort"), perm.get("ToPort"))
        for ip in perm.get("IpRanges", []):
            cidr = ip.get("CidrIp")
            if not cidr or rule_is_eligible(cidr, prefix_threshold):
                continue
            try:
                out.setdefault(key, []).append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
    return out


def build_plan(
    sgs: list[dict],
    approved_ips: list[str],
    *,
    flows: list[dict] | None = None,
    interfaces: list[dict] | None = None,
    max_rules: int = DEFAULT_MAX_RULES,
    tolerance: float = DEFAULT_TOLERANCE,
    prefix_threshold: int = DEFAULT_PREFIX_THRESHOLD,
    region: str | None = None,
    skip: dict[str, str] | None = None,
    own_v6: Iterable[str] = (),
    v6_prefix_threshold: int = DEFAULT_V6_PREFIX_THRESHOLD,
) -> dict:
    """Plan replacements for every eligible rule, scoped to that rule.

    Each eligible rule is rebuilt only from the observed RFC 1918 addresses
    that fall inside its own CIDR, and the result never extends past that
    CIDR. A replacement can therefore narrow a rule but never grant a
    source the rule did not already allow, and public addresses in the
    approved list can never reach a private rule. A rule with no observed
    traffic is revoked with no replacement and listed under
    ``removed_without_evidence`` so the reviewer sees it.

    With ``flows`` (approved/v2) and ``interfaces`` (DescribeNetworkInterfaces
    output), a group's rule is rebuilt only from sources that reached an
    interface carrying that group, on a protocol and port the rule admits;
    see _attribute_flows for evidence that cannot be tied to an interface.
    Without ``flows`` every source inside a rule counts for every group
    carrying it (per rule, not per group).

    Groups in ``skip`` ({group id: reason}) are not planned and are listed
    under ``skipped_groups``. A replacement already covered by a rule the
    plan leaves in place (same protocol and ports) is dropped: it adds
    nothing, and authorising a duplicate fails after the revoke has run.

    IPv6 rules are planned the same way when they are wider than a /64 and
    unique local or inside ``own_v6`` (the account's VPC IPv6 ranges; see
    rule_is_eligible6). Their sources are kept by /64 (V6_SUBNET).
    """
    skip = skip or {}
    skipped: list[dict] = []
    own_v6 = list(own_v6)
    by_group, everywhere, attribution = _attribute_flows(
        [str(a) for a in _normalise_ips(approved_ips)] + [str(a) for a in _normalise_ips6(approved_ips)],
        flows, interfaces)

    private_cache: dict[str, ipaddress.IPv4Address | None] = {}

    def _private(ip: str) -> ipaddress.IPv4Address | None:
        if ip not in private_cache:
            addrs = _normalise_ips([ip])
            private_cache[ip] = addrs[0] if addrs and any(addrs[0] in b for b in RFC1918_BLOCKS) else None
        return private_cache[ip]

    v6_cache: dict[str, ipaddress.IPv6Address | None] = {}

    def _v6(ip: str) -> ipaddress.IPv6Address | None:
        if ip not in v6_cache:
            addrs = _normalise_ips6([ip])
            v6_cache[ip] = addrs[0] if addrs else None
        return v6_cache[ip]

    plan_groups = []
    for sg in sgs:
        eligible = _eligible_rules(sg, prefix_threshold)
        eligible6 = _eligible_rules6(sg, own_v6, v6_prefix_threshold)
        if not eligible and not eligible6:
            continue
        if sg["GroupId"] in skip:
            skipped.append({"group_id": sg["GroupId"], "group_name": sg.get("GroupName"),
                            "reason": skip[sg["GroupId"]]})
            LOG.warning("%s: not planned: %s", sg["GroupId"], skip[sg["GroupId"]])
            continue
        kept = _untouched_ranges(sg, prefix_threshold)
        kept6 = _untouched_ranges6(sg, own_v6, v6_prefix_threshold)
        revokes_per_proto_port: dict[tuple, list[dict]] = {}
        for r in eligible + eligible6:
            key = (r["protocol"], r["from_port"], r["to_port"])
            revokes_per_proto_port.setdefault(key, []).append(r)

        # Per-group budget = max_rules - (rules NOT being touched).
        existing_total = _all_rule_count(sg)
        untouched = existing_total - len(eligible) - len(eligible6)
        budget = max(1, max_rules - untouched)

        # One unit per eligible rule: the observed private sources inside it
        # that reached this group (or cannot be tied to any interface) on a
        # protocol and port the rule admits.
        evidence = by_group.get(sg["GroupId"], []) + everywhere
        units = []
        for key, rules in revokes_per_proto_port.items():
            matching = [f for f in evidence if flow_matches_rule(f, *key)]
            for r in rules:
                net = ipaddress.ip_network(r["cidr"], strict=False)
                pick = _v6 if net.version == 6 else _private
                inside = sorted({a for a in (pick(f["src"]) for f in matching)
                                 if a is not None and a in net})
                units.append((key, net, [str(a) for a in inside]))

        # Share the budget so the group as a whole grants the fewest
        # addresses nobody was seen using: each rule's cover says what every
        # extra slot would save, and _split_budget picks the best split.
        covers = [(_rule_cover6 if net.version == 6 else _rule_cover)(net, ips, budget, tolerance) if ips else None
                  for _key, net, ips in units]
        live = [c for c in covers if c is not None]
        shares = iter(_split_budget([c.cost for c in live], [len(c.curve) - 1 for c in live], budget))

        authorised_by_key: dict[tuple, list[ipaddress.IPv4Network]] = {}
        authorised6_by_key: dict[tuple, list[ipaddress.IPv6Network]] = {}
        removed: list[dict] = []
        for (key, net, ips), cover in zip(units, covers):
            if cover is None:
                removed.append({
                    "cidr": str(net),
                    "protocol": key[0],
                    "from_port": key[1],
                    "to_port": key[2],
                })
                continue
            if net.version == 6:
                authorised6_by_key.setdefault(key, []).extend(
                    n for n in cover.blocks(next(shares)) if not any(n.subnet_of(k) for k in kept6.get(key, [])))
                continue
            authorised_by_key.setdefault(key, []).extend(
                n for n in cover.blocks(next(shares))
                if not any(n.subnet_of(k) for k in kept.get(key, []))
            )

        authorise_perms: list[dict] = []
        for key in dict.fromkeys(list(authorised_by_key) + list(authorised6_by_key)):
            proto, from_p, to_p = key
            nets, nets6 = authorised_by_key.get(key, []), authorised6_by_key.get(key, [])
            if not nets and not nets6:
                continue
            merged = sorted(
                ipaddress.collapse_addresses(nets),
                key=lambda n: (int(n.network_address), n.prefixlen),
            )
            merged6 = sorted(ipaddress.collapse_addresses(nets6), key=lambda n: (int(n.network_address), n.prefixlen))
            authorise_perms.append(_permission(proto, from_p, to_p, [
                {"CidrIp": str(c), "Description": "sg-tightener evidence-based"}
                for c in merged
            ], [{"CidrIpv6": str(c), "Description": "sg-tightener evidence-based"} for c in merged6]))

        if removed:
            LOG.warning(
                "%s: %d eligible rule(s) saw no traffic and will be revoked with "
                "no replacement — check removed_without_evidence in the plan",
                sg["GroupId"], len(removed),
            )

        # If multiple eligible rules share a CIDR set but differ on ports,
        # the operator can ask to merge. We surface that here.
        port_merge_flagged = False
        port_ranges_by_proto: dict[str, list[tuple[int, int]]] = {}
        for k in revokes_per_proto_port:
            proto, fp, tp = k
            if fp is None or tp is None:
                continue
            port_ranges_by_proto.setdefault(str(proto), []).append((int(fp), int(tp)))
        for proto, ranges in port_ranges_by_proto.items():
            merged_ranges = merge_port_ranges(ranges)
            if len(merged_ranges) < len(ranges):
                port_merge_flagged = True

        revoke_perms = []
        restore_perms = []
        for (proto, from_p, to_p), rules in revokes_per_proto_port.items():
            v4, v6 = [r for r in rules if not r.get("v6")], [r for r in rules if r.get("v6")]
            revoke_perms.append(_permission(proto, from_p, to_p,
                                            [{"CidrIp": r["cidr"]} for r in v4],
                                            [{"CidrIpv6": r["cidr"]} for r in v6]))
            # What revert puts back: the same rules with their descriptions,
            # so a round trip leaves the group exactly as it was.
            restore_perms.append(_permission(proto, from_p, to_p, [
                {"CidrIp": r["cidr"], **({"Description": r["description"]} if r.get("description") else {})}
                for r in v4
            ], [{"CidrIpv6": r["cidr"], **({"Description": r["description"]} if r.get("description") else {})}
                for r in v6]))

        plan_groups.append({
            "group_id": sg["GroupId"],
            "group_name": sg.get("GroupName"),
            "vpc_id": sg.get("VpcId"),
            "revoke": revoke_perms,
            "restore": restore_perms,
            "authorise": authorise_perms,
            "removed_without_evidence": removed,
            "port_merge_flagged": port_merge_flagged,
            "budget": budget,
            "current_rule_count": existing_total,
        })

    snapshot = [{
        "group_id": sg["GroupId"],
        "rules": sg.get("IpPermissions", []),
    } for sg in sgs]

    plan = {
        "schema": "sg-tightener.plan/v1",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "region": region,
        "max_rules": max_rules,
        "tolerance": tolerance,
        "prefix_threshold": prefix_threshold,
        "v6_prefix_threshold": v6_prefix_threshold,
        "groups": plan_groups,
        "skipped_groups": skipped,
        "snapshot_hash": state_hash(snapshot),
        **attribution,
    }
    return plan


def _list_network_interfaces(region: str) -> list[dict]:
    ec2 = _client("ec2", region)
    out: list[dict] = []
    for page in ec2.get_paginator("describe_network_interfaces").paginate():
        out.extend(page.get("NetworkInterfaces", []))
    return out


def _list_privatelink_services(region: str) -> tuple[list[dict] | None, list[dict] | None]:
    """(endpoint service configurations, their NLBs) owned in ``region``.

    Either is None when its API call fails; privatelink_provider_groups then
    errs on the side of not planning."""
    try:
        ec2 = _client("ec2", region)
        configs: list[dict] = []
        for page in ec2.get_paginator("describe_vpc_endpoint_service_configurations").paginate():
            configs.extend(page.get("ServiceConfigurations", []))
    except Exception as exc:  # noqa: BLE001 — any failure means "cannot clear NLB groups"
        LOG.warning("could not list PrivateLink endpoint services "
                    "(ec2:DescribeVpcEndpointServiceConfigurations failed: %s); groups on "
                    "load balancer interfaces will not be planned", exc)
        return None, None
    arns = sorted({a for c in configs for a in c.get("NetworkLoadBalancerArns", [])})
    if not arns:
        return configs, []
    try:
        elb = _client("elbv2", region)
        lbs: list[dict] = []
        for i in range(0, len(arns), 20):  # DescribeLoadBalancers takes at most 20 ARNs
            lbs.extend(elb.describe_load_balancers(LoadBalancerArns=arns[i:i + 20]).get("LoadBalancers", []))
    except Exception as exc:  # noqa: BLE001
        LOG.warning("could not describe the NLBs behind endpoint services "
                    "(elasticloadbalancing:DescribeLoadBalancers failed: %s); assuming they "
                    "enforce inbound rules on PrivateLink traffic", exc)
        return configs, None
    return configs, lbs


def _list_vpc_ipv6(region: str) -> list[str]:
    """The region's VPC IPv6 ranges; [] (only unique local IPv6 rules in scope) when they cannot be read."""
    try:
        ec2 = _client("ec2", region)
        out = []
        for page in ec2.get_paginator("describe_vpcs").paginate():
            for v in page.get("Vpcs", []):
                out += [a["Ipv6CidrBlock"] for a in v.get("Ipv6CidrBlockAssociationSet", [])
                        if a.get("Ipv6CidrBlock") and (a.get("Ipv6CidrBlockState") or {}).get("State", "associated")
                        == "associated"]  # fmt: skip
        return sorted(set(out))
    except Exception as exc:  # noqa: BLE001 — without them only unique local IPv6 rules are planned
        LOG.warning("could not read the VPCs' IPv6 ranges (ec2:DescribeVpcs failed: %s); only unique local "
                    "IPv6 rules will be planned", exc)
        return []


def plan_from_approved(approved: dict, region: str, **kw) -> dict:
    """Build a plan from a loaded approved.json against ``region``'s groups.

    An approved/v2 file (with ``flows``) is planned per group, which also
    reads the region's network interfaces. A v1 file has no destinations and
    is planned per rule, with a warning.

    Two kinds of group are never planned (see ``skipped_groups``): groups the
    analysed flow logs do not cover, and groups on NLBs behind PrivateLink
    endpoint services, whose consumers no flow log here can show.
    """
    sgs = _list_security_groups(region)
    interfaces = _list_network_interfaces(region)
    resources = (approved.get("flow_log_check") or {}).get("resources")
    if resources is None:
        LOG.warning(
            "approved.json does not record which VPCs, subnets or interfaces its flow "
            "logs cover, so plan cannot hold back groups those logs never saw. Review "
            "removed_without_evidence closely, or re-run analyse with this version.")
    skip = groups_outside_flow_log_coverage(sgs, interfaces, resources)
    skip.update(privatelink_provider_groups(interfaces, *_list_privatelink_services(region)))
    kw.setdefault("own_v6", _list_vpc_ipv6(region))

    flows = approved.get("flows")
    if flows is None:
        LOG.warning(
            "approved.json has no destination data (%s): every observed source "
            "inside a rule is granted to every group carrying that rule (per "
            "rule, not per group). Re-run analyse with this version for a "
            "per-group plan.", approved.get("schema", "no schema"),
        )
        return build_plan(sgs, approved["ips"], region=region, skip=skip, **kw)
    plan = build_plan(sgs, approved["ips"], flows=flows,
                      interfaces=interfaces, region=region, skip=skip, **kw)
    if plan["unattributed_destinations"]:
        LOG.warning(
            "%d destination(s) in approved.json match no network interface in "
            "%s; sources that reached only them are kept on every group whose "
            "rule admits them (per rule). See unattributed_destinations in the plan.",
            len(plan["unattributed_destinations"]), region,
        )
    if plan["sources_without_flows"]:
        LOG.warning(
            "%d address(es) in approved.json ips have no flow (added by hand or by "
            "sg_diagnose); they are kept on every group whose rule admits them.",
            len(plan["sources_without_flows"]),
        )
    return plan


# --------------------------------------------------------------------------- #
# Apply / revert
# --------------------------------------------------------------------------- #

def _current_snapshot_hash(region: str) -> str:
    sgs = _list_security_groups(region)
    snapshot = [{"group_id": sg["GroupId"], "rules": sg.get("IpPermissions", [])} for sg in sgs]
    return state_hash(snapshot)


def resolve_apply_region(plan: dict, cli_region: str | None, env: dict | None = None) -> str:
    """The region a plan is applied in.

    A plan records the region it was built from, and that is the only region
    whose snapshot hash it can match, so it wins. ``--region`` that disagrees
    is refused rather than silently ignored. Plans written before the region
    was recorded fall back to ``--region``, then AWS_REGION /
    AWS_DEFAULT_REGION.
    """
    env = os.environ if env is None else env
    planned = plan.get("region")
    if planned:
        if cli_region and cli_region != planned:
            raise SystemExit(
                f"plan was built in {planned} but --region is {cli_region}; "
                "a plan only applies in the region it was built from"
            )
        return planned
    region = cli_region or env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION")
    if not region:
        raise SystemExit(
            "this plan does not record its region (it predates that field); "
            "pass --region or re-run plan"
        )
    LOG.warning("plan does not record its region; applying in %s", region)
    return region


# --------------------------------------------------------------------------- #
# Integrity of plans and manifests
# --------------------------------------------------------------------------- #

SIGNING_KEY_ENV = "SG_TIGHTENER_SIGNING_KEY"


def _canonical(doc: dict) -> bytes:
    body = {k: v for k, v in doc.items() if k != "integrity"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def caller_arn() -> str:
    """Who is signing; empty when the caller cannot be read (it is a label, not a check)."""
    try:
        return boto3.client("sts").get_caller_identity()["Arn"]
    except Exception:  # noqa: BLE001
        return ""


def sign(doc: dict, by: str = "") -> dict:
    """Add an ``integrity`` block: SHA-256 of the canonical JSON, who, when, and
    an HMAC-SHA256 when ``SG_TIGHTENER_SIGNING_KEY`` is set. Returns ``doc``."""
    blob = _canonical(doc)
    block = {
        "sha256": hashlib.sha256(blob).hexdigest(),
        "by": by,
        "at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    key = os.environ.get(SIGNING_KEY_ENV, "")
    if key:
        block["hmac_sha256"] = hmac.new(key.encode("utf-8"), blob, hashlib.sha256).hexdigest()
    doc["integrity"] = block
    return doc


def verify(doc: dict) -> tuple[str, str]:
    """Return (status, message). Status is ok, unsigned, unverified (HMAC present
    or expected, but cannot be checked) or modified."""
    block = doc.get("integrity")
    if not isinstance(block, dict) or "sha256" not in block:
        return "unsigned", "no integrity block (written before 2.7.0, or by hand)"
    blob = _canonical(doc)
    if not hmac.compare_digest(hashlib.sha256(blob).hexdigest(), str(block["sha256"])):
        return "modified", "contents changed since it was written (SHA-256 does not match)"
    key = os.environ.get(SIGNING_KEY_ENV, "")
    mac = block.get("hmac_sha256")
    if mac and key:
        good = hmac.new(key.encode("utf-8"), blob, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(good, str(mac)):
            return "modified", f"signature does not match {SIGNING_KEY_ENV} (re-signed or edited without the key)"
        return "ok", "signature verified"
    if mac:
        return "unverified", f"signed, but {SIGNING_KEY_ENV} is not set here; only the SHA-256 was checked"
    if key:
        return "unverified", f"{SIGNING_KEY_ENV} is set but the file was written without it; only the SHA-256 was checked"
    return "ok", "SHA-256 matches"


def check_integrity(doc: dict, what: str, path: str, *, allow_modified: bool = False) -> None:
    """Refuse a modified plan or manifest unless ``allow_modified``; warn on the rest."""
    status, msg = verify(doc)
    by = (doc.get("integrity") or {}).get("by") or "unknown"
    if status == "ok":
        LOG.info("%s %s: %s (written by %s)", what, path, msg, by)
    elif status == "modified":
        if not allow_modified:
            raise SystemExit(
                f"{what} {path}: {msg}.\n"
                f"Refusing to use it. Re-create it, or pass --allow-modified if the change was yours and reviewed."
            )
        LOG.warning("%s %s: %s; continuing because of --allow-modified", what, path, msg)
    else:
        LOG.warning("%s %s: %s", what, path, msg)


def _write_json(path: str, payload: dict, by: str | None = None) -> None:
    """Write ``payload``; with ``by`` (a caller ARN, possibly empty) sign it first."""
    if by is not None:
        sign(payload, by)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def apply_plan(plan: dict, region: str, *, manifest_path: str, tool: str = "sg_tightener apply") -> None:
    """Apply ``plan`` group by group, recording each call that succeeded.

    The manifest is rewritten after every successful AWS call, so it always
    describes exactly what was changed: if a revoke fails nothing is
    recorded for that group, and if the authorise after a successful revoke
    fails only the revoke is. ``revert`` then undoes that and nothing more,
    even if the process is killed part way.
    """
    current = _current_snapshot_hash(region)
    if current != plan["snapshot_hash"]:
        raise RuntimeError(
            "plan is stale — security group state changed since it was generated. "
            "Re-run plan and review again."
        )

    import sg_db  # every change is recorded in the security group database

    ec2 = sg_db.track(_client("ec2", region), region, tool, reason=f"plan of {plan.get('generated_at', 'unknown date')}")
    by = caller_arn()
    manifest = {
        "schema": "sg-tightener.manifest/v1",
        "applied_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "region": region,
        "complete": False,
        "groups": [],
    }
    aws_errors: tuple = (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError)
    for grp in plan["groups"]:
        gid = grp["group_id"]
        manifest_grp: dict = {"group_id": gid, "revoked": [], "authorised": []}
        try:
            if grp["revoke"]:
                ec2.revoke_security_group_ingress(GroupId=gid, IpPermissions=_clean_permissions(grp["revoke"]))
                # Record the rules as they were, descriptions included.
                manifest_grp["revoked"] = grp.get("restore") or grp["revoke"]
                if manifest_grp not in manifest["groups"]:
                    manifest["groups"].append(manifest_grp)
                _write_json(manifest_path, manifest, by)
            if grp["authorise"]:
                ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=_clean_permissions(grp["authorise"]))
                manifest_grp["authorised"] = grp["authorise"]
                if manifest_grp not in manifest["groups"]:
                    manifest["groups"].append(manifest_grp)
                _write_json(manifest_path, manifest, by)
        except aws_errors as exc:
            _write_json(manifest_path, manifest, by)
            raise SystemExit(
                f"apply HALTED on {gid}: {exc}\n"
                f"Partial manifest written to {manifest_path}\n"
                f"Revert: sg_tightener.py revert --manifest {manifest_path}"
            )

    manifest["complete"] = True
    _write_json(manifest_path, manifest, by)
    LOG.info("apply complete; manifest written to %s", manifest_path)


def revert_from_manifest(manifest_path: str, *, allow_modified: bool = False, tool: str = "sg_tightener revert") -> None:
    import sg_db

    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    check_integrity(manifest, "manifest", manifest_path, allow_modified=allow_modified)
    ec2 = sg_db.track(_client("ec2", manifest["region"]), manifest["region"], tool,
                      reason=f"revert of {os.path.basename(manifest_path)}", strict=False)
    aws_errors = (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError)
    failures = 0
    for grp in reversed(manifest["groups"]):
        gid = grp["group_id"]
        if grp.get("authorised"):
            try:
                ec2.revoke_security_group_ingress(GroupId=gid, IpPermissions=_clean_permissions(grp["authorised"]))
            except aws_errors as exc:
                failures += 1
                LOG.warning("revert: could not revoke the tightened rules on %s: %s", gid, exc)
        if grp.get("revoked"):
            try:
                ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=_clean_permissions(grp["revoked"]))
            except aws_errors as exc:
                failures += 1
                LOG.warning("revert: could not re-authorise original rules on %s: %s", gid, exc)
    if failures:
        raise SystemExit(f"revert finished with {failures} failed call(s); see the warnings above")
    LOG.info("revert complete")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sg_tightener.py", description=__doc__.splitlines()[0])
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="mode", required=True)

    a = sub.add_parser("analyse", help="read flow logs and write approved IP list")
    a.add_argument("--region", required=True)
    a.add_argument("--days", type=int, default=DEFAULT_DAYS)
    a.add_argument("--log-group", help="CloudWatch Logs group containing VPC flow logs")
    a.add_argument("--s3-bucket", help="S3 bucket containing VPC flow logs")
    a.add_argument("--s3-prefix", help="S3 prefix under --s3-bucket")
    a.add_argument("--out", default="approved.json")

    pl = sub.add_parser("plan", help="emit a plan.json")
    pl.add_argument("--region", required=True)
    pl.add_argument("--approved", required=True)
    pl.add_argument("--max-rules", type=int, default=DEFAULT_MAX_RULES)
    pl.add_argument("--tolerance", type=float, default=DEFAULT_TOLERANCE)
    pl.add_argument("--prefix-threshold", type=int, default=DEFAULT_PREFIX_THRESHOLD)
    pl.add_argument("--out", default="plan.json")

    ap = sub.add_parser("apply", help="execute a plan")
    ap.add_argument("--plan", required=True)
    ap.add_argument("--region", help="only for plans that predate the recorded region; must match it otherwise")
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--allow-modified", action="store_true",
                    help="apply a plan whose contents changed since plan wrote it")

    rv = sub.add_parser("revert", help="restore pre-apply state from a manifest")
    rv.add_argument("--manifest", required=True)
    rv.add_argument("--yes", action="store_true")
    rv.add_argument("--allow-modified", action="store_true",
                    help="revert from a manifest whose contents changed since apply wrote it")

    for q in (a, pl, ap, rv):
        add_profile_arg(q)
    return p


def _confirm(action: str) -> None:
    answer = input(f"Type 'yes' to {action}: ").strip().lower()
    if answer != "yes":
        sys.exit("aborted")


@friendly_login_errors
def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = _build_parser().parse_args(argv)
    use_profile(args.profile)

    if args.mode == "analyse":
        cfg = AnalyseConfig(
            region=args.region,
            days=args.days,
            log_group=args.log_group,
            s3_bucket=args.s3_bucket,
            s3_prefix=args.s3_prefix,
            out_path=args.out,
        )
        run_analyse(cfg)
        return 0

    if args.mode == "plan":
        with open(args.approved, "r", encoding="utf-8") as fh:
            approved = json.load(fh)
        plan = plan_from_approved(
            approved,
            args.region,
            max_rules=args.max_rules,
            tolerance=args.tolerance,
            prefix_threshold=args.prefix_threshold,
        )
        _write_json(args.out, plan, caller_arn())
        LOG.info(
            "wrote plan covering %d groups to %s",
            len(plan["groups"]), args.out,
        )
        return 0

    if args.mode == "apply":
        with open(args.plan, "r", encoding="utf-8") as fh:
            plan = json.load(fh)
        check_integrity(plan, "plan", args.plan, allow_modified=args.allow_modified)
        region = resolve_apply_region(plan, args.region)
        if not args.yes:
            _confirm(f"apply this plan in {region}")
        ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        manifest_path = f"manifest-{ts}.json"
        apply_plan(plan, region, manifest_path=manifest_path)
        return 0

    if args.mode == "revert":
        if not args.yes:
            _confirm("revert from manifest")
        revert_from_manifest(args.manifest, allow_modified=args.allow_modified)
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
