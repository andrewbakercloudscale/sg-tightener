"""sg-tightener 2.2.0's CIDR collapse and budget split, kept as a reference.

2.3.0 replaced the tolerance stepping, force-fit and proportional budget split
with an exact minimum-waste cover. The tests check that the new code never
grants more addresses than this did. Do not change it.
"""

from __future__ import annotations

import ipaddress
from typing import Sequence

from sg_tightener import (
    DEFAULT_MAX_RULES,
    DEFAULT_TOLERANCE,
    RFC1918_BLOCKS,
    _normalise_ips,
)


def _quiet(*_args) -> None:
    """Stands in for the logger the original warned through."""


def _widest_block_for(
    addr: ipaddress.IPv4Address,
    observed: set[ipaddress.IPv4Address],
    tolerance: float,
) -> ipaddress.IPv4Network:
    """Widest containing CIDR where (block_size - observed_in_block)/block_size <= tolerance.

    Always returns at least the /32 host route, and never widens past the
    RFC 1918 block the address belongs to.
    """
    home_block = next((b for b in RFC1918_BLOCKS if addr in b), None)
    if home_block is None:
        return ipaddress.ip_network(f"{addr}/32")
    best = ipaddress.ip_network(f"{addr}/32")
    for prefix in range(31, home_block.prefixlen - 1, -1):
        candidate = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
        if not candidate.subnet_of(home_block):
            break
        size = candidate.num_addresses
        in_block = sum(1 for o in observed if o in candidate)
        gap = (size - in_block) / size
        if gap <= tolerance:
            best = candidate
        else:
            break
    return best


def _force_fit(
    nets: list[ipaddress.IPv4Network],
    max_rules: int,
) -> list[ipaddress.IPv4Network]:
    """Merge the closest pairs of CIDR blocks until count <= max_rules.

    Operates per-RFC-1918 home block — merges never cross a boundary
    (e.g. a 10/8 block is never merged with a 172.16/12 block).
    """
    if len(nets) <= max_rules:
        return nets

    def home(net: ipaddress.IPv4Network) -> int:
        for i, b in enumerate(RFC1918_BLOCKS):
            if net.subnet_of(b):
                return i
        return -1

    groups: dict[int, list[ipaddress.IPv4Network]] = {}
    for n in nets:
        groups.setdefault(home(n), []).append(n)

    while sum(len(g) for g in groups.values()) > max_rules:
        biggest_key = max(groups, key=lambda k: len(groups[k]))
        if len(groups[biggest_key]) <= 1:
            break
        items = sorted(groups[biggest_key], key=lambda n: int(n.network_address))
        best_pair: tuple[int, int] | None = None
        best_cost = None
        for i in range(len(items) - 1):
            a, b = items[i], items[i + 1]
            super_net = _smallest_covering(a, b)
            if super_net is None:
                continue
            cost = super_net.num_addresses - (a.num_addresses + b.num_addresses)
            if best_cost is None or cost < best_cost:
                best_cost = cost
                best_pair = (i, i + 1)
        if best_pair is None:
            break
        i, j = best_pair
        merged = _smallest_covering(items[i], items[j])
        new_items = items[:i] + [merged] + items[j + 1:]
        groups[biggest_key] = new_items

    return [n for g in groups.values() for n in g]


def _smallest_covering(
    a: ipaddress.IPv4Network,
    b: ipaddress.IPv4Network,
) -> ipaddress.IPv4Network | None:
    home = next((blk for blk in RFC1918_BLOCKS if a.subnet_of(blk) and b.subnet_of(blk)), None)
    if home is None:
        return None
    lo = min(int(a.network_address), int(b.network_address))
    hi = max(int(a.broadcast_address), int(b.broadcast_address))
    for prefix in range(32, home.prefixlen - 1, -1):
        size = 1 << (32 - prefix)
        base = (lo // size) * size
        if base + size - 1 >= hi:
            candidate = ipaddress.ip_network((base, prefix))
            if candidate.subnet_of(home):
                return candidate
    return home


def collapse_ips_to_cidrs(
    ips: Sequence[str],
    max_rules: int = DEFAULT_MAX_RULES,
    tolerance: float = DEFAULT_TOLERANCE,
) -> list[str]:
    """Collapse observed IPs into a CIDR list <= max_rules in size.

    Layer 1: widen each IP to the widest block respecting ``tolerance``.
    Layer 2: deduplicate, widen tolerance in 5% steps if still over budget.
    Layer 3: force-fit merge nearest pairs while respecting RFC 1918 home block.

    Returns sorted ``"a.b.c.d/p"`` strings.
    """
    addrs = _normalise_ips(ips)
    if not addrs:
        return []
    observed = set(addrs)

    def _collapse_at(t: float) -> list[ipaddress.IPv4Network]:
        blocks: set[ipaddress.IPv4Network] = set()
        for a in addrs:
            blocks.add(_widest_block_for(a, observed, t))
        # ipaddress.collapse_addresses merges contiguous & adjacent nets.
        return list(ipaddress.collapse_addresses(blocks))

    t = max(0.0, min(1.0, tolerance))
    nets = _collapse_at(t)
    while len(nets) > max_rules and t < 0.95:
        t = round(min(0.95, t + 0.05), 2)
        _quiet("widening tolerance to %.2f to fit %d rule budget", t, max_rules)
        nets = _collapse_at(t)

    if len(nets) > max_rules:
        _quiet(
            "tolerance widening exhausted; force-fitting %d blocks into %d rules — "
            "request a quota increase from AWS Support to keep precision",
            len(nets), max_rules,
        )
        nets = _force_fit(nets, max_rules)

    nets_sorted = sorted(nets, key=lambda n: (int(n.network_address), n.prefixlen))
    return [str(n) for n in nets_sorted]



def _allocate_budget(needs: list[int], budget: int) -> list[int]:
    """Split ``budget`` rule slots across units that each need ``needs[i]``.

    Every unit with evidence gets at least one slot. When the total need fits,
    each unit gets what it needs; otherwise the slots above the first are
    shared in proportion to each unit's extra need (largest remainder).
    """
    alloc = [1 if n > 0 else 0 for n in needs]
    spare = budget - sum(alloc)
    if spare <= 0:
        return alloc
    extra = [max(0, n - a) for n, a in zip(needs, alloc)]
    total_extra = sum(extra)
    if total_extra <= spare:
        return [a + e for a, e in zip(alloc, extra)]
    shares = [e * spare / total_extra for e in extra]
    floors = [int(x) for x in shares]
    leftover = spare - sum(floors)
    order = sorted(range(len(needs)), key=lambda i: shares[i] - floors[i], reverse=True)
    for i in order[:leftover]:
        floors[i] += 1
    return [a + f for a, f in zip(alloc, floors)]


def _replacements_within(
    original: ipaddress.IPv4Network,
    ips: list[str],
    max_rules: int,
    tolerance: float,
) -> list[ipaddress.IPv4Network]:
    """Collapse ``ips`` (all inside ``original``) without ever leaving it.

    collapse_ips_to_cidrs may widen up to the RFC 1918 home block; any block
    that grew past the original rule is clipped back to the original, so a
    replacement can only ever narrow a rule.
    """
    nets = [ipaddress.ip_network(c) for c in collapse_ips_to_cidrs(
        ips, max_rules=max_rules, tolerance=tolerance)]
    clipped = [original if not n.subnet_of(original) else n for n in nets]
    return list(ipaddress.collapse_addresses(clipped))
