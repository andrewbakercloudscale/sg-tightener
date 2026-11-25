# Handover: how security groups and PrivateLink endpoints are tightened

Status as of v5.49.0 (e20a2b3). Internal: this file names real groups and must not be published.

## The question being answered

How do we choose CIDRs so the gaps (addresses let in but never seen) stay small? Do we always fill a
group up to its rule limit, or rewrite it 50 rules at a time?

Short answer: we don't fill to the limit. We use the fewest rules that keep waste low. The command line
budgets a whole group; the console's Remediate tab did not, and that gap is being closed.

## The AWS limit

- 60 inbound and 60 outbound rules per security group by default (not 50). The quota can be raised.
- Each CIDR × port range counts as one rule. A group of 3 port ranges × 20 CIDRs is 60 rules.
- `DEFAULT_MAX_RULES = 60` in `sg_tightener.py`.

## Algorithm 1: `sg_tightener.py plan` (`build_plan`)

1. **Tolerance blocks** (`_tolerance_blocks`, ~line 269). Each seen IP is widened to the widest aligned
   block where at most 30% of addresses were never seen (`DEFAULT_TOLERANCE = 0.30`). A block never
   grows past its RFC1918 parent (`RFC1918_BLOCKS`, line 161). Then neighbouring blocks are merged.
2. **Optimal cover** (`_Cover`, line 301). An exact dynamic programme over a compressed binary trie of
   the seen addresses. For any rule count k it gives the set of aligned CIDRs that covers every seen
   address with the fewest unseen addresses. So for aligned CIDRs this is optimal, not greedy.
3. **Group budget** (`_split_budget`, line 381). A knapsack splits the group's budget
   (60 − rules we are not touching) across the rules being tightened, where each rule's cost curve
   comes from its `_Cover`.
4. **Stopping.** If the layer-1 blocks already fit, we stop there and keep the 30% headroom so new hosts
   in the same subnet still work. Extra rules are spent only when they cut waste.

Scope rules:
- A re-run only touches rules wider than /24 (`DEFAULT_PREFIX_THRESHOLD = 24`).
- IPv6 clients are kept as their /64 (`V6_SUBNET`). `_rule_cover6` handles them. In scope: unique local
  addresses (fc00::/7) and the VPC's own IPv6 ranges.

## Algorithm 2: console Remediate tab (before the fix in progress)

- `sg_review.py` builds `row["suggest"]` per rule (~line 3360–3530), and `sg_remediate.plan_rule` uses it.
- Each rule called `collapse_ips_to_cidrs(ips, 60, 0.30)` on its own. There was **no group-wide budget**,
  and CIDRs were then multiplied by port ranges.
- Outbound (`_egress_items`, ~line 3190) used a fixed 10 rules per port.

## Problems found in real stored plans (5 accounts, 129 groups)

13 groups would go over 60 rules. Worst:

| Group | Rules after plan | Why |
|---|---|---|
| prd-plsapp-afs1-eks-sonic-cluster-sg | 711 (from 3) | 710 /32s on 443 from 100.64.0.0/16 (EKS pods) |
| prd-plrdoc-afs1-eks-conman-cluster-sg | 266 | same pattern |
| conman-msk-prd | 168 | CIDRs × MSK port ranges |
| acuity-prod | 162 | |
| instana-privatelink-endpoint-sg | 123 replacements | PrivateLink endpoint |

Causes:
1. `RFC1918_BLOCKS` lacks **100.64.0.0/10** (carrier-grade NAT, used for EKS pod IPs). Those addresses
   are treated as public, can't be merged, and become /32s. This is also the source of the log line
   "161 public addresses cannot be merged".
2. No group budget in the console (above).
3. **Apply order is dangerous.** `sg_db.Store.pending` (line 314) sorts removals before adds, and
   `sg_db.push` (line 800) applies them in that order. On an oversized plan it would revoke the /16,
   then AWS refuses adds past 60, and pods are cut off.
4. Per-pod /32s break anyway: pods get new IPs when they reschedule.

## The four fixes

| # | Fix | Where | State |
|---|---|---|---|
| 1 | Treat 100.64.0.0/10 as private when merging | `RFC1918_BLOCKS` in `sg_tightener.py`; `sg_review.private_ip` already includes it | **Not started** |
| 2 | Group-wide budget in the console (60 − untouched, counting CIDRs × port ranges); settings for tolerance, max rules, "fill" and outbound rules per port, saved in `tighten.json` | `sg_review.py` `TIGHTEN`, `tighten_prefs`, `_suggest_group`; Remediate tab | **In progress, uncommitted**, by session ec65ba49 (`tests/unit/test_suggest_group.py`) |
| 3 | Suggest a source security-group reference instead of CIDRs for pods and nodes in the same VPC | `sg_review.py` suggestions | Not started |
| 4 | Apply refuses a plan that would exceed the limit, and adds before removing | `sg_db.pending` / `sg_db.push` | Not started |

Each fix needs a test that fails without it.

Suggested order: 4 first (it is a safety guard and stands alone), then 1 (one line plus a test; it shrinks
the EKS groups from hundreds of /32s to a few blocks), then finish 2, then 3.

## How to check

- Stored plans live in Postgres, `files` table, keys `plans/<account>.json`. Read one with
  `sg_store.File(sg_ipintel.DATA_DIR / "plans/<account>.json")`.
- Count rules per group as Σ(CIDRs × port ranges) for touched rules + untouched rules, and compare with 60.
- Tests: `.venv/bin/python -m pytest -p no:cacheprovider -o addopts="" -q` (about 2 minutes).
- Test accounts with the EKS case: plsapp 934140400269, plrdoc 723735748837.

## Things to know

- Two Claude sessions work in this repo. Don't commit another session's uncommitted hunks.
- Andrew Baker is the sole author: no co-author trailers. Commit locally; push and tag only when asked.
- Unrelated open item: `_pg_tool` doesn't pass `sslmode` to `pg_dump` when `SG_TIGHTENER_PG_DSN` points at a
  remote database.
