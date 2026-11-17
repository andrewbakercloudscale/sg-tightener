# How sg-tightener works

This page explains what each stage does, how the replacement CIDRs are chosen,
and which safety checks stand between a plan and your production network.

---

## The four stages

```
 VPC flow logs ──► analyse ──► approved.json ──► plan ──► plan.json ──► apply ──► manifest-<ts>.json
                                                    ▲                                   │
                                     live SG inventory                                  ▼
                                                                                      revert
```

### 1. `analyse`: what actually connected

`analyse` reads VPC flow logs for the last `--days` (default 90) from either a
CloudWatch Logs group (via Logs Insights) or an S3 bucket, keeps records whose
action is `ACCEPT`, and writes every distinct source IPv4 address to
`approved.json`.

Before reading a single record it runs a **flow-log preflight**:
`ec2:DescribeFlowLogs` finds the flow logs that deliver to your log group or
bucket, and their configured log format decides which column is the source
address. That matters because:

* a custom format puts fields in a different order, and positional parsing
  with the wrong order silently reads the wrong column;
* the default format has no `pkt-srcaddr`, so traffic arriving through a
  transit gateway or NAT gateway is recorded under the intermediate interface,
  not the real client. When `pkt-srcaddr` is present it is preferred.

The preflight **aborts** on configurations that cannot answer the question
(REJECT-only capture, no `action` field, no source field, several different
formats feeding one destination) and **warns** on ones that can answer it
badly (no `pkt-srcaddr`, inactive logs, delivery errors). Without permission
to call `DescribeFlowLogs` it assumes the default format and says so. See
[flow-logs.md](flow-logs.md).

`analyse` refuses to write an empty `approved.json`: an empty list would turn
into "revoke everything".

### 2. `plan`: what the rules should become

`plan` reads `approved.json` and every security group in the region, then for
each group:

1. Picks out the **eligible** rules: IPv4 ingress, source strictly inside one
   RFC 1918 block, prefix shorter than `--prefix-threshold` (default `/24`).
   Everything else counts as a fixed rule.
2. Computes the group's **rule budget**: `--max-rules` (default 60) minus the
   fixed rules.
3. For **each eligible rule separately**, takes only the approved addresses
   that are private, fall **inside that rule's own CIDR**, and **reached an
   interface carrying this group on a protocol and port the rule admits**
   (destination addresses are mapped to groups with
   `DescribeNetworkInterfaces`), and collapses them
   into replacement CIDRs (see below). Any block that would grow past the
   original rule is clipped back to it. A replacement can therefore narrow a
   rule but never allow a source the rule did not already allow, and public
   addresses in `approved.json` can never reach a private rule.
4. Shares the budget across the group's rules: each rule with traffic gets at
   least one slot, and the rest go in proportion to how many blocks each rule
   needs.
5. Writes a `revoke` list (the eligible rules, per protocol and port range), an
   `authorise` list (the replacement CIDRs on the same protocols and ports),
   and `removed_without_evidence`: eligible rules with no observed traffic at
   all, which are revoked with no replacement. Check these carefully.

It also records a SHA-256 hash of every group's current rules
(`snapshot_hash`). Nothing is written to AWS.

### 3. `apply`: make the change, carefully

`apply`:

1. Asks you to type `yes` (skip with `--yes`).
2. Re-reads every security group in the region and recomputes the hash. If
   **anything** changed since `plan`, it refuses: you are about to apply a plan
   to a network it was not made for.
3. For each group in turn: revoke the old rules, authorise the new ones.
4. On the first AWS error it stops, writes a partial manifest, and prints the
   exact `revert` command.
5. On success it writes `manifest-<UTC timestamp>.json`.

The region comes from `AWS_REGION` or `AWS_DEFAULT_REGION`, not from the plan,
so set it to the region you planned against.

### 4. `revert`: undo from the manifest

`revert` walks the manifest backwards: revoke what was authorised, re-authorise
what was revoked. Errors are logged per group and the walk continues, so one
missing rule does not stop the rest of the rollback. Manifests from
`sg_compact` use the same format and are reverted the same way.

---

## How the replacement CIDRs are chosen

The core function is `collapse_ips_to_cidrs(ips, max_rules, tolerance)` in
[`sg_tightener.py`](../sg_tightener.py). It works in three layers.

**Tolerance** is the fraction of addresses inside a candidate block that were
*never observed* and are still allowed. `0.0` means "only exact hosts";
`0.30` (the default) means a block may be up to 30% unused.

**Layer 1: widen each address.** For every observed address, start at `/32`
and widen one bit at a time while the block's unused fraction stays within the
tolerance. Stop at the RFC 1918 block the address belongs to; a `10.x` address
can never produce a block outside `10.0.0.0/8`. Adjacent and overlapping
results are merged.

**Layer 2: relax tolerance to fit the budget.** If there are still more blocks
than the budget allows, raise the tolerance in steps of 0.05 up to 0.95 and try
again. Each step is logged as a warning.

**Layer 3: force-fit.** If even 0.95 is not enough, repeatedly merge the
neighbouring pair of blocks whose smallest covering block wastes the fewest
addresses, within the same RFC 1918 block. This always fits, but loses
precision; the log tells you to ask AWS Support for a higher rules-per-group
quota instead.

Example with the default tolerance:

| Observed | Result |
|---|---|
| `10.4.1.10`, `10.4.1.11` | `10.4.1.10/31` (2 of 2 used) |
| `10.4.1.0` to `10.4.1.200` (201 hosts) | `10.4.1.0/24` (201 of 256 used, 21% unused) |
| `10.4.1.10`, `10.9.7.3` | two `/32`s, far apart |

---

## The other tools

### `sg_diagnose.py`: what did we break?

Reads the last `--hours` of flow logs for `REJECT` records, keeps private
(RFC 1918) source addresses that no current rule in the region covers, and
lists them. You can merge them into `approved.json` interactively and then
re-run `plan` and `apply`. Exit code 1 means it found sources and you chose not
to merge them, which makes it usable as a check in a pipeline.

### `sg_extend.py`: break-glass during an incident

When a DR failover or a supplier's IP change is being blocked *now*, the
analyse/plan/apply loop is too slow. `sg_extend` reads recent `REJECT` flows and
**only adds** ingress rules; it never revokes. Its design:

* **Group discovery.** Without `--groups`, it looks up the destination network
  interface of every rejected flow and finds the security groups attached to
  it. Each group only receives rules for flows that hit its own interfaces.
  `--max-groups` (default 20) refuses runs that would touch more.
* **Per-port rules.** Sources are grouped per protocol and destination port, so
  a rule only opens the port that was actually rejected. `--ports` narrows it
  further.
* **Private by default.** Public sources are ignored unless you pass
  `--include-public`. When you do, sources inside an AWS-published service
  range (from `ip-ranges.amazonaws.com`, cached for 7 days) are summarised into
  that service's range with a labelled description, instead of `/32`s that go
  stale when AWS rotates addresses. The catch-all `AMAZON` range is never used.
* **Budget aware.** Grouping uses `--tolerance` (the same meaning as above);
  CIDRs already covered by an existing rule are skipped; a group that would
  exceed `--max-rules` is skipped with a warning.
* **Manifest.** Every run writes `sg_extend-manifest-<ts>.json` listing exactly
  what it added, so the next tightening cycle can fold it in.

### `sg_compact.py`: get back under the limit

After a few `sg_extend` runs a group can sit at or near 60 rules. `sg_compact`
merges existing RFC 1918 CIDRs into wider ones without reading flow logs. Every
widened block is a superset of what it replaces, so nobody loses access. Run
`plan` without `--ratio` to see which groups are fullest and what each ratio
would reclaim, then pick one. Its plans and manifests share the `sg_tightener`
formats, staleness check and `revert`.

### `sg_ou_report.py`: where to start

Walks an AWS Organization (or a list of accounts), assumes a role in each, scans
every requested region in parallel, and writes an Excel and JSON report of
permissive rules. Severity:

| Rule source | Security group | Network ACL |
|---|---|---|
| `0.0.0.0/0` on 22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 9300 or 11211 | CRITICAL | HIGH |
| `0.0.0.0/0` on any other port | HIGH | HIGH |
| RFC 1918, `/16` or wider | HIGH | MEDIUM |
| RFC 1918, `/17` to `/20` | MEDIUM | LOW |
| RFC 1918, `/21` to `/23` | LOW | not reported |

Accounts are ranked by a weighted score so that one CRITICAL outranks any
number of LOWs. Exit code 1 when any CRITICAL is found.

### `sg_transfer_audit.py`: SFTP servers open to the world

Transfer Family servers fall outside everything above, because the other tools
deliberately leave `0.0.0.0/0` alone. This audit classifies each server:

| Server | Severity |
|---|---|
| `EndpointType = PUBLIC` (no security group exists to restrict it) | CRITICAL |
| `VPC` endpoint with an Elastic IP, security group open to `0.0.0.0/0` on an enabled protocol port | CRITICAL |
| `VPC` / `VPC_ENDPOINT` without an Elastic IP, open to `0.0.0.0/0` | HIGH |
| Security groups could not be resolved or described | MEDIUM |
| Restricted to specific sources | LOW |

The fix for a VPC endpoint is to replace the `0.0.0.0/0` rule with your
partners' CIDRs or `/32` addresses; for a PUBLIC endpoint it is migrating to a
VPC endpoint. Exit code 1 when any CRITICAL is found.

---

## Known limitations

Read these before you apply a plan; they are the reason the runbook says to
review `plan.json` by hand.

* **Evidence that cannot be tied to an interface is kept everywhere.** A source
  whose destination no current network interface owns (a replaced Fargate
  task, a terminated instance, another account), or an address added to `ips`
  by hand, is kept on every group whose rule admits it, not only the group it
  reached. The plan lists these under `unattributed_destinations` and
  `sources_without_flows`. An `approved.json` from an older version (no
  `flows`) is planned this way throughout, with a warning. This errs towards
  keeping access; the replacement is still never wider than the original rule.
* **Rules with no observed traffic are removed.** They appear under
  `removed_without_evidence` in the plan and in a warning. If one should stay,
  delete that group from the plan or add the expected source to
  `approved.json`.
* **The window is the evidence.** Anything that did not connect during the
  analysed window is treated as unused. Use `--days 180` or more where seasonal
  traffic exists.
* **`sg_diagnose --hours` is rounded to whole days** when it queries the logs.
