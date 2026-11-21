# How sg-tightener works

> **Why this exists.** Security groups written once and frozen in Terraform end up letting in whole
> corporate or data centre blocks (`10.0.0.0/8` is 16.7 million addresses) because nobody knows who
> really calls each service. With attackers working from any one compromised host inside the
> network, trusting a whole CIDR block is a high-risk strategy. sg-tightener treats every allowed
> IP address as risk: it takes security group sources out of static configuration and, from VPC flow
> log evidence, fits each group's limited rules to the fewest addresses that cover the real callers.
> See [The shift: IP addresses are risk, not configuration](../README.md#the-shift-ip-addresses-are-risk-not-configuration).

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
   least one slot, and the rest go wherever they save the most: the split that
   grants the fewest never-observed addresses across the whole group (exact,
   not a rule of thumb).
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
[`sg_tightener.py`](../sg_tightener.py). It works in two layers.

**Tolerance** is the fraction of addresses inside a candidate block that were
*never observed* and are still allowed. `0.0` means "only exact hosts";
`0.30` (the default) means a block may be up to 30% unused.

**Layer 1: widen each address.** For every observed address, start at `/32`
and widen one bit at a time while the block's unused fraction stays within the
tolerance. Stop at the RFC 1918 block the address belongs to; a `10.x` address
can never produce a block outside `10.0.0.0/8`. Adjacent and overlapping
results are merged. These blocks are the finest result sg-tightener produces:
the headroom tolerance buys (room for hosts not yet seen) is never given up to
use a spare rule.

**Layer 2: fit the budget exactly.** If there are more blocks than the budget
allows, sg-tightener picks the at most `--max-rules` CIDRs that cover every
layer-1 block while granting the **fewest addresses nobody was seen using**.
Only CIDRs that are the smallest block around some of the layer-1 blocks can
be in the best answer, so it is found exactly over the binary tree of those
blocks (each block's best cover with *k* rules follows from its two halves),
in milliseconds for thousands of addresses. Blocks in different RFC 1918
ranges are never merged; the budget is shared between the ranges the same
exact way, and public addresses are kept as they are. A warning says how many
blocks were merged into how many rules; a higher rules-per-group quota from
AWS Support keeps more precision.

Before 2.3.0, layer 2 raised the tolerance in 0.05 steps and then merged
neighbouring pairs; on clustered traffic that granted 25 to 60% more unused
addresses, often left rule slots empty, and took 28 seconds for 2,000
addresses where the exact cover takes a fraction of one.

Example with the default tolerance:

| Observed | Result |
|---|---|
| `10.4.1.10`, `10.4.1.11` | `10.4.1.10/31` (2 of 2 used) |
| `10.4.1.0` to `10.4.1.200` (201 hosts) | `10.4.1.0/24` (201 of 256 used, 21% unused) |
| `10.4.1.10`, `10.9.7.3` | two `/32`s, far apart |

---

## The other tools

### `sg_diagnose.py`: what did we break?

Reads the last `--hours` of flow logs for `REJECT` records from private
(RFC 1918) sources and judges each one the way AWS did: against the groups on
the interface it tried to reach, on its own protocol and port. A source that
some other group still allows is reported where it was refused. Rejects those
groups do admit (a network ACL, or return traffic) are counted, not listed.
With `--manifest` (the file `apply` wrote), flows a revoked rule would have
admitted are marked **caused by tightening**.

It changes nothing in AWS. For each set of groups it prints the `sg_extend`
command that restores access now (and, with `--manifest`, the `revert`), and
can record the flows in `approved.json` so the next plan keeps them. Recording
alone does not restore access: `plan` only narrows broad rules that still
exist, and the apply removed them. Exit code 1 means it found refused sources
and you chose not to record them, which makes it usable as a pipeline check.

### `sg_extend.py`: break-glass during an incident

When a DR failover or a supplier's IP change is being blocked *now*, the
analyse/plan/apply loop is too slow. `sg_extend` reads recent `REJECT` flows and
**only adds** ingress rules; it never revokes. Its design:

* **Group discovery.** Without `--groups`, it finds the network interface that
  received each rejected flow and the security groups attached to it. Each
  group only receives rules for flows that hit its own interfaces, AWS-service
  ranges included. When the log format has `${interface-id}` (the default and
  recommended formats do), the logging interface decides, which stays exact
  where VPCs reuse addresses; records logged by the sending side are ignored.
  Without it, the address is looked up in the region (EKS delegated prefixes
  included), and an address used in more than one VPC is skipped with a
  warning. `--max-groups` (default 20) refuses runs that would touch more.
* **Per-port rules.** Sources are grouped per protocol and destination port, so
  a rule only opens the port that was actually rejected. `--ports` narrows it
  further.
* **Private by default.** Public sources are ignored unless you pass
  `--include-public`. When you do, sources inside an AWS-published service
  range (from `ip-ranges.amazonaws.com`, cached for 7 days) are summarised into
  that service's range with a labelled description, instead of `/32`s that go
  stale when AWS rotates addresses. The catch-all `AMAZON` range is never used.
* **Budget aware.** Grouping uses `--tolerance` and the same exact fitting as
  `plan` (see above);
  CIDRs already covered by an existing rule are skipped; a group that would
  exceed `--max-rules` is skipped with a warning.
* **Manifest.** Every run writes `sg_extend-manifest-<ts>.json` listing exactly
  what it added, so the next tightening cycle can fold it in. It is rewritten
  after every group, so it survives a crash part way (`complete` stays
  `false`). Unknown `--groups` ids are reported before the confirmation
  prompt and recorded as `NOT_FOUND`; the run exits 1 if any group failed.

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

`::/0` counts as `0.0.0.0/0`. Accounts are ranked by a weighted score so that
one CRITICAL outranks any number of LOWs. Every account gets a row with a
`scan_status`: `ok`, `incomplete` (part of a region's scan failed) or
`failed` (the role could not be assumed); an account that was not scanned is
never shown as clean. Exit code 1 when any CRITICAL is found, else 2 when the
scan was incomplete.

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

### `sg_viz.py`: who talks to what, and what a plan would cut off

Read-only. Exports a region's traffic over a window as one JSON file
(`viz-data.json`) for any viewer or report to draw: every connection (source,
destination interface, port, protocol) with accepted and rejected totals, a
per-bucket timeline, and the security-group rules that allow it.

* **Interface-exact.** Destinations resolve by the flow's `interface-id`, then
  by address, including delegated prefixes (EKS pods), so overlapping VPCs
  become separate connections. An address used in several VPCs with no
  interface id is shown without one, with a warning.
* **Reference rules match.** Each connection carries the source's own
  interface and groups (`src_eni`, `src_groups`, preferring the destination's
  VPC), so a rule that admits another security group is credited.
* **Plan overlay.** With `--plan` (or `overlay` later), every accepted
  connection is marked `blocked` if the plan would stop it, or `kept` with the
  rule that still allows it.

### `sg_review.py`: one account's rules against months of traffic

`sg_review` answers the question to ask before a `plan`: what is each rule
used for, and by whom? It reads one account (the credentials' own) and writes
one HTML page that needs no server and calls nothing.

**Reading.** Per region it takes a snapshot (groups and rules, prefix lists
resolved; interfaces with their addresses, delegated prefixes and groups;
VPCs; network ACLs; VPN static routes; flow logs) and 90 days of inbound rule
changes from CloudTrail. Flow logs in CloudWatch Logs are then read in UTC
slices: hourly for the last day, six-hourly for the last week, daily beyond.
Each slice runs two Logs Insights queries, one for accepted inbound
connections and refused private ones (by source, target, interface, protocol
and port), one for refused internet sources, one row each so scanners cannot
fill the answer. A slice that returns 10,000 rows is split in half down to an
hour, as `analyse` does; one still full at an hour is marked `cut`, and the
rules in its region are reported as Incomplete. Ports from 32768 up are folded
into one, since they are mostly replies to the account's own connections.

**Three timelines.** *Refused*: distinct sources turned away per period, with
what refused each (a network ACL entry, the security group, or a rule since
added). *Over-provisioned*: for each group whose every interface is logged,
the addresses its rules allowed at that time less every address seen anywhere
in the account, summed; the rules at each time are worked back from today's
through CloudTrail's changes, and a change made by rule id (whose earlier value
CloudTrail does not record) freezes that group's history and is said so.
*Active*: distinct sources let in, split by whether they were also seen in the
last 24 hours, so DR tests and monthly batches stand out before a tightening
removes them.

**Rule status.** A rule is called Unused or Tighten only with 30 days of
evidence or more (Too early otherwise). Tighten applies to a private rule wider
than /24 (`plan`'s default threshold) or a public range, with never-seen addresses; the
suggested ranges come from the same `collapse_ips_to_cidrs` that `plan` uses,
clipped to the original rule, keeping sources seen on interfaces since deleted
in the same VPC. The page offers the evidence as approved.json per region, so
`plan` can be run against exactly what was reviewed.

**Attribution and ports.** Each source address is matched, most specific first,
against the account's VPCs, the `--internal` and `--onprem` ranges and the VPN
routes; then against AWS's published prefixes (longest match, so a service
prefix wins over the general AMAZON one), the SaaS providers' published
prefixes, and the AS number table, which gives the owner, country and announced
block. An address on the Tor Project's exit list is a Tor exit whatever network hosts it. Ranges and AS
numbers in the names file win over every public list: a named range is matched with your own ranges,
before AWS's; a named AS number after AWS's. A SaaS or internet source then gets a source type (CDN, secure access,
SaaS, hosting, scanner, Tor or VPN, other) from `sg_ipintel.ORG_ASNS` by AS
number, or else from the first of `ORG_NAMES`' owner-name patterns that
matches; an owner none of whose words starts like a pattern is skipped without
trying them, which keeps the 80,000 owners to about a second. Each source is
counted once per period in its kind, its source type, its network and
each port class it reached, so the graphs can be coloured any of those ways.
The page lists the 150 busiest networks per timeline and sums the rest per
kind. Ports are classed from a fixed table of common services (`PORT_CLASSES`
and `PORT_SERVICES` in `sg_review.py`). A class names what a port usually
carries, not what listens on it.

**Verdicts.** Built from what `read` already collected, with no further AWS call. Each refused
source keeps the first and last time it was refused per target. It is then matched, in order:
sweeping many ports or targets (critical from your own ranges, info from outside); nothing refused in
the last periods (fixed since); let in on that interface and port before, refused after
(a CloudTrail change on one of its groups within two days of the first refusal that removed an entry
covering it is the cause, and the entry is rebuilt as `--ip-permissions` to restore it; otherwise
stopped working); refused by a network ACL; a new address of a client (another source with the same
name or provider let in on that interface and port, last seen within `MOVE_WINDOW`, two days, of the
first refusal); the same provider let in elsewhere; AWS health checks; your own ranges; a partner;
a known service over two or more periods; retries. Sources let in are checked against the scanner
and Tor lists and the hosting type, on the port class. **Needs attention** groups the critical, high
and medium verdicts by key and by the change, source or provider, and ranks them by severity, then
flows times days. Each marker on the timeline whose change caused refusals carries those sources
(`caused`), so the refused graph can mark it.

**`watch` and `org`.** `watch` reads the gap in the last day (`plan_read` and `run_read`, as `read`
does), builds the 24-hour range and keeps an id per item (key, target, name, group, change time) with
when it was posted. `org` lists the accounts through Organizations, assumes a role in each, plans every
read first so the cost is confirmed once, then writes each account's page and a roll-up of the
`summary.attention` counts and items.

**Extract rule.** This runs in the page, without the network. It groups the
refused sources listed by the first security group of the interface that
refused them, the protocol and the port. It covers each group's ticked sources
with the fewest CIDR blocks that hold exactly those addresses. A /31 is used
only when both addresses were refused, so it never adds an address that was not
seen. It writes one `authorize-security-group-ingress` per group. Sources that a
network ACL refused, or that a rule added since already allows, are left out,
because a new security group rule would not change them.

**Naming.** A source is internal (this account's VPCs, or `--internal`
ranges), data centre (`--onprem`, VPN routes, other private space), AWS (from
ip-ranges.json, with the service), SaaS (providers' published ranges, then
known provider AS numbers) or another network by AS number, owner and country
(iptoasn.com). The lists are downloaded once a day (a week for AS numbers) and
looked up locally; no address is sent anywhere.

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
* **PrivateLink.** Interface endpoints (the consumer side) are planned like
  any other interface: their network interface carries the endpoint's group,
  and flow logs record each client reaching it. The provider side is not.
  Flow logs do not record traffic from an interface endpoint to the Network
  Load Balancer behind an endpoint service, and when the NLB enforces its
  inbound rules on PrivateLink traffic (the AWS default) those rules see the
  consumers' own addresses, in their VPCs and accounts. No flow log here can
  show them, so `plan` never touches a group on such an NLB and lists it
  under `skipped_groups`. If endpoint services cannot be listed, every group
  on a load balancer interface is held back.
* **Only groups the flow logs can see.** `plan` skips any group whose VPC, or
  every interface carrying it, is outside the flow logs that fed
  `approved.json` (`skipped_groups`). An `approved.json` from before 2.1.0
  does not record that coverage, and `plan` warns.
* **Overlapping VPC ranges.** With `${interface-id}` in the log format (the
  default and recommended formats have it), each flow is tied to the
  interface that logged it, so VPCs that reuse a range are told apart, and a
  record logged by the sending side is ignored. Without it, an address used
  in more than one VPC is kept per rule and listed under
  `ambiguous_destinations`.
* **Rules with no observed traffic are removed.** They appear under
  `removed_without_evidence` in the plan and in a warning. If one should stay,
  delete that group from the plan or add the expected source to
  `approved.json`.
* **The window is the evidence.** Anything that did not connect during the
  analysed window is treated as unused. Use `--days 180` or more where seasonal
  traffic exists.
