# Changelog

## Unreleased

## 2.3.0 - 2026-11-20

- **Change (`plan`, `sg_extend`): exact rule fitting.** When observed
  addresses do not fit the rule budget, the CIDRs are now chosen exactly: the
  at most `--max-rules` blocks that grant the fewest never-observed addresses.
  This replaces raising the tolerance in steps and force-merging neighbours,
  which on clustered traffic granted 25 to 60% more unused addresses and often
  left rule slots empty. Plans are never wider than 2.2.0's (tested against
  2.2.0's code, kept in `tests/fixtures/legacy_collapse.py`). The tolerance
  blocks are still the finest result, so headroom for new hosts is kept.
- **Change (`plan`): budget split by savings.** A group's slots go to the
  rules where they save the most addresses, not in proportion to how many
  blocks each rule needs, so a rule of 30 neighbouring hosts no longer takes
  slots a rule spanning a /16 needed.
- **Performance:** counting addresses is a binary search, not a scan; 2,000
  addresses take 0.02 s instead of 14 to 28 s, and `plan` no longer collapses
  each rule twice.
- The warnings `widening tolerance to …` and `force-fitting …` are replaced by
  one: `N blocks at tolerance T exceed the B rule budget; merged into M …`.

## 2.2.0 - 2026-11-20

- **Fix (`sg_diagnose`):** a rejected source counted as covered if any rule
  in any group allowed it, on any port, so the breakage tightening causes
  stayed hidden. Each rejected flow is now judged against the groups on its
  own destination interface, on its protocol and port. `--manifest` marks
  flows a revoked rule would have admitted. It prints the `sg_extend` command
  that restores access, and records flows (not just addresses) in
  `approved.json`, saying plainly that recording alone changes nothing.
- **Fix (`plan`):** flows now record the `interface-id` that logged them, so
  where VPCs reuse addresses a source is granted only in the VPC it reached.
  Records logged by the sending side are ignored. Without an interface id, an
  address used in several VPCs is kept per rule and listed under
  `ambiguous_destinations`.
- **Fix (`sg_viz`):** destinations resolve by interface id and delegated
  prefix (EKS pods), overlapping VPCs become separate connections, and
  security-group reference rules match: connections carry the source's own
  interface and groups (`src_eni`, `src_groups`). One unknown group id no
  longer aborts the export.
- **Fix (org reports):** an account whose role could not be assumed, or a
  region whose scan failed, looked the same as a clean one and the run exited
  0. Every account now has a `scan_status`, the JSON carries `complete` and
  `errors`, and the exit code is 2 when the scan was incomplete (1 still wins
  for CRITICAL). `::/0` is treated like `0.0.0.0/0` in both reports, and
  boto3 clients are created under a lock (Sessions are not thread-safe).

## 2.1.0 - 2026-11-20

- **PrivateLink.** `plan` never touches a group on a Network Load Balancer
  behind a PrivateLink endpoint service. Flow logs do not record
  endpoint-to-NLB traffic, and with inbound-rule enforcement on (the default)
  the NLB's rules see the consumers' own addresses, so the plan saw no
  evidence and would have revoked every consumer's access. NLBs with
  enforcement off are planned as before. Interface endpoints (consumer side)
  were already handled and are now tested. `plan` needs
  `ec2:DescribeVpcEndpointServiceConfigurations` and
  `elasticloadbalancing:DescribeLoadBalancers` (added to `iam-policy.json`);
  without them, groups on load balancer interfaces are held back.
- **Fix (safety):** `plan` tightened every group in the region, including
  groups in VPCs the analysed flow logs never covered; those had no evidence
  and lost every eligible rule. `analyse` now records the flow logs' resources
  in `approved.json` (`flow_log_check.resources`) and `plan` lists uncovered
  groups under the new `skipped_groups` instead.
- **Fix:** rules for all traffic (`-1`) could not be applied or reverted: the
  plan sent `FromPort`/`ToPort` of `null`, which boto3 refuses. Plans and
  manifests from 2.0.0 are cleaned when applied or reverted.
- **Fix:** a replacement already covered by a rule the plan keeps (same
  protocol and ports) was authorised again, which fails as a duplicate after
  the broad rule has been revoked, halting apply mid-group. It is now dropped.
- **Fix (`sg_extend`, safety):** with `--include-public`, AWS-service ranges
  (for example a whole regional EC2 prefix) were added to every discovered
  group, not only the groups whose interfaces received those flows.
- **Fix (`sg_extend`):** destinations were matched to interfaces by address
  across the region, so where VPCs reuse a range the twin VPC's group was
  opened too, and EKS pod addresses (delegated prefixes) never resolved. The
  flow record's `interface-id` now decides; without it, an address used in
  more than one VPC is skipped with a warning.
- **Fix (`sg_extend`):** one duplicate made AWS add nothing while the run
  reported partial success; the remaining rules are now added one by one. An
  unknown `--groups` id crashed the run after confirmation; it is now
  reported first and recorded as `NOT_FOUND`. A connection error no longer
  loses the manifest, which is written after every group; the exit code is 1
  when any group failed.
- **Fix:** `sg_compact` revert restored merged rules without their
  descriptions; compact plans now carry `restore`.

## 2.0.0 - 2026-11-17

First release from its own repository (the `v1.x` tags belong to cloudtorepo,
whose history this repository carries). Major because `approved.json` gains
per-destination evidence and `plan` now gives each group only the sources that
reached it. `sg_tightener.py --version` prints the version.

- **Own repository.** Moved out of
  [cloudtorepo](https://github.com/andrewbakercloudscale/cloudtorepo) (where it
  lived in `sg-tightener/`) with its history.
- **Fix:** `sg_diagnose` crashed with a `TypeError` on every run since the
  flow-log preflight was added. It now uses the same preflight as `analyse`.
- **Fix (safety):** `plan` now rebuilds each eligible rule only from observed
  private addresses inside that rule's own CIDR, and clips any widened block
  back to it. Before, every eligible rule in the region received the same
  replacement set, so a plan could allow sources a rule never allowed,
  including public `/32`s from `approved.json`. Rules with no observed traffic
  are listed under the new `removed_without_evidence` plan field. The budget is
  shared across a group's rules.
- `iam-policy.json` gains `transfer:ListServers`, `transfer:DescribeServer`
  and `ec2:DescribeVpcEndpoints`, which `sg_transfer_audit` needs.
- New documentation under `docs/`, CI on Python 3.9 to 3.12.
- **Fix (safety):** a Logs Insights answer stops at 10,000 rows without saying
  so; `analyse` and `sg_extend` took it as the whole answer and the plan then
  revoked access for every source cut off. A full answer is now discarded and
  the window split in half until each part fits; a one-minute window that is
  still full is refused.
- **Fix:** a failed or cancelled Insights query is an error, not an empty
  result, and `analyse` no longer polls with no pause.
- **Fix:** `plan` records its region and `apply` runs there. Before, `apply`
  used `AWS_REGION`, so a plan applied with the wrong one failed confusingly.
  A `--region` that disagrees with the plan is refused.
- **Fix:** the `apply` manifest recorded a whole group as done even when the
  authorise after a successful revoke failed, and was written only at the end.
  It now records each call as it succeeds. `revert` restores rule
  descriptions, exits non-zero when a call fails, and catches connection
  errors as well as API errors.
- **Fix:** `sg_diagnose --hours 2` read 24 hours; the window is now exact.
- **Fix:** `sg_extend` read every flow log as the default format. With a custom
  format its rules were built from the wrong columns, and behind a transit
  gateway from the next-hop address. It now runs the flow-log preflight and
  parses with the configured format, preferring `pkt-srcaddr`.
- **New:** `sg_viz.py export` / `overlay`: one JSON file of who talked to what,
  accepted or rejected, over time, the rule that allowed each connection, and
  which connections a plan would block.
- **Tests:** pytest, split into `tests/unit` and `tests/integration` (moto),
  with a synthetic flow-log generator. 170 tests.
- **Fix (safety):** `plan` gave each group's rule every observed source inside
  it, not only the sources that reached that group: a database on 5432 was
  granted office clients that only ever called the API on 443. `analyse` now
  writes `approved.json` v2 with `flows` (source, destination address,
  destination port, protocol), and `plan` maps each destination to its groups
  through `DescribeNetworkInterfaces` (delegated prefixes included) and keeps a
  source on a rule only when it reached that group on a protocol and port the
  rule admits. A destination no current interface owns, or an address in `ips`
  with no flow, is kept per rule and listed in the plan
  (`unattributed_destinations`, `sources_without_flows`). A v1 file still plans
  per rule, with a warning. Plans record `attribution`. `plan` now needs
  `ec2:DescribeNetworkInterfaces` (already in `iam-policy.json`).

## History before the move

- `analyse` verifies the flow-log configuration and parses per its format.
- `sg_transfer_audit.py`: Transfer Family internet-exposure audit.
- `sg_extend`: group auto-discovery and AWS service range summarisation.
- `sg_compact.py`: CIDR widening to reclaim rule budget.
- `sg_extend` became flow-log driven.
- First release: `sg_tightener`, `sg_diagnose`, `sg_ou_report`.
