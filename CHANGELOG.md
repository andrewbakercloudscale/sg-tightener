# Changelog

## Unreleased

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
