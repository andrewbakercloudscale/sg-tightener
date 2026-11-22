# Changelog

## 5.8.0 - 2026-11-22

- **Over-provisioning by type and owner, over time.** The over-provisioned
  graph gains **Colour by**: kind, source type or network. By network, each
  never-seen address is attributed once: your VPCs, your other accounts' VPCs,
  the routes behind each VPN and your named ranges first, then private space
  no VPC or named range uses, each AWS service and region, each SaaS provider
  and each AS. The biggest three of each kind are named and the rest summed per
  kind. Each window's series carry `over_by_net` and `over_by_group`.
- "N more networks (kind)" replaces "N more External: other networks networks".
- The blog post and guide show the over-provisioning graph by network.

## 5.7.1 - 2026-11-22

Five bugs found testing 5.7.0, each with a regression test:

- **A range in several accounts was named for whichever was read first.** Every
  default VPC is 172.31.0.0/16, so a source there was pinned on one account. A
  range shared by several accounts is now named "One of N accounts (...)".
- **Your names file and `--onprem` lost to automatic account naming** on the
  same range. Every range you name (`--internal`, `--onprem`, VPN routes, the
  names file) now wins.
- **`forget` left the account in `vpcs.json`**, so it kept naming sources in
  other reviews. It is now removed, and entries for reads deleted by hand are
  dropped.
- **Unattributed sources showed "none named"** in the networks table. They now
  show their own address as the block.
- **AWS's catch-all range was named "AWS AWS"**. It is now "AWS (any AWS
  service)".
- README, the review guide and the blog now open with why security groups are
  not static configuration, the backhaul risk of large on-premises CIDR blocks,
  and the need for a management and observability mechanism to shrink them.

## 5.7.0 - 2026-11-22

- **Where traffic comes from.** A new table in the review lists one row per
  network, grouped by kind, for the window chosen: its CIDR blocks, ports,
  sources and flows in and out, interfaces reached, and first and last seen,
  with a search and filter. On-premises ranges, other AWS accounts, AWS
  services by region, Lambda outside a VPC (shown as the region's shared EC2
  ranges, since AWS publishes no Lambda ranges) and SaaS such as Salesforce,
  Zscaler, Okta and GitHub each show separately. Each window carries
  `networks`.
- **Other accounts are named automatically.** `read` records every account's
  VPCs in `~/.sg-tightener/review/vpcs.json` (built from earlier reads the
  first time), and the report names traffic from them as
  "account name (id), VPC name". `--internal` still wins on the same range.
- **Tabs.** The page is split into Traffic, PrivateLink and Exposure tabs, each
  with its critical and high count; the address keeps the tab.
- **PrivateLink inventory.** The PrivateLink tab lists every endpoint service
  and interface endpoint, not just the risky ones, with the sources, networks,
  ports and refusals through each endpoint for the window chosen
  (`pl_inventory`).
- The demo includes Salesforce callers and a sibling account.

## 5.6.0 - 2026-11-22

- **Every graph has the time window.** The **Time window** drop-down is now on
  Needs attention and Ports as well as the top and the three timelines, all in
  step. (Exposure, PrivateLink and the rules table describe the configuration
  now and do not change with the window.)
- **No data is shown as no data.** Every window is built, whatever was read.
  When one reaches back further than the flow logs read, a note beside each
  graph says from when there is data and how many of the window's days were
  read, the time not read is shaded and labelled **No data** on each timeline,
  the over-provisioned lines stop where the data does, and the `read --days`
  command that fills it is given. Partly read periods are shaded lighter. The
  drop-down marks such windows "data for N days only" or "no data". Each
  window carries `covered`, the share of each bar read.
- The console's rejected traffic says which accounts have no data for the
  window chosen, and from when they do (`first`, `covered` per account).
- The demo reads 180 days again, so its year window shows what missing data
  looks like.

## 5.5.0 - 2026-11-22

- **Time window drop-down.** The review's timeline buttons are now a **Time
  window** drop-down (last 24 hours, week, month, 3 months, 6 months, year), at
  the top and above each timeline (refused, over-provisioned, let in), all kept
  in step. Windows not read yet are greyed out with the days to read.
- **A year.** `sg_review.py read --days 365` (and `watch`) reads back a year,
  shown a bar a week ("w/c 5 Nov"), to see yearly batches and DR tests before a
  rule is removed. The page still opens on the longest window up to 6 months.
  The console's rejected traffic offers **Last year** too. The demo covers a
  year.

## 5.4.0 - 2026-11-22

- **Extract rule, one destination at a time.** Refused traffic is turned into
  one rule per destination address by default, numbered "1 of 7", each card
  with its own command, a **Copy this rule's command** button and, opened from
  the console, **Propose this one in the console**: add one, check its refusals
  stop, then the next. A card warns when the destination's security group is on
  other interfaces too, with the `sg_db.py asset-plan` command that gives the
  interface a group of its own. The same range into the same group is written
  once. A toggle switches back to one rule per security group and port.
- **What we know about each source.** Every source is marked **Familiar**,
  **Unfamiliar** or **Do not add**, with the reasons; **What we know** opens
  the evidence: your own interface behind the address (instance, Name tag,
  operating system, type, groups), ports it is already let in on, rules that
  already allow it, first seen and whether it is new, what else it was refused
  on, and the verdict. The window counts the sources ticked by each.
- `sg_review read` reads each attached instance (`ec2:DescribeInstances`, in the
  read-only policy) for its Name tag, operating system and type; destinations
  in Extract rule show them too. The demo names its instances.

## 5.3.0 - 2026-11-22

- **Known malicious addresses.** Every source and outbound destination is
  checked against four free threat lists, downloaded daily and looked up
  locally: abuse.ch Feodo Tracker (botnet command servers), Spamhaus DROP
  (criminal or hijacked netblocks, IPv4 and IPv6), Proofpoint Emerging Threats
  (compromised hosts) and blocklist.de (recent attackers). A new source type,
  **Known malicious**, wins over the AS number and cloud ranges but not over a
  provider's own service (a CDN address keeps its provider's name).
  - Refused: "Known malicious address refused", info.
  - Let in: "Known malicious let in", critical on risky ports.
  - Outbound: "Outbound to a known malicious address", critical.
  - `watch` always posts the let-in and outbound items, whatever `--alerts`.
  - Tighten turns known malicious, Tor and scanner sources away by default
    (new option **Turn away**).
  - Console Rejected traffic marks them **known malicious** or **Tor**, with a
    filter. Your names file takes `type: threat` for your own intelligence.
  - The demo: an attacker refused on SSH for weeks, let in once a contractor
    opened ops-ssh to the world; an app server calling a botnet server.
- **Alerting scripts** in `deploy/alerts`: `sg-alerts.sh` (watch, watch-once,
  reconcile, daily) reading one settings file, with systemd units and timer, a
  launchd agent and a crontab.
- **install.sh** checks every package imports, downloads the address lists
  once, and takes `--dev` for the test packages. Run outside the venv,
  `sg_review.py` says to run `./install.sh` instead of a traceback.
- Tests run against their own data directory, never `~/.sg-tightener`.

## 5.2.0 - 2026-11-22

- **Blast radius.** The Security Group Review has a new card under the
  Tighten panel: type one address (or pick a data centre, internal, SaaS,
  internet or "anyone" address) and see every rule that admits it, worst
  first: the group, ports, the range or group reference that lets it in, and
  the network interfaces behind the group. Risky ports are marked and rules
  open to every address are counted apart. Each row shows what the Tighten
  settings would do to it (unchanged, narrowed or cut off) and the summary
  shows the reach before and after. In the demo, data centre host 10.200.4.22
  goes from 9 groups on 8 interfaces to 6 on 5.
- **`sg_review.py reach ADDRESS [--account ID] [--json]`**: the same from the
  command line, from what was already read; no AWS call.
- **Managing the risk.** New guidance in the Security Group Review guide and
  the README: internet-reachable before open on paper, read 90 days before
  removing anything, tighten admin and database ports first, flow-log blind
  spots, egress, group hygiene, recording changes made outside the tool, and
  the two numbers to report.

## 5.1.0 - 2026-11-22

- **Tighten on the timeline.** The Security Group Review's over-provisioned
  graph has a **Tighten** panel: each rule fitted to the sources that used it,
  with the room chosen per kind (internal, data centre, AWS, SaaS and partners,
  other networks), overridden per source type or per name: each address only,
  the /28, /24, /20 or /16 around each, its published or named range (Lambda,
  Zscaler, a partner from the names file), or keep the rule. Optional: drop
  sources not seen in 60, 30 or 7 days; fit rules open to every address.
- **Rules nothing used are removed by default**: a rule no source used in the
  whole read (30 days or more) is the clearest over-provisioning. The panel
  warns how many are removed and that a DR path or yearly job looks the same;
  untick to keep them.
- The graph shows the **After** point (dashed) and the refused sources each day
  on a right-hand scale, with how many the change would turn away. Rule changes
  are marked ▼ when they took away more addresses than they added (a
  tightening, such as `13.0.0.0/8` → `13.108.0.0/14`) and ▲ otherwise, so a
  spike in refusals after a ▼ shows a source was cut off. The After point is on
  the total line (a rule is fitted as a whole, while the lines by kind split its
  range by owner).
- **Propose from the page.** Opened from the console (**Review and tighten** on
  the Overview, `/review?account=ID`, served with the console's nonce CSP), it
  proposes one change request per region; opened as a file, it downloads a plan
  (`sg-tightener.plan/v1`) for `sg_db.py propose --plan`. Two-person approval
  and enforce mode apply as for any change.
- The console's state marks which accounts `sg_review` has read (`reviewed`).
- Demo: a `webhooks-in` group opened to every AWS, GitHub and Zscaler address,
  a tightening that cut off Lambda callers (refusals spike) and the range put
  back the next day. Tighten takes it from 102.4M never-seen addresses allowed
  to 208k.
- README: the Security Group Review graphs come first ("See it first").

## 5.0.0 - 2026-11-21

Breaking: every account starts in **surveillance** mode. Reports, plans and
change requests work as before, but `sg_db.py apply`, `exec`, `create-group`,
`sg_tightener apply`, `sg_compact apply`, `sg_extend` and the console's Apply
refuse until `sg_db.py check` passes and `sg_db.py mode enforce --account ID
--reason "…"` (or `mode enforce --all`) is set. `revert` works in either mode.

- **Surveillance and enforce modes**, per account with a default (`sg_db.py
  mode`), each change audited. Enforce needs a passing permission check.
- **Permission check with DryRun** (`sg_db.py check --regions R [--ou-id …]
  [--assets]`): every authorize and revoke, ingress and egress, on every
  group, and for assets creating a group, swapping an interface's groups and
  tagging, as EC2 DryRun calls, so SSO permission sets, boundaries, SCPs and
  conditions all count and nothing changes. Stored and shown on the console's
  Overview with a Check button. `apply` runs it first and changes nothing if
  any call would be refused.
- **Assets.** `import` and `reconcile` record every network interface (its
  instance, auto scaling group or EKS cluster, addresses and groups); a change
  of groups is an audit entry of its own, external when made outside the tool.
  `sg_db.py assets`, `asset-log`, and the console's Assets table with History.
- **A group of its own for one asset** (`sg_assets.py`): `asset-plan` merges
  the asset's groups and keeps only the sources that reached that interface;
  `asset-propose` makes it a change request; once a second person approves,
  `asset-apply` creates `sgt-<eni>-<time>` and moves the interface onto it;
  `asset-revert` moves it back. Auto scaling, EKS, ECS and AWS-managed
  interfaces are refused: tighten the shared group, which new instances
  inherit. IAM: `ec2:ModifyNetworkInterfaceAttribute`, `ec2:CreateTags` (write)
  and `ec2:DescribeInstances` (read).
- **IPv6 sources named**: IPv6 ranges for AWS, Cloudflare, Google, Datadog,
  ip2asn and Tor; your VPCs' IPv6 blocks, ULA and link-local count as
  internal. IPv6 works in verdicts, network ACL checks, Extract rule and
  `watch`.
- **IPv6 tightening**: `sg_tightener plan` narrows IPv6 rules wider than `/64`
  that are ULA or inside the region's VPC IPv6 blocks to the `/64`s seen;
  `::/0` and public IPv6 ranges are never touched.
- **New addresses**: each source's first sighting across everything read; a
  source is **new** when first seen in the last 7 days with at least 14 days
  of flow logs before it. Shown on the review page (New only and IPv6 only
  filters), the org page, `watch` alerts ("N new"), and the console's Rejected
  traffic tab, which also marks internal / external / IPv6 / scanning and
  filters on them.

## 4.0.0 - 2026-11-21

Breaking: two-person approval is on by default. `sg_db.py add`, `remove`,
`exec` and `adopt` record a change request instead of changing the database
at once, and `sg_tightener apply` and `sg_compact apply` refuse until the plan
is proposed and approved. `sg_db.py approvals off --reason "…"` restores the
3.0.0 behaviour for a single operator.

- **Security group console (`sg_console.py serve`).** A local web page over the
  database: every account's groups and rules (marked to add / to remove),
  change requests to propose, approve, reject and withdraw, apply and
  reconcile buttons, the audit trail with search and filters and the state
  of its hash chain, and every rejected flow across the accounts
  `sg_review` has read, with **Propose allowing** to turn a refused flow into
  a request. It listens on 127.0.0.1 only; a one-time token sets an HttpOnly,
  SameSite=Strict cookie, every change also needs the token in a header and
  JSON, the Host header is checked, and the page runs under a nonce CSP.
  `docs/console.md`.
- **Two-person approval.** A change is a request (who, why, ticket, the
  changes). A different AWS principal must approve it; a rejection needs a
  note; only the proposer can withdraw it. Approved changes become desired
  and are applied with `sg_db.py apply` (or the console); the request is
  marked applied once AWS holds them. Every step is in the audit trail.
  `sg_extend` (break-glass) and `revert` go straight through. New commands:
  `propose --plan`, `requests`, `approve`, `reject`, `cancel`, `approvals`.
- **Across an OU.** `sg_db.py import` and `reconcile` take `--ou-id`, `--org`
  and `--accounts` and assume `--role-name` in each account; other commands
  take `--account`. `sg_review.py watch --ou-id|--org` alerts on rejected
  traffic in every account. The org page (`sg_review.py org`) has an
  **All rejected traffic** table across every account.

## 3.0.0 - 2026-11-21

Breaking: security groups are managed through a local database, Terraform
cannot manage them with this solution, and the 2.8.0 drift Lambda is removed.

- **Security group database (`sg_db.py`).** Every group and rule lives in
  SQLite (`~/.sg-tightener/sg.db` or `$SG_TIGHTENER_DB`), held as *desired*
  and *synced*. Every change is written with who, why and an optional ticket
  to an append-only (triggers refuse UPDATE and DELETE), hash-chained audit
  trail; `verify` proves nobody edited or removed an entry. Commands:
  `import`, `reconcile`, `show`, `diff`, `add`, `remove`, `exec`, `apply`,
  `adopt`, `create-group`, `log`, `verify`.
- **Changes made outside the tool** (console, CLI, Terraform) are found by
  `reconcile`, recorded as external with who made them from CloudTrail,
  posted to Slack, and printed with how to put AWS back (`apply`) or keep the
  change (`adopt`). A person decides.
- **Every write goes through the database.** `sg_tightener apply`/`revert`,
  `sg_compact apply`/`revert` and `sg_extend` record each change.
  `apply` refuses while AWS has unreviewed external changes or the database
  has changes not applied; `revert` and `sg_extend` (break-glass) warn and go
  ahead. The fixes `sg_review` prints (page, alerts, Extract rule, restore)
  run through `sg_db.py exec --reason …`; the default-group fix is
  `sg_db.py remove --all`.
- **No Terraform for security groups.** The README says so plainly and
  `docs/terraform.md` is now a one-way migration: import, `removed` blocks or
  `terraform state rm`, `data "aws_security_group"` for attachments, an IAM or
  SCP deny on the security group write calls, hourly `reconcile`. New
  `docs/database.md`.
- **Real-time alerts are for rejected traffic.** `sg_review watch` posts only
  refused-traffic items by default (`--alerts all` for the rest), `--every`
  defaults to 5 minutes, and each run also reads a tail from the last full
  hour to five minutes ago, so a refused flow is alerted within about 10
  minutes (`--no-tail` to skip; about twice the cost of a daily read).
- **Removed:** `sg_drift_lambda.py` and `deploy/drift-alerts/` (CloudFormation
  and Terraform). Rules opened wide are still **Needs attention** items in the
  report and in `watch --alerts all`.
- IAM: `ec2:DescribeSecurityGroupRules` in the read policies;
  `ec2:CreateSecurityGroup` (one VPC) in `iam-policy-write.json`; egress and
  `CreateSecurityGroup` in `iam-policy.json`'s write statement.

## 2.8.0 - 2026-11-21

- **Real-time drift alerts.** `sg_drift_lambda.py` and `deploy/drift-alerts/`
  (CloudFormation template and Terraform module). EventBridge sends each
  successful `AuthorizeSecurityGroupIngress` and `ModifySecurityGroupRules`
  call to a Lambda function, which rates the rule it added as `sg_review`'s
  **Rules opened wide** does and, at or above `MinSeverity` (default high),
  alerts within seconds: SNS (email, chat, pager), Slack (webhook in Secrets
  Manager) and Security Hub (the same finding id as `sg_review securityhub`).
  It names who made the change and from which address, and gives the revoke
  command.
- **Optional automatic revoke** (`AutoRevoke` = `critical` or `high`, off by
  default). Groups tagged `sg-tightener-allow-wide=true` are never revoked,
  by the code and by a Deny in the function's policy.
- A CloudWatch alarm on the function's errors posts to the alert topic.
- `python sg_drift_lambda.py event.json` prints the alert a saved event would
  raise, with no AWS call.
- Drift items carry the rule they found (`rule`: protocol, ports, range, rule
  id).

## 2.7.0 - 2026-11-21

- **SSO everywhere.** Every tool that calls AWS takes `--profile` (an
  `aws configure sso` profile works). An expired or missing SSO session, or an
  unknown profile, prints one line with the fix (`aws sso login --profile X`)
  and exits 1, instead of a traceback. The CLI reference has an SSO section:
  permission sets, and how the organisation commands assume roles from an SSO
  login.
- **Internet exposure, not just open rules.** `sg_review` reads route tables
  and works out, per rule open to `0.0.0.0/0` or `::/0`, whether any interface
  using it has a public address in a subnet routed to an internet gateway, with
  network ACLs that let the traffic in. Reachable is critical on a risky port,
  high on others, low on 80/443 (load balancers on web ports left out); open
  but unreachable is low. New page section **6 Exposure and hygiene**.
- **IPv6.** IPv6 ranges, interface addresses and network ACL entries are read;
  a global range of `/32` or wider is a finding, and `::/0` is treated like
  `0.0.0.0/0`.
- **Outbound (`read --egress`).** Optional, about +50% per read. Flags
  interfaces that connected out to Tor exits, VPNs or scanners (high), and
  fits outbound rules to the destinations and ports used, with the
  `authorize-security-group-egress` and revoke commands. Without it, open
  outbound on database groups is listed (low).
- **Group hygiene.** Default security group in use (CIS 5.4), rules that trust
  another account's group, references to deleted groups, one group shared
  across tiers, and open groups no interface uses.
- **Drift alerts.** A rule added in the last 24 hours that lets in `0.0.0.0/0`,
  `::/0`, a public `/16` (IPv6 `/32`) or wider, or a private `/8` on a risky
  port becomes a **Needs attention** item straight away, naming who added it,
  from which address and when, with the revoke command. `watch` posts it.
- **AWS Security Hub.** `sg_review securityhub` (or `--out` for ASFF JSON),
  `--securityhub` on `watch`, `org` and `sg_ou_report`. Stable ids update
  findings in place; findings no longer found are archived.
- **`sg_ou_report`** adds a reachability `note` to every `0.0.0.0/0` and `::/0`
  finding, rates wide IPv6 ranges, and reports `SG (default, in use)` and
  `SG (cross-account reference)`.
- **Least privilege.** `iam-policy-read.json` (with Security Hub as a separate
  optional statement) and `iam-policy-write.json` (ingress and egress writes
  limited to one VPC, denied on groups tagged `sg-tightener=protected`).
  `iam-policy.json` gains `ec2:DescribeRouteTables`,
  `ec2:DescribeStaleSecurityGroups` and `securityhub:BatchImportFindings`.
- **Signed plans and manifests.** Plans and manifests carry an `integrity`
  block (SHA-256, the signer's ARN, the time, and an HMAC-SHA256 when
  `SG_TIGHTENER_SIGNING_KEY` is set). `apply` and `revert` refuse an edited
  file unless `--allow-modified`; older unsigned files work with a warning.
  `sg_extend` manifests are signed too.

## 2.6.0 - 2026-11-21

- **PrivateLink that is too open, on both sides.** `sg_review.py` reads the
  endpoint services the account provides (who may connect, whether connections
  are accepted automatically, the accounts connected, the load balancers behind
  them) and the interface endpoints in its VPCs, and adds a **PrivateLink**
  section:
  - an endpoint service any AWS account may connect to (principal `*`) is
    critical when connections are also accepted without review, high
    otherwise; the fix removes `*`, allows the accounts connected today and
    requires acceptance;
  - named principals accepted automatically are low;
  - a load balancer behind a service that has no security group, or does not
    apply its groups to PrivateLink traffic, is medium;
  - an interface endpoint whose security group lets in `0.0.0.0/0` is high, a
    `/16` or wider medium, with the callers flow logs saw and the ranges that
    cover them.
  Critical, high and medium findings join **Needs attention**, `watch` and
  `org`; each carries the AWS CLI command that fixes it ("Show the fix").
- **`sg_ou_report.py`** makes the provider checks across an organisation
  (`PrivateLink service`, `PrivateLink NLB` findings) and labels security group
  findings on interface endpoints' groups `SG (PrivateLink endpoint)` rather
  than counting them twice. A role without the newer PrivateLink permissions
  is reported, but does not make the account incomplete.
- `iam-policy.json` gains `ec2:DescribeVpcEndpointServicePermissions` and
  `ec2:DescribeVpcEndpointConnections`.
- The demo has an endpoint service open to every account behind a load
  balancer that does not filter PrivateLink traffic, and a Secrets Manager
  endpoint open to `10.0.0.0/8`.

## 2.5.0 - 2026-11-21

- **`sg_review.py` verdicts and Needs attention.** Every refused source gets a
  verdict with a severity (critical, high, medium, low, info) and a one-line
  reason, worked out from what `read` already collected: flows, CloudTrail rule
  history, network ACLs, attribution and the names file. No new AWS call or
  permission. The verdicts are internal scan (critical), scan (info: the
  defences working), fixed since, broken by a change, stopped working, network
  ACL, new address of a client, same provider, health check refused, own
  traffic blocked, partner refused, service refused, retrying and refused.
  Sources let in are checked too: a scanner or Tor exit let in is critical on a
  risky port and high on other non-web ports; a hosting provider let in on a
  risky port is high.
  - A **Needs attention** box at the top of the page lists only the critical,
    high and medium items, grouped by the change, source or provider and ranked
    by severity, then flows times days. Each has its evidence, one action,
    **List these sources** and **Extract rule**.
  - When a CloudTrail rule change caused the refusals, the item names who made
    it and offers **Restore the revoked rule**: the exact
    `authorize-security-group-ingress` command that puts the entry back. A red
    triangle on the refused graph marks the change; selecting it lists the
    sources it cut off.
  - Each refused row, and each flagged let-in row, shows its verdict chip and
    reason.
  - **Extract rule** starts from the verdicts: wanted traffic starts ticked,
    and the dialog offers the restore when a change caused the refusal.
- **New: `sg_review.py watch`** (alert mode). Reads only the flow logs not
  read yet in the last day, builds the last 24 hours and posts the new Needs
  attention items at or above `--min-severity` to a Slack webhook and/or by
  SMTP email. An item still open is posted again after `--repeat` hours; one
  that closes and comes back is posted at once. `--max-cost` skips an expensive
  read; `--loop` runs it every `--every` minutes.
- **New: `sg_review.py org`.** Lists the accounts in an OU (and the OUs under
  it), assumes a role in each, confirms one combined cost, reads them, and
  writes each account's page plus `index.html` and `org.json`
  (`sg-tightener.review-org/v1`): the Needs attention counts and items per
  account, worst first. Accounts whose role cannot be assumed are listed and
  the exit code is 2.
- The demo gains the cases: a revoked rule that cut off two callers, an
  internal host scanning twelve ports, and Censys and a Tor exit let in on RDP
  through a `0.0.0.0/0` rule.

## 2.4.0 - 2026-11-21

- **New: `sg_review.py`**, moved here from the AWS Cloud Risk Review console,
  where it was the Cloud Assurance tab "Security Group Review". `read` reads
  one account's security groups, interfaces, network ACLs, VPN routes, flow
  logs and 90 days of CloudTrail rule changes, then its flow logs by Logs
  Insights a slice at a time (hourly, six-hourly, daily, up to 180 days),
  kept in `~/.sg-tightener/review` so a later read fills only the gap; the
  cost is estimated from earlier reads and confirmed first. `report` writes one
  self-contained HTML page with no server and no network: refused sources,
  over-provisioned addresses and active sources over time, each source named
  (internal, data centre, AWS service, SaaS, AS number, from lists downloaded to
  `~/.sg-tightener/ipintel`), every rule's status (Tighten, Unused, Open to all,
  Too early, Incomplete, Not logged, In use) with ranges from `plan`'s own
  fitting, and CSV and approved.json downloads. `approved` writes the
  approved.json from the command line; `demo` writes a made-up account's page.
  The console's own sign-in is not needed: credentials come from the usual
  chain (`--profile`, `aws sso login`). `iam-policy.json` gains
  `ec2:DescribeVpnConnections`, `ec2:GetManagedPrefixListEntries`,
  `cloudtrail:LookupEvents` and `iam:ListAccountAliases`.
- **`sg_review.py` attribution, ports and Extract rule.**
  - Every source carries everything the lists know about it: the matched
    range, AWS service and region, the AS number, owner, country and announced
    block.
  - The refused and active graphs can be coloured by kind, by **network** (the
    ten busiest AS numbers, AWS services, SaaS providers or named ranges), or by
    **port class**. Selecting one colour in a bar lists just those sources.
  - A new **Ports** section shows the busiest refused and let-in ports, each
    with its service and class (web, remote admin, database, Windows and
    directory, containers, file transfer, mail, messaging, network and
    monitoring, other by range). Risky classes are marked.
  - **Extract rule**, on the refused graph and on each refused source, turns
    the sources listed into inbound rules, one per security group, protocol
    and port. For each rule it shows the port's class and what reaching it
    means, the group and its rules today, the interfaces it applies to, and
    each source's full attribution with a tick box. Scanners and internet
    sources on risky ports start unticked, and sources a rule would not let in
    (network ACL, deleted interface) are listed with the reason.
  - Extract rule writes the `aws ec2 authorize-security-group-ingress`
    commands and a JSON file (`sg-tightener.extracted-rules/v1`). Nothing is
    applied.
  - The rules table and CSV gain the port class and service.
- **`sg_review.py` source types.** Every SaaS or internet source is given a
  type from a built-in list of AS numbers and owner-name patterns
  (`sg_ipintel.ORG_ASNS`, `ORG_NAMES`): CDN, secure access service, SaaS,
  anyone's hosting, internet scanner, Tor or VPN exit, or other. Sources are
  named by provider ("Censys", "DigitalOcean") with the AS number kept beside.
  - Both graphs gain **Colour by: Source type**; sources carry a type chip.
  - Extract rule starts known scanners and Tor or VPN exits unticked, and warns
    about CDN and secure access addresses (shared by every customer) and
    anyone's hosting. The JSON gains `source_type` and `provider`.
  - Google Cloud and Oracle Cloud customer ranges, and hosting networks, are
    now "other networks", not SaaS, so they no longer count as SaaS in the
    over-provisioned split.
- **`sg_review.py` Tor exit list.** The Tor Project's list of exit relays
  (check.torproject.org/torbulkexitlist) is downloaded daily with the other
  address lists. A listed address is a Tor exit whatever network hosts it, so
  exits on ordinary hosting networks are no longer missed.
- **`sg_review.py` names file.** `~/.sg-tightener/names.yaml` (or
  `report --names FILE`, YAML or JSON) names partners and other known networks
  by range or AS number, with a type (partner, internal, datacentre, saas,
  security, cdn, hosting, scanner, anon, other) and a note. Named sources win
  over every public list and show as **Partner** (or their type) on the page;
  partners count as "External: SaaS and partners". `sg_review.py names` writes
  an example file or checks yours. `requirements.txt` gains `pyyaml`.

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
