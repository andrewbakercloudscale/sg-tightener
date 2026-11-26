# The security group console (`sg_console.py`)

One local web page for every account in [the database](database.md): browse every security group and
rule, propose a change, approve or reject someone else's, apply approved changes, reconcile with AWS,
search the audit trail, and see every rejected flow across an OU.

```bash
python sg_console.py install     # always running: starts at login, restarts if it stops, opens the browser
python sg_console.py serve       # or just for now: opens http://127.0.0.1:8765/ (Ctrl-C stops it)
python sg_console.py open        # open it again later (same address every time: bookmark it)
python sg_console.py uninstall   # stop running in the background
```

The command line (`sg_db.py`) stays for scripts and cron; both work on the same database and the
same rules.

## Start here: sign in, choose an OU, read every account in it

No AWS CLI or command line is needed after the console is running.

1. **Sign in.** On the Overview, **AWS sign-in** asks how you sign in:
   - **Access portal (SSO)**: IAM Identity Center, your whole organisation. Pick the portal (every
     portal in `~/.aws/config` is listed; **Add a portal…** takes a new address and region) and
     **Sign in**. The AWS sign-in page opens in a new tab with a code; check it matches and approve. If
     you already ran `aws sso login` for the same portal, you are signed in straight away.
   - **Keys on this computer**: a profile or access key in `~/.aws`. Pick the profile and **Use this
     profile**. It acts as that identity in its own account and assumes one role you name in the others
     (`OrganizationAccountAccessRole` unless you choose another). The organisation's accounts and OUs are
     read with the profile, so use the management account or a delegated administrator to see them
     all; from any other account only its own account is offered.

   ![AWS sign-in: access portal (SSO) or keys on this computer](images/sg-console-sso-signin.png)

   ![The code to check on the AWS sign-in page](images/sg-console-sso-code.png)

   If your company's sign-in page says **you cannot access this right now** after you changed network
   or turned on a VPN such as Zscaler, the browser is reusing its earlier sign-in. **Copy sign-in
   link**, paste it into a private (incognito) window (or quit and reopen the browser) and approve the
   same code; **Open the AWS sign-in page again** reopens it in a normal tab.
2. **Choose one role and the accounts.** **Role in every account** is used in all of them (with SSO,
   the roles you have are looked up in a few accounts, read-only ones first; an account without the role
   is reported when it is read). Then choose accounts **By OU**: tick an OU (for example PROD) to choose
   every account in it and in the OUs under it; open an OU to see its accounts. The OUs are read with
   that role in the management account (SSO) or with the profile (keys), and kept for a day
   (**Reload the OUs** reads them again). **By account** lists every account with a filter instead.
   **Use these N accounts**.

   ![One role for every account, and the PROD OU ticked: 160 accounts](images/sg-console-sso-accounts.png)
3. **Read them all.** The role is shown once at the top, **Role in every account**: pick another and
   **Use this role in all accounts** switches every chosen account. Pick the regions (`all` reads every enabled region) and how far back (start with
   1 day), then **Read all N accounts**. Every account's security groups and network interfaces go into
   the console (free, 4 accounts at a time), and its flow logs are priced. Then one total: **Read flow
   logs for N accounts (about US$…)** spends it (CloudWatch Logs Insights, about US$0.005 a GB
   scanned), **Not now** does not. Accounts with nothing to read, or that could not be read (no access
   with the role, for example), are counted; **Show them** lists those that failed. A bar shows the
   progress, with the time left worked out from the pace so far; **Stop** stops it. **Each account** has
   the same, one account at a time.

   **Only accounts that spend.** By default only accounts that spent over **US$100 in the last 30 days**
   are read (change it next to **Read all**; 0 reads every one). The spend comes from Cost Explorer in the
   management account with your role (one call, about US$0.01, kept a day); without it each account is
   asked for its own, and an account whose spend cannot be read is read anyway. Skipped accounts are
   counted and say what they spent.

   **Groups on no interface are left out.** A security group attached to no network interface protects
   nothing: it is not counted on the Overview (each region says how many were left out), the review and
   over-provisioning ignore it, and the Security groups tab hides it unless **Show groups on no interface**
   is ticked.

   ![One price for every account in the OU before anything is spent](images/sg-console-read-ou.png)
4. **Look across them, then dive in.** **Risk overview** and **Over-provisioning** compare every account
   read, worst first; **Review and tighten** (or **Reduce**) opens one account's Security Group Review:
   the over-provisioning timeline, rejected traffic, and the Tighten panel, whose plan is proposed here
   as a change request.

Nothing is changed in AWS by any of this. Every account starts in **surveillance** mode; a change
reaches AWS only as a request a different person approves, in an account switched to enforce mode.

The SSO sign-in token (valid for the session length Identity Center sets, usually 8 to 12 hours) is kept
in `~/.sg-tightener/sso.json` (mode `0600`) so an always-running console survives a restart (with keys,
only the profile name, role and accounts chosen are kept, in `~/.sg-tightener/keys.json`); role
credentials are held only in memory and renewed as they expire. **Sign out** ends the session at
AWS. A role that can only read is enough to read; applying needs the
[write permissions](permissions.md).

![Signed in with AWS SSO: an account read, with the flow-log cost shown before it is spent](images/sg-console-sso-read.png)

## Always running

The **Always running** switch on the Overview (or `sg_console.py install`) keeps the console running
in the background, starts it when you log in and restarts it if it stops: a launchd agent on macOS
(`~/Library/LaunchAgents/com.sg-tightener.console.plist`), a systemd user service on Linux
(`~/.config/systemd/user/sg-console.service`). Turning it on from a console started by hand hands
over to the background copy at the same address; the page reloads by itself. Its log is
`~/.sg-tightener/console.log`. macOS does not let background programs read Desktop, Documents,
Downloads or iCloud Drive, so when sg-tightener lives there, turning it on copies the tool and the
packages it runs on (about 30 MB) to `~/.sg-tightener/app` and runs that copy; after updating
sg-tightener, turn Always running off and on again (or run `install` again) to refresh it. Proxy and CA bundle settings (`HTTPS_PROXY`, `AWS_CA_BUNDLE`, …) in
the environment it was turned on from are carried over. On Windows, start `sg_console.py serve` from
Task Scheduler at log on.

The address is always `http://127.0.0.1:8765/`: there is no token or password, because AWS SSO is the
sign-in that matters (see [Security model](#security-model) for what stops other web pages using it).
Old bookmarks ending in `?token=…` still work.

![Overview, signed in: every account and region in the database](images/sg-console-overview.png)

## The eight tabs

| Tab | What it shows and does |
|---|---|
| **Overview** | Every account and region: its **mode** (surveillance or enforce), groups, rules, assets, changes waiting to be applied, **whether this identity can apply there** (with a **Check** button: a DryRun of every write, nothing changes), when AWS was last read. The approvals mode, who you are acting as, and whether the audit trail's hash chain is intact. For an account `sg_review.py` has read, **Review and tighten** opens its Security Group Review (`/review?account=ID`), whose **Tighten** panel proposes the fitted rules here as a change request ([how](security-group-review.md#tighten-pull-the-room-back-by-kind-type-and-name)) |
| **Risk overview** | Every account `sg_review.py` has read, side by side: headline tiles, a risk heatmap, over-provisioning by owner and over time, internet exposure, high-risk sources let in, the biggest rules to tighten, and blind spots ([below](#risk-overview-every-account)) |
| **Over-provisioning** | For leaders: over-provisioned addresses by account and per asset, rated red, amber or green, led by a chart of over-provisioning over time by source type, with KPIs and **Remediate** for each account ([below](#over-provisioning-by-account-and-asset)) |
| **Remediate** | Pick an account and the evidence dates: the account before and after (with % reduction, **Explain** and **Export to PDF**), where its traffic comes from, rules open to everyone that nothing outside used (**critical**, with **Propose this group**), a **Re-read from AWS** panel that prices only the hours never read, and every security group region by region (**Refresh from AWS**, **Apply approved changes** (first shows every rule it will add or remove, the groups and interfaces it touches, the request each came from, and which sources the flow logs saw that it would cut off; **Preview approved changes** in surveillance mode), **Propose a change by hand**); untick anything sensitive and propose ([below](#remediate-an-account)) |
| **Outbound** | Every outbound rule, on a group some interface uses, that leaves the account, by risk class: **internet**, **SaaS and partners**, **on-premises**, **other AWS accounts**; which are **too wide** (all protocols, a port range, or more addresses than one destination needs), by account and rule, with the same account picker as Rejected traffic ([below](#outbound-rules-that-leave-the-account)) |
| **Change requests** | Requests waiting for approval, approved, applied, rejected, withdrawn. Approve, or reject with a note, someone else's request; **Cancel request** on your own. **Two-person approval** can be unticked to approve your own on a single-user laptop (audited). Apply an approved one. An **asset request** (from `sg_db.py asset-propose`) shows the interface, the group it gets, the rules not carried over and what goes in their place, and once approved **Create the group and move** the interface |
| **Audit trail** | Every entry, newest first, searchable (who, why, ticket, group, rule) and filtered by time and origin. Changes made outside the tool are red, with who made them from CloudTrail |
| **Rejected traffic** | A line chart of the distinct addresses refused over time, one line per kind of source, then every source the security groups and network ACLs refused, in every account `sg_review.py` has read, worst verdict first. Each source is marked **internal** or **external**, **IPv6**, **scanning**, and **new** (first seen in the last 7 days, never before in at least 14 days of flow logs), with when it was first seen. Filter by account, severity, risky ports, new addresses only, internal / external / IPv6 / scanning, and text. **Fix…** opens everything known about the source (internal or external, IPv6, port scanning, new, threat lists, who it is, every interface, address and port it tried and what refused it, why, and any change in the audit trail that cut it off) and recommends where a rule letting it in belongs: the group on that interface that already serves the port, a group on that interface alone, a group of its own when every group there is shared, or to keep refusing it (scans, threat lists, Tor) or change the network ACL. **Propose this rule** sends it as a change request |

![Change requests: approve or reject someone else's](images/sg-console-requests.png)

![Rejected traffic across every account read](images/sg-console-rejected-traffic.png)

## Remediate an account

The **Remediate** tab is the whole job for one account, for someone who should not have to do the maths:

1. **Pick an account and a look back** (1 month, **3 months** by default, 6 months, 1 year). Accounts without flow
   logs are hidden by default; the page says how many have none (turn on VPC flow logs to CloudWatch Logs) and how
   many have not been read (read them on the Overview: How far back is 30 days by default). With fewer days read than the look back, it says so and
   offers to read them.
2. **Read the summary.** The account **before and after**: security groups, IPv4 addresses let in, ports open, and
   how many rules are narrowed, removed as unused and merged. Rules open to everyone are left for a person to decide
   and not counted. Beside it, **where the traffic comes from**: your VPCs, data centre / on-prem, AWS, SaaS and
   partners, other internet, as a share of the connections let in.
3. **Look closer if you want.** The groups that change are behind one click: each with its interfaces, IPv4
   addresses before and after, its own traffic mix, and **Old and new rules** (the rule now, what the flow logs say,
   the new rule, what it takes away).
4. **Merges are proposed by default.** Groups in the same VPC with the same outbound rules that, once tightened,
   let in nearly the same traffic become one: each member may take on at most 256 more private addresses on the
   ports it has, or one more port (never a risky one) from sources it already lets in, and never a public address or
   everyone. The group on the most interfaces is kept; the others' interfaces move onto it and the emptied groups
   stay, on no interface, to delete later. Interfaces in auto scaling groups, EKS, ECS or managed by AWS are never
   moved, so their groups are never merged.
5. **Untick anything sensitive** (a group, or a merge) and **Propose this remediation**. That makes one rule change
   request per region and one merge request per merge, with the reasons written for you. The approver only approves.
6. **Apply** the rule changes, then **Move N interfaces onto ...** on each merge (Change requests). Each move is
   recorded and can be undone from the interface's History.
7. **If something breaks**, it is refused: it shows on **Rejected traffic**, where **Fix…** lets it in
   again for just that source and port.

![Remediate: the account before and after, and where its traffic comes from](images/sg-console-remediate.png)

![Rules open to everyone that nothing outside your network used: critical](images/sg-console-critical.png)

![Explain: the rule by rule audit behind the numbers](images/sg-console-explain.png)

![Re-read from AWS: only hours never read are read, price first](images/sg-console-reread.png)

![Security groups on Remediate, region by region](images/sg-console-remediate-groups.png)

## Tighten an account: the plan

**Remediate** is built to tighten an account at a time, not a rule at a time. For the account and
region chosen, the flow logs `sg_review.py` read decide what each inbound rule should become:

| The flow logs say | New rule |
|---|---|
| **Narrow the sources** | the ranges that cover every source seen, with 30% headroom, inside the old range |
| **Narrow the ports** | a port range cut to the ports used (replies to the account's own connections stay one range) |
| **Remove: nothing used it** | none: the rule goes |
| **Keep**, **Open to everyone: decide**, **Not enough evidence yet** | unchanged: a person decides, or read more days |

Each change shows the **rule now**, the **new rule**, and what it takes away: addresses (16.8M → 4, −99.9%) and
ports (65,536 → 2). **Propose the whole plan** puts every change into one change request (remove the old rule, add
the new ones), with the reason written for you; **Propose** on a group or a rule sends just that. Nothing changes
in AWS until a second person approves and someone applies it. Groups are listed worst first, 50 to a page;
**Details** opens a group's rules only when you want to look closer.

![Each group, worst first, with Details open on one](images/sg-console-tighten-groups.png)

Every long table in the console (accounts, groups, assets, audit trail, rejected traffic, risk by account) is
split into pages of 50 rows.

## Surveillance and enforce

An account in **surveillance** mode (the default) is reported on and requests are recorded, but
nothing is applied: the Security groups tab says so and Apply is off. When the organisation is ready,
press **Check** on the Overview (or `sg_db.py check`), then
`sg_db.py mode enforce --account ID --reason "…"`. Setting the mode is deliberately a command, not a
button: it is the decision to let the tool change AWS.

## Two-person approval

Approval is on by default. A change is a **request**: proposed with a reason (and a ticket), approved
by a **different person**, then applied. Proposal, approval, rejection and apply are each an entry in
the audit trail.

1. Alice proposes: in the console, or `sg_db.py add|remove|exec|adopt` or `sg_db.py propose --plan plan.json`.
2. Bob approves (`sg_db.py approve 12` or the console). The request's changes become *desired*.
   Alice cannot approve her own request; rejecting needs a note saying why.
3. Anyone applies (`sg_db.py apply --region R` or the console). The request is marked applied once AWS
   holds every change.

"A different person" means a different AWS principal: the role session name for an assumed role
(`AWSReservedSSO_Admin_…/alice` and `…/bob` differ), the user name for an IAM user.

While approval is on, `sg_tightener apply` and `sg_compact apply` refuse and say to propose the plan
instead (`sg_db.py propose --plan plan.json --reason "…"`). `sg_extend` (break-glass) and `revert`
still go through, flagged in the audit trail, so an outage is never waiting for a second person.

One person running a lab can turn it off: `sg_db.py approvals off --reason "single operator"`
(audited). Requests are then approved by the proposer at once.

## Who you are

Signed in with AWS SSO on the page, the console acts as that sign-in, with the role chosen for each
account. Otherwise it acts as the AWS identity it runs as (`--profile`, `AWS_PROFILE`), read again for
every change, exactly like `sg_db.py`. To approve, the second person runs their own console (or
`sg_db.py approve`) with **their** credentials against the **same database**: point both at one PostgreSQL
(`SG_TIGHTENER_PG_DSN`), or run sg-tightener on one shared host (a bastion or a container with a volume), each person signing in with their own
SSO profile.

To apply or reconcile in another account, the console assumes `--role-name` (default
`OrganizationAccountAccessRole`) there, as `sg_db.py --ou-id` does.

## Security model

- **Localhost only.** It listens on `127.0.0.1`. To reach it from a laptop, use an SSH tunnel
  (`ssh -L 8765:127.0.0.1:8765 bastion`), never a public bind.
- **No sign-in of its own.** AWS SSO (or the profile it runs as) is the sign-in; the page opens at
  `http://127.0.0.1:8765/` with no token. Anyone who can use your login on this computer can use it, as
  they could your `~/.aws` credentials, so don't run it on a computer other people log in to.
- **No cross-site changes.** Every change (POST) needs a key that only the console's own page holds,
  in an `X-SG-Token` header, and a JSON body; another web page can send neither and cannot read the
  page to learn the key. The key is kept in `~/.sg-tightener/console-token` (`0600`) so an open page
  keeps working across restarts; `serve --new-token` replaces it.
- **No cross-site reads.** Requests to `/api/` that the browser marks as coming from another site
  (`Sec-Fetch-Site`) or with a foreign `Origin` are refused, and no response allows cross-origin reads.
- **No DNS rebinding.** Requests whose `Host` is not `127.0.0.1:PORT` or `localhost:PORT` are refused.
- **Content Security Policy.** Only the page's own script runs (`script-src 'nonce-…'`), it can only
  talk to the console (`connect-src 'self'`), and it cannot be framed. Every value shown is escaped.
  The review page served at `/review` gets the same nonce on its scripts and loads nothing from
  outside.
- **The database is the boundary.** The console adds no privileges: AWS still decides what the
  identity may do, and the database still refuses a self-approval. The database file is `0600` in a
  `0700` directory.

## Risk overview: every account

The **Risk overview** tab answers "where is the risk, across everything?" from the reads `sg_review.py`
keeps for each account, for the chosen time window (24 hours to a year). Select an account name to
open its review.

- **Tiles**: accounts read, critical items to act on, high-risk sources let in, rules open to the
  internet on risky ports, outbound calls to threat lists, never-seen addresses allowed in, rules to
  tighten or remove, and high-risk sources probing (refused).
- **Where to focus**: a bubble chart, **By owner** or **By account**. Up = more risk: **risk points**
  (100 for each red dimension in the heatmap below, 10 for each orange, 1 for each amber, added across
  an owner's accounts), so one critical outweighs nine highs. Right = more important: the monthly
  spend (last 30 days, from Cost Explorer in the management account; without it, network interfaces).
  Size = accounts owned, or an account's interfaces. Colour = the worst account. Both scales are
  logarithmic. The shaded **Start here** corner holds those with a critical risk and above the middle
  spend; they are labelled, and listed under the chart worst first with **Review and tighten** (an
  account) or **Their accounts** (an owner). Select a bubble to list it. The owner is the account's
  Organizations tag (`Owner`, `AccountOwner`, `BusinessOwner`, `OwnerName`, `OwnerEmail`,
  `TechnicalOwner`, `ProductOwner`, `TeamOwner`, `Contact` or `Team`, the first found); accounts
  without one are drawn as "No owner tag". Tags are looked up in the background with the role in the
  management account and kept a day.

  ![Where to focus, by owner: risk points against monthly spend, with the Start here corner](images/sg-console-focus-owner.png)

  ![Where to focus, by account](images/sg-console-focus-account.png)
- **Risk by account**: a heatmap, one row per account, worst first. Each of eight dimensions is
  green (nothing found), amber (worth a look), orange (high) or red (act now); the **risk score** adds
  the levels across the row. The dimensions are needs attention (critical / high), high-risk sources
  let in, open to the internet on risky ports (and other open rules), outbound to threat lists,
  never-seen addresses allowed, rules to tighten, high-risk probing, and blind spots.

![Risk by account: eight dimensions per account, worst first](images/sg-console-risk-heatmap.png)

- **Over-provisioned by owner**: the addresses the rules let in today that were never seen in the flow
  logs, split by who owns them: internal (your VPCs), data centre and other private space, AWS, SaaS
  and partners, and other networks. **By source type** splits by secure access, SaaS and big tech, and
  ISP and business instead. **Share** shows each account as 100% to compare the mix. Pull back the
  biggest owner first: unused private space and whole provider ranges are usually most of it.

![Over-provisioned by owner, by kind and size](images/sg-console-over-by-owner.png)

![By source type, as a share](images/sg-console-over-by-owner-share.png)

- **Over time**: never-seen addresses allowed, summed across accounts (each tightening is a step
  down), and high-risk probing per period (a jump means someone is looking).
- **Open to the internet, by port class**, with every rule open to `0.0.0.0/0` or `::/0` on a risky
  port; **high-risk sources let in** (scanners, threat lists, Tor exits a rule allowed); the **biggest
  rules to tighten** across accounts; and **blind spots**: coverage under 98% of the window, groups
  without flow logs, under 7 days of evidence, and accounts in the console never read.

![The whole Risk overview](images/sg-console-risk-overview.png)

The same data is at `GET /api/macro?range=1m` (`24h`, `1w`, `1m`, `3m`, `6m`, `1y`).

## Over-provisioning: by account and asset

It opens with **over-provisioning over time**: the addresses let in that never sent anything, every account added
up, at the end of each period, by **source type** or by **where it comes from**, with the total now and its change.
It needs flow logs: accounts read for their groups only are counted and the page says how to read their flow logs.

![Over-provisioning over time, by source type](images/sg-console-over-time.png)

The **Over-provisioning** tab is the leaders' view: how much each account lets in that nobody uses,
which assets carry it, and whether it is coming down.

**Over-exposure per asset** is, for one network interface, the number of addresses its security groups
(all of them together) let reach it that were never seen in the flow logs. IPv4; a rule open to the
whole internet is not counted in the number (it would swamp it) but is shown, and makes the asset red
on a risky port.

| Rating | Over-exposure of the asset |
|---|---|
| **Green** (right-sized) | up to 256 never-seen addresses, a /24 |
| **Amber** | up to 65,536, a /16 |
| **Red** | more than 65,536, or open to the internet on a remote admin, database, Windows or container port |

An account is red if any of its assets is red, amber if any is amber, green otherwise. Assets whose
groups have no flow logs are not rated (they are counted as not logged).

**KPIs**: never-seen addresses allowed in across every account and the change over the window; assets
right-sized (the share rated green) against a **90% target**; red and amber assets and their change;
average over-exposure per asset and the worst asset; accounts green; assets left to fix to reach the
target; rules to tighten or remove.

![Over-provisioning KPIs and assets by rating over time](images/sg-console-over-provisioning.png)

- **Assets by rating over time**: red, amber and green assets at the end of each period, across every
  account. Red shrinking and green growing is the goal.
- **By account**, worst first: rating, the red/amber/green split, right-sized share against the target,
  over-provisioned now, change in the window with a trend line, average per asset, worst asset, and
  **Reduce**, which opens the account's review whose **Tighten** panel proposes the fitted rules for
  two-person approval.

![By account: rating, split, right-sized share, change, trend and Reduce](images/sg-console-over-by-account.png)

- **Biggest wins**: the rules that would fix the most, ranked by never-seen addresses times the assets
  the rule reaches.
- **Every asset**: rating, asset (name, kind, interface, region, public IP), groups, over-exposure,
  change in the window, and risky ports open to the internet; filter by account, rating and text.

![Every asset in an account, rated](images/sg-console-over-per-asset.png)

## Outbound rules that leave the account

The **Outbound** tab, and a section of the same name on each account, list every outbound rule that
reaches outside the account, riskiest class first:

| Class | What it reaches | Too wide when it allows more than |
|---|---|---|
| **Internet** | public addresses that are not a named SaaS or AWS service | one address |
| **SaaS and partners** | a named provider (from public lists or your names file), or a small range on AWS | 256 addresses |
| **On-premises** | private ranges outside the account (the data centre over VPN or Direct Connect) | 65,536 addresses |
| **Other AWS accounts** | another account's VPC, a group across a peering, a PrivateLink endpoint to another account's service | 65,536 addresses |

All protocols, or a range of ports, is always too wide. Left out, because they are not a way out of
the account: the account's own VPCs, AWS service ranges and AWS-managed prefix lists (S3, DynamoDB),
transit gateway interfaces and groups no interface uses. The default **all traffic to 0.0.0.0/0** (and
**::/0**) is on almost every group, so it is hidden until **Include the default** is ticked; a rule that
changes it (a database group allowed everywhere, all of `100.0.0.0/8` when `100.64.0.0/10` was meant) is
always shown. **Explain** says how each number is worked out.

![Outbound: rules leaving the account by risk class, too wide only](images/sg-console-outbound.png)

![The same rules on an account](images/sg-console-outbound-account.png)

## Connection resets

Flow logs record the TCP flags of each flow, so the same read counts the connections that were
**reset** (RST): by the source, or by your side. Each account shows them over time, each load balancer's
resets, and the sources reset the most, with what to do:

- **block**: a threat list, scanner or Tor address resetting connections, or most of an internet
  source's connections reset. **Block** proposes a network ACL inbound deny ahead of the allows (in
  enforce mode, audited, with the command to undo it). Internal addresses are never blocked.
- **investigate** or **check**: a named provider or partner, which may be a real client.
- **Load balancer reset counts (CloudWatch, 7 days)** adds the load balancers' own counters
  (NLB TCP resets; ALB rejected connections, TLS errors and 5XX).

Slices read before this was added carry no resets: they appear as accounts are read again.

![Connection resets: chart, load balancers and sources to block](images/sg-console-resets.png)

## Signing in behind Zscaler

**Sign in** and **Renew** first check that Zscaler is on (the AWS access portal is reached through it);
if it is off they stop and say so (press again to sign in anyway). A sign-in that fails after
switching Zscaler on is usually the browser reusing connections it opened before: **Reset sign-in
network** flushes DNS and opens Chrome's socket page, where **Flush socket pools** finishes the job.

## Data use on a phone hotspot

**Settings, Data use** shows how this Mac is connected (macOS marks a phone hotspot as a metered
connection; an iPhone Personal Hotspot is also known by its address).

- **Read flow logs only on Wi-Fi**: on a hotspot, Read all, Read one, Read and the scheduled read wait,
  and a read a restart stopped carries on only once back on Wi-Fi. Reports work as normal.
- **Keep prices when the console restarts** (on): a read of many accounts keeps each account's price
  as it is worked out, so after a restart only the accounts not yet reached are priced again.

AWS scans the flow logs on its side: the gigabytes on the bill are not downloaded. Pricing takes roughly
0.5 MB an account, reading a few MB an account.

![Settings: Data use](images/sg-console-data-use.png)

## When the database is not running

The database runs in Docker (colima on a Mac), so after a restart it may be stopped. The console still
opens, and every page shows **The database is not running** with a **Start the database** button: it starts
colima if Docker's engine is stopped (the first start can take a few minutes), then the PostgreSQL
container, shows each step, and reloads the page once the database answers. The same from a terminal:
`python sg_store.py start`. `brew services start colima` starts colima at login so this is rarely needed.

## Rejected traffic across an OU

The **Rejected traffic** tab reads what `sg_review.py` keeps for each account in the database (12 months). Fill it for a whole OU and keep it fresh:

```bash
python sg_review.py org   --regions eu-west-1 --ou-id ou-ab12-cdef3456 --days 7 --yes
python sg_review.py watch --regions eu-west-1 --ou-id ou-ab12-cdef3456 --slack https://hooks.slack.com/… --loop
```

`watch --ou-id` reads every account each loop (every 5 minutes, up to five minutes ago) and alerts on
rejected traffic that needs attention; an account whose role cannot be assumed is logged and the rest
carry on. The same table is on the org page (`sg-review-org/index.html`, **All rejected traffic**).

### The address book: who an IP address is, before you let it in

**Look up an IP address** on **Rejected traffic** (and the **Before you let it in** section of **Fix…**, and
each added source in the **Apply** preview) answers, from every account read:

| Question | Answered from |
|---|---|
| Whose is it? | One of our interfaces (account, instance, name, groups); an AWS service and region from AWS's published ranges; or the AS number, its owner, country and block |
| Is it on a threat list or Tor? | The threat lists and the Tor exit list |
| What operating system? | Our own EC2 instances only (`PlatformDetails`). Nothing is probed or scanned: the tool only reads |
| What port is it asking for? | The port catalogue: service, class, and whether it is a database or another risky port |
| Has it scanned? | Ports refused and addresses tried, in every account |
| Have we seen it before? | First and last seen across the estate |
| Is it already let in elsewhere? Refused elsewhere? Do our hosts connect to it? | Every account's flow logs, with the ports |

The book is built in the background from each account's whole read (every private source, the 3,000 busiest
public ones per account) and kept in the database with the other report rows. IP addresses are reused: each
sighting carries its dates. A range being let in is shown by its size: every address in it is let in, not just
the ones seen.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--port` | `8765` | Port on 127.0.0.1 |
| `--db` | `$SG_TIGHTENER_PG_DSN`, else `sg_store.py setup`'s database | A PostgreSQL address (`postgresql://…`) |
| `--profile` | the usual credential chain | AWS profile, for example an SSO one |
| `--role-name`, `--external-id` | `OrganizationAccountAccessRole` | Role assumed in other accounts to apply and reconcile (not used when signed in with SSO on the page) |
| `--new-token` | off | Make a new page key (pages already open must be reloaded) |
| `--no-browser` | off | Do not open the browser at start |
| `--data-dir` | `~/.sg-tightener` | Where `sg_review` keeps what it read |
