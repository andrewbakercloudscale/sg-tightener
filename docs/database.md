# The security group database

> **Why.** One owner for every security group, one place to change a rule, and one history of every
> change, including the ones made behind the tool's back. Terraform cannot manage security groups
> with this solution ([why](../README.md#security-groups-live-in-a-local-database-not-in-terraform)).

`sg_db.py` keeps every security group and rule in a local SQLite database:

- `$SG_TIGHTENER_DB`, or `~/.sg-tightener/sg.db` (the directory is `0700`, the file `0600`);
- `--db FILE` on any `sg_db.py` command.

---

## Desired and synced

Each group's rules are held twice:

| | What it is | Changed by |
|---|---|---|
| **desired** | What the rules should be | `sg_db.py add`, `remove`, `exec`, `adopt`, `create-group`; `sg_tightener apply`/`revert`, `sg_compact apply`/`revert`, `sg_extend` |
| **synced** | What AWS held the last time the tool read or changed it | Every read of AWS |

- `sg_db.py diff` shows desired against synced: what `apply` would change.
- `sg_db.py apply` makes AWS match desired, then reads each group back as synced.
- `sg_db.py reconcile` reads AWS. Anything that differs from synced was changed outside the tool: it
  is recorded as **external** and taken as synced. Desired is not touched, so `apply` would put it
  back, and `adopt` accepts it into desired. A person decides.
- A group created outside the tool is taken into both (the tool never deletes groups); one deleted
  outside is dropped and recorded.

`apply` refuses when AWS changed since it was last read: run `reconcile` first, so a person has
seen the change before it is overwritten. `sg_tightener apply` and `sg_compact apply` refuse the
same way, and also while the database has changes not applied yet. `revert` and `sg_extend`
(break-glass) go ahead, warn, and record what they did.

---

## The audit trail

Every change is one row in `audit`, written in the same transaction as the change:

| Column | What it holds |
|---|---|
| `seq`, `at` | Order and UTC time |
| `actor` | The caller's IAM identity (role session or user) |
| `origin` | `import`, `tool` (sg_db.py), `apply`, `external`, `sg_tightener apply`, `sg_compact revert`, `sg_extend`, … |
| `action` | `group-imported`, `desired-changed`, `applied`, `rules-changed`, `group-created`, `group-deleted`, `adopted`, `authorize-security-group-ingress`, … |
| `account`, `region`, `group_id` | Where |
| `detail` | JSON: the rules added and removed; for external changes, who made them from CloudTrail |
| `reason`, `ticket` | Why. Required for every change made with `sg_db.py` |
| `prev`, `hash` | The hash chain |

It is append-only: triggers refuse `UPDATE` and `DELETE` on the table. Each entry's `hash` is the
SHA-256 of the entry (without `seq` and `hash`) and the previous entry's hash, so `sg_db.py verify`
shows whether anyone dropped the triggers and edited, removed or reordered an entry.

```bash
python sg_db.py log --since 7d                    # who changed what, and why
python sg_db.py log --group sg-0abc --json        # one group's whole history
python sg_db.py verify                            # audit trail intact: 1,204 entries
```

---

## Change requests and two-person approval

Every change is a **request** (`requests` table): who proposed it, why, the ticket, the changes, and
its status: `pending`, `approved`, `rejected`, `cancelled`, `applied`. Approval is on by default
(`meta.approvals`).

```bash
python sg_db.py add --region eu-west-1 --group sg-0db… --proto tcp --port 5432 --source 10.4.9.0/24 \
    --reason "ETL reads the replica" --ticket CHG-2044
# change request #12 recorded, waiting for a second person: sg_db.py approve 12; then sg_db.py apply --region eu-west-1
python sg_db.py requests                      # what is waiting (another person, their own credentials)
python sg_db.py approve 12 --note "checked"   # or: reject 12 --note "why"
python sg_db.py apply --region eu-west-1      # request 12 is marked applied once AWS holds it
```

- The approver must be a different AWS principal from the proposer; rejecting needs a note; only the
  proposer can cancel. Each step is an audit entry (`request-proposed`, `request-approved`,
  `request-rejected`, `request-cancelled`, then `desired-changed` and `applied`).
- `add`, `remove`, `exec` and `adopt` create requests. A plan from `sg_tightener plan` or
  `sg_compact plan` becomes one request with `propose --plan plan.json --reason "…"`.
- While approval is on, `sg_tightener apply` and `sg_compact apply` refuse and say to propose the
  plan. `sg_extend` (break-glass) and `revert` go straight through and are recorded as such.
- `approvals off --reason "…"` (audited) makes the proposer's request approved at once, for a single
  operator.

The [console](console.md) does all of this from a web page.

## Surveillance and enforce modes

Every account is in one of two modes (`modes` table; account `*` is the default for the rest):

| Mode | What happens |
|---|---|
| **surveillance** (the default) | Everything is read and reported: over-provisioned rules, what they should be (`sg_tightener plan`, `asset-plan`), change requests. **Nothing is applied**: `apply`, `exec`, `create-group`, `sg_tightener`/`sg_compact apply`, `sg_extend` and `asset-apply` refuse and say so. `exec` records the request and says "recorded, not applied" |
| **enforce** | Approved changes can be applied, per account, per group or per asset |

```bash
python sg_db.py mode show                                  # every account's mode
python sg_db.py check --regions eu-west-1 --assets         # can this identity apply here? (DryRun)
python sg_db.py mode enforce --account 123456789012 --reason "CAB-17: payments may apply"
python sg_db.py mode surveillance --all --reason "default for every other account"
```

- `mode enforce --account ID` needs a permission check for that account first, and refuses when the
  last one failed (`--anyway` to override, recorded). Every mode change is audited (`mode-enforce`,
  `mode-surveillance`).
- `revert` and `asset-revert` work in either mode: undoing is always allowed.

## Checking permissions first (DryRun)

`sg_db.py check --regions R [--ou-id …] [--assets] [--sample N]` calls each write sg-tightener makes,
authorize and revoke, ingress and egress, on every group, as an EC2 **DryRun**: AWS answers whether
the call would be allowed, taking every policy into account (identity, permission boundary, SCPs, tag
and VPC conditions), and nothing changes. `--assets` also checks creating a group, swapping an
interface's groups and tagging. The result is stored (`permissions` table, audited
`permissions-checked`) and shown on the console's Overview. Exit 1 when a call would be refused, 2 when
an account could not be reached.

`apply` (and the console's Apply) runs the same check on the groups it is about to change and stops
before changing anything when a call would be refused: a change is never left half done for want of a
permission.

## Assets: an audit trail per network interface, and a group of its own

`import` and `reconcile` record every network interface (`assets` table): the instance it belongs to,
its auto scaling group or EKS cluster, its addresses (IPv4 and IPv6) and its groups. A change to an
asset's groups is an audit entry of its own (`asset-groups-changed`, with before and after, external
when made outside the tool), and interfaces that came and went (auto scaling) are one entry together.

```bash
python sg_db.py assets --region eu-west-1                     # every interface, and whether it can have its own group
python sg_db.py asset-log --instance i-0abc…                   # every group change on that instance's interfaces
```

To tighten **one asset on its own** without touching the shared group:

```bash
python sg_db.py asset-plan --region eu-west-1 --eni eni-0db1… --approved approved.json   # writes asset-plan.json
python sg_db.py asset-propose --plan asset-plan.json --reason "only the API reads the database"
python sg_db.py approve 14                                     # a different person
python sg_db.py asset-apply 14                                 # enforce mode only
python sg_db.py asset-revert --region eu-west-1 --eni eni-0db1… --reason "…"   # back to the groups it had
```

- The plan merges the rules of the asset's groups and keeps only the sources **that reached this
  interface** in the flow logs (plus hand-added addresses in `approved.json`), signed like every plan.
- `asset-apply` creates `sgt-<eni>-<time>` in the same VPC with exactly those rules, then moves the
  interface onto it (`asset-group-created`, `asset-swapped`). If a rule cannot be added, the interface
  is not moved. It refuses when the interface's groups changed since the plan.
- **Auto scaling, EKS and ECS assets are refused**: a new instance would start with the launch
  template's groups again. Tighten the shared groups instead (every instance inherits that change), or
  change the launch template. Load balancers, NAT gateways and other interfaces AWS manages are refused
  too.

## Across an OU

One database holds every account. `import` and `reconcile` take `--ou-id ou-…` (every active account
in that OU and those under it), `--org` (the whole organisation) or `--accounts id1,id2`, and assume
`--role-name` (default `OrganizationAccountAccessRole`, `--external-id` if it needs one) in each.
Other commands take `--account ID`. An account whose role cannot be assumed is reported and the rest
carry on; `reconcile` then exits 2.

```bash
python sg_db.py import    --regions eu-west-1,us-east-1 --ou-id ou-ab12-cdef3456
python sg_db.py reconcile --regions eu-west-1,us-east-1 --ou-id ou-ab12-cdef3456 --slack https://hooks.slack.com/…
python sg_db.py show --region eu-west-1 --account 444455556666
```

## Commands

| Command | What it does |
|---|---|
| `import --regions R1,R2 [--ou-id OU \| --org \| --accounts IDS]` | Takes every group and rule in those regions into the database (the other tools import a region on first use) |
| `reconcile --regions R1,R2 [--slack URL] [--no-cloudtrail]` | Records and reports changes made outside the tool; exit 1 when there are any, or changes not applied |
| `show --region R [--group G]` | Every rule the database holds (`+` wanted but not in AWS yet, `-` in AWS but not wanted) |
| `diff --region R [--group G]` | What `apply` would change; exit 1 when there is something |
| `add --region R --group G --proto P --port N --source S --reason "…" [--ticket T] [--direction in\|out]` | Wants a rule. `--source` is a CIDR, `pl-…`, `sg-…` or `ACCOUNT/sg-…` |
| `remove --region R --group G (--proto … --source … \| --all) --reason "…"` | Stops wanting a rule, or every rule in a direction |
| `exec --reason "…" -- aws ec2 authorize\|revoke-security-group-ingress\|egress …` | Runs a printed AWS CLI command through the database: records it, then applies it (`--no-apply` to record only) |
| `apply --region R [--group G] [--yes]` | Makes AWS match the database |
| `adopt --region R [--group G] --reason "…"` | Accepts what AWS holds into desired |
| `create-group --region R --vpc V --name N --description D --reason "…"` | Creates a group in AWS and the database |
| `log [--since 24h\|7d] [--region R] [--group G] [--json]` | The audit trail |
| `verify` | Checks the hash chain |
| `propose --plan plan.json --reason "…"` | An `sg_tightener` or `sg_compact` plan as one change request |
| `requests [--status pending] [--json]` | Change requests |
| `approve ID [--note "…"]`, `reject ID --note "…"`, `cancel ID` | Decide a request (a different person), or withdraw your own |
| `approvals on\|off --reason "…"` | Two-person approval (on by default) |
| `mode [show\|surveillance\|enforce] (--account ID \| --all) --reason "…" [--anyway]` | Surveillance (report only, the default) or enforce (apply) |
| `check --regions R [--ou-id …] [--assets] [--sample N]` | DryRun every write on every group: can this identity apply here? Nothing changes |
| `assets --region R [--account ID] [--json]` | Every network interface, its groups and whether it can have its own group |
| `asset-plan --region R (--eni E \| --instance I) --approved approved.json [--out F]` | A group of its own for one asset, from its own flows |
| `asset-propose --plan asset-plan.json --reason "…"`, `asset-apply ID [--yes]` | Propose it; apply it once approved (enforce mode) |
| `asset-revert --region R --eni E --reason "…"`, `asset-log (--eni E \| --instance I) [--json]` | Put the asset's groups back; its history |

---

## Running it

- **One database per estate.** Keep it on the host (or in the container volume) that runs
  sg-tightener, and run `reconcile` hourly from cron.
- **Back it up.** `sqlite3 ~/.sg-tightener/sg.db ".backup /backups/sg-$(date +%F).db"` is safe while
  the tools run. If it is lost, `import` rebuilds the groups and rules from AWS, but the history is
  gone.
- **Concurrency.** Writers take an immediate lock (WAL mode), so two tools changing the database at
  once queue rather than interleave.
- **Permissions.** `apply` and `exec` need the write calls in
  [`iam-policy-write.json`](../iam-policy-write.json), including the egress ones and, for
  `create-group`, `ec2:CreateSecurityGroup`. `reconcile` needs `ec2:DescribeSecurityGroups` and,
  for who made a change, `cloudtrail:LookupEvents` ([permissions](permissions.md)).
