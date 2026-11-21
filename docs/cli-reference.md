# CLI reference

Every tool prints its own help with `--help`. Defaults below are taken from the
code. All tools use your normal AWS credential chain (`AWS_PROFILE`, SSO,
instance role, and so on), and every command that calls AWS takes `--profile`.

## SSO and profiles

AWS IAM Identity Center (SSO) works with every tool. Set up a profile once,
log in, and pass it:

```bash
aws configure sso --profile sec-prod          # once: start URL, region, account, permission set
aws sso login --profile sec-prod              # each working day (the session lasts 1-12 hours)
python sg_review.py read --regions eu-west-1 --profile sec-prod
python sg_tightener.py plan --region eu-west-1 --approved approved.json --profile sec-prod
```

`--profile P` is the same as `AWS_PROFILE=P` for that one run. When the SSO
session has expired, or the profile does not exist, the tool prints one line
with the fix instead of a traceback, and exits 1:

```text
ERROR AWS login needed: the SSO session has expired or was never started. Run: aws sso login --profile sec-prod
```

Permission sets: create one from [`iam-policy-read.json`](../iam-policy-read.json)
(as an inline policy) for everyone, and a second from
[`iam-policy-write.json`](../iam-policy-write.json) for change windows. See
[permissions](permissions.md).

Across an organisation (`sg_ou_report`, `sg_transfer_audit`, `sg_review org`):
log in with an SSO profile for the management (or delegated administrator)
account. The tools then assume `--role-name` in each member account. The
`AWSReservedSSO_...` roles SSO creates cannot be assumed by name from another
account, so keep `--role-name` pointing at `OrganizationAccountAccessRole` or,
better, a read-only role you deploy to every account (StackSets) whose trust
policy allows the management account's SSO role.

Flow-log source, used by `analyse`, `sg_diagnose` and `sg_extend`: give
**either** `--log-group` **or** `--s3-bucket` (with an optional `--s3-prefix`).

---

## `sg_tightener.py`

### `analyse`

Read accepted flows and write the observed source addresses.

| Flag | Default | Meaning |
|---|---|---|
| `--region` | required | AWS region |
| `--days` | `90` | How far back to read |
| `--log-group` | | CloudWatch Logs group with VPC flow logs |
| `--s3-bucket` | | S3 bucket with VPC flow logs |
| `--s3-prefix` | | Prefix inside the bucket, e.g. `AWSLogs/123456789012/vpcflowlogs` |
| `--out` | `approved.json` | Output file |

Fails if the flow-log configuration cannot support the analysis, or if no
source addresses were observed.

### `plan`

Build replacement rules. Reads AWS, writes nothing to it.

| Flag | Default | Meaning |
|---|---|---|
| `--region` | required | AWS region |
| `--approved` | required | The `approved.json` from `analyse` |
| `--max-rules` | `60` | Rules allowed per security group. When the observed sources do not fit, blocks are merged to grant the fewest unused addresses |
| `--tolerance` | `0.30` | Fraction of unused addresses allowed inside a replacement block. Also the finest result: spare rules never split a block below it |
| `--prefix-threshold` | `24` | Only rules wider than this prefix are eligible |
| `--out` | `plan.json` | Output file |

### `apply`

| Flag | Default | Meaning |
|---|---|---|
| `--plan` | required | The reviewed `plan.json` |
| `--region` | from the plan | Only for plans written before the region was recorded. If given for a newer plan it must match, or `apply` refuses |
| `--yes` | off | Skip the typed `yes` confirmation |
| `--allow-modified` | off | Apply a plan whose contents changed after `plan` wrote it (see below) |

`plan` signs `plan.json` and `apply` signs the manifest (see
[file formats](file-formats.md#integrity)). `apply` refuses a plan edited after
it was written, and `revert` a manifest edited after `apply` wrote it, unless
`--allow-modified` is given. Files written before 2.7.0 have no signature and
are used with a warning.

The region is read from the plan; `AWS_REGION` is ignored for plans that record one.
The manifest is rewritten after every successful AWS call, so it always lists
exactly what was changed.
Writes `manifest-<YYYYMMDDTHHMMSSZ>.json` in the current directory.

### `revert`

| Flag | Default | Meaning |
|---|---|---|
| `--manifest` | required | A manifest from `apply` |
| `--yes` | off | Skip the typed `yes` confirmation |
| `--allow-modified` | off | Revert from a manifest whose contents changed after `apply` wrote it |

Region is read from the manifest.

---

## `sg_diagnose.py`

| Flag | Default | Meaning |
|---|---|---|
| `--region` | required | AWS region |
| `--hours` | `24` | Window of `REJECT` flows to read, in hours (minimum 1) |
| `--approved` | `approved.json` | File to record refused flows in, for the next plan |
| `--manifest` | | The manifest `apply` wrote: flows its revoked rules would have admitted are marked as caused by the tightening |
| `--log-group` / `--s3-bucket` / `--s3-prefix` | | Flow-log source |
| `--apply` | off | Kept for compatibility; the commands to restore access are always printed |

Needs `${dstaddr}` and `${dstport}` in the log format. Exit codes: `0` nothing
refused, or refused and recorded; `1` refused and not recorded.

---

## `sg_extend.py`

| Flag | Default | Meaning |
|---|---|---|
| `--region` | required | AWS region |
| `--groups` | discover | Comma-separated `sg-…` ids. Omit to derive them from the rejected flows' destination interfaces |
| `--log-group` / `--s3-bucket` / `--s3-prefix` | | Flow-log source |
| `--hours` | `24` | Window of `REJECT` flows to read |
| `--tolerance` | `0.30` | Fraction of unused addresses allowed inside a grouping block (same meaning and fitting as `plan`) |
| `--ports` | all | Destination ports or ranges to act on, e.g. `443,5432,8000-8100` |
| `--include-public` | off | Also add non-RFC 1918 sources |
| `--no-aws-summarise` | off | With `--include-public`, add AWS-service sources as `/32`s rather than their service range |
| `--max-groups` | `20` | Discovery mode: refuse runs touching more groups than this |
| `--description` | `sg-extend break-glass` | Description set on every added rule |
| `--max-rules` | `60` | Per-group budget; a group that would exceed it is skipped |
| `--yes` | off | Skip the typed `extend` confirmation |

Writes `sg_extend-manifest-<ts>.json`. Exits 1 if adding rules failed on any group.

---

## `sg_compact.py`

### `plan`

| Flag | Default | Meaning |
|---|---|---|
| `--region` | required | AWS region |
| `--ratio` | none | Unused fraction allowed in a widened block. Without it, only the report is printed |
| `--ratios` | `0.0,0.1,0.25,0.5,0.75,0.9` | Ratios to show in the sweep |
| `--max-rules` | `60` | Rule limit to report against |
| `--out` | `plan.json` | Output file (only written with `--ratio`) |

### `apply` / `revert`

Same flags as `sg_tightener.py apply` / `revert`. Region is read from the plan,
falling back to `AWS_REGION`. Writes `sg_compact-manifest-<ts>.json`.

---

## `sg_ou_report.py`

| Flag | Default | Meaning |
|---|---|---|
| `--regions` | required | Comma-separated regions |
| `--ou-id` | whole org | Scan only accounts under this OU (recursively) |
| `--accounts` | | Comma-separated account ids instead of Organizations discovery |
| `--role-name` | `OrganizationAccountAccessRole` | Role assumed in each account |
| `--out` | `report.xlsx` | Excel report |
| `--json` | `report.json` | JSON report |
| `--max-workers` | `16` | Parallel account/region scans |
| `--securityhub` | off | Also send each account's findings to its Security Hub (ASFF), and archive the ones no longer found |
| `--securityhub-state` | `securityhub-state.json` | What was sent last time, used to archive |

Exit codes: `0` every account and region scanned, nothing CRITICAL; `1` a
CRITICAL finding; `2` the scan was incomplete (see `errors` in the JSON and
`scan_status` per account) and nothing CRITICAL was found.

Findings are security group and network ACL rules, plus PrivateLink: an endpoint
service any AWS account may connect to (`PrivateLink service`, CRITICAL when
connections are accepted without review, HIGH otherwise, LOW for named
principals accepted automatically) and a load balancer behind one that does not
filter PrivateLink traffic (`PrivateLink NLB`, MEDIUM). Security group findings
on an interface endpoint's groups are labelled `SG (PrivateLink endpoint)`. A
PrivateLink check the role may not make is listed in `errors` with
`"optional": true` and does not make the account incomplete.

Also reported:

- a global IPv6 range of `/32` or wider: HIGH on critical ports, MEDIUM
  otherwise (`::/0` is rated like `0.0.0.0/0`);
- `SG (default, in use)` (MEDIUM): a default security group with rules that
  interfaces still use (CIS AWS Foundations 5.4);
- `SG (cross-account reference)` (MEDIUM): a rule that trusts another
  account's security group;
- on every `0.0.0.0/0` and `::/0` finding, a `note` saying whether it is
  reachable from the internet today: how many interfaces have a public address
  in a subnet routed to an internet gateway. Reachability is read with
  `ec2:DescribeNetworkInterfaces` and `ec2:DescribeRouteTables`; without them
  the note is missing and the error is optional.

---

## `sg_transfer_audit.py`

Same flags as `sg_ou_report.py`, with outputs defaulting to
`transfer_report.xlsx` and `transfer_report.json`. Exit codes as
`sg_ou_report.py`.

---

## `sg_drift_lambda.py`

The Lambda handler for [real-time drift alerts](../deploy/drift-alerts/README.md). Locally it prints
the alert a saved event would raise, with no AWS call:

```bash
python sg_drift_lambda.py event.json     # an EventBridge event, or a bare CloudTrail record
```

Exit codes: `0` nothing high or critical, `1` a high or critical rule, `2` wrong usage. In Lambda it
is configured by environment variables: `MIN_SEVERITY`, `SNS_TOPIC_ARN`, `SLACK_SECRET_ARN`,
`SECURITY_HUB`, `AUTO_REVOKE`, `ACCOUNT_NAME`.

---

## `sg_viz.py`

Read-only. Writes one JSON file (`sg-tightener.viz/v1`) for drawing a region's
traffic: every connection (source, destination interface, port, protocol)
with accepted and rejected totals, the security-group rules that allow it,
and per-bucket counts for a timeline.

```bash
python sg_viz.py export  --region eu-west-1 --log-group vpc-flow-logs --days 7 \
                         [--bucket 3600] [--plan plan.json] [--out viz-data.json]
python sg_viz.py overlay --data viz-data.json --plan plan.json
```

| Flag | Default | Meaning |
|---|---|---|
| `--days` / `--hours` | 7 days | Window, ending now |
| `--bucket` | 1h up to 7 days, 6h up to 31, then 1 day | Seconds per timeline bucket |
| `--log-group` / `--s3-bucket` `--s3-prefix` | | Where the flow logs are |
| `--plan` | | Mark every observed accepted connection the plan would stop (`plan_impact: blocked`) |

Large windows are split under the Logs Insights 10,000-row limit, as in `analyse`.

---

## `sg_review.py`

One account at a time, read-only. `read` calls AWS; `report`, `approved` and
`demo` work from what was read and make no AWS call. Everything read is kept
under `--data-dir` (default `~/.sg-tightener`): `review/<account>.json.gz`
(mode 0700 directory) and the address-naming lists in `ipintel/`.

```bash
python sg_review.py read     --regions eu-west-1,us-east-1 [--days 1] [--profile P] [--yes]
python sg_review.py report   [--account ID] [--onprem "10.200.0.0/16 Johannesburg DC"] \
                             [--internal "10.40.0.0/16 Payments prod"] [--names FILE] [--offline] [--out FILE]
python sg_review.py approved --region eu-west-1 [--account ID] [--out approved.json]
python sg_review.py demo     [--offline] [--out sg-review-demo.html]
python sg_review.py names    [--out FILE]
python sg_review.py forget   --account ID
python sg_review.py watch    --regions R [--slack URL] [--email-to A,B] [--min-severity high] [--repeat 24] \
                             [--max-cost 0.50] [--loop [--every 60]]
python sg_review.py org      --regions R [--ou-id OU] [--role-name OrganizationAccountAccessRole] [--days 1] \
                             [--accounts ID,ID] [--range 1w] [--out-dir sg-review-org] [--yes]
python sg_review.py securityhub [--account ID] [--range 1w] [--profile P] [--out findings.json]
```

| Flag | Default | Meaning |
|---|---|---|
| `read --regions` | required | Regions to read. The account is the credentials' own |
| `read --days` | `1` | `1`, `7`, `30`, `90` or `180`. Only time not read before is read. Start with `1`: it measures the bytes per second, and longer reads are estimated from it |
| `read --profile` | credential chain | AWS profile, for example an `aws sso login` one |
| `read --name` | account alias | Name shown in the report |
| `read --egress` | off | Also read outbound connections, so the report can fit outbound rules and flag connections to Tor exits or scanners. Each read costs about half as much again. Once given it stays on for that account |
| `read --yes` | off | Skip the typed `yes` after the cost estimate |
| `report --account` | the only one read | Which account's read to report |
| `report --onprem` | | Data centre ranges to name, comma separated, each `CIDR name` |
| `report --internal` | | Your other accounts' ranges, named like `--onprem`, counted as internal |
| `report --names` | `~/.sg-tightener/names.yaml` if it exists | Names file (YAML or JSON): partners and other networks named by range or AS number. See [Your names file](security-group-review.md#your-names-file) |
| `watch --slack` / `--email-to` | `SG_REVIEW_SLACK_WEBHOOK` | Where new **Needs attention** items go; printed when neither is given. SMTP from `--smtp-host`, `--smtp-port` (587), `--email-from`, `SG_REVIEW_SMTP_USER`/`_PASSWORD`, `--smtp-plain` |
| `watch --min-severity` | `high` | Post items at or above `critical`, `high` or `medium` |
| `watch --repeat` | `24` | Hours before an item still open is posted again |
| `watch --max-cost` | `0.50` | Skip a read estimated above this many US$ |
| `watch --loop`, `--every` | off, `60` | Keep running, once every so many minutes |
| `org --ou-id` | whole organisation | Accounts in this OU and every OU under it |
| `org --role-name` | `OrganizationAccountAccessRole` | Role assumed in each account (`--external-id` if it needs one) |
| `org --days`, `--range` | `1`, `1w` | How far back to read; the range the roll-up counts |
| `org --out-dir` | `sg-review-org` | `index.html`, `org.json` and one page per account |
| `org --yes` | off | Skip the one typed `yes` after the combined cost |
| `watch --securityhub`, `org --securityhub` | off | Also send the findings to Security Hub in each account read |
| `securityhub --range` | `1w` | The range the findings come from (`24h`, `1w`, `1m`, `3m`, `6m`). Sends critical to low findings (Needs attention, rules opened wide, PrivateLink, exposure and hygiene) to Security Hub in their regions, as ASFF, and archives the ones sent before that are no longer found. Needs `securityhub:BatchImportFindings` |
| `securityhub --out` | | Write the ASFF JSON to this file instead of sending it |
| `report --offline` | off | Do not refresh the AWS, SaaS, Tor exit and AS-number lists (refreshed daily, weekly for AS numbers) |
| `report --out` | `sg-review-<account>.html` | The page: open it in any browser, offline. It describes your network: treat it as confidential |
| `approved --region` | required | The region whose approved.json to write (the page offers the same file per region) |
| `approved --out` | `approved.json` | Output file, for `sg_tightener.py plan --approved` |
| `demo --out` | `sg-review-demo.html` | The page for a made-up account; no AWS call |
| `names --out` | `~/.sg-tightener/names.yaml` | Check the names file and list what it names, or write an example one if there is none |
| `forget --account` | | Delete what was read for that account |
| `--data-dir` (before the command) | `~/.sg-tightener` | Where reads and the address-naming lists are kept |

What each flag does to the graphs, with example images: [Security Group Review](security-group-review.md).

Ctrl-C during `read` stops after the slices in flight and keeps what was read.
`read` exits 1 if not confirmed, 130 when stopped.

---

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

Runs the whole suite offline (unit tests and moto integration tests). Exit code `0` on success.
