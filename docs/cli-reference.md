# CLI reference

Every tool prints its own help with `--help`. Defaults below are taken from the
code. All tools use your normal AWS credential chain (`AWS_PROFILE`, SSO,
instance role, and so on).

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
| `--max-rules` | `60` | Rules allowed per security group |
| `--tolerance` | `0.30` | Fraction of unused addresses allowed inside a replacement block |
| `--prefix-threshold` | `24` | Only rules wider than this prefix are eligible |
| `--out` | `plan.json` | Output file |

### `apply`

| Flag | Default | Meaning |
|---|---|---|
| `--plan` | required | The reviewed `plan.json` |
| `--region` | from the plan | Only for plans written before the region was recorded. If given for a newer plan it must match, or `apply` refuses |
| `--yes` | off | Skip the typed `yes` confirmation |

The region is read from the plan; `AWS_REGION` is ignored for plans that record one.
The manifest is rewritten after every successful AWS call, so it always lists
exactly what was changed.
Writes `manifest-<YYYYMMDDTHHMMSSZ>.json` in the current directory.

### `revert`

| Flag | Default | Meaning |
|---|---|---|
| `--manifest` | required | A manifest from `apply` |
| `--yes` | off | Skip the typed `yes` confirmation |

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
| `--tolerance` | `0.30` | Fraction of unused addresses allowed inside a grouping block |
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

Exit codes: `0` every account and region scanned, nothing CRITICAL; `1` a
CRITICAL finding; `2` the scan was incomplete (see `errors` in the JSON and
`scan_status` per account) and nothing CRITICAL was found.

---

## `sg_transfer_audit.py`

Same flags as `sg_ou_report.py`, with outputs defaulting to
`transfer_report.xlsx` and `transfer_report.json`. Exit codes as
`sg_ou_report.py`.

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

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

Runs the whole suite offline (unit tests and moto integration tests). Exit code `0` on success.
