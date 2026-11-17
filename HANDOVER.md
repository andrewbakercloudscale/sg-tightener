# Handover: sg-tightener testing and web UI

Written 2026-11-17 at the end of the session that moved sg-tightener into its
own repository. Start the next session in this folder.

## Status update (2026-11-17, second session)

- **Goal A (testing): done.** pytest, `tests/unit` + `tests/integration` (moto),
  `tests/fixtures/flowgen.py` (synthetic flow logs + `FakeLogs` Insights
  emulator). 170 passing, 1 xfail. Risks 1 to 5 below are fixed and tested;
  see CHANGELOG.
- **New finding, not fixed:** `approved.json` has source IPs only, so `plan`
  grants every observed source inside a rule to every group, not only the
  sources that reached that group's interfaces on that port. Pinned by
  `test_a_group_only_gets_sources_that_reached_it` (xfail, strict). Fix needs
  analyse to record (src, dst, port) and plan to map dst IPs to groups.
- **Goal B changed by the owner:** no standalone viewer. `sg_viz.py` keeps
  `export` and `overlay` (data only). The picture goes into the
  aws-org-level-risk-framework-reporting console as a new "Access Graph"
  report (network + IAM, N hops from a selected account).

---

## 1. Where things are

| What | Where |
|---|---|
| Local repo | `/Users/cp363412/Desktop/github/sg-tightener` (branch `main`) |
| GitHub (public) | <https://github.com/andrewbakercloudscale/sg-tightener> |
| Website page | <https://cloudtorepo.com/tightener.html>, source `websites/cloudtorepo/tightener.html`, deployed with `websites/cloudtorepo/sync.sh` |
| Blog post | andrewbaker.ninja post 9738 (introduces the tool, embeds code); post 9778 linked the old path and was updated |
| CI | `.github/workflows/test.yml`, Python 3.9 to 3.12 on ubuntu-22.04 |
| Docs | `README.md`, `docs/` (how-it-works, runbook, cli-reference, flow-logs, file-formats, permissions) |

House rules that apply here: commit locally, **push only when the owner says
so**. Every bug fix gets a test that fails without it. Tests run offline, with
no AWS credentials.

## 2. What was done this session

- Moved from `cloudtorepo/sg-tightener/` with its 6-commit history
  (`git subtree split`). The old folder was deleted from cloudtorepo and pushed.
  Every link on cloudtorepo.com and the blog now points to the new repo.
- **Fixed `sg_diagnose`**, which crashed on every run (`TypeError`) after the
  flow-log preflight was added. The preflight is now `preflight_flow_logs()`,
  shared by `analyse` and `sg_diagnose`.
- **Fixed `plan` (safety):** each eligible rule is now rebuilt only from
  observed RFC 1918 addresses inside its own CIDR, clipped to that CIDR. A plan
  can narrow a rule, never widen it, and public IPs never reach private rules.
  Rules with no traffic appear under `removed_without_evidence` in `plan.json`.
- `iam-policy.json` gained the three permissions `sg_transfer_audit` needs.
- Full documentation set, LICENSE, CONTRIBUTING, SECURITY, CHANGELOG, CI.
- Tests: 110, all passing.

---

## 3. Goal A: testing

### Current state

`sg_tightener_test.py` is one unittest file with 110 tests. It covers the pure
functions well: CIDR collapse, eligibility, port merging, flow-log format
checks, log-line parsing, query building, `sg_extend` grouping and AWS-range
summarisation, `sg_compact`, `build_plan` scoping, and the `sg_diagnose`
wiring.

**Nothing tests the AWS-facing paths end to end.** `analyse`, `apply`,
`revert`, the staleness check, the partial-manifest-on-failure path, the
S3 reader and the two organization reports have never run in a test.
`moto` is not installed.

### Known risks to test first (likely real bugs)

1. **Silent truncation at 10,000 rows.** `build_cloudwatch_query` ends in
   `limit 10000` (`sg_tightener.py` ~line 498 and 512), and so does
   `sg_extend.read_rejected_flows_cloudwatch`. An estate with more than 10,000
   distinct sources gets a partial `approved.json` with no warning, and the
   new `plan` then **revokes rules for the sources that were cut off**. At
   minimum warn when the result count equals the limit. A better fix splits
   the query by time or by `/16` until each part is under the limit.
2. **`apply` takes its region from `AWS_REGION`, not from the plan.** Applying
   a `eu-west-1` plan with `AWS_REGION=us-east-1` fails the staleness check,
   which is safe but confusing. `sg_compact` already stores `region` in its
   plan; `sg_tightener plan` should too, and `apply` should refuse a mismatch.
3. **`revert` after a partial apply.** Check that a manifest written on failure
   reverts exactly what was done and no more.
4. **`sg_diagnose --hours`** is turned into whole days, so `--hours 2` reads
   24 hours.
5. **S3 reader** with `.gz` objects, mixed prefixes, and a custom format with
   `pkt-srcaddr`.

### Suggested approach

- Add `moto[ec2,logs,s3,organizations,sts]` as a **dev-only** dependency
  (`requirements-dev.txt`), so production installs stay small.
- Write a **synthetic flow-log generator** (`tests/fixtures/flowgen.py`):
  given a small topology (a few ENIs, SGs, client CIDRs, a timeline with
  accepted and rejected bursts), emit flow-log lines in either the default or
  the recommended custom format. The same generator will feed the web UI demo.
- Split tests into `tests/unit/` (the existing file, moved) and
  `tests/integration/` (moto). Keep `python sg_tightener_test.py` working, or
  switch the README, CI and website snippet to `python -m pytest` in one change.
- Integration scenarios to cover, using moto EC2 and S3 (Logs Insights is
  barely emulated by moto, so mock `start_query` / `get_query_results` with
  canned results):
  - analyse → plan → apply → revert round trip returns the exact original rules;
  - a rule changed between plan and apply makes `apply` refuse;
  - an AWS error mid-apply writes a partial manifest that reverts cleanly;
  - `sg_extend` never calls `RevokeSecurityGroupIngress` (assert on the mock);
  - org reports across two fake accounts, and the CRITICAL exit code.
- Property-style check worth adding: for random rule sets and random observed
  IPs, every authorised CIDR in a plan is a subnet of some revoked CIDR on the
  same group and port.

---

## 4. Goal B: a simple web UI

### What the owner asked for

Users should be able to **see what is connected to what, what is being
blocked, and over what timeline.**

### Recommended shape

Keep the tool's character: Python, read-only by default, no hosted service,
nothing paid. Two parts.

**1. `sg_viz.py export`: a read-only data extractor.** Writes one JSON file
(`viz-data.json`) for a region and time window:

```json
{
  "schema": "sg-tightener.viz/v1",
  "region": "eu-west-1",
  "window": { "start": "…", "end": "…", "bucket_seconds": 3600 },
  "interfaces": [ { "eni": "eni-…", "ip": "10.4.1.20", "groups": ["sg-…"], "description": "…", "vpc_id": "…" } ],
  "groups": [ { "group_id": "sg-…", "name": "…", "rules": [ … IpPermissions … ] } ],
  "flows": [ { "src": "10.9.7.3", "dst": "10.4.1.20", "port": 5432, "proto": "tcp",
               "action": "ACCEPT", "bucket": "2026-11-17T09:00:00Z", "packets": 120, "bytes": 52000 } ],
  "flow_log_check": { "verified": true, "fields": [ … ], "warnings": [] }
}
```

Flows are **aggregated** by (src, dst, port, proto, action, time bucket) so a
90-day window stays small. Logs Insights query shape:
`stats sum(packets), sum(bytes), count() by srcaddr, dstaddr, dstport, protocol, action, bin(1h)`
(using `pkt-srcaddr` when present, exactly as `build_cloudwatch_query` picks
the source field). Respect the 10,000-row limit from risk 1 by splitting the
window.

**2. `viewer/index.html`: one static page, no server.** It opens
`viz-data.json` through a file picker or drag and drop, so network data never
leaves the user's machine. Three linked views:

| View | Shows |
|---|---|
| **Timeline** (top) | Accepted vs rejected per bucket, stacked. Dragging across it selects a time range that filters the other two views |
| **Connection map** (centre) | Sources (grouped into CIDR clusters, expandable to IPs) → interfaces → security groups. Edge colour: green accepted, red rejected, both = split; thickness = volume |
| **Table** (bottom or side) | The selected edges: source, destination, port, first and last seen, counts, and the security-group rule that allowed it (or "no rule" for rejects) |

Then the feature that ties the UI to the tool: **plan overlay.** Load a
`plan.json` next to the data and highlight, in amber, every observed
accepted flow that the plan's `authorise` list would no longer cover. That
answers "what will this change block?" before anyone runs `apply`. Also show
`removed_without_evidence` rules.

Optional: `sg_viz.py serve` that only does `http.server` on `127.0.0.1` with
the JSON preloaded, for people who will not use a file picker.

### Reuse, do not re-implement

| Need | Existing code |
|---|---|
| Find flow logs, field order, `pkt-srcaddr` choice | `preflight_flow_logs`, `parse_log_format`, `build_cloudwatch_query` in `sg_tightener.py` |
| Parse S3 flow-log lines | `ips_from_flow_log_lines` (returns only IPs today; generalise it to return records) |
| Security groups | `_list_security_groups` |
| Interface IP → security groups | `derive_groups_from_dst_ips` in `sg_extend.py` (uses `DescribeNetworkInterfaces`) |
| Does a rule cover this source and port | `_existing_nets_for` / `filter_existing` in `sg_extend.py`; `sg_diagnose._covered_by_any_rule` |
| AWS service labels for public IPs | `classify_aws_service` in `sg_extend.py` |

### Front-end constraints

- One HTML file, CSS and JS inline. Libraries only from a pinned CDN (e.g.
  `cytoscape@3.30.x` for the graph; plain SVG or a small chart library for the
  timeline). No build step.
- Works offline once loaded; no telemetry; no request to anything except the
  CDN.
- Must handle a few thousand edges: cluster sources by `/24` by default and
  expand on click.
- Light and dark themes. The cloudtorepo site styling (`websites/cloudtorepo/style.css`)
  is a good visual reference, and a screenshot could go on `tightener.html`.

### Testing the UI

- Generate `viz-data.json` from the synthetic flow generator (section 3) and
  commit it as `viewer/sample-data.json` so the viewer has a demo with no AWS.
- Unit-test `sg_viz.py` aggregation and the plan-overlay calculation in Python
  (keep the overlay logic in Python and export it in the JSON, rather than
  re-deriving coverage in JavaScript).
- One Playwright smoke test: load the sample, drag a time range, confirm the
  table filters and the overlay highlights the expected edges.

### Suggested order

1. Synthetic flow generator + moto integration tests + fix risk 1 (truncation).
2. `sg_viz.py export` with tests, against the synthetic data.
3. Viewer: timeline + table first, then the connection map, then plan overlay.
4. Docs: `docs/web-ui.md`, README tools table, CLI reference, a screenshot and
   a short section on `tightener.html` (deploy with `sync.sh`).

## 5. Open questions for the owner

- pytest or keep unittest? (pytest is the simpler runner for the moto suite.)
- Should the viewer ever load data straight from AWS (needs a local server with
  credentials), or stay strictly file-based? File-based is recommended.
- Should the cloudtorepo site host a public demo of the viewer with the
  synthetic sample data?
