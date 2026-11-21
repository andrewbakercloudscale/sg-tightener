# Runbook

> **Why this exists.** Security groups written once and frozen in Terraform end up letting in whole
> corporate or data centre blocks (`10.0.0.0/8` is 16.7 million addresses) because nobody knows who
> really calls each service. With attackers working from any one compromised host inside the
> network, trusting a whole CIDR block is a high-risk strategy. sg-tightener treats every allowed
> IP address as risk: it takes security group sources out of static configuration and, from VPC flow
> log evidence, fits each group's limited rules to the fewest addresses that cover the real callers.
> See [The shift: IP addresses are risk, not configuration](../README.md#the-shift-ip-addresses-are-risk-not-configuration).

Step-by-step procedures for the three situations sg-tightener is built for:
a planned tightening, a post-change check, and a live incident.

---

## Before you start (once per account)

- [ ] **Flow logs exist and cover the VPCs you will tighten.** They must capture
      `ACCEPT` traffic (`ALL` is fine). See [flow-logs.md](flow-logs.md).
- [ ] **Transit gateway or NAT in the path?** Then the flow-log format needs
      `${pkt-srcaddr}`. Without it `analyse` records gateway addresses, not
      clients. Create a replacement flow log with the recommended format and
      wait for it to accumulate a full window before analysing.
- [ ] **The flow logs are old enough.** 90 days by default. If the account runs
      quarterly DR tests, year-end jobs or blue/green deployments, wait for and
      analyse at least 180 days.
- [ ] **Two IAM roles**: [`iam-policy-read.json`](../iam-policy-read.json)
      for `analyse`, `plan` and the reports, and
      [`iam-policy-write.json`](../iam-policy-write.json) (scoped to one VPC)
      for `apply` and `revert` during the change window. See
      [permissions.md](permissions.md).
- [ ] **The rule quota.** The default limit is 60 inbound rules per group. If
      your account's quota is higher, pass it as `--max-rules`.

---

## Planned tightening

1. **Find the worst accounts first.**

   ```bash
   python sg_ou_report.py --regions eu-west-1,us-east-1 \
     --ou-id ou-xxxx-xxxxxxxx --out report.xlsx --json report.json
   ```

2. **Analyse.** One region per run.

   ```bash
   python sg_tightener.py analyse --region eu-west-1 \
     --log-group /aws/vpc/flowlogs --days 90 --out approved.json
   ```

   Read every `WARNING flow-log config:` line. A warning about `pkt-srcaddr`
   in a transit-gateway estate means stop and fix the flow logs.

3. **Add known idle sources.** If a DR host or batch server is known to be
   needed but was quiet during the window, add its address to `ips` in
   `approved.json`. With no flow recorded it is kept on every group whose rule
   admits it. Public addresses can stay; `plan` ignores them.

4. **Plan.**

   ```bash
   python sg_tightener.py plan --region eu-west-1 \
     --approved approved.json --out plan.json
   ```

   A `… blocks at tolerance … exceed the … rule budget` warning means the
   observed addresses did not fit the rule budget at the requested tolerance,
   so blocks were merged (granting the fewest extra addresses possible).
   Consider a quota increase first if that is too wide.

5. **Review `plan.json`.** For each group compare `revoke` with `authorise`:
   - Do the new CIDRs make sense for what this group protects?
   - **`removed_without_evidence`**: these rules saw no traffic and will be
     revoked with nothing in their place. Confirm each one is really unused.
   - **`skipped_groups`**: groups left alone on purpose, each with a reason
     (outside the flow logs' coverage, or an NLB behind a PrivateLink endpoint
     service). Tighten those by other means, for example from the consumers'
     own flow logs.
   - Is `port_merge_flagged` true? Then several port ranges share sources and
     could be merged by hand.
   - Delete groups you are not ready to change from the `groups` array.
     Removing a group does not invalidate the plan.

   Have a second engineer review production plans. With two-person approval on (the default)
   this is enforced: propose the plan, and a different person approves it.

   ```bash
   python sg_db.py propose --plan plan.json --reason "quarterly tightening" --ticket CHG-2101
   # the second engineer, with their own credentials, on the same host:
   python sg_db.py requests
   python sg_db.py approve 14 --note "reviewed plan.json"     # or in sg_console.py
   python sg_db.py apply --region eu-west-1                   # in the change window
   ```

   To undo, propose the reverse (`sg_db.py add …` for what was removed) or, mid-incident, use
   `sg_extend` (break-glass, no approval needed). The audit trail shows every rule the request changed.
   Steps 6 and 7 apply when approvals are off (`sg_db.py approvals off --reason "…"`).

6. **Apply in a change window,** with someone watching the services involved.
   First `python sg_db.py reconcile --regions eu-west-1`: `apply` refuses while a change made
   outside sg-tightener has not been reviewed, or the database holds changes not yet applied.
   Every rule `apply` changes is recorded in the database's audit trail.

   ```bash
   export AWS_REGION=eu-west-1
   python sg_tightener.py apply --plan plan.json
   ```

   If it says the plan is stale, someone changed a security group in that
   region since step 4. Re-plan and review again; do not edit the hash.

7. **Keep the manifest.** `manifest-<timestamp>.json` is your undo button.
   Store it with the change record.

---

## After the change (first 24 to 72 hours)

```bash
python sg_diagnose.py --region eu-west-1 \
  --log-group /aws/vpc/flowlogs --hours 24 --approved approved.json \
  --manifest manifest-<ts>.json
```

* **"nothing to do"**: no private source is being refused by the groups on the
  interface it tried to reach.
* **A list of flows**: each was refused by its destination's groups. Those
  marked **CAUSED BY TIGHTENING** were allowed by a rule the apply revoked.
  Decide whether each is legitimate, then restore access with the printed
  `sg_extend` command (or `revert` the whole apply). Answer `y` to record them
  in `approved.json` so the next plan keeps them; that alone changes nothing
  in AWS.

Run it daily for the first week, and again after the next month-end.

---

## Something broke and it must work now

**Option A: undo the whole change.**

```bash
python sg_tightener.py revert --manifest manifest-<timestamp>.json
```

**Option B: open only what is being refused** (keeps the rest of the
tightening). This only adds rules.

```bash
# You know the region and roughly the port, not the groups:
python sg_extend.py --region eu-west-1 \
  --log-group /aws/vpc/flowlogs --hours 2 --ports 443 \
  --description "INC-1234 supplier cutover"

# You know exactly which groups:
python sg_extend.py --region eu-west-1 --groups sg-0abc,sg-0def \
  --log-group /aws/vpc/flowlogs --hours 2
```

It names the groups it will change (in discovery mode) and asks you to type
`extend` before adding anything. Afterwards:

* keep `sg_extend-manifest-<ts>.json` with the incident record;
* if a group was **skipped** for exceeding its rule budget, raise
  `--tolerance`, run `sg_compact`, or raise the quota, then re-run;
* the next planned tightening should start from a fresh `analyse`, which will
  now see the traffic you allowed.

---

## A group is at the rule limit

```bash
python sg_compact.py plan --region eu-west-1              # ranking + ratio sweep
python sg_compact.py plan --region eu-west-1 --ratio 0.5 --out compact.json
python sg_compact.py apply --plan compact.json    # region is read from the plan
# undo:
python sg_compact.py revert --manifest sg_compact-manifest-<ts>.json
```

Pick the smallest ratio that brings every group under the limit with a margin
for future `sg_extend` runs.

---

## Transfer Family exposure

```bash
python sg_transfer_audit.py --regions eu-west-1,af-south-1 \
  --ou-id ou-xxxx-xxxxxxxx
```

For each CRITICAL or HIGH server, collect the partners' source addresses and
replace the `0.0.0.0/0` rule through the database (`sg_db.py add` and `remove`, then `apply`;
never in Terraform). PUBLIC endpoints have
no security group and must be migrated to a VPC endpoint first.
