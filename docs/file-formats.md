# File formats

All files are JSON and carry a `schema` field. Generated files are ignored by
git (see `.gitignore`); they describe your network, so treat them as
confidential.

---

## `approved.json` (`sg-tightener.approved/v2`)

Written by `analyse`, extended by `sg_diagnose`, read by `plan`.

```json
{
  "schema": "sg-tightener.approved/v2",
  "region": "eu-west-1",
  "days": 90,
  "generated_at": "2026-11-17T09:00:00+00:00",
  "source": "cloudwatch",
  "flow_log_check": {
    "verified": true,
    "fields": ["version", "account-id", "...", "pkt-srcaddr"],
    "warnings": []
  },
  "ips": ["10.4.1.10", "10.4.1.11", "10.9.7.3"],
  "flows": [
    { "src": "10.4.1.10", "dst": "10.4.2.20", "dstport": 5432, "protocol": "6" },
    { "src": "10.4.1.11", "dst": "10.4.2.20", "dstport": 5432, "protocol": "6" },
    { "src": "10.9.7.3",  "dst": "10.4.3.30", "dstport": 443,  "protocol": "6" }
  ]
}
```

| Field | Meaning |
|---|---|
| `ips` | Every observed source address (the `src` values of `flows`, plus anything added by hand or by `sg_diagnose`) |
| `flows` | One entry per distinct accepted ingress (source, destination address, destination port, protocol). `dst` prefers `pkt-dstaddr`; `protocol` is the IANA number (`"6"` TCP, `"17"` UDP). `dst`, `dstport` or `protocol` is `null` when the record had none |

`plan` maps each `dst` to the network interface that owns it
(`DescribeNetworkInterfaces`, including delegated `/28` prefixes) and gives a
group's rule only the sources that reached an interface carrying that group,
on a protocol and port the rule admits. Evidence that cannot be tied to an
interface is kept on **every** group whose rule admits it (the older per-rule
behaviour) and listed in the plan, so a replaced interface never costs access:

* a `dst` that no interface in the region owns now (deleted or replaced, such
  as a Fargate task or an autoscaled instance, or in another account): see
  `unattributed_destinations`;
* an address in `ips` that no flow mentions: see `sources_without_flows`.

You may still add addresses to `ips` by hand, for example a known DR host that
was idle during the window; with no flow it is kept on every rule that admits
it. `plan` ignores public addresses.

**Older files.** An `approved.json` with no `flows` (`sg-tightener.approved/v1`,
from an earlier version, or from `analyse` against a log format with no
destination address or port) still plans, per rule: every observed source
inside a rule is granted to every group carrying that rule, and `plan` prints a
warning saying so. Re-run `analyse` for a per-group plan.

---

## `plan.json` (`sg-tightener.plan/v1`)

Written by `plan` and `sg_compact plan`, read by `apply`.

```json
{
  "schema": "sg-tightener.plan/v1",
  "generated_at": "2026-11-17T09:05:00+00:00",
  "region": "eu-west-1",
  "max_rules": 60,
  "tolerance": 0.3,
  "prefix_threshold": 24,
  "snapshot_hash": "9f2c…",
  "groups": [
    {
      "group_id": "sg-0abc1234",
      "group_name": "app-db",
      "vpc_id": "vpc-0def5678",
      "current_rule_count": 7,
      "budget": 55,
      "port_merge_flagged": false,
      "revoke": [
        { "IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
          "IpRanges": [{ "CidrIp": "10.4.0.0/16" }] }
      ],
      "restore": [ … the revoked rules with their descriptions … ],
      "removed_without_evidence": [],
      "authorise": [
        { "IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
          "IpRanges": [
            { "CidrIp": "10.4.1.10/31", "Description": "sg-tightener evidence-based" }
          ] }
      ]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `snapshot_hash` | SHA-256 of every group's rules in the region when the plan was made. `apply` refuses if it no longer matches. Do not edit |
| `budget` | Rules available for replacements: `max_rules` minus the rules being kept |
| `revoke` / `authorise` | Passed unchanged to `RevokeSecurityGroupIngress` / `AuthorizeSecurityGroupIngress` |
| `region` | Where the plan was built. `apply` runs there and refuses a different `--region` |
| `restore` | What `revert` puts back: the revoked rules with their original descriptions |
| `removed_without_evidence` | Eligible rules with no observed traffic: revoked, nothing authorised in their place |
| `port_merge_flagged` | Several eligible port ranges on the same protocol could be merged |
| `attribution` | `per-group` (built from `flows`) or `per-rule` (an `approved.json` without them) |
| `unattributed_destinations` | Per-group plans only: destinations that matched no network interface; their sources were kept per rule |
| `sources_without_flows` | Per-group plans only: addresses in `ips` with no flow; kept per rule |

`sg_compact` plans also carry `tool`, `region` and `ratio`.

You may delete whole entries from `groups` to leave those groups untouched.
Editing `revoke` or `authorise` is possible but bypasses the algorithm; review
carefully.

---

## Manifests (`sg-tightener.manifest/v1`)

Written by `apply` (`manifest-<ts>.json`) and `sg_compact apply`
(`sg_compact-manifest-<ts>.json`), read by `revert`.

```json
{
  "schema": "sg-tightener.manifest/v1",
  "applied_at": "2026-11-17T10:00:00+00:00",
  "region": "eu-west-1",
  "complete": true,
  "groups": [
    { "group_id": "sg-0abc1234", "revoked": [ … ], "authorised": [ … ] }
  ]
}
```

The manifest is rewritten after each successful AWS call and records only calls
that succeeded. When `apply` stops on an error, or is killed, `complete` is
`false` and `revert` undoes exactly what was done (for example a revoke whose
authorise then failed).

`sg_extend` writes `sg_extend-manifest-<ts>.json` (`sg-extend.manifest/v1`) listing the rules it added
per group. It is a record for the next tightening cycle, not an input to
`revert`: to undo a break-glass change, revoke those rules by hand.

---

## Reports

`sg_ou_report.py` and `sg_transfer_audit.py` write an Excel workbook (summary
sheet ranked by severity, plus every finding) and the same data as JSON.
