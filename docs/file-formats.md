# File formats

All files are JSON and carry a `schema` field. Generated files are ignored by
git (see `.gitignore`); they describe your network, so treat them as
confidential.

---

## `approved.json` (`sg-tightener.approved/v1`)

Written by `analyse`, extended by `sg_diagnose`, read by `plan`.

```json
{
  "schema": "sg-tightener.approved/v1",
  "region": "eu-west-1",
  "days": 90,
  "generated_at": "2026-11-17T09:00:00+00:00",
  "source": "cloudwatch",
  "flow_log_check": {
    "verified": true,
    "fields": ["version", "account-id", "...", "pkt-srcaddr"],
    "warnings": []
  },
  "ips": ["10.4.1.10", "10.4.1.11", "10.9.7.3"]
}
```

You may edit `ips` by hand, for example to add a known DR host that was idle
during the window. `plan` only reads `ips`, and ignores public addresses.

---

## `plan.json` (`sg-tightener.plan/v1`)

Written by `plan` and `sg_compact plan`, read by `apply`.

```json
{
  "schema": "sg-tightener.plan/v1",
  "generated_at": "2026-11-17T09:05:00+00:00",
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
| `removed_without_evidence` | Eligible rules with no observed traffic: revoked, nothing authorised in their place |
| `port_merge_flagged` | Several eligible port ranges on the same protocol could be merged |

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
  "groups": [
    { "group_id": "sg-0abc1234", "revoked": [ … ], "authorised": [ … ] }
  ]
}
```

A partial manifest is written when `apply` stops on an error, and reverts only
what was done.

`sg_extend` writes `sg_extend-manifest-<ts>.json` (`sg-extend.manifest/v1`) listing the rules it added
per group. It is a record for the next tightening cycle, not an input to
`revert`: to undo a break-glass change, revoke those rules by hand.

---

## Reports

`sg_ou_report.py` and `sg_transfer_audit.py` write an Excel workbook (summary
sheet ranked by severity, plus every finding) and the same data as JSON.
