# Permissions

Three policy files, from widest to narrowest use:

| File | For | Holds |
|---|---|---|
| [`iam-policy-read.json`](../iam-policy-read.json) | Everyone who runs the suite: `analyse`, `plan`, `sg_diagnose`, `sg_review`, both organization reports, `sg_compact plan` | Every describe and query call, plus the separate optional statement `OptionalSecurityHubExport` (`securityhub:BatchImportFindings`); drop it if you do not use `--securityhub` |
| [`iam-policy-write.json`](../iam-policy-write.json) | The people who apply changes, for the change window only | Authorize and revoke, ingress and egress, limited to one VPC by `ec2:Vpc`, `ec2:CreateSecurityGroup` in that VPC (`sg_db.py create-group`), and denied on any group tagged `sg-tightener=protected`. Replace `REGION`, `ACCOUNT_ID` and `VPC_ID`; use one statement per VPC if you need more |
| [`iam-policy.json`](../iam-policy.json) | A single role, when you cannot split | The read statement, the Security Hub statement and `WriteForApplyAndRevert` (authorize and revoke, ingress and egress, and `ec2:CreateSecurityGroup`) on `*` |

`sg_tightener apply`/`revert`, `sg_extend` and `sg_compact apply` write
ingress only. `sg_db.py apply` and `exec` write whatever the database holds,
ingress and egress, including the egress commands `sg_review` prints.

Security groups are managed only through sg-tightener's database: deny every
other role (Terraform's above all) the security group write calls. The policy
is in [Moving security groups out of Terraform](terraform.md#5-deny-terraforms-role-the-security-group-write-calls).

To narrow a write session further without a new role, pass a session policy
when you assume it; the session gets the intersection of the two:

```bash
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT_ID:role/sg-tightener-write \
  --role-session-name change-1234 --duration-seconds 3600 \
  --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
    "Action":["ec2:AuthorizeSecurityGroupIngress","ec2:RevokeSecurityGroupIngress"],
    "Resource":"arn:aws:ec2:eu-west-1:ACCOUNT_ID:security-group/sg-0123456789abcdef0"}]}'
```

---

## Per tool

| Tool | Needs |
|---|---|
| `analyse` | `ec2:DescribeFlowLogs`; CloudWatch: `logs:StartQuery`, `logs:GetQueryResults`, `logs:StopQuery`, `logs:DescribeLogGroups`; or S3: `s3:ListBucket`, `s3:GetObject` |
| `plan` | `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces` (to map each destination to its groups), `ec2:DescribeVpcEndpointServiceConfigurations` and `elasticloadbalancing:DescribeLoadBalancers` (to find NLBs behind PrivateLink endpoint services; without them every group on a load balancer interface is held back) |
| `apply`, `revert` | `ec2:DescribeSecurityGroups` plus the write statement (every change is also recorded in the database) |
| `sg_db.py import`, `reconcile`, `show`, `diff`, `log`, `verify` | `sts:GetCallerIdentity`, `ec2:DescribeSecurityGroups`; `reconcile` also `cloudtrail:LookupEvents` to name who made a change (optional: `--no-cloudtrail`). `show`, `diff`, `log` and `verify` make no AWS call |
| `sg_db.py --ou-id`/`--org`/`--accounts`, `sg_console.py` in other accounts | As the command, in each account via the assumed role; in the account it runs from `sts:AssumeRole` on `--role-name`, and for `--ou-id`/`--org` `organizations:ListAccounts`, `organizations:ListAccountsForParent`, `organizations:ListOrganizationalUnitsForParent` |
| `sg_console.py` | As `sg_db.py`: `reconcile` and `apply` from the page need what those commands need; the other tabs read the database and `sg_review`'s saved reads, with no AWS call. Proposing, approving and rejecting make no AWS call |
| `sg_db.py check` | The same write calls as `apply`, made as DryRun (nothing changes), so the check needs the write permissions it is checking: an identity without them is reported as unable to apply, which is the answer. With `--assets` also `ec2:CreateSecurityGroup`, `ec2:ModifyNetworkInterfaceAttribute`, `ec2:CreateTags` |
| `sg_db.py import`, `reconcile` (assets), `assets` | `ec2:DescribeNetworkInterfaces`, `ec2:DescribeInstances` (auto scaling and EKS tags); `--no-assets` skips both |
| `sg_db.py asset-plan` | As `plan` (it reads `approved.json` and the groups) |
| `sg_db.py asset-apply`, `asset-revert` | As `reconcile`, plus `ec2:CreateSecurityGroup`, `ec2:CreateTags`, `ec2:AuthorizeSecurityGroupIngress`/`Egress`, `ec2:RevokeSecurityGroupEgress` (the new group's default outbound rule) and `ec2:ModifyNetworkInterfaceAttribute`. `iam-policy-write.json` scopes the last to one VPC |
| `sg_db.py apply`, `exec`, `create-group` | As `reconcile`, plus the write statement; `exec` with `--security-group-rule-ids` also `ec2:DescribeSecurityGroupRules`; `create-group` `ec2:CreateSecurityGroup` |
| `sg_diagnose` | As `analyse`, plus `ec2:DescribeSecurityGroups` |
| `sg_extend` | As `analyse` (minus `DescribeFlowLogs`), `ec2:DescribeNetworkInterfaces`, `ec2:DescribeSecurityGroups`, `ec2:AuthorizeSecurityGroupIngress` |
| `sg_compact` | `ec2:DescribeSecurityGroups`; the write statement to apply |
| `sg_ou_report` | In the management (or delegated admin) account: `organizations:List*`, `organizations:DescribeOrganization`, `sts:GetCallerIdentity`, `sts:AssumeRole`. In each member account, via the assumed role: `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkAcls`; for the reachability note `ec2:DescribeNetworkInterfaces` and `ec2:DescribeRouteTables`; for the PrivateLink checks `ec2:DescribeVpcEndpointServiceConfigurations`, `ec2:DescribeVpcEndpointServicePermissions`, `ec2:DescribeVpcEndpoints`, `elasticloadbalancing:DescribeLoadBalancers` (a refusal is listed but does not make the account incomplete) |
| `sg_transfer_audit` | As `sg_ou_report`, plus in each member account `transfer:ListServers`, `transfer:DescribeServer`, `ec2:DescribeVpcEndpoints` |
| `sg_review read` | `sts:GetCallerIdentity`; `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces`, `ec2:DescribeVpcs`, `ec2:DescribeNetworkAcls`, `ec2:DescribeVpnConnections`, `ec2:DescribeFlowLogs`, `ec2:GetManagedPrefixListEntries`; `ec2:DescribeRouteTables` (internet exposure: without it no rule is reported as reachable, only as open); `ec2:DescribeStaleSecurityGroups` (references to deleted groups); `ec2:DescribeInstances` (each instance's Name tag and operating system, shown in Extract rule; without it the page names the interface only); `cloudtrail:LookupEvents` (rule changes; without it earlier rules are taken as today's); for PrivateLink, `ec2:DescribeVpcEndpointServiceConfigurations`, `ec2:DescribeVpcEndpointServicePermissions`, `ec2:DescribeVpcEndpointConnections`, `ec2:DescribeVpcEndpoints` and `elasticloadbalancing:DescribeLoadBalancers` (without them the PrivateLink section says what was not read); `logs:StartQuery`, `logs:GetQueryResults`, `logs:StopQuery`; optional `iam:ListAccountAliases` for the account's name. `report`, `approved` and `demo` make no AWS call |
| `sg_review watch` | As `sg_review read` |
| `sg_review securityhub`, `--securityhub` on `watch`, `org` and `sg_ou_report` | As the command it is on, plus `securityhub:BatchImportFindings` in each account findings are sent to (Security Hub must be enabled in that region) |
| `sg_review org` | In the management (or delegated admin) account: `organizations:ListAccounts`, `organizations:ListAccountsForParent`, `organizations:ListOrganizationalUnitsForParent`, `sts:AssumeRole`. In each member account, via the assumed role: as `sg_review read` |

`Resource` is `*` because these describe and query calls do not support
resource-level restrictions. To limit where writes can land, add a condition
on the write statement, for example `aws:ResourceTag` or `ec2:Vpc`.

## Cross-account

The organization commands (`sg_ou_report`, `sg_transfer_audit`, `sg_review org`, `sg_review watch --ou-id`, `sg_db.py --ou-id`, and `sg_console.py` for other accounts) assume `--role-name` (default
`OrganizationAccountAccessRole`) in each account. That default role has
administrator access; for routine scans create a narrower read-only role with
the member-account permissions above and pass its name.

## Network access

`sg_extend --include-public` downloads
`https://ip-ranges.amazonaws.com/ip-ranges.json` and caches it for 7 days in
`~/.cache/sg-tightener/`.
Nothing else calls anything outside AWS APIs.
