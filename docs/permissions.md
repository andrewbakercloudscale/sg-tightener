# Permissions

[`iam-policy.json`](../iam-policy.json) holds every permission the suite uses,
in two statements:

* `ReadOnlyForAnalysePlanReport`: everything that only reads.
* `WriteForApplyAndRevert`: `ec2:AuthorizeSecurityGroupIngress` and
  `ec2:RevokeSecurityGroupIngress`.

Split them into two roles. Most runs (`analyse`, `plan`, `sg_diagnose`, both
reports, `sg_compact plan`) need only the read-only one. Give the write role to
the people who apply changes, and only for the change window.

---

## Per tool

| Tool | Needs |
|---|---|
| `analyse` | `ec2:DescribeFlowLogs`; CloudWatch: `logs:StartQuery`, `logs:GetQueryResults`, `logs:StopQuery`, `logs:DescribeLogGroups`; or S3: `s3:ListBucket`, `s3:GetObject` |
| `plan` | `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces` (to map each destination to its groups), `ec2:DescribeVpcEndpointServiceConfigurations` and `elasticloadbalancing:DescribeLoadBalancers` (to find NLBs behind PrivateLink endpoint services; without them every group on a load balancer interface is held back) |
| `apply`, `revert` | `ec2:DescribeSecurityGroups` plus the write statement |
| `sg_diagnose` | As `analyse`, plus `ec2:DescribeSecurityGroups` |
| `sg_extend` | As `analyse` (minus `DescribeFlowLogs`), `ec2:DescribeNetworkInterfaces`, `ec2:DescribeSecurityGroups`, `ec2:AuthorizeSecurityGroupIngress` |
| `sg_compact` | `ec2:DescribeSecurityGroups`; the write statement to apply |
| `sg_ou_report` | In the management (or delegated admin) account: `organizations:List*`, `organizations:DescribeOrganization`, `sts:GetCallerIdentity`, `sts:AssumeRole`. In each member account, via the assumed role: `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkAcls`; for the PrivateLink checks `ec2:DescribeVpcEndpointServiceConfigurations`, `ec2:DescribeVpcEndpointServicePermissions`, `ec2:DescribeVpcEndpoints`, `elasticloadbalancing:DescribeLoadBalancers` (a refusal is listed but does not make the account incomplete) |
| `sg_transfer_audit` | As `sg_ou_report`, plus in each member account `transfer:ListServers`, `transfer:DescribeServer`, `ec2:DescribeVpcEndpoints` |
| `sg_review read` | `sts:GetCallerIdentity`; `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces`, `ec2:DescribeVpcs`, `ec2:DescribeNetworkAcls`, `ec2:DescribeVpnConnections`, `ec2:DescribeFlowLogs`, `ec2:GetManagedPrefixListEntries`; `cloudtrail:LookupEvents` (rule changes; without it earlier rules are taken as today's); for PrivateLink, `ec2:DescribeVpcEndpointServiceConfigurations`, `ec2:DescribeVpcEndpointServicePermissions`, `ec2:DescribeVpcEndpointConnections`, `ec2:DescribeVpcEndpoints` and `elasticloadbalancing:DescribeLoadBalancers` (without them the PrivateLink section says what was not read); `logs:StartQuery`, `logs:GetQueryResults`, `logs:StopQuery`; optional `iam:ListAccountAliases` for the account's name. `report`, `approved` and `demo` make no AWS call |
| `sg_review watch` | As `sg_review read` |
| `sg_review org` | In the management (or delegated admin) account: `organizations:ListAccounts`, `organizations:ListAccountsForParent`, `organizations:ListOrganizationalUnitsForParent`, `sts:AssumeRole`. In each member account, via the assumed role: as `sg_review read` |

`Resource` is `*` because these describe and query calls do not support
resource-level restrictions. To limit where writes can land, add a condition
on the write statement, for example `aws:ResourceTag` or `ec2:Vpc`.

## Cross-account

The two organization reports assume `--role-name` (default
`OrganizationAccountAccessRole`) in each account. That default role has
administrator access; for routine scans create a narrower read-only role with
the member-account permissions above and pass its name.

## Network access

`sg_extend --include-public` downloads
`https://ip-ranges.amazonaws.com/ip-ranges.json` and caches it for 7 days in
`~/.cache/sg-tightener/`.
Nothing else calls anything outside AWS APIs.
