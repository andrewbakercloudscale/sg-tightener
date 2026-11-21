# Moving security groups out of Terraform

> **You cannot manage security groups in Terraform with this solution.** Not the groups, not their
> rules, not some of the rules. Every security group and every rule lives in sg-tightener's local
> database (`~/.sg-tightener/sg.db`, see [the database](database.md)), and every change to them is
> recorded there with who, why and when. The same applies to CloudFormation, CDK, Pulumi and the
> console. See
> [Security groups live in a local database, not in Terraform](../README.md#security-groups-live-in-a-local-database-not-in-terraform).

This page is a one-way migration. Do it once per Terraform root that owns security groups.

---

## Why there is no "keep some of it in Terraform"

Earlier versions of this guide suggested `lifecycle { ignore_changes = [ingress] }`, or keeping
security group references and public rules as `aws_vpc_security_group_ingress_rule` resources. Both
leave two owners for one group:

- `ignore_changes` hides real drift: a rule someone adds in the console never shows in a plan.
- A rule resource Terraform owns comes back on the next `terraform apply` after sg-tightener revoked
  it, and a narrowed replacement Terraform does not own is invisible to code review.
- Nobody can answer "who allowed this, and why?" from one place.

With the database there is one owner, one history and one place to change a rule.

What stays in Terraform: VPCs, subnets, instances, launch templates, load balancers, endpoints,
databases, and their **attachments** to security groups, by group id.

---

## The migration

### 1. Import every group and rule into the database

```bash
python sg_db.py import --regions eu-west-1,us-east-1 --profile prod
python sg_db.py show --region eu-west-1          # every group and rule, as the database holds them
```

Nothing changes in AWS. From now on the database is the source of truth.

### 2. Make Terraform forget the groups, without destroying them

Delete the `aws_security_group`, `aws_vpc_security_group_ingress_rule`,
`aws_vpc_security_group_egress_rule` and `aws_security_group_rule` resources from the code, and tell
Terraform to forget them rather than destroy them.

Terraform 1.7 or later, one `removed` block per resource (or module):

```hcl
removed {
  from = aws_security_group.db
  lifecycle { destroy = false }
}

removed {
  from = aws_vpc_security_group_ingress_rule.db_from_corp
  lifecycle { destroy = false }
}

removed {
  from = module.payments.aws_security_group.this
  lifecycle { destroy = false }
}
```

Older versions:

```bash
terraform state list | grep -E 'aws_security_group|aws_vpc_security_group_(ingress|egress)_rule|aws_security_group_rule'
terraform state rm aws_security_group.db aws_vpc_security_group_ingress_rule.db_from_corp
```

A module that creates its own security group (many community modules do) usually has a switch such
as `create_security_group = false` and a `security_group_ids` input: turn it off and pass the ids.

### 3. Refer to groups by id only

Attachments stay in Terraform and look the group up:

```hcl
data "aws_security_group" "db" {
  vpc_id = var.vpc_id
  name   = "payments-db"
}

resource "aws_db_instance" "payments" {
  # ...
  vpc_security_group_ids = [data.aws_security_group.db.id]
}
```

### 4. `terraform plan` shows no change to any group or rule

It should show only the state removals. If it wants to create, change or delete a security group or
a rule, stop: a resource is still in the code.

### 5. Deny Terraform's role the security group write calls

So a forgotten module cannot put a group back under Terraform. On the role Terraform runs as (or as
a service control policy for every role except sg-tightener's):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "SecurityGroupsAreManagedBySgTightener",
    "Effect": "Deny",
    "Action": [
      "ec2:CreateSecurityGroup",
      "ec2:DeleteSecurityGroup",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:ModifySecurityGroupRules",
      "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
      "ec2:UpdateSecurityGroupRuleDescriptionsEgress"
    ],
    "Resource": "*"
  }]
}
```

As an SCP, add a condition such as
`"Condition": {"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/sg-tightener"}}` so the role
sg-tightener runs as keeps the calls. Attaching a group to an instance or load balancer
(`ec2:ModifyNetworkInterfaceAttribute`, `ec2:RunInstances` with `SecurityGroupIds`) is not denied:
attachments stay in Terraform.

### 6. Run reconcile hourly

```cron
0 * * * *  cd /opt/sg-tightener && .venv/bin/python sg_db.py reconcile --regions eu-west-1 --slack "$WEBHOOK"
```

Any change made outside sg-tightener (a Terraform root you missed, the console, the CLI) is recorded
in the audit trail as external, with who made it from CloudTrail, posted to Slack, and printed with
the two ways out: `sg_db.py apply` puts AWS back to what the database says, `sg_db.py adopt --reason
"…"` keeps the change. A person decides.

---

## New security groups

Create them through the database, then attach them in Terraform by name or id:

```bash
python sg_db.py create-group --region eu-west-1 --vpc vpc-0abc --name payments-cache \
  --description "redis for payments" --reason "new cache tier" --ticket CHG-1234
python sg_db.py add --region eu-west-1 --group sg-0new --proto tcp --port 6379 \
  --source sg-0app --reason "app tier to cache" --ticket CHG-1234
python sg_db.py apply --region eu-west-1 --group sg-0new
```

A group created in the console instead is found by `reconcile`, recorded as external and taken into
the database as it is.

---

## What changes for your teams

- A security group change is a `sg_db.py` command with a reason, not a pull request. The audit trail
  (`sg_db.py log`) replaces the Terraform history for groups, and records more: changes made outside
  the tool are in it too.
- `terraform plan` no longer shows security group rules. `sg_db.py diff` shows what the database will
  change; `sg_db.py show` shows every rule.
- When you export an estate to Terraform, for example with [CloudtoRepo](https://cloudtorepo.com),
  leave security groups out and refer to them with `data "aws_security_group"`.
