# Taking security group sources out of Terraform

> **Why.** A security group's sources are not infrastructure. They are a fact about who talks to
> whom, and that changes every week. Pinned in Terraform they can only grow, so they end up as whole
> corporate or data centre blocks (`10.0.0.0/8` is 16.7 million addresses). sg-tightener keeps them
> at the fewest addresses that cover the real callers, from VPC flow log evidence. For that to stick,
> Terraform must stop putting the broad blocks back. See
> [The shift: IP addresses are risk, not configuration](../README.md#the-shift-ip-addresses-are-risk-not-configuration).

Keep in Terraform what really is infrastructure: the security group itself, its name, VPC and tags,
its attachments to instances, load balancers and endpoints, rules that reference other security
groups or prefix lists, and deliberate public rules such as `0.0.0.0/0` on 443 for an internet-facing
load balancer. Take out the private CIDR sources sg-tightener manages: RFC 1918 blocks wider than
`/24` (see [what it changes](../README.md#what-it-changes-and-what-it-never-touches)).

---

## Which pattern you have

| Your code today | What Terraform does to a rule sg-tightener changes | Use |
|---|---|---|
| `ingress { }` blocks inside `aws_security_group` | Puts the old rule back and deletes the new ones on the next `apply`: inline blocks are the complete list | [Pattern A](#pattern-a-inline-ingress-blocks) |
| `aws_vpc_security_group_ingress_rule` or `aws_security_group_rule` resources | Recreates the rule it owns if it was revoked; ignores rules it does not own | [Pattern B](#pattern-b-separate-rule-resources) |
| A module that takes `ingress_cidr_blocks` or similar | Same as whichever pattern the module uses inside | Pass an empty list for the private sources, then A or B |

Never mix inline `ingress` blocks and separate rule resources for the same group. Terraform then
fights itself on every plan.

---

## Pattern A: inline ingress blocks

Before:

```hcl
resource "aws_security_group" "db" {
  name   = "payments-db"
  vpc_id = var.vpc_id

  ingress {
    description     = "app tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  ingress {
    description = "corporate network"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]          # 16.7 million addresses
  }
}
```

The simplest change is to let the group's rules live outside Terraform once they are created:

```hcl
resource "aws_security_group" "db" {
  name   = "payments-db"
  vpc_id = var.vpc_id

  ingress {
    description     = "app tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  # Private CIDR sources are managed by sg-tightener from flow log evidence.
  lifecycle {
    ignore_changes = [ingress]
  }
}
```

`ignore_changes = [ingress]` ignores every inbound rule, including the security-group reference
above, once the group exists. If you want Terraform to keep managing references and public rules,
move to Pattern B instead: it is the cleaner long-term shape.

---

## Pattern B: separate rule resources

Give the group no inline rules, and keep only the rules Terraform should own as their own resources:

```hcl
resource "aws_security_group" "db" {
  name   = "payments-db"
  vpc_id = var.vpc_id
  # no ingress blocks: Terraform leaves rules it does not own alone
}

resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "app tier"
}

# The corporate-network rule is gone from code. sg-tightener plans its replacement from the
# flow logs and applies the narrowed blocks; Terraform never sees them.
```

Rules that sg-tightener writes are separate rules in AWS that no Terraform resource owns, so
`terraform plan` stays clean.

---

## Migrating without an outage

The broad rule must stay in AWS until sg-tightener replaces it. Deleting it from code with a normal
`apply` would revoke it first and cut off the callers. So remove it from Terraform's state, not from
AWS:

1. **Read the evidence.** `sg_tightener.py analyse` over 30 to 90 days, or `sg_review.py read` to see
   each rule's use first.
2. **Stop Terraform owning the broad rules.**
   - Pattern A: add `lifecycle { ignore_changes = [ingress] }`, remove the CIDR `ingress` block from
     the code, and `apply`. Nothing changes in AWS.
   - Pattern B: delete the rule resource from the code and tell Terraform to forget it rather than
     destroy it:

     ```hcl
     removed {                      # Terraform 1.7 or later
       from = aws_vpc_security_group_ingress_rule.db_from_corp
       lifecycle {
         destroy = false
       }
     }
     ```

     On older versions: `terraform state rm aws_vpc_security_group_ingress_rule.db_from_corp`.
3. **`terraform plan` shows no change to the group's rules.** If it wants to delete or add one, stop:
   something still owns it.
4. **Tighten.** `sg_tightener.py plan`, review, `apply` (it writes a manifest), then
   `sg_diagnose.py --manifest` to confirm nothing was cut off. `revert` puts the old rules back.
5. **Keep it tight.** Re-run analyse and plan on a schedule, and `sg_review.py watch` to hear when a
   change breaks something or a rule is too open.

---

## New services

For a new service, create the group in Terraform with only its references and deliberate public
rules. If callers from private ranges are needed on day one, add them as narrow `/32` or small
blocks you know, outside Terraform, or with `sg_extend.py` during an incident. Let sg-tightener fit
the rules once flow logs have evidence. Do not start with a `/8` "for now": it never comes out.

---

## Drift and audits

- Terraform state no longer lists those sources. The source of truth is the security group in AWS,
  with each rule's description saying what set it and when, and the sg-tightener manifest of every
  change.
- `sg_review.py report` gives an auditor the whole picture for an account: every rule, what used it,
  what it lets in that was never seen, and its history from CloudTrail.
- When you export an estate to Terraform, for example with [CloudtoRepo](https://cloudtorepo.com),
  keep the same split: references and public rules in code, private sources left to sg-tightener.
