# Real-time drift alerts

`sg_review.py watch`, run hourly, alerts on a rule opened wide within the hour. This alerts within
seconds: an EventBridge rule sends every successful `AuthorizeSecurityGroupIngress` and
`ModifySecurityGroupRules` call to a Lambda function (`sg_drift_lambda.py`), which judges the rule it
added exactly as `sg_review.py` does for **Rules opened wide**:

| Added | Severity |
|---|---|
| `0.0.0.0/0` or `::/0` on a risky port (remote admin, database, Windows, containers) or all traffic | Critical |
| `0.0.0.0/0` or `::/0` on another non-web port | High |
| `0.0.0.0/0` or `::/0` on 80 or 443 | Medium |
| A public `/16` or wider (IPv6 `/32` or wider) | High on a risky port, medium otherwise |
| A private `/8` on a risky port | Medium |

At or above the minimum severity it alerts, naming who made the change, from which address, the
group, and the command that takes it back out:

- an **SNS topic** (email, or subscribe chat and pager endpoints);
- **Slack**, from a webhook URL kept in Secrets Manager;
- **Security Hub**, with the same finding id `sg_review.py securityhub` uses, so the batch run later
  updates that finding rather than adding a copy;
- optionally it **revokes** the rule at once (`AutoRevoke` = `critical` or `high`). A group tagged
  `sg-tightener-allow-wide=true` is never revoked: the alert says so, and the function's policy denies
  it as well.

A CloudWatch alarm on the function's errors posts to the same topic, so a broken alert path is seen.

## Before you start

- A **CloudTrail trail** recording management events in the account (EventBridge receives
  "AWS API Call via CloudTrail" events only when one is logging). An organisation trail counts.
- One stack **per region** you use: EventBridge sees only API calls made in its own region.

## CloudFormation

```bash
deploy/drift-alerts/build.sh                     # copies the five modules into deploy/drift-alerts/build/
aws cloudformation package --template-file deploy/drift-alerts/template.yaml \
    --s3-bucket my-artifacts-bucket --output-template-file deploy/drift-alerts/packaged.yaml
aws cloudformation deploy --template-file deploy/drift-alerts/packaged.yaml \
    --stack-name sg-tightener-drift --capabilities CAPABILITY_IAM --region eu-west-1 \
    --parameter-overrides AlertEmail=secops@example.com MinSeverity=high AutoRevoke=off
```

For every account in an organisation, deploy `packaged.yaml` as a service-managed **StackSet** to the
OUs and regions you want (the artifact bucket must be readable from those accounts, or package once
per region).

| Parameter | Default | Meaning |
|---|---|---|
| `MinSeverity` | `high` | `critical`, `high` or `medium` |
| `AlertEmail` | | Subscribe this address to the topic (confirm the email AWS sends) |
| `SlackSecretArn` | | Secrets Manager secret with the Slack webhook URL (plain, or `{"url": "..."}`) |
| `SecurityHub` | `false` | Also send the finding to Security Hub (enabled in that region) |
| `AutoRevoke` | `off` | `critical` or `high`: revoke a rule rated this or worse as soon as it is added |
| `AccountName` | | Shown in alerts next to the account id |

## Terraform

```hcl
module "sg_drift" {
  source       = "github.com/andrewbakercloudscale/sg-tightener//deploy/drift-alerts?ref=v2.8.0"
  alert_email  = "secops@example.com"
  min_severity = "high"
  auto_revoke  = "off"
}
```

Variables as the parameters above (`slack_secret_arn`, `security_hub` as a bool, `account_name`). For
several regions, instantiate the module once per aliased provider. Needs AWS provider 6.0 or later.

## Try it first

```bash
python sg_drift_lambda.py tests/fixtures/events/authorize-ssh-world.json
```

prints the alert a saved event would raise, with no AWS call. Exit code 1 means high or critical. Any
CloudTrail record of an `AuthorizeSecurityGroupIngress` call works, bare or wrapped as EventBridge
delivers it.

After deploying, open a rule in a test group and watch the alert arrive:

```bash
aws ec2 authorize-security-group-ingress --group-id sg-TEST --protocol tcp --port 22 --cidr 0.0.0.0/0
```

## Turning on AutoRevoke

Run with `AutoRevoke=off` for a couple of weeks first and look at what would have been revoked. Then
tag the groups where wide rules are meant (`sg-tightener-allow-wide=true`: internet-facing load
balancers, public SFTP) and switch it on. With it on, a critical rule lives only for the seconds
between the call and the revoke.
