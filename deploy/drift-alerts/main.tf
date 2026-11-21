# sg-tightener real-time drift alerts, as a Terraform module.
#
#   module "sg_drift" {
#     source        = "github.com/andrewbakercloudscale/sg-tightener//deploy/drift-alerts"
#     alert_email   = "secops@example.com"
#     auto_revoke   = "off"
#   }
#
# One per region: EventBridge only sees API calls made in its own region. Needs a CloudTrail trail
# recording management events in the account.

terraform {
  required_version = ">= 1.3"
  required_providers {
    aws     = { source = "hashicorp/aws", version = ">= 6.0" }
    archive = { source = "hashicorp/archive", version = ">= 2.4" }
  }
}

variable "min_severity" {
  type        = string
  default     = "high"
  description = "Alert at or above this severity: critical, high or medium."
  validation {
    condition     = contains(["critical", "high", "medium"], var.min_severity)
    error_message = "min_severity must be critical, high or medium."
  }
}

variable "alert_email" {
  type        = string
  default     = ""
  description = "Optional. Subscribe this address to the alert topic."
}

variable "slack_secret_arn" {
  type        = string
  default     = ""
  description = "Optional. Secrets Manager secret holding a Slack incoming-webhook URL."
}

variable "security_hub" {
  type        = bool
  default     = false
  description = "Also send each finding to Security Hub in this region."
}

variable "auto_revoke" {
  type        = string
  default     = "off"
  description = "off, critical or high: revoke a rule rated this or worse as soon as it is added. Groups tagged sg-tightener-allow-wide=true are never revoked."
  validation {
    condition     = contains(["off", "critical", "high"], var.auto_revoke)
    error_message = "auto_revoke must be off, critical or high."
  }
}

variable "account_name" {
  type        = string
  default     = ""
  description = "Optional. Shown in alerts next to the account id."
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  name   = "sg-tightener-drift-${data.aws_region.current.region}"
  root   = "${path.module}/../.."
  files  = ["sg_drift_lambda.py", "sg_review.py", "sg_ipintel.py", "sg_securityhub.py", "sg_tightener.py"]
  revoke = var.auto_revoke != "off"
}

data "archive_file" "code" {
  type        = "zip"
  output_path = "${path.module}/.terraform-build/drift.zip"
  dynamic "source" {
    for_each = local.files
    content {
      content  = file("${local.root}/${source.value}")
      filename = source.value
    }
  }
}

resource "aws_sns_topic" "alerts" {
  name = local.name
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_group" "fn" {
  name              = "/aws/lambda/${local.name}"
  retention_in_days = 90
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "fn" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.fn.arn}:*"]
  }
  statement {
    sid       = "ReadTheGroup"
    actions   = ["ec2:DescribeSecurityGroups"]
    resources = ["*"]
  }
  statement {
    sid       = "Alert"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
  dynamic "statement" {
    for_each = var.slack_secret_arn == "" ? [] : [1]
    content {
      sid       = "SlackWebhook"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [var.slack_secret_arn]
    }
  }
  dynamic "statement" {
    for_each = var.security_hub ? [1] : []
    content {
      sid       = "SecurityHub"
      actions   = ["securityhub:BatchImportFindings"]
      resources = ["*"]
    }
  }
  dynamic "statement" {
    for_each = local.revoke ? [1] : []
    content {
      sid       = "Revoke"
      actions   = ["ec2:RevokeSecurityGroupIngress"]
      resources = ["arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:security-group/*"]
    }
  }
  dynamic "statement" {
    for_each = local.revoke ? [1] : []
    content {
      sid       = "NeverRevokeAllowedGroups"
      effect    = "Deny"
      actions   = ["ec2:RevokeSecurityGroupIngress"]
      resources = ["*"]
      condition {
        test     = "StringEquals"
        variable = "aws:ResourceTag/sg-tightener-allow-wide"
        values   = ["true"]
      }
    }
  }
}

resource "aws_iam_role" "fn" {
  name_prefix        = "sg-tightener-drift-"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "fn" {
  role   = aws_iam_role.fn.id
  policy = data.aws_iam_policy_document.fn.json
}

resource "aws_lambda_function" "drift" {
  function_name                  = local.name
  description                    = "sg-tightener real-time drift alerts"
  runtime                        = "python3.12"
  handler                        = "sg_drift_lambda.handler"
  filename                       = data.archive_file.code.output_path
  source_code_hash               = data.archive_file.code.output_base64sha256
  role                           = aws_iam_role.fn.arn
  timeout                        = 30
  memory_size                    = 256
  reserved_concurrent_executions = 5
  environment {
    variables = {
      HOME             = "/tmp"
      MIN_SEVERITY     = var.min_severity
      SNS_TOPIC_ARN    = aws_sns_topic.alerts.arn
      SLACK_SECRET_ARN = var.slack_secret_arn
      SECURITY_HUB     = tostring(var.security_hub)
      AUTO_REVOKE      = var.auto_revoke
      ACCOUNT_NAME     = var.account_name
    }
  }
  depends_on = [aws_cloudwatch_log_group.fn, aws_iam_role_policy.fn]
}

resource "aws_cloudwatch_event_rule" "added" {
  name        = local.name
  description = "Security group rules added (CloudTrail management events)"
  event_pattern = jsonencode({
    source        = ["aws.ec2"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"]
      errorCode   = [{ exists = false }]
    }
  })
}

resource "aws_cloudwatch_event_target" "fn" {
  rule = aws_cloudwatch_event_rule.added.name
  arn  = aws_lambda_function.drift.arn
  retry_policy {
    maximum_retry_attempts       = 4
    maximum_event_age_in_seconds = 3600
  }
}

resource "aws_lambda_permission" "events" {
  function_name = aws_lambda_function.drift.function_name
  action        = "lambda:InvokeFunction"
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.added.arn
}

resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "sg-tightener-drift-errors-${data.aws_region.current.region}"
  alarm_description   = "The drift-alert function failed; alerts may have been missed."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.drift.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

output "topic_arn" {
  value       = aws_sns_topic.alerts.arn
  description = "Subscribe more endpoints (chat, pager) here."
}

output "function_name" {
  value = aws_lambda_function.drift.function_name
}
