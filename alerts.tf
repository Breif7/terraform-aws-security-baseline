data "aws_iam_policy_document" "alerts_key" {
  # checkov:skip=CKV_AWS_109:Key policies must name the account root; "*" in a key policy means this key only
  # checkov:skip=CKV_AWS_111:Same as above (standard AWS default key policy statement)
  # checkov:skip=CKV_AWS_356:Same as above
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root"]
    }
  }
  statement {
    sid       = "AwsServicesUse"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "sns.amazonaws.com", "cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
  statement {
    sid       = "CloudWatchLogsUse"
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${local.account_id}:log-group:/aws/lambda/${var.name_prefix}-*"]
    }
  }
}

resource "aws_kms_key" "alerts" {
  description             = "${var.name_prefix} security alerts topic"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.alerts_key.json
  tags                    = var.tags
}

resource "aws_kms_alias" "alerts" {
  name          = "alias/${var.name_prefix}-alerts"
  target_key_id = aws_kms_key.alerts.key_id
}

resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-alerts"
  kms_master_key_id = aws_kms_key.alerts.arn
  tags              = var.tags
}

resource "aws_sns_topic_subscription" "email" {
  for_each  = toset(var.alert_emails)
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "${var.name_prefix}-guardduty-findings"
  description = "GuardDuty findings with severity >= ${var.alert_min_severity}"
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail      = { severity = [{ numeric = [">=", var.alert_min_severity] }] }
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_rule" "securityhub" {
  name        = "${var.name_prefix}-securityhub-findings"
  description = "New, active Security Hub findings labelled ${join("/", local.securityhub_labels)}"
  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity    = { Label = local.securityhub_labels }
        Workflow    = { Status = ["NEW"] }
        RecordState = ["ACTIVE"]
        # GuardDuty findings also flow into Security Hub; skip them so each alert arrives once.
        ProductName = [{ "anything-but" = "GuardDuty" }]
      }
    }
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "alerts" {
  for_each = {
    guardduty   = aws_cloudwatch_event_rule.guardduty.name
    securityhub = aws_cloudwatch_event_rule.securityhub.name
  }
  rule      = each.value
  target_id = "sns"
  arn       = aws_sns_topic.alerts.arn
}

data "aws_iam_policy_document" "alerts_topic" {
  statement {
    sid       = "EventBridgePublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.guardduty.arn, aws_cloudwatch_event_rule.securityhub.arn]
    }
  }
  statement {
    sid       = "CloudWatchAlarmsPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts_topic.json
}
