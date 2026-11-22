data "archive_file" "remediation" {
  count       = var.enable_iam_key_remediation ? 1 : 0
  type        = "zip"
  source_file = "${path.module}/src/disable_iam_key.py"
  output_path = "${path.module}/.build/disable_iam_key.zip"
}

data "aws_iam_policy_document" "remediation_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "remediation" {
  count = var.enable_iam_key_remediation ? 1 : 0
  statement {
    sid       = "DeactivateUserKeys"
    actions   = ["iam:UpdateAccessKey"]
    resources = ["arn:${data.aws_partition.current.partition}:iam::${local.account_id}:user/*"]
  }
  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
  statement {
    sid       = "EncryptNotification"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = [aws_kms_key.alerts.arn]
  }
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.remediation[0].arn}:*"]
  }
  statement {
    sid       = "DeadLetter"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.remediation_dlq[0].arn]
  }
  statement {
    sid       = "Tracing" # X-Ray write actions don't support resource-level permissions
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

# Failed async invocations land here instead of disappearing; the alarm below emails on the first one.
resource "aws_sqs_queue" "remediation_dlq" {
  count                     = var.enable_iam_key_remediation ? 1 : 0
  name                      = "${var.name_prefix}-iam-key-remediation-dlq"
  kms_master_key_id         = aws_kms_key.alerts.arn
  message_retention_seconds = 1209600
  tags                      = var.tags
}

resource "aws_cloudwatch_metric_alarm" "remediation_dlq" {
  count               = var.enable_iam_key_remediation ? 1 : 0
  alarm_name          = "${var.name_prefix}-iam-key-remediation-failed"
  alarm_description   = "The IAM key remediation Lambda failed; the finding is in the dead-letter queue."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.remediation_dlq[0].name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = var.tags
}

resource "aws_iam_role" "remediation" {
  count              = var.enable_iam_key_remediation ? 1 : 0
  name               = "${var.name_prefix}-iam-key-remediation"
  assume_role_policy = data.aws_iam_policy_document.remediation_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "remediation" {
  count  = var.enable_iam_key_remediation ? 1 : 0
  name   = "least-privilege"
  role   = aws_iam_role.remediation[0].id
  policy = data.aws_iam_policy_document.remediation[0].json
}

resource "aws_cloudwatch_log_group" "remediation" {
  count             = var.enable_iam_key_remediation ? 1 : 0
  name              = "/aws/lambda/${var.name_prefix}-iam-key-remediation"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.alerts.arn
  tags              = var.tags
}

resource "aws_lambda_function" "remediation" {
  # checkov:skip=CKV_AWS_117:Calls only public AWS APIs (IAM, SNS); a VPC would need NAT or endpoints and add no isolation
  # checkov:skip=CKV_AWS_272:Users deploy this module from source; code signing needs a signing profile they own
  count                          = var.enable_iam_key_remediation ? 1 : 0
  function_name                  = "${var.name_prefix}-iam-key-remediation"
  role                           = aws_iam_role.remediation[0].arn
  runtime                        = "python3.12"
  handler                        = "disable_iam_key.lambda_handler"
  filename                       = data.archive_file.remediation[0].output_path
  source_code_hash               = data.archive_file.remediation[0].output_base64sha256
  timeout                        = 30
  reserved_concurrent_executions = 5
  kms_key_arn                    = aws_kms_key.alerts.arn

  environment {
    variables = {
      TOPIC_ARN  = aws_sns_topic.alerts.arn
      ACCOUNT_ID = local.account_id
      DRY_RUN    = tostring(var.remediation_dry_run)
    }
  }

  tracing_config {
    mode = "Active"
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.remediation_dlq[0].arn
  }

  depends_on = [aws_cloudwatch_log_group.remediation, aws_iam_role_policy.remediation]
  tags       = var.tags
}

resource "aws_cloudwatch_event_rule" "remediation" {
  count       = var.enable_iam_key_remediation ? 1 : 0
  name        = "${var.name_prefix}-iam-key-findings"
  description = "GuardDuty findings about IAM user credentials"
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail      = { type = [for p in local.iam_user_finding_prefixes : { prefix = p }] }
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "remediation" {
  count     = var.enable_iam_key_remediation ? 1 : 0
  rule      = aws_cloudwatch_event_rule.remediation[0].name
  target_id = "lambda"
  arn       = aws_lambda_function.remediation[0].arn
}

resource "aws_lambda_permission" "remediation" {
  count         = var.enable_iam_key_remediation ? 1 : 0
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.remediation[0].arn
}
