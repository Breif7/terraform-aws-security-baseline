# Tests with mocked providers: no AWS account or credentials needed.
mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111122223333" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-east-1" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  # Mocked apply generates random strings; ARN-validated attributes need ARN-shaped values.
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000000" }
  }
  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:us-east-1:111122223333:security-baseline-alerts" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/security-baseline-iam-key-remediation" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:us-east-1:111122223333:security-baseline-iam-key-remediation-dlq" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:111122223333:log-group:/aws/lambda/security-baseline-iam-key-remediation" }
  }
  mock_resource "aws_cloudwatch_event_rule" {
    defaults = { arn = "arn:aws:events:us-east-1:111122223333:rule/security-baseline" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:us-east-1:111122223333:function:security-baseline-iam-key-remediation" }
  }
}

mock_provider "aws" {
  alias = "management"
}

mock_provider "archive" {}

variables {
  alert_emails = ["secops@example.com"]
}

run "defaults" {
  command = plan

  assert {
    condition     = length(aws_guardduty_detector_feature.this) == 6
    error_message = "All six GuardDuty protection plans should be enabled by default."
  }
  assert {
    condition     = length(aws_guardduty_organization_admin_account.this) == 1 && length(aws_securityhub_organization_admin_account.this) == 1
    error_message = "Admin delegation should be on by default."
  }
  assert {
    condition     = aws_guardduty_organization_configuration.this.auto_enable_organization_members == "ALL"
    error_message = "Every member account must get GuardDuty."
  }
  assert {
    condition     = aws_securityhub_account.this.enable_default_standards == false
    error_message = "Default standards must be off so explicit subscriptions don't collide."
  }
  assert {
    condition     = contains(keys(aws_securityhub_standards_subscription.this), "standards/cis-aws-foundations-benchmark/v/3.0.0")
    error_message = "CIS 3.0 should be subscribed by default."
  }
  assert {
    condition     = aws_kms_key.alerts.enable_key_rotation
    error_message = "The alerts key must rotate."
  }
  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.guardduty.event_pattern).detail.severity[0].numeric[1] == 7
    error_message = "GuardDuty alerts should start at severity 7."
  }
  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.securityhub.event_pattern).detail.findings.Severity.Label == ["HIGH", "CRITICAL"]
    error_message = "Security Hub labels must match severity 7."
  }
  assert {
    condition     = length(aws_lambda_function.remediation) == 0 && output.remediation_function_name == null
    error_message = "Remediation must be opt-in."
  }
  assert {
    condition     = length(aws_sns_topic_subscription.email) == 1
    error_message = "One email subscription expected."
  }
}

run "severity_threshold_moves_both_filters" {
  command = plan
  variables {
    alert_min_severity = 4
  }
  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.securityhub.event_pattern).detail.findings.Severity.Label == ["MEDIUM", "HIGH", "CRITICAL"]
    error_message = "Severity 4 should include MEDIUM."
  }
}

run "remediation_enabled_is_least_privilege_and_dry_run" {
  command = apply # mocked: no AWS calls, but computed values become known
  variables {
    enable_iam_key_remediation = true
  }
  assert {
    condition     = aws_lambda_function.remediation[0].environment[0].variables.DRY_RUN == "true"
    error_message = "Remediation must start in dry-run mode."
  }
  assert {
    condition     = aws_lambda_function.remediation[0].reserved_concurrent_executions == 5
    error_message = "Remediation concurrency must be capped."
  }
  assert {
    condition     = length(aws_lambda_permission.remediation) == 1 && length(aws_cloudwatch_event_target.remediation) == 1
    error_message = "The finding rule must be wired to the Lambda."
  }
  assert {
    condition     = length(jsondecode(aws_cloudwatch_event_rule.remediation[0].event_pattern).detail.type) == 6
    error_message = "All IAM-user finding families should route to the Lambda."
  }
  assert {
    condition     = length(aws_lambda_function.remediation[0].dead_letter_config) == 1 && aws_cloudwatch_metric_alarm.remediation_dlq[0].threshold == 0
    error_message = "Failed remediations must land in a DLQ that alarms on the first message."
  }
  assert {
    condition     = aws_sqs_queue.remediation_dlq[0].kms_master_key_id != null
    error_message = "The DLQ holds finding details and must be encrypted."
  }
}

run "already_delegated" {
  command = plan
  variables {
    delegate_org_admin = false
  }
  assert {
    condition     = length(aws_guardduty_organization_admin_account.this) == 0 && length(aws_securityhub_organization_admin_account.this) == 0
    error_message = "No management-account resources when delegation already exists."
  }
}

run "rejects_bad_input" {
  command = plan
  variables {
    alert_min_severity = 11
    alert_emails       = ["not-an-email"]
    guardduty_features = ["MADE_UP"]
  }
  expect_failures = [var.alert_min_severity, var.alert_emails, var.guardduty_features]
}
