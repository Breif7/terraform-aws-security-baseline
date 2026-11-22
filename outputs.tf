output "guardduty_detector_id" {
  description = "GuardDuty detector in the security account."
  value       = aws_guardduty_detector.this.id
}

output "alerts_topic_arn" {
  description = "SNS topic that receives filtered findings. Subscribe Slack/Chatbot/PagerDuty here."
  value       = aws_sns_topic.alerts.arn
}

output "alerts_kms_key_arn" {
  description = "KMS key encrypting the alert topic and the remediation logs."
  value       = aws_kms_key.alerts.arn
}

output "securityhub_standards" {
  description = "Subscribed Security Hub standard ARNs."
  value       = sort([for s in aws_securityhub_standards_subscription.this : s.standards_arn])
}

output "remediation_function_name" {
  description = "IAM key remediation Lambda, or null when disabled."
  value       = one(aws_lambda_function.remediation[*].function_name)
}
