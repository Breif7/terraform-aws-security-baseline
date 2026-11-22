variable "name_prefix" {
  description = "Prefix for every resource name."
  type        = string
  default     = "security-baseline"

  validation {
    condition     = can(regex("^[a-z0-9-]{1,32}$", var.name_prefix))
    error_message = "name_prefix must be 1-32 lowercase letters, digits or hyphens."
  }
}

variable "delegate_org_admin" {
  description = "Delegate GuardDuty and Security Hub administration to this account using the aws.management provider. Set false if it is already delegated."
  type        = bool
  default     = true
}

variable "guardduty_features" {
  description = "GuardDuty protection plans enabled here and auto-enabled for every organization member."
  type        = list(string)
  default     = ["S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "EBS_MALWARE_PROTECTION", "RDS_LOGIN_EVENTS", "LAMBDA_NETWORK_LOGS", "RUNTIME_MONITORING"]

  validation {
    condition = alltrue([for f in var.guardduty_features : contains(
      ["S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "EBS_MALWARE_PROTECTION", "RDS_LOGIN_EVENTS", "LAMBDA_NETWORK_LOGS", "RUNTIME_MONITORING"], f
    )])
    error_message = "Unknown GuardDuty feature name."
  }
}

variable "securityhub_standards" {
  description = "Security Hub standards to subscribe to, as the part of the ARN after '::' (region is added)."
  type        = list(string)
  default = [
    "standards/aws-foundational-security-best-practices/v/1.0.0",
    "standards/cis-aws-foundations-benchmark/v/3.0.0",
  ]
}

variable "securityhub_auto_enable_standards" {
  description = "Default standards for new member accounts: DEFAULT or NONE."
  type        = string
  default     = "DEFAULT"

  validation {
    condition     = contains(["DEFAULT", "NONE"], var.securityhub_auto_enable_standards)
    error_message = "Must be DEFAULT or NONE."
  }
}

variable "alert_emails" {
  description = "Addresses subscribed to the alert topic. Each one must confirm the subscription email."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for e in var.alert_emails : can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", e))])
    error_message = "Every alert_emails entry must be an email address."
  }
}

variable "alert_min_severity" {
  description = "Minimum GuardDuty severity (1-10) that triggers an alert. 7 = High and Critical only. Security Hub uses the matching labels."
  type        = number
  default     = 7

  validation {
    condition     = var.alert_min_severity >= 1 && var.alert_min_severity <= 10
    error_message = "alert_min_severity must be between 1 and 10."
  }
}

variable "enable_iam_key_remediation" {
  description = "Deploy the Lambda that deactivates IAM access keys GuardDuty reports as compromised (only for users in this account)."
  type        = bool
  default     = false
}

variable "remediation_dry_run" {
  description = "When true the remediation Lambda only reports what it would do. Flip to false after watching it for a while."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention for the remediation Lambda."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags added to every taggable resource."
  type        = map(string)
  default     = {}
}
