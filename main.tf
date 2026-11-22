data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  # GuardDuty severity is 1-10; Security Hub uses labels. Keep both filters equivalent.
  securityhub_labels = (
    var.alert_min_severity >= 9 ? ["CRITICAL"] :
    var.alert_min_severity >= 7 ? ["HIGH", "CRITICAL"] :
    var.alert_min_severity >= 4 ? ["MEDIUM", "HIGH", "CRITICAL"] :
    ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  )
  # GuardDuty finding families whose resource is an IAM user's access key.
  iam_user_finding_prefixes = [
    "UnauthorizedAccess:IAMUser/", "CredentialAccess:IAMUser/", "Exfiltration:IAMUser/",
    "Impact:IAMUser/", "Persistence:IAMUser/", "PrivilegeEscalation:IAMUser/",
  ]
}
