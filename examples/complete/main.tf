# Apply with credentials for the security account; the management provider assumes a role there.
provider "aws" {
  region = "us-east-1"
}

provider "aws" {
  alias  = "management"
  region = "us-east-1"
  assume_role {
    role_arn = var.management_role_arn
  }
}

variable "management_role_arn" {
  description = "Role in the organization's management account allowed to delegate GuardDuty/Security Hub admin."
  type        = string
}

module "security_baseline" {
  source = "../.."

  providers = {
    aws            = aws
    aws.management = aws.management
  }

  name_prefix                = "acme-security"
  alert_emails               = ["secops@example.com"]
  alert_min_severity         = 7
  enable_iam_key_remediation = true
  remediation_dry_run        = true

  tags = {
    Owner = "security"
  }
}

output "alerts_topic_arn" {
  value = module.security_baseline.alerts_topic_arn
}
