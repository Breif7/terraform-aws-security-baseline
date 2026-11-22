# Detector in the security account, with feature-based protection plans
# (the older `datasources` block is deprecated in the AWS provider).
resource "aws_guardduty_detector" "this" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = var.tags
}

resource "aws_guardduty_detector_feature" "this" {
  for_each    = toset(var.guardduty_features)
  detector_id = aws_guardduty_detector.this.id
  name        = each.value
  status      = "ENABLED"
}

# Run from the management account: make the security account the delegated administrator.
resource "aws_guardduty_organization_admin_account" "this" {
  count            = var.delegate_org_admin ? 1 : 0
  provider         = aws.management
  admin_account_id = data.aws_caller_identity.current.account_id
  depends_on       = [aws_guardduty_detector.this]
}

# Run from the security account: every current and future member gets GuardDuty.
resource "aws_guardduty_organization_configuration" "this" {
  detector_id                      = aws_guardduty_detector.this.id
  auto_enable_organization_members = "ALL"
  depends_on                       = [aws_guardduty_organization_admin_account.this]
}

resource "aws_guardduty_organization_configuration_feature" "this" {
  for_each    = toset(var.guardduty_features)
  detector_id = aws_guardduty_detector.this.id
  name        = each.value
  auto_enable = "ALL"
  depends_on  = [aws_guardduty_organization_configuration.this]
}
