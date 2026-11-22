# Default standards are off so the explicit subscriptions below don't collide with them.
resource "aws_securityhub_account" "this" {
  enable_default_standards  = false
  auto_enable_controls      = true
  control_finding_generator = "SECURITY_CONTROL"
}

resource "aws_securityhub_organization_admin_account" "this" {
  count            = var.delegate_org_admin ? 1 : 0
  provider         = aws.management
  admin_account_id = data.aws_caller_identity.current.account_id
  depends_on       = [aws_securityhub_account.this]
}

resource "aws_securityhub_organization_configuration" "this" {
  auto_enable           = true
  auto_enable_standards = var.securityhub_auto_enable_standards
  depends_on            = [aws_securityhub_organization_admin_account.this]
}

# One place to read findings from every region.
resource "aws_securityhub_finding_aggregator" "this" {
  linking_mode = "ALL_REGIONS"
  depends_on   = [aws_securityhub_account.this]
}

resource "aws_securityhub_standards_subscription" "this" {
  for_each      = toset(var.securityhub_standards)
  standards_arn = "arn:${data.aws_partition.current.partition}:securityhub:${data.aws_region.current.region}::${each.value}"
  depends_on    = [aws_securityhub_account.this]
}
