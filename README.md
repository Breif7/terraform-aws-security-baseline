# terraform-aws-security-baseline

[![CI](https://github.com/Breif7/terraform-aws-security-baseline/actions/workflows/ci.yml/badge.svg)](https://github.com/Breif7/terraform-aws-security-baseline/actions/workflows/ci.yml)
![Terraform](https://img.shields.io/badge/terraform-%E2%89%A51.7-7B42BC) ![AWS provider](https://img.shields.io/badge/aws%20provider-%E2%89%A56.0-FF9900) ![Checkov](https://img.shields.io/badge/checkov-0%20failed-brightgreen) ![License](https://img.shields.io/badge/license-MIT-green)

**Organization-wide threat detection for AWS in one module.** It sets up GuardDuty and Security Hub for every account in your AWS Organization, sends you only the findings that matter, and can optionally deactivate leaked IAM keys on its own.

```
             management account                       security account (this module)
          ┌────────────────────────┐   delegates   ┌──────────────────────────────────────────┐
          │ aws.management provider├──────────────►│ GuardDuty detector + 6 protection plans  │
          └────────────────────────┘    admin      │ Security Hub + standards + aggregator    │
                                                   │        │ findings                        │
  every member account ── auto-enabled ──────────► │        ▼                                 │
  (current and future)                             │ EventBridge (severity ≥ 7) ─► SNS (KMS)  │──► email / Chatbot
                                                   │        │ IAM-user findings               │
                                                   │        ▼                       ▲ failures│
                                                   │ Lambda: deactivate key ──► DLQ ─► alarm  │
                                                   └──────────────────────────────────────────┘
```

## What you get

| Area | Details |
| --- | --- |
| **GuardDuty** | Detector with S3, EKS audit, EBS malware, RDS login, Lambda network and Runtime Monitoring. The same plans are auto-enabled for all current and future members (`auto_enable_organization_members = "ALL"`). |
| **Security Hub** | Delegated admin, auto-enable for members, a cross-region finding aggregator, and AWS Foundational Best Practices + CIS v3.0 (configurable). Default standards are off so the explicit subscriptions don't collide. |
| **Alerts** | One KMS-encrypted SNS topic (key rotation on). GuardDuty findings are filtered by numeric severity and Security Hub findings by the matching labels. GuardDuty findings are de-duplicated out of the Security Hub rule, so each alert arrives once. |
| **Remediation** (opt-in) | A Lambda deactivates the access key behind GuardDuty `*:IAMUser/*` findings. It only acts on long-lived keys of IAM users in this account; everything else is reported for manual action. It starts in **dry-run** mode. Failed runs go to an encrypted DLQ with an alarm. |

## Usage

```hcl
provider "aws" {                       # security (delegated admin) account
  region = "us-east-1"
}

provider "aws" {                       # management account, only to delegate admin
  alias  = "management"
  region = "us-east-1"
  assume_role { role_arn = "arn:aws:iam::<management-account-id>:role/OrganizationAdmin" }
}

module "security_baseline" {
  source  = "github.com/Breif7/terraform-aws-security-baseline?ref=v0.1.0"
  providers = { aws = aws, aws.management = aws.management }

  alert_emails               = ["secops@example.com"]
  alert_min_severity         = 7       # GuardDuty 1-10; Security Hub gets HIGH + CRITICAL
  enable_iam_key_remediation = true
  remediation_dry_run        = true    # watch the "WOULD DEACTIVATE" emails first, then set false
}
```

If admin is already delegated, set `delegate_org_admin = false`; the management provider then creates nothing. A full example is in [`examples/complete`](examples/complete).

### Inputs

| Name | Default | Description |
| --- | --- | --- |
| `name_prefix` | `security-baseline` | Prefix for every resource name |
| `delegate_org_admin` | `true` | Delegate GuardDuty and Security Hub admin from the management account |
| `guardduty_features` | all 6 | Protection plans to enable and auto-enable |
| `securityhub_standards` | FSBP 1.0, CIS 3.0 | Standard ARN suffixes |
| `securityhub_auto_enable_standards` | `DEFAULT` | `DEFAULT` or `NONE` for new members |
| `alert_emails` | `[]` | Email subscribers; each must confirm |
| `alert_min_severity` | `7` | 1–10 |
| `enable_iam_key_remediation` | `false` | Deploy the remediation Lambda |
| `remediation_dry_run` | `true` | Report only |
| `log_retention_days` | `365` | Lambda logs |
| `tags` | `{}` | Added to all taggable resources |

Outputs: `guardduty_detector_id`, `alerts_topic_arn`, `alerts_kms_key_arn`, `securityhub_standards`, `remediation_function_name`.

## Verification

| Check | Result |
| --- | --- |
| `terraform test` (mocked providers, no AWS account needed) | 5 runs pass: defaults, severity mapping, remediation wiring and dry-run, existing delegation, input validation |
| Lambda unit tests (`pytest tests`) | 11 pass: every skip rule, live vs dry run, malformed events |
| Checkov | 72 passed, **0 failed**, 5 skipped. Each skip has a written reason next to it |
| `terraform validate` on `examples/complete` | valid |

How the Checkov result got to zero, including the two real gaps it found (no dead-letter queue, missing X-Ray permissions), is in [docs/case-study.md](docs/case-study.md).

## Limits

- **Cost:** GuardDuty, Security Hub and Runtime Monitoring are billed per account and per volume. Check the 30-day trials before you roll this out to a large organization.
- **Region:** it covers one region. Deploy once per region you use. Security Hub's aggregator already collects findings from all regions into this one.
- **Member-account keys:** remediation can't deactivate keys in member accounts; it emails them for manual action. That would need a cross-account role.
- **Untested against a live AWS account:** the tests run against mocked providers. Plan against a sandbox organization before you apply.

## Development

```
terraform fmt -recursive -check
terraform init -backend=false && terraform test
pip install pytest && pytest tests
```

Built from the hands-on AWS security labs I keep privately: org-wide GuardDuty and Security Hub, and automated remediation. Rewritten as a reusable module.

MIT © Breif7
