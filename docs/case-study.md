# Case study: from lab code to a module that passes its own security scan

## Starting point

My private AWS security labs worked, but they weren't publishable:

- they hardcoded an account ID and a personal email;
- they used GuardDuty's deprecated `datasources` block;
- each lab was a standalone root module.

The goal: one reusable module that a security team could trust, verified without an AWS account.

## The loop

```
write → terraform test (mocked) → Checkov → read each finding → fix or justify → repeat
```

Every number below comes from an actual run (21 November 2026, Terraform 1.17, AWS provider 6.73, Checkov 3.4.6).

### Round 1: what the tests caught before any scanner

| Finding | Effect if shipped | Fix |
| --- | --- | --- |
| The remediation policy interpolated a log-group ARN that is `null` when remediation is off | Every user with the default settings gets a plan error | Gave the policy document the same `count` as the resources it serves |
| The KMS key policy didn't allow CloudWatch Logs | `terraform apply` fails on the encrypted log group | Added a `logs.<region>` statement, scoped to this module's log groups |
| Provider v6 deprecated `aws_region.name` | 7 deprecation warnings on every plan | Switched to `.region` and required provider ≥ 6.0 |
| The test asserted a computed ARN during `plan` | "Unknown condition value" | Ran that case as a mocked `apply` with ARN-shaped mock values |

### Round 2: Checkov baseline (no skips)

With the default inputs Checkov reported **40 passed, 3 failed**. Those defaults leave remediation off, so the Lambda wasn't scanned at all.

**Lesson:** scan the configuration people will actually enable. I re-ran it on `examples/complete`, which turns remediation on: **68 passed, 6 failed**.

| Check | Resource | Verdict |
| --- | --- | --- |
| CKV_AWS_109, 111, 356 | KMS key policy `kms:*` on `*` for the account root | **Justified skip.** It's AWS's default key-policy statement; inside a key policy `*` means "this key" |
| CKV_AWS_117 | Lambda not in a VPC | **Justified skip.** It only calls IAM and SNS; a VPC would need NAT or endpoints and isolate nothing |
| CKV_AWS_272 | Lambda code signing | **Justified skip.** Users deploy from source; signing needs a profile they own |
| **CKV_AWS_116** | **Lambda without a dead-letter queue** | **Real gap.** EventBridge invokes the Lambda asynchronously. If it fails (throttling, IAM error), the finding that should have deactivated a leaked key would vanish silently. |

### Round 3: fix the real gap, and what fixing it uncovered

The fix for CKV_AWS_116 was:

- an SQS dead-letter queue, encrypted with the module's key and with 14-day retention;
- a CloudWatch alarm on its first message, sent to the same alert topic.

Wiring it exposed two more problems that no scanner flagged:

1. **CloudWatch alarms can't publish to a KMS-encrypted topic** unless both the key policy and the topic policy allow `cloudwatch.amazonaws.com`. Added both, scoped to this account.
2. **`tracing_config = Active` needs `xray:PutTraceSegments`**, which the least-privilege role lacked, so traces would have failed on every run. Added the two X-Ray write actions (they don't support resource-level permissions).

New test assertions lock these in. The DLQ must exist, be encrypted and alarm at threshold 0.

### Final

| Run | Passed | Failed | Skipped (with reasons) |
| --- | --- | --- | --- |
| Round 2, defaults | 40 | 3 | 0 |
| Round 2, example with remediation | 68 | 6 | 0 |
| **Round 3, example with remediation** | **72** | **0** | **5** |

The tests ended at `terraform test` 5/5 and Lambda pytest 11/11.

## What I learned

- **Scanners find what they look for; tests find what you broke.** Round 1's four problems would all have failed a real deployment, and Checkov saw none of them.
- **The default configuration hides code from scanners.** Count-conditional resources need to be scanned with the options turned on.
- **One real finding is worth the noise.** Of 6 failures, 5 were reasonable to skip, but the remaining one was a silent-failure path in a security control. Fixing it surfaced two more permission bugs.
- **Write the reason next to every skip.** A skip without a reason is technical debt; a skip with one is documentation.

## Reproduce

```
terraform init -backend=false && terraform test
pip install pytest checkov
pytest tests
checkov -d examples/complete --framework terraform --compact
```
