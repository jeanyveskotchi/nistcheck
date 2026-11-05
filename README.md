# nistcheck

[![CI](https://github.com/jeanyveskotchi/nistcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/jeanyveskotchi/nistcheck/actions/workflows/ci.yml)

A small, dependency-free policy-as-code checker that scans a **Terraform plan** for misconfigurations and maps each finding to a **NIST SP 800-53** control. It exits non-zero on any HIGH finding, so it can block a risky `terraform apply` in CI.

It reads the plan's `planned_values`, which means it checks what the infrastructure *will look like after apply*, including resources inside child modules, not just the raw `.tf` source.

## What it checks

| Control | What it means | Resources checked | Severity |
|---|---|---|---|
| **SC-7** Boundary Protection | SSH (22) / RDP (3389) or all traffic open to `0.0.0.0/0` or `::/0` | `aws_security_group`, `oci_core_security_list` | HIGH |
| **SC-7** Boundary Protection | Database reachable from the internet | `aws_db_instance` | HIGH |
| **AC-3** Access Enforcement | Bucket readable or writable by the public | `aws_s3_bucket`, `oci_objectstorage_bucket` | HIGH |
| **SC-28** Protection of Information at Rest | Storage not encrypted | `aws_ebs_volume`, `aws_db_instance` | HIGH |
| **AC-6** Least Privilege | IAM policy allows `Action: "*"` on `Resource: "*"` | `aws_iam_policy`, `aws_iam_role_policy` | HIGH |
| **AU-2** Event Logging | CloudTrail logging switched off | `aws_cloudtrail` | MEDIUM |

Covers both **AWS** and **Oracle Cloud (OCI)** resources.

## Usage

Requires Python 3.8+. No third-party packages.

```bash
terraform plan -out plan.out
terraform show -json plan.out > plan.json
python nistcheck.py plan.json          # human-readable
python nistcheck.py plan.json --json   # machine-readable
```

Try it on the bundled sample plan:

```bash
python nistcheck.py examples/insecure_plan.json
```

```
[HIGH] SC-7 aws_security_group.web: Admin port (SSH/RDP) open to the whole internet
[HIGH] AC-3 aws_s3_bucket.logs: Bucket ACL allows public access
[HIGH] SC-28 aws_db_instance.app: Database storage is not encrypted at rest
[HIGH] SC-7 aws_db_instance.app: Database is publicly accessible
[HIGH] AC-6 aws_iam_policy.admin: Policy allows every action on every resource (least privilege)
[MEDIUM] AU-2 aws_cloudtrail.main: CloudTrail logging is switched off
[HIGH] AC-3 module.storage.oci_objectstorage_bucket.public: Object Storage bucket allows public access
7 finding(s)
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No HIGH findings |
| `1` | At least one HIGH finding (fails the pipeline) |
| `2` | No plan file given |

## Using it as a CI gate

```yaml
- run: terraform plan -out plan.out && terraform show -json plan.out > plan.json
- run: python nistcheck.py plan.json
```

This repo's own workflow (`.github/workflows/ci.yml`) runs the unit tests on several Python versions and checks that the clean sample plan passes and the insecure one fails.

## Running the tests

```bash
pip install pytest
pytest -v
```

## Project layout

```
nistcheck.py                  # the checker (single file, stdlib only)
tests/test_nistcheck.py       # unit tests, one per rule
examples/insecure_plan.json   # plan that should fail
examples/secure_plan.json     # plan that should pass
.github/workflows/ci.yml      # tests + self-check on every push
```

## Limitations

- Checks a fixed set of rules; it is not a full compliance audit and does not replace tools like Checkov or tfsec.
- Mapping a misconfiguration to one control is a simplification; real assessments look at control families and implementation evidence.
- Only inspects resource attributes in the plan. Settings managed outside Terraform, or split into separate resources (e.g. `aws_s3_bucket_public_access_block`), are not cross-referenced yet.

## Ideas for next steps

- Cross-check S3 buckets against `aws_s3_bucket_public_access_block` and `aws_s3_bucket_server_side_encryption_configuration`
- Add Azure and GCP equivalents
- SARIF output so findings show up in GitHub code scanning
- Per-rule allowlist for accepted risks

## License

MIT, see [LICENSE](LICENSE).
