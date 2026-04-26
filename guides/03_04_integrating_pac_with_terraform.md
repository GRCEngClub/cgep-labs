# Lab 3.4: Integrating PaC with Terraform via Conftest (AWS)

You wrote three Rego policies in Lab 3.3 against GCP fixtures. This lab does two things. It runs those policies against an AWS Terraform plan via Conftest. And, more interestingly, it forces you to add AWS variants to your library because the original GCP-typed rules don't match AWS resource types. The library survives the cloud change because the control IDs do.

## Learning objectives

- Wire Conftest into the Terraform plan workflow as a fail-closed gate.
- Add AWS-resource-type variants of the SC-28 and AC-3 policies, preserving control IDs.
- Demonstrate a blocked merge by feeding a deliberately broken plan to the gate.

## Prerequisites

- Lab 2.3 (AWS S3 compliant primitive) workspace on disk. We use its plan as the input.
- Lab 3.3 policy library (`policies/`) carried into this lab. Three rules, three controls.
- Conftest installed (`conftest --version`). Tested with `0.50` and newer.

## Estimated time & cost

- 45 minutes.
- Free. No additional AWS resources beyond Lab 2.3.

## Architecture

```
  Lab 2.3 workspace          policy-gate.sh (this lab)         CI (Lab 4.3)
  ─────────────────          ────────────────────────         ──────────────
  terraform plan -out=tfplan ─▶  terraform show -json    ─▶   on every PR:
                                  conftest test               run policy-gate.sh,
                                  (per namespace)             fail closed on any
                                                              violation
```

## Step-by-step walkthrough

### Step 1 Carry the Lab 3.3 library forward, run its tests

```bash
cp -r ../lab-3-3/policies ./policies
opa test -v policies/    # 8/8 PASS
```

Sanity check the library still works in this workspace before extending it.

### Step 2 Generate plan.json from Lab 2.3

```bash
cd ../lab-2-3
eval "$(aws configure export-credentials --profile <your-sandbox> --format env)"
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
```

Copy `plan.json` into the Conftest workspace, or point Conftest at it directly.

### Step 3 The cross-cloud lesson

Run the GCP policies against the AWS plan:

```bash
conftest test --policy policies --namespace compliance.sc28 plan.json
conftest test --policy policies --namespace compliance.ac3  plan.json
conftest test --policy policies --namespace compliance.cm6  plan.json
```

The first two pass with zero coverage. They check `google_storage_bucket` and `google_compute_firewall`. There are no GCP resources in this plan. The CM-6 rule fires (or doesn't) depending on whether your AWS resources carry the four required tags.

The lesson: a control ID is portable, but a Rego rule that hardcodes `resource.type == "google_storage_bucket"` is not. Either you generalize the rule or you add per-cloud variants. Adding variants keeps each rule readable; generalizing makes one rule that handles every type. We add variants here.

### Step 4 Add the AWS variant of SC-28

```rego
# policies/sc28_encryption_aws.rego
# METADATA
# title: SC-28 - Encryption at Rest (AWS S3)
# description: "Every aws_s3_bucket must have an aws_s3_bucket_server_side_encryption_configuration that references it."
# custom:
#   control_id: SC-28
#   framework: nist-800-53
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration { bucket = aws_s3_bucket.<name>.id ... } for the bucket."
package compliance.sc28_aws

import rego.v1

deny contains msg if {
	bucket := bucket_addresses[_]
	not has_encryption(bucket)
	msg := sprintf(
		"[SC-28] %s: aws_s3_bucket has no matching aws_s3_bucket_server_side_encryption_configuration. Remediation: add one referencing this bucket.",
		[bucket],
	)
}

bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_encryption(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])
```

> **Why match by reference, not by value.** At plan time, the bucket name is "(known after apply)" because the random_id suffix isn't generated yet. Both `aws_s3_bucket.values.bucket` and the encryption resource's `values.bucket` are `null` in the JSON. Use `configuration.root_module.resources[].expressions.bucket.references` instead. Each reference is a string like `"aws_s3_bucket.primary.id"` that Terraform resolves at apply.

### Step 5 Add the AWS variant of AC-3

The AWS variant is more discriminating than the GCP one: it requires a public-access-block resource AND that all four flags are set true.

```rego
# policies/ac3_no_public_aws.rego
# METADATA
# title: AC-3 - Access Enforcement (AWS S3 public access block)
# description: "Every aws_s3_bucket must have an aws_s3_bucket_public_access_block referencing it, with all four flags true."
# custom:
#   control_id: AC-3
#   framework: nist-800-53
#   severity: critical
package compliance.ac3_aws

import rego.v1

deny contains msg if {
	bucket := bucket_addresses[_]
	not has_complete_pab(bucket)
	msg := sprintf(
		"[AC-3] %s: missing or incomplete aws_s3_bucket_public_access_block. All four flags must be true.",
		[bucket],
	)
}

bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_complete_pab(bucket_addr) if {
	pab := pab_for(bucket_addr)
	planned := pab_planned_values(pab.address)
	planned.block_public_acls == true
	planned.block_public_policy == true
	planned.ignore_public_acls == true
	planned.restrict_public_buckets == true
}

pab_for(bucket_addr) := pab if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_public_access_block"
	some ref in r.expressions.bucket.references
	pab_references_bucket(ref, bucket_addr)
	pab := {"address": sprintf("aws_s3_bucket_public_access_block.%s", [r.name])}
}

pab_references_bucket(ref, bucket_addr) if ref == bucket_addr
pab_references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])

pab_planned_values(addr) := values if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	values := r.values
}
```

### Step 6 Add the AWS variant of CM-6

The GCP rule used `labels`. AWS uses `tags`. With provider `default_tags` enabled, the merged tag set lives in `tags_all`.

```rego
# policies/cm6_required_tags_aws.rego
# METADATA
# title: CM-6 - Configuration Settings (AWS required tags)
# custom:
#   control_id: CM-6
#   framework: nist-800-53
#   severity: medium
package compliance.cm6_aws

import rego.v1

required := {"Project", "Environment", "ManagedBy", "ComplianceScope"}

labelable_type(t) if t == "aws_s3_bucket"
labelable_type(t) if t == "aws_dynamodb_table"
labelable_type(t) if t == "aws_lambda_function"
labelable_type(t) if t == "aws_kms_key"
labelable_type(t) if t == "aws_cloudtrail"

deny contains msg if {
	resource := all_resources[_]
	labelable_type(resource.type)
	provided := tag_keys(resource)
	missing := required - provided
	count(missing) > 0
	msg := sprintf(
		"[CM-6] %s: missing required tags %v. Remediation: add the missing tags or use provider default_tags.",
		[resource.address, sort_array(missing)],
	)
}

all_resources contains r if { some r in input.planned_values.root_module.resources }
all_resources contains r if {
	some child in input.planned_values.root_module.child_modules
	some r in child.resources
}

tag_keys(resource) := keys if {
	resource.values.tags_all
	keys := {k | resource.values.tags_all[k]}
}

tag_keys(resource) := keys if {
	not resource.values.tags_all
	resource.values.tags
	keys := {k | resource.values.tags[k]}
}

tag_keys(resource) := set() if {
	not resource.values.tags_all
	not resource.values.tags
}

sort_array(s) := sorted if { sorted := sort([x | some x in s]) }
```

### Step 7 Run the gate against the compliant plan

```bash
for ns in compliance.sc28_aws compliance.ac3_aws compliance.cm6_aws ; do
  echo "=== $ns ==="
  conftest test --policy policies --namespace $ns plan.json
done
```

Expected:

```
=== compliance.sc28_aws ===
1 test, 1 passed, 0 warnings, 0 failures, 0 exceptions
=== compliance.ac3_aws ===
1 test, 1 passed, 0 warnings, 0 failures, 0 exceptions
=== compliance.cm6_aws ===
1 test, 1 passed, 0 warnings, 0 failures, 0 exceptions
```

Lab 2.3's plan now has full AWS coverage from your policy library.

### Step 8 Break it and watch the gate fire

Copy the Lab 2.3 workspace, remove the primary bucket's encryption configuration block, regenerate the plan, run Conftest:

```bash
mkdir broken && cp ../lab-2-3/*.tf broken/
# Edit broken/main.tf: delete the aws_s3_bucket_server_side_encryption_configuration.primary resource
( cd broken && terraform init && terraform plan -out=tfplan && terraform show -json tfplan > plan.json )

conftest test --policy policies --namespace compliance.sc28_aws broken/plan.json
```

Output:

```
FAIL - broken/plan.json - compliance.sc28_aws - [SC-28] aws_s3_bucket.primary: aws_s3_bucket has no matching aws_s3_bucket_server_side_encryption_configuration. Remediation: add one referencing this bucket.

1 test, 0 passed, 0 warnings, 1 failure, 0 exceptions
```

The exit code is non-zero. The deny message names the resource, the control, and the fix. A developer reading the failed PR knows exactly what to do.

### Step 9 The wrapper script

The CI workflow in Lab 4.3 calls a single script. Build it now.

```bash
#!/usr/bin/env bash
# scripts/policy-gate.sh
set -euo pipefail

POLICY_DIR="policies"
WORKSPACE=""
EVIDENCE_DIR="evidence/lab-3-4"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" ]] && { echo "Usage: $0 --workspace <path>" >&2; exit 2; }
mkdir -p "$EVIDENCE_DIR"

( cd "$WORKSPACE" && terraform show -json tfplan > "$WORKSPACE/plan.json" )

EXIT=0
{
  echo "["
  FIRST=1
  for ns in compliance.sc28_aws compliance.ac3_aws compliance.cm6_aws compliance.cm6 ; do
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    OUT=$(conftest test --policy "$POLICY_DIR" --namespace "$ns" --output=json "$WORKSPACE/plan.json" || true)
    if echo "$OUT" | python3 -c 'import sys,json; d=json.load(sys.stdin); sys.exit(0 if all(len(r.get("failures") or [])==0 for r in d) else 1)'; then : ; else EXIT=1 ; fi
    echo "$OUT"
  done
  echo "]"
} > "$EVIDENCE_DIR/conftest-results.json"

if [[ $EXIT -eq 0 ]]; then echo "policy-gate: PASS"
else echo "policy-gate: FAIL"; echo "See $EVIDENCE_DIR/conftest-results.json"
fi
exit $EXIT
```

Key choices:

- `|| true` on each conftest call so a failure in one namespace doesn't abort the script before the others run.
- `--output=json` so CI gets a machine-readable artifact.
- A python3 one-liner for the pass/fail decision because portable JSON parsing in pure bash is masochism.

## Verification

- Compliant plan: exit 0, zero failures across all four namespaces.
- Broken plan: exit 1, at least one failure citing SC-28 with full metadata in the deny message.
- `evidence/lab-3-4/conftest-results.json` exists in both runs.

## Portfolio submission checklist

- [ ] `policies/` has both GCP and AWS variants for SC-28, AC-3, CM-6. Six files, three control IDs.
- [ ] `scripts/policy-gate.sh` committed and executable.
- [ ] `evidence/lab-3-4/conftest-pass.json` and `evidence/lab-3-4/conftest-fail.json` captured.
- [ ] `policies/README.md` notes which file targets which cloud.

## Troubleshooting

- **`policies: no such file or directory`**. Conftest's `--policy` is a directory path, and it's resolved relative to your current shell. Always pass the absolute or canonically-relative path.
- **`no policies matched`**. Your package declaration doesn't match the namespace you passed with `--namespace`. The package in the file must be the same string.
- **A passing fixture fires anyway**. Plan JSON puts module-wrapped resources under `child_modules[]`. Recurse the same way the GCP rules do, or your library has gaps.
- **Bucket name comparisons return undefined.** At plan time AWS resource IDs are unknown. Match by reference in `configuration.root_module.resources[].expressions.<arg>.references`, not by literal value in `planned_values`.

## Cleanup

The Conftest gate is local. Nothing in the cloud to destroy beyond Lab 2.3.

## How this feeds the capstone

`scripts/policy-gate.sh` is the exact script CI calls in Lab 4.3. The capstone's GitHub Actions workflow shells out to this script with `--workspace ./terraform`, the plan is checked, the workflow goes green or red. Make this bulletproof here so you don't fight it later.
