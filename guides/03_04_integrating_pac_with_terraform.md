# Lab 3.4: Integrating Policy as Code with Terraform via Conftest (AWS)

In Lab 3.3 you wrote three Rego policies against GCP fixtures. This lab runs that library against an *AWS* plan, and in doing so teaches the most important lesson in the chapter: a control ID travels across clouds, but a Rego rule that hardcodes a GCP resource type does not. You'll watch the GCP rules pass with zero coverage on AWS infrastructure, then write AWS variants that keep the same control IDs. By the end you'll have a single script, `policy-gate.sh`, that your CI pipeline calls to block any pull request that violates a control.

For the GRC folks, this is the moment "the policy" becomes cloud-portable: SC-28 means the same thing on AWS and GCP even though the implementation differs. For the technical folks, this is wiring a policy engine into the plan workflow as a fail-closed gate, the thing that turns a manual review into an automatic one.

## Before you begin

If this is your first lab, set up [your tools](../getting-started/tools.md) and [your repo](../getting-started/repo-structure.md) first.

New tool for this lab:

- **Conftest**, a utility built on OPA that runs Rego policies against structured config (like a Terraform plan) and returns a pass/fail exit code, which is exactly what a CI gate needs. Official install: https://www.conftest.dev/install/ (releases at https://github.com/open-policy-agent/conftest/releases).
  - macOS: `brew install conftest`
  - Linux/Windows: download the archive from the releases page, extract `conftest`, put it on your PATH.
  - Confirm with `conftest --version` (tested with 0.50 and newer).

You also need your `policies/` library from Lab 3.3 already in the repo (it is, since the wiki keeps one `policies/` directory at the root), and your Lab 2.3 AWS S3 code committed under `terraform/primitives/compliant-s3/`.

> Because the repo has a single `policies/` directory, the original lab's "copy the policy folder from the previous lab" step disappears. Your 3.3 library is already where this lab needs it.

## Time and cost

- Time: about 45 minutes.
- Cost: free. You only generate plans; nothing is applied.

## Architecture

```
  Lab 2.3 code                  policy-gate.sh (this lab)        CI (Lab 4.3)
  ────────────                  ────────────────────────        ────────────
  terraform plan -out=tfplan ─▶ terraform show -json     ─▶     on every PR:
                                conftest test                   run policy-gate.sh,
                                (per control namespace)         fail closed on any
                                                                violation
```

## Where these files live

```
cgep-labs/
├── policies/
│   ├── sc28_encryption_aws.rego      ← new in this lab
│   ├── ac3_no_public_aws.rego        ← new in this lab
│   ├── cm6_required_tags_aws.rego    ← new in this lab
│   └── README.md                     ← update for AWS variants
├── scripts/
│   └── policy-gate.sh                ← new in this lab
└── evidence/lab-3-4/
    ├── conftest-pass.json            ← filled in when you run the gate
    └── conftest-fail.json            ← filled in when you run the gate
```

### Scaffold this lab's empty files

Run this once from the repo root (`cgep-labs`). It creates every path in the diagram above as an empty file so the later steps are "open and paste," not "guess where this goes."

```bash
# from the repo root
mkdir -p policies scripts evidence/lab-3-4

touch \
  policies/sc28_encryption_aws.rego \
  policies/ac3_no_public_aws.rego \
  policies/cm6_required_tags_aws.rego \
  scripts/policy-gate.sh

# README may already exist from Lab 3.3; create it only if missing
touch policies/README.md
chmod +x scripts/policy-gate.sh

find policies/*_aws.rego scripts/policy-gate.sh evidence/lab-3-4 | sort
```

## Step-by-step walkthrough

### Step 1: Confirm the 3.3 library still passes

Before extending the library, make sure it's healthy:

```bash
# from the repo root
opa test -v policies/    # expect 8/8 PASS
```

### Step 2: Generate a plan from your Lab 2.3 code

You don't need the Lab 2.3 bucket to be live. `terraform plan` computes what *would* be created, so a plan works even with nothing deployed. It does need AWS credentials to check current state, but it applies nothing and costs nothing.

> Commands below use `--profile default`. If you named your AWS CLI profile something else in Lab 2.3, replace `default` with that name.

```bash
# from the repo root
cd terraform/primitives/compliant-s3
eval "$(aws configure export-credentials --profile default --format env)"  # if you use SSO
terraform init
# Pass the same vars Lab 2.3 used so plan doesn't prompt (CI can't type answers):
terraform plan -out=tfplan -var="project_name=cgep-lab" -var="environment=dev"
terraform show -json tfplan > plan.json
cd ../../..
```

### Step 3: The cross-cloud lesson

Run your GCP policies against the AWS plan and watch what happens:

```bash
conftest test --policy policies --namespace compliance.sc28 terraform/primitives/compliant-s3/plan.json
conftest test --policy policies --namespace compliance.ac3  terraform/primitives/compliant-s3/plan.json
conftest test --policy policies --namespace compliance.cm6  terraform/primitives/compliant-s3/plan.json
```

The SC-28 and AC-3 rules pass, but they pass with *zero coverage*. They look for `google_storage_bucket` and `google_compute_firewall`, and there are none in an AWS plan, so they have nothing to check and nothing to complain about. That's a dangerous kind of "pass": green, but meaningless.

This is the lesson. The control ID `SC-28` is portable; the rule `resource.type == "google_storage_bucket"` is not. You have two choices: generalize each rule to handle every cloud's types, or write per-cloud variants. Variants keep each rule short and readable, so that's what you'll do, and you'll keep the same control IDs so the library stays organized by control rather than by cloud.

### Step 4: AWS variant of SC-28

Open **`policies/sc28_encryption_aws.rego`** from the scaffold and paste:

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

> **Why this matches by reference instead of by value.** On AWS, encryption is a separate resource that points at the bucket, not a block inside it. And at plan time the bucket name is "known after apply" (the `random_id` suffix hasn't been generated), so the value-level fields are `null` in the JSON. The rule instead reads `configuration.root_module.resources[].expressions.bucket.references`, which holds strings like `"aws_s3_bucket.primary.id"` that Terraform resolves at apply. The policy asks "is an encryption resource wired to this bucket?" rather than "do the names match?", which is the only question answerable at plan time.

### Step 5: AWS variant of AC-3

This one is stricter than the GCP version: it requires the public-access-block resource to exist *and* all four of its flags to be `true`. Open **`policies/ac3_no_public_aws.rego`** and paste:

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

Notice this rule reads from *both* halves of the plan JSON. It uses `configuration` to find which public-access-block points at which bucket (the wiring, known at plan time), and `planned_values` to read the four flag values (which are real booleans you set literally, not "known after apply"). Knowing which half holds which kind of fact is most of the skill in writing Terraform-plan policies.

### Step 6: AWS variant of CM-6

GCP used `labels`; AWS uses `tags`. With provider `default_tags` turned on (as in your Lab 2.3 code), the merged set lands in `tags_all`. Open **`policies/cm6_required_tags_aws.rego`** and paste:

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

The three `tag_keys` definitions handle three states: tags merged by `default_tags` (`tags_all`), only locally-set tags (`tags`), or none at all. Rego picks whichever definition matches, which is how you write "fall back gracefully" without an if-else ladder.

### Step 7: Run the gate against the compliant plan

```bash
for ns in compliance.sc28_aws compliance.ac3_aws compliance.cm6_aws ; do
  echo "=== $ns ==="
  conftest test --policy policies --namespace $ns terraform/primitives/compliant-s3/plan.json
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

Now your Lab 2.3 plan has real AWS coverage. These passes mean something, unlike the empty GCP passes in Step 3.

### Step 8: Break it and watch the gate fire

Copy your Lab 2.3 code to a throwaway folder, remove the encryption resource, regenerate the plan, and run the gate. (Don't commit this folder; it exists only to prove the gate works.)

```bash
# from the repo root
mkdir -p /tmp/broken && cp terraform/primitives/compliant-s3/*.tf /tmp/broken/
# Edit /tmp/broken/main.tf: delete the aws_s3_bucket_server_side_encryption_configuration.primary resource
( cd /tmp/broken && terraform init \
    && terraform plan -out=tfplan -var="project_name=cgep-lab" -var="environment=dev" \
    && terraform show -json tfplan > plan.json )

conftest test --policy policies --namespace compliance.sc28_aws /tmp/broken/plan.json
```

Output:

```
FAIL - /tmp/broken/plan.json - compliance.sc28_aws - [SC-28] aws_s3_bucket.primary: aws_s3_bucket has no matching aws_s3_bucket_server_side_encryption_configuration. Remediation: add one referencing this bucket.

1 test, 0 passed, 0 warnings, 1 failure, 0 exceptions
```

The exit code is non-zero, which is what makes this a *gate*: in CI, a non-zero exit fails the build and blocks the merge. The message names the resource, the control, and the fix, so the developer who broke it can fix it without anyone explaining what SC-28 means.

### Step 9: The wrapper script

Your CI workflow in Lab 4.3 calls one script. Build it now so CI has something stable to call. Open **`scripts/policy-gate.sh`** from the scaffold and paste:

```bash
#!/usr/bin/env bash
# scripts/policy-gate.sh
# Usage: policy-gate.sh --workspace <path> [--policy <dir>]
# Requires a saved tfplan inside the workspace (from terraform plan -out=tfplan).
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

# Write plan.json next to tfplan. Use -chdir so a relative WORKSPACE path
# doesn't get doubled after a cd (a common bash footgun).
terraform -chdir="$WORKSPACE" show -json tfplan > "$WORKSPACE/plan.json"

EXIT=0
{
  echo "["
  FIRST=1
  # AWS namespaces only. Including a GCP namespace here would "pass" with zero
  # coverage on an AWS plan — the exact empty-pass lesson from Step 3.
  for ns in compliance.sc28_aws compliance.ac3_aws compliance.cm6_aws ; do
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    # Capture JSON even when conftest exits non-zero; use that exit code for the gate.
    set +e
    OUT=$(conftest test --policy "$POLICY_DIR" --namespace "$ns" --output=json "$WORKSPACE/plan.json")
    STATUS=$?
    set -e
    [[ $STATUS -eq 0 ]] || EXIT=1
    printf '%s' "$OUT"
  done
  echo
  echo "]"
} > "$EVIDENCE_DIR/conftest-results.json"

if [[ $EXIT -eq 0 ]]; then echo "policy-gate: PASS"
else echo "policy-gate: FAIL"; echo "See $EVIDENCE_DIR/conftest-results.json"
fi
exit $EXIT
```

Three choices in there are worth understanding, because you'll see the same patterns in every CI script you write:

- Capturing `STATUS` after each `conftest` call stops one namespace's failure from killing the script before the others run, so you collect *all* violations, not just the first.
- `--output=json` makes the result a machine-readable artifact CI can store as evidence.
- Pass/fail uses Conftest's own exit code. No extra JSON parser (Python, `jq`, etc.) is required — Conftest already exits non-zero when a namespace has failures.

Run it both ways to produce your evidence:

```bash
# from the repo root
mkdir -p evidence/lab-3-4

# compliant: point at the Lab 2.3 workspace (needs tfplan from Step 2)
bash scripts/policy-gate.sh --workspace terraform/primitives/compliant-s3
cp evidence/lab-3-4/conftest-results.json evidence/lab-3-4/conftest-pass.json

# failing: point at the broken copy from Step 8 (it already has its own tfplan)
bash scripts/policy-gate.sh --workspace /tmp/broken
cp evidence/lab-3-4/conftest-results.json evidence/lab-3-4/conftest-fail.json
```

## Verification

- Compliant plan: exit 0, zero failures across all namespaces.
- Broken plan: exit 1, at least one SC-28 failure with the full remediation message.
- `evidence/lab-3-4/conftest-results.json` exists after each run.

Before you commit, update **`policies/README.md`** so it notes which file targets which cloud (the three GCP files from Lab 3.3 and the three `*_aws.rego` files from this lab).

## Commit your work

```bash
# from the repo root
git add policies/*_aws.rego policies/README.md scripts/policy-gate.sh evidence/lab-3-4
git commit -m "Lab 3.4: AWS policy variants + Conftest gate + evidence"
git push
```

## Cleanup

Nothing to tear down in the cloud; this lab is all local evaluation. Delete the throwaway `/tmp/broken` folder when you're done. (If you generated a plan against live Lab 2.3 resources, none were applied, so there's nothing to destroy.)

## Portfolio submission checklist

- [ ] `policies/` holds GCP and AWS variants for SC-28, AC-3, CM-6 (six files, three control IDs).
- [ ] `scripts/policy-gate.sh` committed and executable.
- [ ] `evidence/lab-3-4/conftest-pass.json` and `conftest-fail.json` captured.
- [ ] `policies/README.md` notes which file targets which cloud.

## Troubleshooting

- **`no policies matched`.** The `package` declared in your file doesn't match the `--namespace` string. They must be identical, character for character.
- **`policies: no such file or directory`.** `--policy` is a directory path resolved from your current shell. Run from the repo root, or pass the full path.
- **A bucket you expect to flag passes.** Module-wrapped resources sit under `child_modules[]`. Recurse the same way the GCP rules do, or the AWS rules will miss module output.
- **Comparisons against bucket names come back undefined.** At plan time AWS IDs are unknown. Match by reference in `configuration...expressions.<arg>.references`, never by literal value.

## How this feeds the rest of the course

`scripts/policy-gate.sh` is the exact script your CI calls in Lab 4.3. The capstone's GitHub Actions workflow runs it with `--workspace ./terraform`, and the build goes green or red on the result. Getting it solid here means it's one less thing to debug when the whole pipeline is running. Your six policies, three control IDs, become the same IDs your OSCAL component cites in Chapter 6, with the Conftest results as their evidence.
