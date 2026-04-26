# Lab 4.3: Building a GRC Evidence Pipeline (AWS + GitHub Actions)

The local Conftest gate from Lab 3.4 catches violations on your laptop. CI catches them across the whole team. This lab wires the gate into GitHub Actions, runs it on every pull request, and uploads a named evidence artifact for every run. The YAML file you commit IS your CM-3 + CM-6 + CA-2 + RA-5 + AU-9 evidence.

## Learning objectives

- Wire AWS OIDC trust to a GitHub Actions workflow so the workflow assumes an IAM role without long-lived keys.
- Run terraform plan, Conftest, and tfsec on every PR; fail closed on any high-severity finding.
- Upload a named evidence artifact (`grc-evidence-<run-id>`) attached to every run.

## Prerequisites

- A GitHub repository you own. The reference implementation is wired to the [`cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter).
- AWS account with permission to create an IAM OIDC provider and an IAM role.
- Lab 2.3, Lab 3.3, Lab 3.4 artifacts (Terraform, policies, `policy-gate.sh`) committed into the repo.
- AWS CLI v2 with a working profile.

## Estimated time & cost

- 60 to 90 minutes.
- Cost: free. GitHub Actions free tier covers this. AWS cost is the same as Lab 2.3 since this workflow only plans.

## Architecture

```
  PR opened  ───▶  workflow run
                       │
                       ├── Configure AWS creds (OIDC, no keys on disk)
                       ├── terraform init / plan
                       ├── Conftest gate          (fails closed on policy failures)
                       ├── tfsec scan             (fails closed on high/critical)
                       ├── Upload evidence artifact (plan.json, conftest-results.json, tfsec.sarif)
                       └── Comment on PR with summary
```

Lab 4.4 adds Cosign signing and uploads the bundle to the Lab 2.5 vault.

## Step-by-step walkthrough

### Step 1 Set up GitHub OIDC trust with AWS

A small Terraform module creates the OIDC provider and a read-only role scoped to your repo.

```hcl
# oidc/main.tf
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" { region = "us-east-1" }

variable "github_org"  { type = string }
variable "github_repo" { type = string }

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "grc_gate" {
  name = "cgep-grc-gate"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike   = { "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*" }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.grc_gate.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

output "role_arn" { value = aws_iam_role.grc_gate.arn }
```

Apply:

```bash
cd oidc
terraform init
terraform apply -var=github_org=YourOrg -var=github_repo=YourRepo
```

If the OIDC provider already exists in the account (some other automation created it), import:

```bash
terraform import aws_iam_openid_connect_provider.github \
  arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com
terraform apply -var=github_org=YourOrg -var=github_repo=YourRepo
```

The `StringLike` on `sub` keeps this role bound to one specific repository. Don't loosen it. A role trusted by `repo:*:*` is trusted by every public repo on GitHub.

### Step 2 Add the role ARN as a repo variable

```bash
gh variable set AWS_ROLE_ARN \
  --body "arn:aws:iam::ACCOUNT:role/cgep-grc-gate" \
  --repo YourOrg/YourRepo
```

### Step 3 Write the workflow

```yaml
# .github/workflows/grc-gate.yml
name: grc-gate

on:
  pull_request:
    branches: [main]
  workflow_dispatch:

permissions:
  id-token: write       # required for AWS OIDC + Cosign keyless (Lab 4.4)
  contents: read
  pull-requests: write  # required to comment on the PR

env:
  AWS_REGION: us-east-1
  TF_WORKING_DIR: terraform

jobs:
  grc-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ vars.AWS_ROLE_ARN }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.6.6
          terraform_wrapper: false

      - name: Install Conftest
        run: |
          curl -fsSL https://github.com/open-policy-agent/conftest/releases/download/v0.50.0/conftest_0.50.0_Linux_x86_64.tar.gz \
            | tar -xz -C /usr/local/bin conftest

      - name: Install tfsec
        run: |
          curl -fsSL https://github.com/aquasecurity/tfsec/releases/download/v1.28.14/tfsec-linux-amd64 \
            -o /usr/local/bin/tfsec && chmod +x /usr/local/bin/tfsec

      - name: Terraform plan
        working-directory: ${{ env.TF_WORKING_DIR }}
        run: |
          terraform init -input=false
          terraform validate
          terraform plan -out=tfplan -no-color | tee plan.txt
          terraform show -json tfplan > plan.json

      - name: Conftest policy gate
        id: conftest
        working-directory: ${{ env.TF_WORKING_DIR }}
        run: |
          mkdir -p ../evidence
          {
            echo "["
            FIRST=1
            for ns in compliance.sc28_aws compliance.ac3_aws compliance.cm6_aws compliance.cm6 ; do
              [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
              conftest test --policy ../policies --namespace "$ns" --output=json plan.json || true
            done
            echo "]"
          } > ../evidence/conftest-results.json
          python3 -c '
          import json, sys
          d = json.load(open("../evidence/conftest-results.json"))
          fails = sum(len(r.get("failures") or []) for results in d for r in results)
          print(f"conftest failures: {fails}")
          sys.exit(0 if fails == 0 else 1)
          '

      - name: tfsec scan
        id: tfsec
        if: always()
        working-directory: ${{ env.TF_WORKING_DIR }}
        run: |
          tfsec . --format sarif --out ../evidence/tfsec.sarif || true
          python3 -c '
          import json, sys
          d = json.load(open("../evidence/tfsec.sarif"))
          high = sum(
              1 for run in d.get("runs", [])
              for r in run.get("results", [])
              if (r.get("level") or "").lower() in ("error","critical","high")
          )
          print(f"tfsec high+critical: {high}")
          sys.exit(0 if high == 0 else 1)
          '

      - name: Copy plan into evidence
        if: always()
        run: |
          cp ${{ env.TF_WORKING_DIR }}/plan.json evidence/plan.json
          cp ${{ env.TF_WORKING_DIR }}/plan.txt  evidence/plan.txt

      - name: Upload evidence artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: grc-evidence-${{ github.run_id }}
          path: evidence/
          retention-days: 90
```

A few specific choices worth understanding:

- **`permissions: id-token: write`** is required for `aws-actions/configure-aws-credentials` to mint an OIDC token. Without it, OIDC silently fails.
- **`if: always()`** on the tfsec scan and the upload step. Without this, a Conftest failure aborts the job before evidence is captured. The whole point of CI evidence is that it's preserved on failure.
- **`|| true`** after the conftest and tfsec calls. The tools exit non-zero on findings; we want the JSON output regardless. The pass/fail decision is made by the python3 inline checks that follow.
- **Pinned versions** on every action. Floating tags drift. Pin them.

### Step 4 Open a PR and watch it run

```bash
git checkout -b add-grc-gate
git add .github/workflows/grc-gate.yml policies/ scripts/ oidc/
git commit -m "Add GRC evidence pipeline"
git push -u origin add-grc-gate
gh pr create --title "Add GRC evidence pipeline" --body "Reference pipeline."
```

The workflow fires immediately. Watch:

```bash
gh run list --limit 3
gh run watch
```

Reference run from the [`cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter) demo:

```
conftest failures: 5
tfsec high+critical: 12
```

Both gates fired. The starter has eight named gaps, so this is the expected outcome. The evidence artifact `grc-evidence-<run-id>` is attached to the run with `plan.json`, `conftest-results.json`, `tfsec.sarif`, and the human-readable `plan.txt`.

### Step 5 The two-PR demonstration

The capstone wants both a green and a red PR in your repo's history. To produce them:

1. **Red PR**: open a branch that introduces a violation (delete an `aws_s3_bucket_server_side_encryption_configuration`, or pass `block_public_acls = false`). Open it as a PR. The workflow runs, Conftest fails, the merge is blocked.
2. **Green PR**: revert or fix that change. The workflow runs again, Conftest passes, the PR merges.

Both runs leave evidence artifacts in the workflow history. Both URLs go in your capstone write-up.

### Takeaway: The YAML file is itself evidence

Every line in `.github/workflows/grc-gate.yml` is a control statement.

| Workflow content | NIST control |
|---|---|
| `on: pull_request` plus branch protection requiring this check | CM-3 (configuration change control) |
| `default_tags` enforced via Conftest in this same workflow | CM-6 (configuration settings) |
| The workflow itself is a continuous monitoring assessment | CA-2 (control assessments), CA-7 (continuous monitoring) |
| `tfsec` scanning every change | RA-5 (vulnerability monitoring and scanning) |
| Workflow run history retained, evidence artifacts retained 90 days, signed in Lab 4.4 | AU-9 (protection of audit information) |

The workflow file is checked in. The history is preserved. An assessor traversing the OSCAL component you write in Lab 6.1 follows an evidence URI that points at this workflow's run output.

## Verification

- A PR triggers the workflow.
- The workflow run is visible in the Actions tab.
- An evidence artifact `grc-evidence-<run-id>` is attached to the run with `plan.json`, `conftest-results.json`, `tfsec.sarif`, `plan.txt`.
- Compliant code: workflow ends successful. Non-compliant code: workflow fails with named control IDs in the Conftest output.

## Portfolio submission checklist

- [ ] `oidc/` Terraform module that creates the OIDC provider + role, committed to the repo.
- [ ] `.github/workflows/grc-gate.yml` committed.
- [ ] `vars.AWS_ROLE_ARN` set in repo variables.
- [ ] At least one workflow run visible in the Actions tab.
- [ ] One green PR and one red PR in repo history (capstone requirement).

## Troubleshooting

- **`Error: Could not assume role with OIDC: invalid identity token`**. The `sub` condition in the trust policy doesn't match. Check the exact format: `repo:OWNER/REPO:ref:refs/heads/BRANCH` for branch pushes, `repo:OWNER/REPO:pull_request` for PR runs. Use `StringLike` with `repo:OWNER/REPO:*` for catch-all.
- **`Permission denied`** on terraform init. The role needs read on the state backend (typically S3 + DynamoDB). `ReadOnlyAccess` covers this. For a real apply pipeline, you'd attach a more targeted policy.
- **Conftest finds no policies**. The path passed via `--policy` is interpreted relative to the working directory of the step. Always pass an absolute or canonically-relative path.
- **tfsec false positives**. Add a `.tfsec/config.yml` in your repo to suppress specific rule IDs with a justification comment. Don't use `--exclude` flags scattered through the workflow; centralize the exclusions.
- **Artifact retention**. GitHub default is 90 days. For real compliance evidence, set `retention-days: 365` and copy to your Lab 2.5 vault on every successful run (Lab 4.4 wires this up).

## Cleanup

Delete test branches. The workflow file stays; it's the deliverable. The IAM role and OIDC provider stay; they're free.

## How this feeds the capstone

This is the capstone's pipeline. In Lab 4.4 we add the Cosign signing step and the upload to your Lab 2.5 vault. In Lab 6.1 your OSCAL component's evidence URIs point at signed objects in the vault, which were written by this workflow. The full chain is: PR opened, gate runs, evidence signed, evidence stored, OSCAL points at it, assessor traverses without you in the room.
