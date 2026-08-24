# Lab 4.3: Building a GRC Evidence Pipeline (AWS + GitHub Actions)

The Conftest gate from Lab 3.4 catches violations on your laptop. That's good for you, but it does nothing for a teammate who skips it. This lab moves the gate to where nobody can skip it: GitHub's servers, running automatically on every pull request. The workflow you write plans your Terraform, runs your policies, scans for misconfigurations, and saves a named evidence file for every single run. The result is a control that enforces itself and documents itself at the same time.

This is the first lab where the "engineering" in GRC Engineering really shows. For the GRC folks, you're building continuous monitoring that produces an audit trail without anyone collecting it by hand. For the technical folks, this is a CI pipeline, with the unusual goal that its *output* is compliance evidence, not just a green check.

A note for anyone new to CI: continuous integration just means automation that runs on a server whenever you push code. GitHub Actions is GitHub's version. You describe the steps in a YAML file, commit it, and GitHub runs those steps for you on every pull request. That's the whole idea.

## Before you begin

If this is your first lab, set up [your tools](../getting-started/tools.md) and [your repo](../getting-started/repo-structure.md) first. This lab builds on Labs 2.3, 3.3, and 3.4, so those need to be committed.

New tool for this lab:

- **GitHub CLI (`gh`)**, for creating pull requests and setting repo variables from the terminal. Install from the official page: https://cli.github.com/. Authenticate once with `gh auth login`.

Two tools run *inside* the workflow on GitHub's servers, so you don't install them locally; the workflow downloads them:

- **Conftest** (you already know it from Lab 3.4).
- **tfsec**, a static scanner that flags risky Terraform. Note that tfsec is now in maintenance mode, folded into **Trivy** (`trivy config` is the supported successor, and the old check IDs carry over). The lab uses tfsec because it's small and pinnable; everything here works the same if you later switch the scan step to Trivy.

You also need an AWS account where you can create an IAM role and an OIDC provider. Commands below use `--profile default`; if you named your profile something else in Lab 2.3, replace `default` with that name.

## Time and cost

- Time: 60 to 90 minutes. Budget extra for the OIDC setup; it's the fiddly part.
- Cost: free. GitHub Actions' free tier covers this, and the workflow only plans, so AWS costs nothing.

## Architecture

```
  PR opened  ───▶  workflow runs on GitHub's servers
                       │
                       ├── Get AWS credentials via OIDC   (no keys stored anywhere)
                       ├── terraform init / plan
                       ├── Conftest gate                  (fails the build on a policy violation)
                       ├── tfsec scan                     (fails on high/critical findings)
                       ├── Upload evidence artifact        (plan.json, conftest-results.json, tfsec.sarif)
                       └── (Lab 4.4 adds: sign + store in the vault)
```

## The OIDC idea, in plain language

The workflow needs to read your AWS account to run a plan. The old way was to paste an AWS access key into GitHub's secrets. That's a long-lived credential sitting in a settings page, and if it leaks, someone has standing access to your account.

OIDC replaces that with something better. GitHub and AWS establish a trust relationship once. Then, on each run, GitHub hands AWS a short-lived token that proves "this is a workflow from *this specific repository*," and AWS gives back temporary credentials that expire when the job ends. No secret is stored, nothing outlives the run, and the trust is scoped to one repo. You set this up once and forget it.

## Where these files live

```
cgep-labs/
├── terraform/primitives/oidc-trust/
│   └── main.tf                         ← OIDC provider + IAM role
├── .github/workflows/
│   └── grc-gate.yml                    ← the CI pipeline
└── evidence/lab-4-3/                   ← filled by the workflow artifact
    ├── plan.json
    ├── plan.txt
    ├── conftest-results.json
    └── tfsec.sarif
```

### Scaffold this lab's empty files

Run this once from the repo root (`cgep-labs`). It creates every path in the diagram above as an empty file so the later steps are "open and paste," not "guess where this goes."

```bash
# from the repo root
mkdir -p terraform/primitives/oidc-trust .github/workflows evidence/lab-4-3

touch \
  terraform/primitives/oidc-trust/main.tf \
  .github/workflows/grc-gate.yml

find terraform/primitives/oidc-trust .github/workflows evidence/lab-4-3 -type f | sort
```

## Step-by-step walkthrough

### Step 1: Create the OIDC trust in AWS

This small Terraform creates the OIDC provider and a read-only role bound to your repository. Put it in a primitive, since you apply it once. Open **`terraform/primitives/oidc-trust/main.tf`** from the scaffold and paste:

```hcl
# terraform/primitives/oidc-trust/main.tf
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

Apply it. Substitute your GitHub org (or username) and the `cgep-labs` repo name:

```bash
# from the repo root
cd terraform/primitives/oidc-trust
eval "$(aws configure export-credentials --profile default --format env)"  # if you use SSO
terraform init
terraform apply -var=github_org=<your-github-org> -var=github_repo=cgep-labs
ROLE_ARN=$(terraform output -raw role_arn)
cd ../../..
```

If the account already has a GitHub OIDC provider (some other automation may have created one), Terraform will error on the duplicate. Import it instead of recreating:

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --profile default)
terraform import aws_iam_openid_connect_provider.github \
  "arn:aws:iam::${ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"
terraform apply -var=github_org=<your-github-org> -var=github_repo=cgep-labs
ROLE_ARN=$(terraform output -raw role_arn)
```

> The `StringLike` condition on `sub` is what binds this role to one repository. Do not loosen it to `repo:*:*`. A role trusted by every repo on GitHub is a role trusted by every attacker who can open a public repo. This single line is the difference between scoped trust and an open door.

### Step 2: Tell GitHub which role to assume

Save the role ARN as a repo variable so the workflow can read it. Use the `$ROLE_ARN` you just captured (no copy-paste from the console):

```bash
gh variable set AWS_ROLE_ARN \
  --body "$ROLE_ARN" \
  --repo <your-github-org>/cgep-labs
```

### Step 3: Write the workflow

This is the heart of the lab. Open **`.github/workflows/grc-gate.yml`** from the scaffold and paste. The paths here point at your `cgep-labs` layout (the compliant-s3 workspace, the root-level `policies/`, and a per-lab evidence folder).

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
  TF_WORKING_DIR: terraform/primitives/compliant-s3

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
          # Same vars as Lab 2.3 / 3.4. -input=false means missing vars fail the job
          # instead of hanging on an interactive prompt the runner can't answer.
          terraform plan -out=tfplan -input=false -no-color \
            -var="project_name=cgep-lab" -var="environment=dev" | tee plan.txt
          terraform show -json tfplan > plan.json

      - name: Conftest policy gate
        id: conftest
        run: |
          mkdir -p evidence/lab-4-3
          EXIT=0
          {
            echo "["
            FIRST=1
            # AWS namespaces only (same set as scripts/policy-gate.sh from Lab 3.4).
            for ns in compliance.sc28_aws compliance.ac3_aws compliance.cm6_aws ; do
              [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
              set +e
              OUT=$(conftest test --policy policies --namespace "$ns" --output=json "$TF_WORKING_DIR/plan.json")
              STATUS=$?
              set -e
              [[ $STATUS -eq 0 ]] || EXIT=1
              printf '%s' "$OUT"
            done
            echo
            echo "]"
          } > evidence/lab-4-3/conftest-results.json
          if [[ $EXIT -eq 0 ]]; then echo "conftest: PASS"; else echo "conftest: FAIL"; exit 1; fi

      - name: tfsec scan
        id: tfsec
        if: always()
        run: |
          # Write SARIF for the artifact, then re-run with a severity floor so
          # tfsec's own exit code is the gate (no JSON parsing required).
          tfsec "$TF_WORKING_DIR" --format sarif --out evidence/lab-4-3/tfsec.sarif || true
          tfsec "$TF_WORKING_DIR" --minimum-severity HIGH

      - name: Copy plan into evidence
        if: always()
        run: |
          cp "$TF_WORKING_DIR"/plan.json evidence/lab-4-3/plan.json
          cp "$TF_WORKING_DIR"/plan.txt  evidence/lab-4-3/plan.txt

      - name: Upload evidence artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: grc-evidence-${{ github.run_id }}
          path: evidence/lab-4-3/
          retention-days: 90
```

Four choices in this file are worth understanding, because they're the difference between a workflow that works and one that fails in confusing ways:

- **`permissions: id-token: write`** is what lets the credentials step mint an OIDC token. Leave it out and OIDC fails silently with a misleading error. This is the single most common first-run problem.
- **`if: always()`** on the scan, copy, and upload steps. Without it, a Conftest failure ends the job immediately and you lose the evidence. The entire value of CI evidence is that it survives the failure it documents, so these steps must run even after a gate fails.
- **Tool-native exit codes for the gate.** Conftest exits non-zero on policy failures; `tfsec --minimum-severity HIGH` exits non-zero on high/critical findings. The SARIF/`--output=json` writes are for the evidence artifact; the tools themselves decide pass/fail. No Python (or other JSON parser) is required on the runner.
- **Pinned versions** on every action and download (`@v4`, `v0.50.0`, `v1.28.14`). Floating tags change under you. For supply-chain safety, the more cautious choice is pinning third-party actions to a specific commit SHA rather than a moving tag.

### Step 4: Open a PR and watch it run

```bash
# from the repo root
git checkout -b add-grc-gate
git add .github/workflows/grc-gate.yml policies/ scripts/ terraform/primitives/oidc-trust/
git commit -m "Add GRC evidence pipeline"
git push -u origin add-grc-gate
gh pr create --title "Add GRC evidence pipeline" --body "Reference pipeline."
```

The workflow fires the moment the PR opens. Follow it live:

```bash
gh run list --limit 3
gh run watch
```

If your Lab 2.3 code is compliant, the gates pass and the run goes green. If you point this at deliberately broken infrastructure (next step), you'll see output like `conftest failures: 5`. Either way, an evidence artifact named `grc-evidence-<run-id>` is attached to the run, holding `plan.json`, `conftest-results.json`, `tfsec.sarif`, and the human-readable `plan.txt`.

### Step 5: The two-PR demonstration

Your capstone wants proof the gate actually blocks bad code, which means your repo history needs one PR that failed and one that passed.

1. **Red PR.** Branch off, introduce a violation (delete the `aws_s3_bucket_server_side_encryption_configuration`, or set `block_public_acls = false`), and open it as a PR. The workflow runs, Conftest fails, and with branch protection on, the merge is blocked.
2. **Green PR.** Fix or revert the change. The workflow runs again, passes, and the PR merges.

Both runs leave evidence artifacts in the Actions history. Both URLs go in your capstone write-up. That pair, a block and a pass, is the clearest possible demonstration that the control works.

### The point: the YAML file is itself evidence

This is the idea to carry forward. Every meaningful line in this workflow maps to a control:

| What's in the workflow | NIST control |
|---|---|
| `on: pull_request` plus branch protection requiring this check | CM-3 (configuration change control) |
| Required tags enforced through Conftest in this same run | CM-6 (configuration settings) |
| The workflow running on every change is itself an assessment | CA-2, CA-7 (assessment, continuous monitoring) |
| `tfsec` scanning every change | RA-5 (vulnerability scanning) |
| Run history and evidence retained (signed in Lab 4.4) | AU-9 (protection of audit information) |

The file is committed. The history is preserved. In Chapter 6, the OSCAL component you write points an evidence link straight at this workflow's run output. The auditor follows the link instead of asking you for a screenshot.

## Verification

- Opening a PR triggers the workflow, visible in the Actions tab.
- An artifact `grc-evidence-<run-id>` is attached with `plan.json`, `conftest-results.json`, `tfsec.sarif`, and `plan.txt`.
- Compliant code ends green; non-compliant code fails with named control IDs in the Conftest output.

## Portfolio submission checklist

- [ ] `terraform/primitives/oidc-trust/` creates the OIDC provider and role.
- [ ] `.github/workflows/grc-gate.yml` committed.
- [ ] `vars.AWS_ROLE_ARN` set in repo variables.
- [ ] At least one workflow run in the Actions tab.
- [ ] One green PR and one red PR in the repo history (capstone requirement).

## Troubleshooting

- **`Could not assume role with OIDC: invalid identity token`.** The `sub` condition doesn't match the run. For PR runs the subject is `repo:OWNER/REPO:pull_request`; the `StringLike` with `repo:OWNER/REPO:*` covers both PR and branch runs.
- **`Permission denied` on terraform init.** The role needs read access to your state backend. `ReadOnlyAccess` covers a plan-only pipeline; a real apply pipeline needs a narrower, write-capable policy.
- **Conftest finds no policies.** `--policy` is resolved from the step's working directory. The workflow above runs the gate from the repo root and passes `policies`, so don't add a `working-directory` to that step.
- **OIDC fails even though the role exists.** Almost always the missing `id-token: write` permission. Check that block first.
- **tfsec noise.** Suppress specific rule IDs in a `.tfsec/config.yml` with a justifying comment rather than scattering `--exclude` flags. If you migrate to Trivy, the same IDs work with a `.trivyignore` file.

## Cleanup

Delete the test branches. Keep the workflow file (it's the deliverable) and the IAM role and OIDC provider (they're free and you'll reuse them). If you want them gone, `terraform destroy` in `terraform/primitives/oidc-trust/`.

## How this feeds the rest of the course

This is your capstone's pipeline. In Lab 4.4 you add a Cosign signing step and an upload to the Lab 2.5 vault, completing the chain of custody. In Chapter 6 your OSCAL component's evidence links point at signed objects this workflow produced. The full arc: a PR opens, the gate runs, evidence is captured and signed, the evidence lands in the immutable vault, and an assessor follows the OSCAL link to it, all without you in the room.
