# Capstone Project Brief

You've reached the capstone. Everything you've learned in this course (IaC, policy as code, CI/CD, evidence management, OSCAL) comes together in one GitHub repo you build yourself.

You ship the repo, you pass the capstone.

## The on-ramp: labs are optional, encouraged, and the same skills

The capstone tests the same skills the chapter labs taught. The labs are optional. They are also strongly encouraged. Every lab produces an artifact you can carry directly into your capstone repo.

If you skipped the labs you can still pass. The capstone brief assumes you didn't. Read the "What you've already built" section at the bottom before you decide.

## The system

You are the first GRC engineer at **Acme Health**, a 50-person telehealth company. The engineering team has shipped a Patient Intake API. It works. It is not audit-defensible. The CTO has asked you to make it audit-defensible in 30 days, and to do so without slowing the engineering team down.

The starter is real code, in a real repo: [`GRCEngClub/cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter). Fork it, deploy it, then govern it.

Step zero, the deploy gate, is making the starter run in your sandbox:

```bash
git clone https://github.com/GRCEngClub/cgep-app-starter
cd cgep-app-starter
make deploy AWS_PROFILE=<your-sandbox>
make test   AWS_PROFILE=<your-sandbox>
```

If `make test` returns `{"submission_id": "...", "status": "received"}`, you have something to govern. If it doesn't, fix that before going further. Real GRC engineers inherit working systems; demonstrating you can stand one up is the floor.

## The brief

Acme is pursuing three flags simultaneously: **HIPAA Security Rule** (PHI is at stake), **SOC 2 Type II** (an enterprise customer is asking), and **CMMC Level 2** (a federal pilot is on the table). You won't satisfy all three. You will pick one as your **primary framework**, defend that choice in your write-up, and structure every layer below around it.

The starter ships with eight named, intentional gaps. Your job is to design and build a system around the starter that closes them and produces evidence that the system stays closed.

See [`GAPS.md`](https://github.com/GRCEngClub/cgep-app-starter/blob/main/GAPS.md) and [`FRAMEWORKS.md`](https://github.com/GRCEngClub/cgep-app-starter/blob/main/FRAMEWORKS.md) in the starter for the full list and the framework primers.

## Four layers, one repo

Each layer maps to a chapter. The repo proves you can integrate them.

### Layer 1: Terraform baseline (around the starter)

The starter gives you the workload. You add the GRC baseline that makes it defensible.

Required new resources you provision:

- **KMS key(s)** you own, with rotation enabled. Bring the starter's S3 uploads bucket and DynamoDB table under your CMK.
- **S3 evidence bucket with Object Lock** (COMPLIANCE or GOVERNANCE mode, your call, defend it). Versioned. Encrypted with your KMS key. This is where every pipeline run lands.
- **CloudTrail** trail (multi-region, log-file-validation on) writing management events to a dedicated bucket.
- **Required hardening overrides** on the starter's resources to close the gaps from `GAPS.md` (e.g., `aws_s3_bucket_server_side_encryption_configuration` with `sse_algorithm = "aws:kms"`, `aws_lambda_function.intake.vpc_config`, IAM policy tightened from `dynamodb:*`).

Use the starter's VPC. Don't build a second one. Closing GAP-05 means moving the Lambda *into* the VPC the starter already created.

Don't pad. The capstone is about coverage and integration of what's there. A small Terraform that closes five gaps cleanly beats a large Terraform that adds new resources without governing the starter.

### Layer 2: OPA policy suite

Five or more Rego policies enforcing controls from your **declared primary framework** (HIPAA Security Rule, SOC 2 TSC, or CMMC L2).

Each policy:

- Has a metadata block naming the framework, control ID(s), severity, and remediation.
- Has its own `_test.rego` with passing and failing fixtures.
- Catches a real gap from `GAPS.md`. Not a generic tag check.
- Cites the control ID in the deny message so a developer reading the failed PR knows what to fix.

Conftest runs the suite against your Terraform plan in the pipeline. The pipeline fails closed. We will run your policies against a copy of the starter with one of your fixed gaps re-introduced and confirm the gate fires.

### Layer 3: GitHub Actions pipeline

One workflow. Five named steps, in order:

1. **Plan** the Terraform.
2. **Policy check** with Conftest.
3. **Apply** on merge to `main`.
4. **Sign** the evidence bundle with Cosign (keyless, via GitHub OIDC).
5. **Upload** the signed bundle to the evidence vault you stood up in Layer 1.

Two pull requests must exist in your repo's history: one that passed and merged, one that failed the policy gate and was blocked. Both are evidence the gate works.

### Layer 4: OSCAL component

One `component-definition.json` in your repo, describing what you actually built, the starter plus the controls you wrapped around it.

- Real UUIDs.
- The `source` field on each `control-implementation` points at your declared framework's catalog.
- Implementation statements reference real resources from your Terraform (use Terraform addresses or ARNs as `props`).
- Evidence links resolve to real signed objects in your vault.
- A profile selecting the controls your component implements.

If the OSCAL describes a system you didn't build, or cites a framework whose catalog you didn't declare, the layer fails. We check.

## The output

A working evidence vault. Every push to `main` produces a signed, timestamped artifact in immutable storage, automatically. That is the whole point.

## Three deliverables, due in 30 days

| Artifact | Format | What it proves |
|---|---|---|
| **Public GitHub repo** | Terraform + Rego + YAML | You can build the whole pipeline end-to-end. |
| **Evidence bundle** | Signed `.tar.gz` in S3 | Your pipeline produces audit-grade evidence. |
| **Write-up** | `WRITEUP.md` in the repo | You can explain your design choices to a stakeholder. |

Submission is the repo URL plus the commit SHA you want graded.

The write-up is not optional. Sections: design decisions, control coverage, trade-offs you made, what you'd do with another sprint, and what you didn't get to. Honest gaps don't lose points. Hand-waving does.

## Three things we score hard

1. **End-to-end integration.** Open a PR, the gate runs, the gate decides whether apply happens, apply triggers signing, signing uploads to the vault. Not four disconnected demos.
2. **Working evidence pipeline.** The grader pulls a recent run and verifies it: Cosign signature against the public Sigstore log, SHA-256 recompute, Object Lock retention check. All three must hold.
3. **Clear design reasoning.** Your write-up explains *why* you chose each tool and what trade-offs you accepted. Not just *what*.

## Three mistakes to avoid

1. **Too much scope.** Thirty resources cleanly integrated beats two hundred bolted on. Small and integrated wins.
2. **Copy-paste OSCAL.** An OSCAL file that doesn't actually describe your system is worse than no OSCAL file. Authenticity over completeness.
3. **Unsigned evidence.** If your pipeline produces a plan but doesn't sign and immutably store it, you haven't demonstrated chain of custody.

## What you decide (and defend in the write-up)

A short list. The required pieces above are not on this list.

- **Primary framework**, HIPAA Security Rule, SOC 2 Trust Services Criteria, or CMMC Level 2. Pick one. See `FRAMEWORKS.md` in the starter for the primer.
- AWS region.
- COMPLIANCE vs GOVERNANCE mode on the Object Lock vault.
- Whether the pipeline applies on merge to `main`, or after a manual approval gate post-merge.
- Single AWS account vs separate evidence-vault account (cleaner: separate; acceptable for 30 days: single).
- Which gaps to close in Terraform vs which to enforce only in policy. Both are valid; defend it.

## Suggested 30-day plan

Break it into weeks. Don't start day 29.

- **Week 1 · Design.** Pick your system. Map controls. Sketch the repo structure. Open a one-page design doc in the repo. This becomes the spine of `WRITEUP.md`.
- **Week 2 · Build infra.** Terraform baseline. Evidence bucket with Object Lock. KMS key. CloudTrail. Apply once by hand from a feature branch. Don't start the pipeline until the baseline applies clean.
- **Week 3 · Policy + pipeline.** Write 5 Rego policies. Build the GitHub Actions workflow. Wire signing. Open the green PR. Open a second PR that intentionally violates a policy and watch it go red.
- **Week 4 · OSCAL + write-up.** Author `component-definition.json`. Validate with `trestle`. Wire evidence URIs to real vault objects. Write reflection. Submit.

If you're in week three with no baseline running, cut scope. Trade workload resources for a working pipeline. Every time.

## Submission checklist

When the boxes are checked, send the repo URL and commit SHA.

- [ ] Your repo is a fork (or clear derivative) of `cgep-app-starter`. The starter's resources are still present and runnable.
- [ ] Your declared **primary framework** is named in `WRITEUP.md`'s first paragraph and in your OSCAL component's `control-implementation.source`.
- [ ] `terraform/` adds KMS keys, S3 evidence bucket with Object Lock, CloudTrail, and the gap-closing overrides.
- [ ] `policies/` has 5 or more Rego policies with tests. `opa test ./policies` passes. Each policy cites a control ID from your declared framework.
- [ ] `.github/workflows/grc-gate.yml` runs Plan, Policy check, Apply, Sign, Upload.
- [ ] One green PR and one red PR are visible in repo history.
- [ ] At least one signed evidence bundle in your vault. Cosign verifies. SHA matches. Object Lock retention active.
- [ ] `oscal/components/<your-component>.json` validates with `trestle`.
- [ ] `WRITEUP.md` covers framework choice, gap remediation, design trade-offs, and what you didn't get to.
- [ ] `README.md` is short, with verification instructions for the grader.

## What you've already built (if you did the labs)

The labs are optional. They are also the on-ramp. If you did them, you don't start the capstone from scratch, you assemble. Here's the direct mapping:

| Lab | What it gives you for the capstone |
|---|---|
| **2.3** First Compliant Resource | Your S3 hardening pattern (encryption, public-access-block, versioning, tags). Drop into the gap-closing overrides on the starter's uploads bucket. |
| **2.4** Modules for Compliance | The reusable-module discipline. Wrap your KMS + S3 hardening as a module so dev and prod consume the same floor. |
| **2.5** IaC as Compliance Evidence | Your evidence vault with Object Lock, plus `capture-evidence.sh`. The capstone vault IS Lab 2.5's vault. |
| **3.3** Writing Rego | Your starting policy library. The metadata block format, the test fixture pattern. Three policies you can adapt. |
| **3.4** Conftest + Terraform | `scripts/policy-gate.sh`. The capstone pipeline calls this directly. |
| **4.3** GRC Evidence Pipeline | `.github/workflows/grc-gate.yml`. The capstone pipeline IS this workflow with two extra steps. |
| **4.4** Chain of Custody | The Cosign + S3 Object Lock signing pattern. Wires Lab 4.3 into Lab 2.5. |
| **5.2** AWS Security Services | CloudTrail + Config baseline. The capstone Layer 1 native-controls layer. |
| **6.1** Introduction to OSCAL | Your component-definition skeleton. Replace the Lab 6.1 component's controls with your declared-framework controls and re-validate. |

If you did the labs as you went, the capstone is one week of design, two weeks of wiring, one week of writing.

If you skipped them, you have 30 days to learn what they teach AND ship the capstone. Doable. Tighter.

Ship the repo. Earn the cert.
