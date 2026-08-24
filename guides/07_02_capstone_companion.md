# Capstone: Assemble Your Evidence Pipeline

> **This is the how-to, not the contract.** The graded requirements, deliverables, and scoring live in the [Capstone Brief](07_01_capstone_brief.md). Read that first. This companion walks you through assembling the work, lab by lab.

This is where everything converges. The capstone isn't a new topic; it's the integration of every skill the course taught into one repository you own. If you did the labs, the most important thing to understand before you start is this: you are not building from scratch, you are *assembling*. Each lab handed you a piece, and the capstone is where they snap together into a system that produces audit-grade evidence on every push, automatically.

This companion doesn't rewrite the brief. The brief (the `Capstone Project Brief`) is the authoritative spec, and you should read it in full. What this page does is make the brief navigable for someone who's new to either the GRC side or the engineering side: it translates the scenario, makes the choices you have to defend legible, shows you how your lab artifacts assemble into the final repo, and scaffolds the write-up that's worth a large share of your score.

## The mindset shift: you're integrating, not inventing

The single most common way capstones go wrong is treating it like a from-scratch sprint and trying to build a huge new system in 30 days. The brief is explicit that the opposite wins: a small, cleanly integrated repo beats a large, bolted-together one. Your job isn't to add the most resources. It's to take a working application that *isn't* audit-defensible and wrap it in a system that makes it defensible and keeps it that way. If you did the labs, you've already built every layer of that system once. The capstone is the version where they all talk to each other.

## Step zero: the deploy gate

Before any governance work, you have to get the starter application running in your own AWS sandbox. This is a real gate, not a formality: a GRC engineer inherits working systems, and proving you can stand one up is the floor.

> The commands below use `AWS_PROFILE=default`. If you named your AWS CLI profile something else in Lab 2.3, replace `default` with that name.

```bash
git clone https://github.com/GRCEngClub/cgep-app-starter
cd cgep-app-starter
make deploy AWS_PROFILE=default
make test   AWS_PROFILE=default
```

`make deploy` provisions the starter's infrastructure (the Patient Intake API and its supporting resources) into your account. `make test` exercises it. If `make test` returns something like `{"submission_id": "...", "status": "received"}`, the application is live and you have something to govern. If it doesn't, stop and fix that first. Everything downstream assumes a working system underneath.

Fork the starter (don't just clone it) so your capstone repo is a clear derivative with its own history, which is where your two graded pull requests will live.

## The scenario, in plain terms

You're the first GRC engineer at a 50-person telehealth company. Engineering shipped a Patient Intake API that works but can't survive an audit. The CTO wants it audit-defensible in 30 days, *without* slowing engineering down. That last clause is the whole philosophy of the course: governance that runs as automated checks in the pipeline instead of as meetings and tickets. The starter ships with eight intentional, named gaps (listed in `GAPS.md` in the starter repo). Your work is to design a system that closes them and proves they stay closed.

## Decision 1: pick your primary framework

The company is chasing three compliance flags at once, and you must pick exactly one as your primary framework, then structure everything beneath it around that choice and defend the choice in your write-up. You don't need deep expertise in any of them to choose well; you need to understand what each is *for*. The starter's `FRAMEWORKS.md` has the primers; here's the orientation:

- **HIPAA Security Rule** is about protecting health information (PHI). Because this is a telehealth company handling patient data, it's the most natural fit for the scenario, and its safeguards map cleanly onto the encryption, access-control, and audit-logging work you've already done. If you're newer to compliance, this is often the most defensible pick precisely because the connection to the system is obvious.
- **SOC 2 Type II** is about demonstrating, over a period of time, that your controls operate effectively. Its Trust Services Criteria (security, availability, confidentiality, and so on) are broad and very common in enterprise sales. Choose this if you want to emphasize the *continuous* nature of your evidence pipeline, since SOC 2 Type II is fundamentally about controls working over time, which is exactly what your signed-evidence-on-every-push design proves.
- **CMMC Level 2** is about protecting controlled information for federal work, and it leans heavily on NIST 800-53 / 800-171 control families, the same families your Rego policies already cite. Choose this if you want the tightest mapping between your existing control IDs and the framework's requirements.

There's no wrong choice, only an undefended one. The graders score your *reasoning*, not your framework. Pick the one you can argue for in three sentences, and make sure your OSCAL component's `source` field points at that framework's catalog, because they check that the framework you declare and the framework your OSCAL cites are the same.

## The four layers, and the labs that built them

The repo has four layers, each mapping to a chapter you've completed. For each, here's what "done" looks like and which of your own lab artifacts you carry in.

**Layer 1, the Terraform baseline.** You wrap the starter with the GRC infrastructure that makes it defensible: KMS keys you own (with rotation), an Object Lock evidence bucket, a multi-region CloudTrail, and the specific hardening overrides that close the gaps. The discipline from Lab 2.4 (wrap your KMS + S3 hardening as a reusable module), the hardening pattern from Lab 2.3, the vault from Lab 2.5, and the CloudTrail baseline from Lab 5.2 all land here. Crucial constraint from the brief: use the starter's existing VPC, don't build a second one. Closing the VPC gap means moving the starter's Lambda *into* the VPC it already created, not standing up new networking.

**Layer 2, the OPA policy suite.** Five or more Rego policies enforcing controls from your declared framework, each with a metadata block, each with passing and failing tests, and each catching a *real* gap from `GAPS.md` rather than a generic tag check. Your Lab 3.3 library is the starting point and your Lab 3.4 AWS variants and `policy-gate.sh` are the machinery (the gate uses Conftest's exit codes directly — keep that pattern when you extend the script for your framework). The graders will reintroduce one of your fixed gaps and confirm your gate fires, so your policies have to catch real misconfigurations, not just check for labels.

**Layer 3, the GitHub Actions pipeline.** One workflow with five named steps in order: plan, policy-check, apply-on-merge, sign, upload. This is your Lab 4.3 workflow with the Lab 4.4 signing and upload steps added. The capstone asks for one thing the labs didn't: an actual *apply* on merge to `main`, so the pipeline doesn't just check, it deploys. Two pull requests must exist in your history, one that passed and merged and one that failed the gate and was blocked. Those two PRs are how you prove the gate has teeth.

**Layer 4, the OSCAL component.** One `component-definition.json` describing what you actually built, with real UUIDs, a `source` pointing at your declared framework's catalog, implementation statements referencing real Terraform addresses or ARNs, and evidence links that resolve to real signed objects in your vault, plus a profile selecting your controls. This is your Lab 6.1 component with its controls swapped for your framework's, re-validated with `trestle`. The brief is blunt: if the OSCAL describes a system you didn't build, the layer fails, and they check.

## The decisions you make and defend

Beyond the framework, the brief leaves a handful of choices to you. These aren't busywork; each is a real engineering trade-off, and naming the trade-off is how you defend it. Here's each one in plain terms so you can decide with confidence:

- **AWS region.** Mostly free choice; pick one and be consistent. If your framework or scenario implies data-residency requirements, note that as your reason.
- **Object Lock mode: COMPLIANCE or GOVERNANCE.** COMPLIANCE means *nobody*, not even the account root, can delete evidence before retention expires, which is the strongest possible chain-of-custody claim but means you can't clean up. GOVERNANCE lets a privileged caller bypass the lock, which is friendlier for a 30-day project. Either is defensible; the strong answer explains the trade-off (tamper-resistance versus operational flexibility) rather than just picking.
- **Apply on merge, or apply after a manual approval gate.** Auto-apply on merge is fully continuous but gives the pipeline real deploy power. A post-merge manual gate keeps a human in the loop before production changes. Defend based on how much you trust the gate and the blast radius of a bad apply.
- **Single account or a separate evidence-vault account.** A separate account for the vault is cleaner (the evidence lives outside the account being audited, so an account compromise can't quietly rewrite it), but a single account is acceptable for 30 days. If you go single-account, say so and note what you'd change for production.
- **Which gaps to close in Terraform versus enforce only in policy.** Some gaps you fix in the infrastructure itself; others you might leave as a policy that blocks any future reintroduction. Both are valid. The interesting write-up explains why a given gap belongs in one bucket versus the other.

The pattern across all of these: the graders reward clear reasoning over any particular answer. A defended GOVERNANCE vault beats an undefended COMPLIANCE one.

## A worked repo layout

Here's how your lab artifacts assemble into the capstone repo. If you've been building in the canonical `cgep-labs` structure throughout the course, most of this is copy-and-adapt rather than write-from-scratch.

```
your-cgep-capstone/                 (fork of cgep-app-starter)
├── terraform/
│   ├── <starter's existing app resources>     # keep these; they're the workload
│   ├── kms.tf                  ← Lab 2.4 discipline: your CMK with rotation
│   ├── evidence-vault.tf       ← Lab 2.5: Object Lock bucket
│   ├── cloudtrail.tf           ← Lab 5.2: multi-region trail
│   ├── oidc-trust.tf           ← Lab 4.3: GitHub OIDC role
│   └── hardening.tf            ← gap-closing overrides on the starter's resources
├── policies/
│   ├── *.rego                  ← Lab 3.3 + 3.4: 5+ policies for your framework
│   └── tests/*_test.rego       ← passing + failing fixtures
├── scripts/
│   ├── policy-gate.sh          ← Lab 3.4
│   ├── capture-evidence.sh     ← Lab 2.5
│   └── verify-evidence.sh      ← Lab 4.4
├── .github/workflows/
│   └── grc-gate.yml            ← Lab 4.3 + 4.4: plan→check→apply→sign→upload
├── oscal/
│   ├── components/<your-component>.json   ← Lab 6.1, controls swapped to your framework
│   └── profiles/cge-p-minimum.json        ← Lab 6.1
├── WRITEUP.md                  ← the graded reasoning document
└── README.md                  ← short; grader verification steps
```

The point of laying it out this way is to make the assembly visible: nearly every file traces back to a lab you've already done. The capstone is the wiring, not the parts.

### Scaffold the files you'll add on top of the starter

After you fork and clone `cgep-app-starter`, run this once from that repo root so the new paths exist as empty files before you copy content over from `cgep-labs`. (Keep the starter's existing Terraform; this only adds the governance layer.)

```bash
# from your-cgep-capstone/ (fork of cgep-app-starter)
mkdir -p \
  terraform \
  policies/tests \
  scripts \
  .github/workflows \
  oscal/components \
  oscal/profiles

touch \
  terraform/kms.tf \
  terraform/evidence-vault.tf \
  terraform/cloudtrail.tf \
  terraform/oidc-trust.tf \
  terraform/hardening.tf \
  scripts/policy-gate.sh \
  scripts/capture-evidence.sh \
  scripts/verify-evidence.sh \
  .github/workflows/grc-gate.yml \
  oscal/components/your-component.json \
  oscal/profiles/cge-p-minimum.json \
  WRITEUP.md

chmod +x scripts/*.sh

find terraform policies scripts .github/workflows oscal WRITEUP.md -maxdepth 2 -type f 2>/dev/null | sort
```

When a later section says "bring over Lab 2.5's vault" or "paste your Lab 3.4 gate," open the matching empty file above and paste into that path — don't create a second copy under a different name.

## The 30-day plan, with checkpoints

Break it into weeks, and don't start on day 29. Each week has a checkpoint that tells you whether to keep going or cut scope.

**Week 1, design.** Pick your framework, map your chosen controls to the eight gaps, sketch the repo structure, and write a one-page design doc in the repo. That doc becomes the spine of your `WRITEUP.md`, so this week is never wasted. *Checkpoint:* you can state, in a paragraph, your framework and which gaps you'll close in Terraform versus policy.

**Week 2, build the infrastructure.** The Terraform baseline: KMS, the Object Lock evidence bucket, CloudTrail, and the gap-closing overrides. Apply it once by hand from a feature branch. *Checkpoint:* the baseline applies clean on its own. Do not start the pipeline until it does, because debugging Terraform through CI is far harder than debugging it locally.

**Week 3, policy and pipeline.** Write your five-plus Rego policies, build the workflow, wire signing, and produce both PRs (the green one that merges and the red one the gate blocks). *Checkpoint:* a real PR run goes green, and a deliberately broken one goes red, both with evidence in the vault.

**Week 4, OSCAL and write-up.** Author and validate the component definition, point its evidence links at real vault objects, then write the reflection and submit. *Checkpoint:* `trestle validate` passes and an evidence link resolves to a verifiable bundle.

The brief's scope-cutting rule is worth memorizing: if you reach week three without a baseline running, cut workload scope to get a working pipeline. A small system with a real, signing, immutable evidence pipeline passes. A large system without one does not. Trade resources for the pipeline every single time.

## How the grader verifies (so you can self-check first)

Three things are scored hard, and you can check all three yourself before you submit:

1. **End-to-end integration.** Open a PR and watch the chain actually connect: the gate runs, the gate's result decides whether apply happens, apply triggers signing, signing uploads to the vault. If those are four separate demos that don't trigger each other, that's the most common point loss. Confirm it's one connected flow.
2. **A working evidence pipeline.** The grader pulls a recent run and runs the same three checks your Lab 4.4 `verify-evidence.sh` runs: the Cosign signature verifies against the public Sigstore log, the SHA-256 recomputes to match, and Object Lock retention is still active. Run your own verify script against your latest run before submitting. If it prints `CHAIN INTACT`, you've pre-passed the part graders weight most heavily.
3. **Clear design reasoning.** Your write-up explains *why*, not just *what*. This is the next section.

## Scaffolding your WRITEUP.md

The write-up is not optional and honest gaps don't lose points, but hand-waving does. Graders would rather read "I didn't get to X, and here's how I'd approach it" than a vague claim of completeness. Here's a skeleton you can drop in and fill:

```markdown
# Acme Health: GRC Engineering Capstone Write-up

## Primary framework
[Name your framework in the first paragraph. Three sentences on why it fits
this telehealth system better than the other two.]

## Control coverage
[For each gap from GAPS.md: which control it maps to, and whether you closed
it in Terraform, enforced it in policy, or both. A table works well here.]

## Design decisions
[Walk each decision from the brief: region, Object Lock mode, apply-on-merge
vs manual gate, single vs separate account, Terraform-vs-policy split.
For each, state what you chose and the trade-off you accepted.]

## How the pipeline produces evidence
[Trace one run end to end: PR opened → gate → apply → sign → vault.
Name the run ID an assessor can verify.]

## Trade-offs and what I'd do with another sprint
[Be specific and honest. This section earns more than a padded "everything works."]

## What I didn't get to
[Name it plainly. This costs nothing and signals judgment.]
```

If you wrote your one-page design doc in Week 1, most of the first three sections are already drafted.

## Submission checklist

The graded checklist is maintained in one place, the [Capstone Brief](07_01_capstone_brief.md#submission-checklist). Work from that list, not a copy of it, so you're never checking boxes against a stale version.

## Three mistakes to avoid

- **Too much scope.** Thirty resources cleanly integrated beat two hundred bolted on.
- **Copy-paste OSCAL.** An OSCAL file that doesn't describe your real system is worse than none. Authenticity over completeness.
- **Unsigned evidence.** A pipeline that produces a plan but never signs and immutably stores it hasn't demonstrated chain of custody, which is the entire point.

## The finish line

The output of all of this is one thing: a working evidence vault where every push to `main` produces a signed, timestamped artifact in immutable storage, automatically. An assessor who never meets you can start at your OSCAL component, follow a link to a vault object, verify it, and see `CHAIN INTACT`. That traversal is the whole course demonstrated in a single command, and if you did the labs, you've already built every link in it. Now you assemble them, wire them together, explain your choices, and ship.

Ship the repo. Earn the cert.
