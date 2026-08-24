# Set up your repo

This is the `cgep-labs` repository shape every later lab reuses. Do it once, before Lab 2.3.

Prerequisite: [Set up your tools](tools.md).

This is the part that tripped up the last cohort, so we're going to be explicit. Every lab in this course drops files into the same repository, in the same shape. Get the shape right once, here, and the rest of the course just slots into it. Get it wrong, and you'll spend later labs hunting for files that aren't where the guide expects.

## The mental model

You're building **one repository** called `cgep-labs`. It lives in two places at once:

- **On your machine**, as a folder you work in.
- **On GitHub**, as the published copy your instructor reviews.

These aren't two different things. When you `git push`, your local folder becomes the GitHub copy, file for file. So when a guide talks about "the version that gets evaluated," it means your `cgep-labs` repo on GitHub, which is just your local folder after you've pushed it. There's no separate "submission" copy to assemble.

(Your final capstone is a separate repository later on, a fork of the starter app. It uses this exact same structural discipline, so the habits you build here carry straight over.)

## Create the structure

Pick a home for your work (your Documents folder is fine) and build the skeleton — including the empty files this lab will fill in. From your terminal:

```bash
mkdir -p cgep-labs
cd cgep-labs

# Repo-wide folders every later lab reuses
mkdir -p terraform/primitives terraform/modules scripts evidence

# This lab's empty files (matches the diagram below)
mkdir -p terraform/primitives/compliant-s3 evidence/lab-2-3
touch README.md .gitignore \
  terraform/primitives/compliant-s3/main.tf \
  terraform/primitives/compliant-s3/variables.tf \
  terraform/primitives/compliant-s3/outputs.tf \
  terraform/primitives/compliant-s3/README.md

# Confirm the shape
find terraform/primitives/compliant-s3 evidence/lab-2-3 -type f | sort
```

Here's what you just created and what each folder is for:

```
cgep-labs/                        ← repository root. Everything lives under here.
│
├── README.md                     ← what this repo is (you'll create this below)
├── .gitignore                    ← tells Git which files NOT to publish
│
├── terraform/                    ← all your infrastructure-as-code
│   ├── primitives/               ← standalone units you deploy directly
│   │   └── compliant-s3/         ← THIS lab lives here
│   │       ├── main.tf
│   │       ├── variables.tf
│   │       ├── outputs.tf
│   │       └── README.md
│   └── modules/                  ← reusable modules (Lab 2.4 fills this in)
│
├── scripts/                      ← shared scripts (Lab 2.5 adds one here)
│
└── evidence/                     ← captured proof, one folder per lab
    └── lab-2-3/                  ← THIS lab's evidence lands here
        ├── plan.json             ← filled in when you capture evidence
        └── state.json            ← filled in when you capture evidence
```

Two ideas are doing all the work in this layout, and they're worth saying out loud:

- **Code and evidence are separate.** Your Terraform lives under `terraform/`. The proof you capture lives under `evidence/`, named by lab. A reviewer can find every artifact for Lab 2.3 in `evidence/lab-2-3/` without digging through your code. This separation is also why a later lab can capture evidence *from* an earlier lab's workspace; the workspace is always `terraform/.../<thing>`, and the evidence always lands in `evidence/lab-X-Y/`.
- **`primitives/` vs `modules/`.** A primitive is something you deploy as-is. A module is a reusable template that other code calls. This lab builds a primitive. Lab 2.4 builds your first module. Keeping them in separate folders keeps that distinction visible.

## Add a `.gitignore` before you commit anything

This step matters more than it looks. When Terraform runs, it creates files you must **not** publish to GitHub:

- `terraform.tfstate` and its backups: Terraform's record of what it built. It can contain sensitive values, and it's specific to your machine.
- The `.terraform/` directory: hundreds of megabytes of downloaded provider plugins. No one needs your copy.
- `.terraform.lock.hcl`: the provider dependency lock. It's useful in a long-lived production repo, but it's not part of this course's submission, so we keep it out to match the checklist exactly.
- `tfplan`: the saved binary plan from `terraform plan -out=tfplan`. It's scratch input for `apply`, not an artifact a reviewer wants.
- `*.tfvars`: where people often put secrets.

A `.gitignore` file tells Git to skip these. Open the empty **`.gitignore`** at the repo root (created in the scaffold above) and paste this in, or overwrite it from the terminal:

```bash
cat > .gitignore << 'EOF'
# Terraform working files (never publish these)
.terraform/
.terraform.lock.hcl
*.tfstate
*.tfstate.*
*.tfvars
tfplan
*.tfplan
crash.log

# OS noise
.DS_Store
EOF
```

Notice what this does *not* ignore: your `evidence/` folder. The files in there are named `plan.json` and `state.json`, not `*.tfstate`, so they sail right past these rules. That's deliberate. The live state file is private working data; the evidence snapshot is the artifact you *want* reviewed. Same data, captured for two different purposes, treated two different ways. Understanding that distinction is half of what this course is about.

## Initialize Git and push to GitHub

```bash
git init
git add .
git commit -m "Scaffold cgep-labs repo structure"
```

Then create an empty repository named `cgep-labs` on GitHub (don't let GitHub add a README or .gitignore, since you already have them), and connect it:

```bash
git remote add origin https://github.com/<your-username>/cgep-labs.git
git branch -M main
git push -u origin main
```

From now on, finishing a lab means committing your new files and running `git push`. That published copy is what gets reviewed.

---


---

## What's next

Continue with [Lab 2.3: Building Your First Compliant Resource](../guides/02_03_first_compliant_resource.md). Unfamiliar terms? See the [Glossary](../guides/glossary.md). For videos and official docs, see [Additional Resources](../guides/additional_resources.md).
