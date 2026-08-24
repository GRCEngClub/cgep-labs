# Set up your tools

Complete this once before any lab. It covers the tools every guide assumes.

If you already have Git Bash (or a native bash shell), Terraform, and the AWS CLI working, continue to [Set up your repo](repo-structure.md).

Skip ahead to Part 2 if you already have Git Bash, Terraform, and the AWS CLI working. If any of those is new to you, read on. Getting this right once saves you from a dozen confusing errors later.

## The tools you need, and where to get them

Every link below points at the official source. Don't install these from random blog mirrors; cloud tooling is exactly the kind of thing you want to get from the vendor.

| Tool | What it does | Official download |
|---|---|---|
| **Git for Windows (Git Bash)** | Gives Windows a Unix-style terminal so every command in these guides runs as written. Mac and Linux already have this. | https://git-scm.com/download/win |
| **Terraform** | Turns your `.tf` files into real cloud resources. The core of every IaC lab. | https://developer.hashicorp.com/terraform/install |
| **AWS CLI v2** | Lets you talk to AWS from the terminal, and lets Terraform authenticate. | https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html |

Three more tools show up in later labs. You don't need them today, but here's where they live so you can install them ahead of time if you like:

| Tool | First used in | Official download |
|---|---|---|
| **Google Cloud CLI (`gcloud`)** | Lab 2.4 (GCP) | https://cloud.google.com/sdk/docs/install |
| **OPA (Open Policy Agent)** | Lab 3.3 (Rego policies) | https://www.openpolicyagent.org/docs and releases at https://github.com/open-policy-agent/opa/releases |
| **Cosign** | Lab 2.5 / Lab 4.4 (signing evidence) | https://docs.sigstore.dev/cosign/system_config/installation/ and releases at https://github.com/sigstore/cosign/releases |

## Windows users: set up Git Bash

These guides are written in bash, the command language that ships with Mac and Linux. On Windows, the closest thing you'll already have is PowerShell, but PowerShell uses different syntax for a lot of these commands. Rather than translate every command, we standardize the whole cohort on **Git Bash**, which gives you a real bash terminal on Windows. When a guide says to run `mkdir -p terraform/primitives/compliant-s3`, you'll be able to paste it exactly as written.

1. Download and run the installer from https://git-scm.com/download/win. Accepting the default options at every screen is fine.
2. After it installs, you'll have a "Git Bash" entry in your Start menu. That's your terminal for these labs.

**Make Git Bash your default terminal in VS Code.** If you use VS Code (recommended), tell it to open Git Bash instead of PowerShell so your integrated terminal matches the guides:

- Open the Command Palette with `Ctrl+Shift+P`.
- Type `Terminal: Select Default Profile` and select it.
- Choose **Git Bash** from the list.
- Open a new terminal (`` Ctrl+` ``). It should now be a Git Bash prompt.

**Run this one config command before you do anything else.** Windows and Unix disagree about how lines end in text files, and that disagreement can silently corrupt shell scripts you'll write in later labs. This setting tells Git to leave your files alone:

```bash
git config --global core.autocrlf input
```

### Git Bash quirks worth knowing now

You probably won't hit these in this lab, but they cause real head-scratching later, so file them away:

- **Mangled paths.** Git Bash tries to be helpful by converting anything that looks like a Unix path (starting with `/`) into a Windows path. That's great for filenames and wrong for things like S3 keys, ARNs, or `file:///...` arguments. If a command fails with a path that looks half-rewritten, run it again with `MSYS_NO_PATHCONV=1` in front, for example `MSYS_NO_PATHCONV=1 aws s3api ...`.
- **`sha256sum` vs `shasum`.** Git Bash ships `sha256sum`. macOS ships `shasum -a 256`. They compute the same hash; later lab scripts detect which one you have automatically.

## Mac and Linux users

You already have bash, so there's nothing extra to install for the terminal itself. Install Terraform and the AWS CLI from the official links above. On Mac, Homebrew is the easy path: `brew install terraform awscli`. On Ubuntu, the install pages above include `apt` instructions.

## Confirm everything works

Open your terminal (Git Bash on Windows) and run each of these. You want a version number back from each one, not a "command not found":

```bash
git --version
terraform version
aws --version
```

If any command isn't found, the tool either didn't install or isn't on your PATH. The official install pages above each have a "verify your installation" section that walks through fixing PATH issues for your OS.

## Connect the AWS CLI to your account

Terraform doesn't log into AWS by itself. It borrows credentials from the AWS CLI. You need a working CLI profile before Terraform will do anything.

- If your sandbox uses a plain access key, run `aws configure` and paste in your key, secret, and default region (`us-east-1` for this lab).
- If your sandbox uses AWS SSO (also called IAM Identity Center), run `aws configure sso` and follow the browser prompts.

Commands in this guide (and later labs) use `--profile default` so you can paste them as-is if you kept the usual AWS CLI profile name. **If you named your profile something else during `aws configure` or `aws configure sso`, replace `default` with that name** wherever you see `--profile default`.

Confirm the CLI can reach your account:

```bash
aws sts get-caller-identity --profile default
```

A JSON blob with your account ID means you're connected.

---

Next: [Set up your repo](repo-structure.md), then [Lab 2.3](../guides/02_03_first_compliant_resource.md).
