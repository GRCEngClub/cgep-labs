# cgep-labs

> Hands-on labs and reference workspaces for the **Certified GRC Engineer Practitioner (CGE-P)** by the [GRC Engineering Club](https://grcengclub.com).

## What's here

```
guides/        Lab guides, one markdown file per lab
reference/     Companion Terraform / Rego / shell workspaces, one per lab
```

The guides are the lab. The reference workspaces are the same code in deployable form so you can run it and see it work, then build your own version in your capstone repo.

## Lab inventory

| # | Lab | Cloud |
|---|---|---|
| [2.3](guides/02_03_first_compliant_resource.md) | First Compliant Resource | AWS |
| [2.4](guides/02_04_terraform_modules_for_compliance.md) | Terraform Modules for Compliance | GCP |
| [2.5](guides/02_05_iac_as_compliance_evidence.md) | IaC as Compliance Evidence | AWS |
| [3.3](guides/03_03_writing_compliance_policies_rego.md) | Writing Compliance Policies in Rego | GCP |
| [3.4](guides/03_04_integrating_pac_with_terraform.md) | Integrating PaC with Terraform (Conftest) | AWS |
| [4.3](guides/04_03_grc_evidence_pipeline.md) | Building a GRC Evidence Pipeline | AWS + GitHub Actions |
| [4.4](guides/04_04_evidence_chain_of_custody.md) | Evidence Management & Chain of Custody | AWS |
| [5.2](guides/05_02_aws_security_services.md) | AWS Security Services Baseline | AWS |
| [5.4](guides/05_04_gcp_security_services.md) | GCP Security Services Baseline | GCP |
| [6.1](guides/06_01_introduction_to_oscal.md) | Introduction to OSCAL | Cloud-agnostic |
| [7.1](guides/07_01_capstone_brief.md) | Capstone Brief | AWS |

The labs alternate between AWS and GCP on purpose. The compliance-by-default pattern is cloud-agnostic; doing it in two providers makes that obvious.

## How this connects

- The lab guides live here and are mirrored into the lessons on [cert.grcengclub.com](https://cert.grcengclub.com).
- The capstone wraps the workload in [`GRCEngClub/cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter), a deliberately non-compliant Patient-Intake API. Several labs reference it.
- Every lab produces an artifact that drops directly into your capstone repo. The capstone is assembly, not from-scratch construction.

## Running a reference workspace

Each `reference/lab-X-Y/` is a self-contained Terraform / Rego / shell workspace. The published guide tells the full story; this directory is the code.

For Terraform-touching labs:

```bash
cd reference/lab-2-3
eval "$(aws configure export-credentials --profile <your-sandbox> --format env)"
terraform init
terraform plan -out=tfplan
terraform apply -auto-approve tfplan
# verify with the commands in the guide
terraform destroy -auto-approve
```

For Rego-only labs (3.3, 3.4):

```bash
cd reference/lab-3-3
opa test -v policies/
```

Always tear down at the end of the session. Reference workspaces are not meant to live deployed.

## Required tooling

- `terraform >= 1.6`
- `opa >= 0.60`
- `conftest >= 0.50` (Lab 3.4 onwards)
- `cosign >= 2.0` (Lab 4.4)
- `tfsec` (Lab 4.3)
- `compliance-trestle` Python package (Lab 6.1)
- `aws` CLI v2 with a working SSO or access-key profile
- `gcloud` CLI for GCP labs

## Contributing

PRs welcome for:

- Cloud version drift (a Terraform argument deprecated, a CLI flag renamed).
- Bugs in reference workspaces.
- Clarity edits to lab guides.

Out of scope: scope expansion, alternate framework framings beyond NIST 800-53 / HIPAA / SOC 2 / CMMC L2.

## License

MIT.
