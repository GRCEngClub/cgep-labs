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
| 2.3 | First Compliant Resource | AWS |
| 2.4 | Terraform Modules for Compliance | GCP |
| 2.5 | IaC as Compliance Evidence | AWS |
| 3.3 | Writing Compliance Policies in Rego | GCP |
| 3.4 | Integrating PaC with Terraform (Conftest) | AWS |
| 4.3 | Building a GRC Evidence Pipeline | AWS + GitHub Actions |
| 4.4 | Evidence Management & Chain of Custody | AWS |
| 5.2 | AWS Security Services Baseline | AWS |
| 5.4 | GCP Security Services Baseline | GCP |
| 6.1 | Introduction to OSCAL | Cloud-agnostic |
| 7.1 | Capstone brief | AWS |

The labs alternate between AWS and GCP on purpose. The compliance-by-default pattern is cloud-agnostic; doing it in two providers makes that obvious.

## How this connects

- The lab guides live here and are mirrored into the lessons on [cert.grcengclub.com](https://cert.grcengclub.com).
- The capstone wraps the workload in [`GRCEngClub/cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter), a deliberately non-compliant Patient-Intake API. Several labs reference it.
- Every lab produces an artifact that drops directly into your capstone repo. The capstone is assembly, not from-scratch construction.

## Running a reference workspace

Each `reference/lab-X-Y/` is a self-contained Terraform workspace. The published guide tells the full story. This directory is the code.

```bash
cd reference/lab-2-3
eval "$(aws configure export-credentials --profile <your-sandbox> --format env)"
terraform init
terraform plan -out=tfplan
terraform apply -auto-approve tfplan
# verify with the commands in guides/02_03_first_compliant_resource.md
terraform destroy -auto-approve
```

Always tear down at the end of the session. Reference workspaces are not meant to live deployed.

## Contributing

PRs welcome for:

- Cloud version drift (a Terraform argument deprecated, a CLI flag renamed).
- Bugs in reference workspaces.
- Clarity edits to lab guides.

Out of scope for now: scope expansion, alternate framework framings beyond NIST 800-53 / HIPAA / SOC 2 / CMMC L2.

## License

MIT.
