# Additional Resources

Curated videos and official docs for concepts used in the labs. Start with [Getting Started](../getting-started/tools.md) if you have not set up tools yet.

## Terraform / Infrastructure as Code

- [HashiCorp — Terraform explained (YouTube)](https://www.youtube.com/watch?v=h970ZBgGo58) — short mental model for plan/apply and providers before [Lab 2.3](02_03_first_compliant_resource.md).
- [Terraform Install docs](https://developer.hashicorp.com/terraform/install) — official install paths referenced in Getting Started.
- [Terraform Language docs](https://developer.hashicorp.com/terraform/language) — resources, modules, and variables used across Chapter 2.

## AWS CLI

- [AWS — Getting started with the AWS CLI (YouTube)](https://www.youtube.com/watch?v=Y2X_zXbf9LQ) — profiles, identity, and basic commands used before Terraform can authenticate.
- [AWS CLI install guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) — vendor install instructions from Getting Started.
- [sts get-caller-identity](https://docs.aws.amazon.com/cli/latest/reference/sts/get-caller-identity.html) — the connectivity check used in the labs.

## OPA / Rego / Conftest

- [Open Policy Agent — Introduction (YouTube)](https://www.youtube.com/watch?v=Xorjk5XOiOw) — why OPA exists before you write `deny` rules in [Lab 3.3](03_03_writing_compliance_policies_rego.md).
- [OPA docs](https://www.openpolicyagent.org/docs) — language and CLI reference.
- [Conftest docs](https://www.conftest.dev/) — running Rego against Terraform plan JSON in [Lab 3.4](03_04_integrating_pac_with_terraform.md).

## OSCAL / trestle

- [NIST — Introduction to OSCAL (YouTube)](https://www.youtube.com/watch?v=gq7PDc87M-U) — catalog / profile / component mental model for [Lab 6.1](06_01_introduction_to_oscal.md).
- [OSCAL site](https://pages.nist.gov/OSCAL/) — official models and examples.
- [compliance-trestle](https://github.com/oscal-compass/compliance-trestle) — the validation/authoring toolkit used in Lab 6.1.

## GitHub Actions and OIDC

- [GitHub — Introduction to GitHub Actions (YouTube)](https://www.youtube.com/watch?v=cP-cnX55YVY) — workflow basics before [Lab 4.3](04_03_grc_evidence_pipeline.md).
- [Configuring OpenID Connect in Amazon Web Services](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services) — the keyless AWS trust pattern used in Lab 4.3.

## Evidence signing (Cosign / Sigstore)

- [Sigstore — Overview (YouTube)](https://www.youtube.com/watch?v=BD9ezcZKGE8) — why keyless signing helps chain-of-custody claims in [Lab 4.4](04_04_evidence_chain_of_custody.md).
- [Cosign docs](https://docs.sigstore.dev/cosign/system_config/installation/) — install and verify commands used with the evidence vault.

## AWS security services

- [AWS — AWS CloudTrail overview (YouTube)](https://www.youtube.com/watch?v=xoX48dSSOQw) — continuous activity logging for [Lab 5.2](05_02_aws_security_services.md).
- [Security Hub user guide](https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html) — findings aggregation mapped to controls.
- [AWS Config developer guide](https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html) — configuration history / rules context from Lab 5.2.

## GCP security services

- [Google Cloud — Organization Policy Service (docs)](https://cloud.google.com/resource-manager/docs/organization-policy/overview) — guardrails used in [Lab 5.4](05_04_gcp_security_services.md).
- [Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation) — keyless federation concepts parallel to the AWS OIDC lab.
- [Cloud Audit Logs](https://cloud.google.com/logging/docs/audit) — GCP's always-on admin/data access logging story.

## How to suggest additions

Open a PR that edits `wiki-source/Additional-Resources.md` in the main repo. Prefer official org channels and primary documentation over random tutorials.
