# Infrastructure as Code for Compliance

The idea behind this repository is to lab out what IaC could look like in a FedRAMP 20x space using Terraform, OPA, and GitHub Actions on AWS.

Policies are mapped to [FedRAMP 20x Key Security Indicators (KSIs)](https://www.fedramp.gov/2026/reference/20x/b/key-security-indicators/) and validated both at deploy time and on a persistent schedule meeting the 20x continuous monitoring cadence.

## Repository Structure

```
compliance-iac/
├── .github/workflows/
│   ├── terraform.yml               # Plan + policy check on PR, apply on merge to main
│   ├── terraform-promote.yml       # Multi-env promotion: staging/prod with approval gates
│   └── conmon.yml                  # Scheduled KSI validation (every 2 days)
├── terraform/
│   ├── bootstrap/                  # Backend state resources (local state, run first)
│   ├── environments/
│   │   ├── dev/                    # Dev environment (10.0.0.0/16, 2 AZs)
│   │   ├── staging/                # Staging environment (10.1.0.0/16, 2 AZs)
│   │   └── prod/                   # Production environment (10.2.0.0/16, 3 AZs)
│   └── modules/
│       ├── vpc/                    # VPC, subnets, NAT, flow logs
│       ├── iam/                    # Account password policy, admin/readonly roles
│       ├── kms/                    # KMS key with rotation
│       ├── guardduty/              # Threat detection
│       ├── securityhub/            # Centralized findings aggregation
│       ├── config/                 # Configuration recording
│       ├── cloudwatch/             # Security log groups and alarms
│       ├── sns/                    # Security alert topics + EventBridge rules
│       ├── secretsmanager/         # Secrets with auto-rotation
│       ├── backup/                 # Backup plans and vault with lock
│       └── evidence-store/         # S3 bucket for compliance evidence
├── policies/
│   ├── rego/
│   │   ├── svc/                    # Service Configuration KSIs
│   │   ├── cna/                    # Cloud Native Architecture KSIs
│   │   ├── iam/                    # Identity and Access Management KSIs
│   │   ├── mla/                    # Monitoring, Logging, and Auditing KSIs
│   │   ├── rpl/                    # Recovery Planning KSIs
│   │   └── lib/                    # Shared Rego helpers + exception handling
│   ├── control-mapping.yaml        # KSI-to-policy-to-module mapping
│   └── exceptions.yaml             # Exception/waiver registry
├── scripts/
│   ├── generate_evidence.py        # Run validation and produce evidence artifacts
│   ├── upload_evidence.py          # Push evidence to S3
│   ├── generate_cert_package.py    # Generate FedRAMP Certification Package
│   └── generate_ocr.py             # Generate Ongoing Certification Report
└── reports/
    └── templates/
        └── ongoing-certification-report.md  # Quarterly OCR template
```