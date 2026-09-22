#!/usr/bin/env python3
"""
Produces CSO overview, KSI implementation summary, Security Decision Record,
and copies the control mapping and exception registry into a single package
directory.
"""

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

KSI_IMPLEMENTATIONS = [
    {
        "ksi": "KSI-SVC-SIN",
        "name": "Securing Information",
        "status": "implemented",
        "validation_methods": [
            {"type": "opa_policy", "path": "policies/rego/svc/securing_information.rego", "automated": True},
            {"type": "terraform_module", "path": "terraform/modules/kms", "automated": True},
        ],
        "evidence": "ksi-results.json",
    },
    {
        "ksi": "KSI-SVC-ACM",
        "name": "Automating Configuration Management",
        "status": "implemented",
        "validation_methods": [
            {"type": "opa_policy", "path": "policies/rego/svc/automating_config_management.rego", "automated": True},
            {"type": "drift_detection", "path": "scripts/generate_evidence.py", "automated": True},
        ],
        "evidence": "terraform-drift.json",
    },
    {
        "ksi": "KSI-SVC-ASM",
        "name": "Automating Secret Management",
        "status": "implemented",
        "validation_methods": [
            {"type": "opa_policy", "path": "policies/rego/svc/automating_secret_management.rego", "automated": True},
            {"type": "terraform_module", "path": "terraform/modules/secretsmanager", "automated": True},
        ],
        "evidence": "ksi-results.json",
    },
    {
        "ksi": "KSI-CNA-RNT",
        "name": "Restricting Network Traffic",
        "status": "implemented",
        "validation_methods": [
            {"type": "opa_policy", "path": "policies/rego/cna/restricting_network_traffic.rego", "automated": True},
        ],
        "evidence": "ksi-results.json",
    },
    {
        "ksi": "KSI-CNA-MAT",
        "name": "Minimizing Attack Surface",
        "status": "implemented",
        "validation_methods": [
            {"type": "opa_policy", "path": "policies/rego/cna/minimizing_attack_surface.rego", "automated": True},
            {"type": "terraform_module", "path": "terraform/modules/guardduty", "automated": True},
        ],
        "evidence": "ksi-results.json",
    },
    {
        "ksi": "KSI-CNA-ULN",
        "name": "Using Logical Networking",
        "status": "implemented",
        "validation_methods": [
            {"type": "opa_policy", "path": "policies/rego/cna/using_logical_networking.rego", "automated": True},
        ],
        "evidence": "ksi-results.json",
    },
    {
        "ksi": "KSI-CNA-RVP",
        "name": "Reviewing Protections",
        "status": "implemented",
        "validation_methods": [
            {"type": "opa_policy", "path": "policies/rego/cna/reviewing_protections.rego", "automated": True},
        ],
        "evidence": "ksi-results.json",
    },
    {
        "ksi": "KSI-IAM-ELP",
        "name": "Ensuring Least Privilege",
        "status": "implemented",
        "validation_methods": [
            {"type": "opa_policy", "path": "policies/rego/iam/ensuring_least_privilege.rego", "automated": True},
        ],
        "evidence": "ksi-results.json",
    },
    {
        "ksi": "KSI-IAM-AAM",
        "name": "Automating Account Management",
        "status": "implemented",
        "validation_methods": [
            {"type": "opa_policy", "path": "policies/rego/iam/automating_account_management.rego", "automated": True},
            {"type": "terraform_module", "path": "terraform/modules/iam", "automated": True},
        ],
        "evidence": "ksi-results.json",
    },
    {
        "ksi": "KSI-IAM-APM",
        "name": "Adopting Passwordless Methods",
        "status": "implemented",
        "validation_methods": [
            {"type": "opa_policy", "path": "policies/rego/iam/adopting_passwordless_methods.rego", "automated": True},
        ],
        "evidence": "ksi-results.json",
    },
    {
        "ksi": "KSI-IAM-SNU",
        "name": "Securing Non-User Authentication",
        "status": "implemented",
        "validation_methods": [
            {"type": "opa_policy", "path": "policies/rego/iam/securing_non_user_auth.rego", "automated": True},
        ],
        "evidence": "ksi-results.json",
    },
    {
        "ksi": "KSI-MLA-LET",
        "name": "Logging Event Types",
        "status": "implemented",
        "validation_methods": [
            {"type": "opa_policy", "path": "policies/rego/mla/logging_event_types.rego", "automated": True},
            {"type": "terraform_module", "path": "terraform/modules/cloudwatch", "automated": True},
        ],
        "evidence": "ksi-results.json",
    },
    {
        "ksi": "KSI-MLA-EVC",
        "name": "Evaluating Configurations",
        "status": "implemented",
        "validation_methods": [
            {"type": "pipeline", "path": ".github/workflows/persistent-validation.yml", "automated": True},
        ],
        "evidence": "pipeline execution logs",
    },
    {
        "ksi": "KSI-MLA-OSM",
        "name": "Operating SIEM Capability",
        "status": "implemented",
        "validation_methods": [
            {"type": "opa_policy", "path": "policies/rego/mla/operating_siem.rego", "automated": True},
            {"type": "terraform_module", "path": "terraform/modules/securityhub", "automated": True},
        ],
        "evidence": "ksi-results.json",
    },
    {
        "ksi": "KSI-MLA-RVL",
        "name": "Reviewing Logs",
        "status": "implemented",
        "validation_methods": [
            {"type": "pipeline", "path": ".github/workflows/persistent-validation.yml", "automated": True},
        ],
        "evidence": "evidence artifacts in S3",
    },
    {
        "ksi": "KSI-RPL-ABO",
        "name": "Aligning Backups with Objectives",
        "status": "implemented",
        "validation_methods": [
            {"type": "opa_policy", "path": "policies/rego/rpl/aligning_backups.rego", "automated": True},
            {"type": "terraform_module", "path": "terraform/modules/backup", "automated": True},
        ],
        "evidence": "ksi-results.json",
    },
    {
        "ksi": "KSI-INR-RIR",
        "name": "Reviewing Incident Response Procedures",
        "status": "implemented",
        "validation_methods": [
            {"type": "terraform_module", "path": "terraform/modules/sns", "automated": True},
            {"type": "terraform_module", "path": "terraform/modules/cloudwatch", "automated": True},
        ],
        "evidence": "SNS + EventBridge + CloudWatch alarms",
    },
]

SECURITY_DECISIONS = [
    {
        "id": "SDR-001",
        "title": "Infrastructure as Code for all resources",
        "decision": "All AWS infrastructure is managed via Terraform with no manual console changes permitted",
        "rationale": "Ensures reproducibility, auditability, and drift detection (KSI-SVC-ACM, KSI-MLA-EVC)",
        "date": "TODO",
        "status": "active",
    },
    {
        "id": "SDR-002",
        "title": "Policy-as-Code for compliance enforcement",
        "decision": "OPA/Rego policies enforce KSI compliance at plan time and during persistent validation",
        "rationale": "Automated, repeatable compliance checks that run pre-deploy and every 2 days (KSI-MLA-EVC)",
        "date": "TODO",
        "status": "active",
    },
    {
        "id": "SDR-003",
        "title": "KMS encryption for all data at rest",
        "decision": "All S3 buckets, EBS volumes, RDS instances, and secrets use AWS KMS encryption",
        "rationale": "Meets KSI-SVC-SIN requirements for securing information from unwanted access",
        "date": "TODO",
        "status": "active",
    },
    {
        "id": "SDR-004",
        "title": "GitHub Actions OIDC for AWS access",
        "decision": "CI/CD pipelines authenticate to AWS via OIDC federation, not long-lived credentials",
        "rationale": "Eliminates static credentials in CI, aligns with KSI-IAM-SNU",
        "date": "TODO",
        "status": "active",
    },
    {
        "id": "SDR-005",
        "title": "Evidence retention policy",
        "decision": "Compliance evidence retained for 18 months in versioned, encrypted S3",
        "rationale": "Meets Class D historical metrics requirement; lifecycle transitions to IA at 90d, Glacier at 180d",
        "date": "TODO",
        "status": "active",
    },
]


def write_json(path: Path, data: dict) -> None:
    """Write a dict to a JSON file with pretty formatting."""
    path.write_text(json.dumps(data, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate FedRAMP 20x Certification Package")
    parser.add_argument("--output-dir", default="certification-package", help="Output directory (default: certification-package)")
    args = parser.parse_args()

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=== Generating FedRAMP 20x Certification Package ===")
    print(f"  Output: {output_dir}/")
    print(f"  Date:   {timestamp}")
    print()

    write_json(output_dir / "cso-overview.json", {
        "document_type": "cso_overview",
        "generated_at": timestamp,
        "cloud_service_offering": {
            "name": "TODO: Service name",
            "description": "TODO: Service description",
            "service_model": "TODO: IaaS/PaaS/SaaS",
            "deployment_model": "TODO: Public/Private/Community/Hybrid",
            "impact_level": "TODO: Low/Moderate/High",
            "target_certification_class": "TODO: A/B/C/D",
        },
        "environments": ["dev", "staging", "prod"],
        "infrastructure": {
            "provider": "AWS",
            "regions": ["us-east-2"],
            "managed_by": "Terraform",
        },
    })

    print(">>> Generating KSI implementation summary...")
    write_json(output_dir / "ksi-implementation.json", {
        "document_type": "ksi_implementation",
        "generated_at": timestamp,
        "ksi_count": len(KSI_IMPLEMENTATIONS),
        "ksis": KSI_IMPLEMENTATIONS,
    })

    write_json(output_dir / "security-decision-record.json", {
        "document_type": "security_decision_record",
        "generated_at": timestamp,
        "decisions": SECURITY_DECISIONS,
    })

    print(">>> Copying exception registry...")
    exceptions_src = Path("policies/exceptions.yaml")
    if exceptions_src.exists():
        shutil.copy2(exceptions_src, output_dir / "exceptions.yaml")
    else:
        print("  No exceptions file found")

    print(">>> Copying control mapping...")
    shutil.copy2(Path("policies/control-mapping.yaml"), output_dir / "control-mapping.yaml")

    print()
    print(f"=== Certification Package generated in {output_dir}/ ===")
    print()
    print("Files:")
    for f in sorted(output_dir.iterdir()):
        print(f"  {f.name} ({f.stat().st_size} bytes)")

    print()
    print("TODO items remaining:")
    todo_count = 0
    for f in sorted(output_dir.glob("*.json")):
        content = f.read_text()
        for i, line in enumerate(content.splitlines(), 1):
            if "TODO" in line:
                print(f"  {f.name}:{i}: {line.strip()}")
                todo_count += 1
    if todo_count == 0:
        print("  None found")


if __name__ == "__main__":
    main()
