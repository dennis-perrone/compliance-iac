#!/usr/bin/env python3
"""Generate FedRAMP 20x persistent validation evidence artifacts.

Runs Terraform drift detection and OPA policy evaluation against a target
environment, then produces machine-readable (JSON) and human-readable (Markdown)
evidence artifacts.
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

KSI_COVERAGE = [
    {"ksi": "KSI-SVC-SIN", "name": "Securing Information", "policy": "svc/securing_information.rego", "method": "OPA policy check"},
    {"ksi": "KSI-SVC-ACM", "name": "Automating Configuration Management", "policy": "svc/automating_config_management.rego", "evidence": "terraform-drift.json", "method": "OPA + Terraform drift detection"},
    {"ksi": "KSI-SVC-ASM", "name": "Automating Secret Management", "policy": "svc/automating_secret_management.rego", "method": "OPA policy check"},
    {"ksi": "KSI-CNA-RNT", "name": "Restricting Network Traffic", "policy": "cna/restricting_network_traffic.rego", "method": "OPA policy check"},
    {"ksi": "KSI-CNA-MAT", "name": "Minimizing Attack Surface", "policy": "cna/minimizing_attack_surface.rego", "method": "OPA policy check"},
    {"ksi": "KSI-CNA-ULN", "name": "Using Logical Networking", "policy": "cna/using_logical_networking.rego", "method": "OPA policy check"},
    {"ksi": "KSI-CNA-RVP", "name": "Reviewing Protections", "policy": "cna/reviewing_protections.rego", "method": "OPA policy check"},
    {"ksi": "KSI-IAM-ELP", "name": "Ensuring Least Privilege", "policy": "iam/ensuring_least_privilege.rego", "method": "OPA policy check"},
    {"ksi": "KSI-IAM-AAM", "name": "Automating Account Management", "policy": "iam/automating_account_management.rego", "method": "OPA policy check"},
    {"ksi": "KSI-IAM-APM", "name": "Adopting Passwordless Methods", "policy": "iam/adopting_passwordless_methods.rego", "method": "OPA policy check"},
    {"ksi": "KSI-IAM-SNU", "name": "Securing Non-User Authentication", "policy": "iam/securing_non_user_auth.rego", "method": "OPA policy check"},
    {"ksi": "KSI-MLA-LET", "name": "Logging Event Types", "policy": "mla/logging_event_types.rego", "method": "OPA policy check"},
    {"ksi": "KSI-MLA-EVC", "name": "Evaluating Configurations", "policy": "mla/evaluating_configurations.rego", "method": "Pipeline execution"},
    {"ksi": "KSI-MLA-OSM", "name": "Operating SIEM Capability", "policy": "mla/operating_siem.rego", "method": "OPA policy check"},
    {"ksi": "KSI-RPL-ABO", "name": "Aligning Backups with Objectives", "policy": "rpl/aligning_backups.rego", "method": "OPA policy check"},
]


def run_command(cmd: list[str], cwd: str | None = None, capture: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command and return the result."""
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=capture,
        text=True,
    )


def get_tool_version(cmd: list[str]) -> str:
    """Get a tool's version string, returning 'unknown' on failure."""
    try:
        result = run_command(cmd)
        return result.stdout.strip().splitlines()[0] if result.returncode == 0 else "unknown"
    except FileNotFoundError:
        return "not installed"


def get_commit_sha() -> str:
    """Get the current git commit SHA."""
    sha = os.environ.get("GITHUB_SHA")
    if sha:
        return sha
    result = run_command(["git", "rev-parse", "HEAD"])
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def detect_drift(working_dir: str, evidence_dir: Path) -> bool:
    """Run terraform plan to detect drift. Returns True if drift is detected."""
    print(">>> Terraform drift detection...")

    result = run_command(["terraform", "init", "-input=false"], cwd=working_dir)
    if result.returncode != 0:
        print(f"  ERROR: terraform init failed\n{result.stderr}", file=sys.stderr)
        sys.exit(1)

    drift_file = evidence_dir / "terraform-drift.json"
    result = run_command(
        ["terraform", "plan", "-detailed-exitcode", "-json", "-out=drift-plan.out"],
        cwd=working_dir,
    )

    drift_file.write_text(result.stdout)

    plan_file = Path(working_dir) / "drift-plan.out"
    if plan_file.exists():
        plan_file.unlink()

    if result.returncode == 2:
        print("  DRIFT DETECTED — see terraform-drift.json")
        return True
    elif result.returncode == 1:
        print(f"  ERROR running terraform plan\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    else:
        print("  No drift detected")
        return False


def run_conftest(plan_json: Path, policy_dir: str) -> list:
    """Run conftest against plan JSON and return parsed results."""
    print(">>> OPA policy evaluation...")

    result = run_command([
        "conftest", "test",
        str(plan_json),
        "--policy", policy_dir,
        "--all-namespaces",
        "--output", "json",
        "--no-color",
    ])

    if result.stdout.strip():
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            print(f"  Warning: could not parse conftest output", file=sys.stderr)
    return []


def summarize_results(conftest_results: list) -> dict:
    """Summarize conftest results into pass/fail/warn counts."""
    total_pass = 0
    total_fail = 0
    total_warn = 0

    for entry in conftest_results:
        total_pass += entry.get("successes", 0)
        failures = entry.get("failures", [])
        total_fail += len(failures) if isinstance(failures, list) else 0
        warnings = entry.get("warnings", [])
        total_warn += len(warnings) if isinstance(warnings, list) else 0

    return {
        "total_pass": total_pass,
        "total_fail": total_fail,
        "total_warnings": total_warn,
    }


def write_ksi_results(evidence_dir: Path, run_id: str, timestamp: str,
                      environment: str, commit_sha: str, drift_detected: bool,
                      summary: dict, conftest_results: list) -> None:
    """Write the machine-readable KSI results JSON."""
    results = {
        "version": "1.0.0",
        "run_id": run_id,
        "timestamp": timestamp,
        "environment": environment,
        "commit_sha": commit_sha,
        "validation_type": "persistent",
        "cadence_days": 2,
        "drift_detected": drift_detected,
        "summary": summary,
        "ksi_coverage": KSI_COVERAGE,
        "conftest_results": conftest_results,
    }

    (evidence_dir / "ksi-results.json").write_text(
        json.dumps(results, indent=2) + "\n"
    )


def write_metadata(evidence_dir: Path, run_id: str, timestamp: str,
                    environment: str, commit_sha: str) -> None:
    """Write the run metadata JSON."""
    github_run_id = os.environ.get("GITHUB_RUN_ID", "local")
    github_server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    github_repo = os.environ.get("GITHUB_REPOSITORY", "local")

    metadata = {
        "run_id": run_id,
        "timestamp": timestamp,
        "environment": environment,
        "commit_sha": commit_sha,
        "pipeline_id": github_run_id,
        "pipeline_url": f"{github_server}/{github_repo}/actions/runs/{github_run_id}",
        "validation_type": "persistent",
        "tools": {
            "terraform": get_tool_version(["terraform", "version"]),
            "conftest": get_tool_version(["conftest", "--version"]),
            "opa": get_tool_version(["opa", "version"]),
        },
    }

    (evidence_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n"
    )


def write_summary(evidence_dir: Path, run_id: str, timestamp: str,
                   environment: str, commit_sha: str, drift_detected: bool,
                   summary: dict) -> None:
    """Write the human-readable validation summary in Markdown."""
    drift_status = "DRIFT DETECTED — review terraform-drift.json" if drift_detected else "No drift detected"

    ksi_rows = "\n".join(
        f"| {ksi['ksi']} | {ksi['name']} | {ksi['method']} |"
        for ksi in KSI_COVERAGE
    )

    md = f"""# Persistent Validation Report

| Field | Value |
|-------|-------|
| Run ID | {run_id} |
| Timestamp | {timestamp} |
| Environment | {environment} |
| Commit | {commit_sha} |

## Drift Detection

{drift_status}

## KSI Policy Results

| Metric | Count |
|--------|-------|
| Pass | {summary['total_pass']} |
| Fail | {summary['total_fail']} |
| Warnings | {summary['total_warnings']} |

## KSI Coverage

| KSI | Name | Method |
|-----|------|--------|
{ksi_rows}

## Evidence Artifacts

- [ksi-results.json](ksi-results.json) — Machine-readable KSI results
- [terraform-drift.json](terraform-drift.json) — Terraform plan output
- [metadata.json](metadata.json) — Run metadata
"""

    (evidence_dir / "validation-summary.md").write_text(md)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate FedRAMP 20x persistent validation evidence")
    parser.add_argument("environment", nargs="?", default="dev", help="Target environment (default: dev)")
    parser.add_argument("--policy-dir", default="policies/rego", help="Path to Rego policies")
    parser.add_argument("--run-id", default=None, help="Override the run ID")
    args = parser.parse_args()

    environment = args.environment
    policy_dir = args.policy_dir
    working_dir = f"terraform/environments/{environment}"
    run_id = args.run_id or os.environ.get("GITHUB_RUN_ID") or datetime.now().strftime("%Y%m%d-%H%M%S")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    commit_sha = get_commit_sha()

    evidence_dir = Path("evidence") / run_id
    evidence_dir.mkdir(parents=True, exist_ok=True)

    print("=== Persistent Validation Run ===")
    print(f"  Run ID:      {run_id}")
    print(f"  Environment: {environment}")
    print(f"  Timestamp:   {timestamp}")
    print(f"  Commit:      {commit_sha}")
    print()

    drift_detected = detect_drift(working_dir, evidence_dir)

    conftest_results = run_conftest(
        evidence_dir / "terraform-drift.json",
        policy_dir,
    )

    print(">>> Generating KSI evidence artifacts...")
    summary = summarize_results(conftest_results)

    write_ksi_results(evidence_dir, run_id, timestamp, environment,
                      commit_sha, drift_detected, summary, conftest_results)
    write_metadata(evidence_dir, run_id, timestamp, environment, commit_sha)
    write_summary(evidence_dir, run_id, timestamp, environment,
                  commit_sha, drift_detected, summary)

    print()
    print(f"=== Evidence generated in {evidence_dir}/ ===")
    for f in sorted(evidence_dir.iterdir()):
        print(f"  {f.name} ({f.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
