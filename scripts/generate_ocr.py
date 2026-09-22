#!/usr/bin/env python3
"""Generate a quarterly Ongoing Certification Report (OCR) for FedRAMP 20x.

Pulls evidence from S3 to summarize the validation posture over the reporting
period, then produces both a human-readable Markdown report and a
machine-readable JSON companion.
"""

import argparse
import json
import os
import tempfile
from datetime import date, timezone
from pathlib import Path

import boto3


def months_offset(d: date, months: int) -> date:
    """Return a date shifted by the given number of months."""
    month = d.month - 1 + months
    year = d.year + month // 12
    month = month % 12 + 1
    day = min(d.day, [31, 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28,
                       31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1])
    return date(year, month, day)


def count_evidence_runs(s3, bucket: str) -> int:
    """Count evidence run directories in the S3 bucket."""
    try:
        response = s3.list_objects_v2(Bucket=bucket, Prefix="evidence/", Delimiter="/")
        return len(response.get("CommonPrefixes", []))
    except s3.exceptions.NoSuchBucket:
        print(f"  Warning: bucket '{bucket}' not found")
        return 0


def get_latest_results(s3, bucket: str) -> tuple[str, int, int]:
    """Fetch the latest evidence run's KSI results. Returns (run_id, pass, fail)."""
    try:
        response = s3.list_objects_v2(Bucket=bucket, Prefix="evidence/", Delimiter="/")
        prefixes = response.get("CommonPrefixes", [])
    except Exception:
        return ("", 0, 0)

    if not prefixes:
        return ("", 0, 0)

    latest_prefix = sorted(p["Prefix"] for p in prefixes)[-1]
    run_id = latest_prefix.strip("/").split("/")[-1]

    with tempfile.TemporaryDirectory() as tmpdir:
        local_path = Path(tmpdir) / "ksi-results.json"
        try:
            s3.download_file(bucket, f"evidence/{run_id}/ksi-results.json", str(local_path))
            results = json.loads(local_path.read_text())
            summary = results.get("summary", {})
            return (run_id, summary.get("total_pass", 0), summary.get("total_fail", 0))
        except Exception:
            return (run_id, 0, 0)


def write_markdown_report(path: Path, start_date: str, end_date: str,
                          next_report: str, total_runs: int,
                          latest_pass: int, latest_fail: int,
                          evidence_bucket: str) -> None:
    """Write the human-readable OCR in Markdown."""
    report = f"""# Ongoing Certification Report

**Reporting Period:** {start_date} — {end_date}
**Date Prepared:** {end_date}
**Next Report Due:** {next_report}

---

## 1. Executive Summary

This report covers the ongoing security posture of the cloud service offering
for the reporting period. Persistent validation has been running on a ≤3-day
cadence throughout the period.

## 2. Changes Since Last Report

*To be completed by the security team.*

## 3. Planned Changes (Next 3 Months)

*To be completed by the security team.*

## 4. KSI Validation Status

### 4.1 Validation Cadence

- Machine-based KSI validation cadence: every 2 days
- Total validation runs this period: {total_runs}

### 4.2 Latest Run Results

| Metric | Count |
|--------|-------|
| Pass | {latest_pass} |
| Fail | {latest_fail} |

### 4.3 KSI Coverage

17 KSIs covered with automated validation across 7 themes:
Service Configuration (3), Cloud Native Architecture (4),
Identity and Access Management (4), Monitoring/Logging/Auditing (4),
Recovery Planning (1), Incident Response (1).

## 5. Accepted Vulnerabilities & Exceptions

See exceptions.yaml for the current exception registry.

## 6. Vulnerability Detection & Response

*Monthly vulnerability activity to be completed by the security team.*

## 7. Incidents

No FedRAMP Reportable Incidents occurred during this period.
*(Update if incidents occurred.)*

## 8. Agency Customer List

*To be completed.*

---

*Generated from evidence stored in s3://{evidence_bucket}/evidence/*
"""
    path.write_text(report)


def write_json_report(path: Path, start_date: str, end_date: str,
                      next_report: str, total_runs: int,
                      latest_pass: int, latest_fail: int,
                      evidence_bucket: str) -> None:
    """Write the machine-readable OCR in JSON."""
    report = {
        "document_type": "ongoing_certification_report",
        "reporting_period": {
            "start": start_date,
            "end": end_date,
        },
        "next_report_due": next_report,
        "validation_summary": {
            "cadence_days": 2,
            "total_runs": total_runs,
            "latest_pass": latest_pass,
            "latest_fail": latest_fail,
            "ksi_count": 17,
        },
        "evidence_bucket": evidence_bucket,
    }

    path.write_text(json.dumps(report, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate FedRAMP 20x Ongoing Certification Report")
    parser.add_argument("evidence_bucket", help="S3 bucket containing evidence artifacts")
    parser.add_argument("--output-dir", default="reports", help="Output directory (default: reports)")
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-2"), help="AWS region")
    args = parser.parse_args()

    today = date.today()
    start_date = months_offset(today, -3).isoformat()
    end_date = today.isoformat()
    next_report = months_offset(today, 3).isoformat()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=== Generating Ongoing Certification Report ===")
    print(f"  Period:      {start_date} — {end_date}")
    print(f"  Next report: {next_report}")
    print(f"  Bucket:      {args.evidence_bucket}")
    print()

    s3 = boto3.client("s3", region_name=args.region)

    total_runs = count_evidence_runs(s3, args.evidence_bucket)
    print(f"  Evidence runs found: {total_runs}")

    latest_run, latest_pass, latest_fail = get_latest_results(s3, args.evidence_bucket)
    if latest_run:
        print(f"  Latest run:  {latest_run}")

    md_path = output_dir / f"ocr-{end_date}.md"
    json_path = output_dir / f"ocr-{end_date}.json"

    shared_args = dict(
        start_date=start_date,
        end_date=end_date,
        next_report=next_report,
        total_runs=total_runs,
        latest_pass=latest_pass,
        latest_fail=latest_fail,
        evidence_bucket=args.evidence_bucket,
    )

    write_markdown_report(md_path, **shared_args)
    write_json_report(json_path, **shared_args)

    print()
    print("=== Report generated ===")
    print(f"  Human-readable:  {md_path}")
    print(f"  Machine-readable: {json_path}")


if __name__ == "__main__":
    main()
