#!/usr/bin/env python3
"""Upload evidence artifacts to S3 with KMS encryption."""

import argparse
import os
import sys
from pathlib import Path

import boto3


def upload_evidence(evidence_dir: Path, bucket: str, region: str) -> None:
    """Upload all files in the evidence directory to S3 with KMS encryption."""
    run_id = evidence_dir.name
    s3_prefix = f"evidence/{run_id}"

    print(f"Uploading evidence to s3://{bucket}/{s3_prefix}/...")

    s3 = boto3.client("s3", region_name=region)

    for file_path in sorted(evidence_dir.iterdir()):
        if not file_path.is_file():
            continue
        key = f"{s3_prefix}/{file_path.name}"
        s3.upload_file(
            str(file_path),
            bucket,
            key,
            ExtraArgs={"ServerSideEncryption": "aws:kms"},
        )
        print(f"  Uploaded {file_path.name}")

    print()
    print("Evidence uploaded successfully.")
    print(f"  Bucket:  {bucket}")
    print(f"  Prefix:  {s3_prefix}")
    print(f"  Region:  {region}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Upload evidence artifacts to S3")
    parser.add_argument("evidence_dir", help="Path to the evidence run directory")
    parser.add_argument("--bucket", default="compliance-evidence-store", help="S3 bucket name (default: compliance-evidence-store)")
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-2"), help="AWS region")
    args = parser.parse_args()

    evidence_dir = Path(args.evidence_dir)
    if not evidence_dir.is_dir():
        print(f"Error: evidence directory '{evidence_dir}' not found", file=sys.stderr)
        sys.exit(1)

    upload_evidence(evidence_dir, args.bucket, args.region)


if __name__ == "__main__":
    main()
