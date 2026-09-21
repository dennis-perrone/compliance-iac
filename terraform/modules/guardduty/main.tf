locals {
  name_prefix = "${var.project_name}-${var.environment}"
  common_tags = merge(var.tags, {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  })
}

resource "aws_guardduty_detector" "this" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = var.enable_eks_audit_logs
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-guardduty"
  })
}

resource "aws_guardduty_publishing_destination" "s3" {
  count = var.findings_bucket_arn != "" ? 1 : 0

  detector_id      = aws_guardduty_detector.this.id
  destination_arn  = var.findings_bucket_arn
  destination_type = "S3"
  kms_key_arn      = var.findings_kms_key_arn
}
