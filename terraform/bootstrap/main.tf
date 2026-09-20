terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = var.project_name
      ManagedBy = "terraform"
      Purpose   = "terraform-backend"
    }
  }
}

locals {
  environments = toset(var.environments)
}

resource "aws_dynamodb_table" "lock" {
  name         = "${var.project_name}-tfstate-lock"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    Name = "${var.project_name}-tfstate-lock"
  }
}

resource "aws_s3_bucket" "state" {
  for_each = local.environments

  bucket = "${var.project_name}-tfstate-${each.key}"

  tags = {
    Name        = "${var.project_name}-tfstate-${each.key}"
    Environment = each.key
  }
}

resource "aws_s3_bucket_versioning" "state" {
  for_each = local.environments

  bucket = aws_s3_bucket.state[each.key].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  for_each = local.environments

  bucket = aws_s3_bucket.state[each.key].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  for_each = local.environments

  bucket = aws_s3_bucket.state[each.key].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "state" {
  for_each = local.environments

  bucket = aws_s3_bucket.state[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.state[each.key].arn,
          "${aws_s3_bucket.state[each.key].arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" : "false"
          }
        }
      }
    ]
  })
}
