locals {
  name_prefix = "${var.project_name}-${var.environment}"
  common_tags = merge(var.tags, {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  })
}

resource "aws_secretsmanager_secret" "this" {
  for_each = var.secrets

  name        = "${local.name_prefix}/${each.key}"
  description = each.value.description
  kms_key_id  = var.kms_key_arn

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}/${each.key}"
  })
}

resource "aws_secretsmanager_secret_rotation" "this" {
  for_each = { for k, v in var.secrets : k => v if v.rotation_lambda_arn != "" }

  secret_id           = aws_secretsmanager_secret.this[each.key].id
  rotation_lambda_arn = each.value.rotation_lambda_arn

  rotation_rules {
    automatically_after_days = each.value.rotation_days
  }
}
