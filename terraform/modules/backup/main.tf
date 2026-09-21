locals {
  name_prefix = "${var.project_name}-${var.environment}"
  common_tags = merge(var.tags, {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  })
}

resource "aws_backup_vault" "this" {
  name        = "${local.name_prefix}-vault"
  kms_key_arn = var.kms_key_arn

  tags = local.common_tags
}

resource "aws_backup_vault_lock_configuration" "this" {
  backup_vault_name  = aws_backup_vault.this.name
  min_retention_days = var.min_retention_days
}

resource "aws_backup_plan" "this" {
  name = "${local.name_prefix}-plan"

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.this.name
    schedule          = "cron(0 5 ? * * *)"
    start_window      = 60
    completion_window = 180

    lifecycle {
      cold_storage_after = var.cold_storage_after_days > 0 ? var.cold_storage_after_days : null
      delete_after       = var.delete_after_days
    }
  }

  tags = local.common_tags
}

resource "aws_backup_selection" "this" {
  name         = "${local.name_prefix}-selection"
  iam_role_arn = aws_iam_role.backup.arn
  plan_id      = aws_backup_plan.this.id

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "true"
  }
}

resource "aws_iam_role" "backup" {
  name = "${local.name_prefix}-backup"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "backup.amazonaws.com"
      }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "restore" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}
