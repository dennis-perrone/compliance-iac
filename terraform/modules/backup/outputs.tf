output "vault_arn" {
  description = "ARN of the backup vault"
  value       = aws_backup_vault.this.arn
}

output "plan_arn" {
  description = "ARN of the backup plan"
  value       = aws_backup_plan.this.arn
}
