output "admin_role_arn" {
  description = "ARN of the admin IAM role"
  value       = aws_iam_role.admin.arn
}

output "readonly_role_arn" {
  description = "ARN of the read-only IAM role"
  value       = aws_iam_role.readonly.arn
}
