output "key_arn" {
  description = "ARN of the KMS key"
  value       = aws_kms_key.primary.arn
}

output "key_id" {
  description = "ID of the KMS key"
  value       = aws_kms_key.primary.key_id
}

output "alias_name" {
  description = "Alias name of the KMS key"
  value       = aws_kms_alias.primary.name
}
