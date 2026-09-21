output "security_log_group_name" {
  description = "Name of the security CloudWatch log group"
  value       = aws_cloudwatch_log_group.security.name
}

output "security_log_group_arn" {
  description = "ARN of the security CloudWatch log group"
  value       = aws_cloudwatch_log_group.security.arn
}
