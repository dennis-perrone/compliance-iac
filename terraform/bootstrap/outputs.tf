output "state_bucket_names" {
  description = "Map of environment to state bucket name"
  value       = { for env, bucket in aws_s3_bucket.state : env => bucket.id }
}

output "state_bucket_arns" {
  description = "Map of environment to state bucket ARN"
  value       = { for env, bucket in aws_s3_bucket.state : env => bucket.arn }
}

output "lock_table_name" {
  description = "DynamoDB lock table name"
  value       = aws_dynamodb_table.lock.name
}

output "lock_table_arn" {
  description = "DynamoDB lock table ARN"
  value       = aws_dynamodb_table.lock.arn
}
