output "bucket_name" {
  description = "Name of the evidence store S3 bucket"
  value       = aws_s3_bucket.evidence.id
}

output "bucket_arn" {
  description = "ARN of the evidence store S3 bucket"
  value       = aws_s3_bucket.evidence.arn
}
