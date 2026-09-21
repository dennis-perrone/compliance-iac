variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "log_retention_days" {
  description = "Number of days to retain CloudWatch logs"
  type        = number
  default     = 365
}

variable "kms_key_arn" {
  description = "KMS key ARN for encrypting CloudWatch log groups"
  type        = string
  default     = ""
}

variable "alarm_sns_topic_arns" {
  description = "SNS topic ARNs for CloudWatch alarm notifications"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
