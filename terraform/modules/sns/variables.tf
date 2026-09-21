variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "kms_key_id" {
  description = "KMS key ID for encrypting SNS messages"
  type        = string
  default     = ""
}

variable "alert_email_addresses" {
  description = "Email addresses to subscribe to security alerts"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
