variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN for encrypting backups"
  type        = string
}

variable "min_retention_days" {
  description = "Minimum retention period enforced by vault lock"
  type        = number
  default     = 30
}

variable "cold_storage_after_days" {
  description = "Days before transitioning to cold storage (0 to skip)"
  type        = number
  default     = 90
}

variable "delete_after_days" {
  description = "Days before deleting backup"
  type        = number
  default     = 365
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
