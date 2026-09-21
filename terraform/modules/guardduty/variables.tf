variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "enable_eks_audit_logs" {
  description = "Enable EKS audit log monitoring in GuardDuty"
  type        = bool
  default     = false
}

variable "findings_bucket_arn" {
  description = "S3 bucket ARN for publishing GuardDuty findings (empty to skip)"
  type        = string
  default     = ""
}

variable "findings_kms_key_arn" {
  description = "KMS key ARN for encrypting GuardDuty findings published to S3 (required if findings_bucket_arn is set)"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
