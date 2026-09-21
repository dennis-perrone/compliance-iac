variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN for encrypting secrets"
  type        = string
}

variable "secrets" {
  description = "Map of secrets to create"
  type = map(object({
    description         = string
    rotation_lambda_arn = optional(string, "")
    rotation_days       = optional(number, 90)
  }))
  default = {}
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
