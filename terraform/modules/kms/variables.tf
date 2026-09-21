variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "key_admin_arns" {
  description = "ARNs of IAM principals allowed to administer the key"
  type        = list(string)
}

variable "key_user_arns" {
  description = "ARNs of IAM principals allowed to use the key for encryption/decryption"
  type        = list(string)
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
