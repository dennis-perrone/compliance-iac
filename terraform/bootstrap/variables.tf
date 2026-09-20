variable "aws_region" {
  description = "AWS region for the backend resources"
  type        = string
  default     = "us-east-2"
}

variable "project_name" {
  description = "Project name used for bucket and table naming"
  type        = string
  default     = "compliance"
}

variable "environments" {
  description = "List of environments to create state buckets for"
  type        = list(string)
  default     = ["dev", "staging", "prod"]
}
