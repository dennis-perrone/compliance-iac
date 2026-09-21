output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.this.id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.this.cidr_block
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "nat_gateway_ids" {
  description = "IDs of the NAT gateways"
  value       = var.enable_nat_gateway ? aws_nat_gateway.this[*].id : []
}

output "flow_log_group_name" {
  description = "Name of the CloudWatch log group for VPC flow logs"
  value       = aws_cloudwatch_log_group.flow_logs.name
}
