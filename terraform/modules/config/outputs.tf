output "recorder_id" {
  description = "AWS Config recorder ID"
  value       = aws_config_configuration_recorder.this.id
}
