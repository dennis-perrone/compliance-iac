locals {
  name_prefix = "${var.project_name}-${var.environment}"
  common_tags = merge(var.tags, {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  })
}

resource "aws_cloudwatch_log_group" "security" {
  name              = "/${local.name_prefix}/security"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  alarm_name          = "${local.name_prefix}-unauthorized-api-calls"
  alarm_description   = "Alerts on unauthorized API calls (AccessDenied/UnauthorizedAccess)"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedAPICalls"
  namespace           = local.name_prefix
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"

  alarm_actions = var.alarm_sns_topic_arns

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "root_account_usage" {
  alarm_name          = "${local.name_prefix}-root-account-usage"
  alarm_description   = "Alerts on any root account usage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsage"
  namespace           = local.name_prefix
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = var.alarm_sns_topic_arns

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "console_signin_failures" {
  alarm_name          = "${local.name_prefix}-console-signin-failures"
  alarm_description   = "Alerts on repeated console sign-in failures"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ConsoleSignInFailures"
  namespace           = local.name_prefix
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"

  alarm_actions = var.alarm_sns_topic_arns

  tags = local.common_tags
}
