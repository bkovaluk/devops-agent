output "triage_function_name" {
  description = "Name of the triage function."
  value       = aws_lambda_function.triage.function_name
}

output "triage_function_arn" {
  description = "ARN of the triage function."
  value       = aws_lambda_function.triage.arn
}

output "investigator_function_name" {
  description = "Name of the investigator function."
  value       = aws_lambda_function.investigator.function_name
}

output "investigator_function_arn" {
  description = "ARN of the investigator function."
  value       = aws_lambda_function.investigator.arn
}

output "alarms_queue_url" {
  description = "URL of the alarms queue."
  value       = aws_sqs_queue.alarms.url
}

output "alarms_queue_arn" {
  description = "ARN of the alarms queue."
  value       = aws_sqs_queue.alarms.arn
}

output "alarms_dlq_url" {
  description = "URL of the alarms dead-letter queue."
  value       = aws_sqs_queue.alarms_dlq.url
}

output "alarms_dlq_arn" {
  description = "ARN of the alarms dead-letter queue."
  value       = aws_sqs_queue.alarms_dlq.arn
}

output "work_queue_url" {
  description = "URL of the work queue."
  value       = aws_sqs_queue.work.url
}

output "work_queue_arn" {
  description = "ARN of the work queue."
  value       = aws_sqs_queue.work.arn
}

output "work_dlq_url" {
  description = "URL of the work dead-letter queue."
  value       = aws_sqs_queue.work_dlq.url
}

output "work_dlq_arn" {
  description = "ARN of the work dead-letter queue."
  value       = aws_sqs_queue.work_dlq.arn
}

output "findings_table_name" {
  description = "Name of the findings table."
  value       = aws_dynamodb_table.findings.name
}

output "findings_table_arn" {
  description = "ARN of the findings table."
  value       = aws_dynamodb_table.findings.arn
}

output "role_arn" {
  description = "ARN of the execution role both functions run as."
  value       = aws_iam_role.lambda.arn
}

output "event_rule_arn" {
  description = "ARN of the EventBridge rule that sends CloudWatch alarms to the alarms queue."
  value       = aws_cloudwatch_event_rule.alarms.arn
}

output "model_arns" {
  description = "The primary and fallback model ARNs the investigator calls: the module's application inference profiles, or the ARNs given."
  value       = local.model_arns
}

output "catalog_parameter_name" {
  description = "Name of the SSM parameter holding catalog_json; null without one."
  value       = one(aws_ssm_parameter.catalog[*].name)
}

output "datadog_event_rule_arn" {
  description = "ARN of the rule on the Datadog partner event bus; null without one."
  value       = one(aws_cloudwatch_event_rule.datadog[*].arn)
}
