output "role_arn" {
  description = "ARN of the read-only role the agent assumes in this account."
  value       = aws_iam_role.read.arn
}

output "role_name" {
  description = "Name of the read-only role; the agent module's member_role_name."
  value       = aws_iam_role.read.name
}

output "forward_rule_arn" {
  description = "ARN of the rule that forwards this account's alarms to the central event bus."
  value       = aws_cloudwatch_event_rule.forward.arn
}
