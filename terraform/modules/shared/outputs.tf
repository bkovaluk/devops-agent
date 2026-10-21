output "read_policy_json" {
  description = "The read grants of the curated tools and the context bundle."
  value       = data.aws_iam_policy_document.read.json
}

output "deny_policy_json" {
  description = "The explicit deny list that wins over every grant."
  value       = data.aws_iam_policy_document.deny.json
}

output "managed_policy_arn" {
  description = "AWS's own policy for its DevOps Agent, for the generic aws_call tool: Describe, List and Get across most services, kept current by AWS. The deny list still wins over it."
  value       = "arn:${local.partition}:iam::aws:policy/AIDevOpsAgentAccessPolicy"
}

output "alarm_event_pattern" {
  description = "The EventBridge pattern of the alarm events the agent investigates: entering ALARM, name not starting with an excluded prefix."
  value = jsonencode({
    source      = ["aws.cloudwatch"]
    detail-type = ["CloudWatch Alarm State Change"]
    detail = {
      state = { value = ["ALARM"] }
      alarmName = [
        {
          anything-but = {
            prefix = var.exclude_alarm_prefixes
          }
        }
      ]
    }
  })
}
