output "investigator_function_name" {
  description = "Name of the investigator function."
  value       = module.devops_agent.investigator_function_name
}

output "findings_table_name" {
  description = "Name of the findings table."
  value       = module.devops_agent.findings_table_name
}

output "central_event_bus_arn" {
  description = "The bus the member accounts forward their alarms to."
  value       = module.devops_agent.central_event_bus_arn
}

output "member_role_arns" {
  description = "The read-only roles the agent assumes, by member."
  value = {
    member_a = module.member_a.role_arn
    member_b = module.member_b.role_arn
  }
}
