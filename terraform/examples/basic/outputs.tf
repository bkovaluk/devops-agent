output "investigator_function_name" {
  description = "Name of the investigator function."
  value       = module.devops_agent.investigator_function_name
}

output "findings_table_name" {
  description = "Name of the findings table."
  value       = module.devops_agent.findings_table_name
}

output "alarms_queue_url" {
  description = "URL of the alarms queue."
  value       = module.devops_agent.alarms_queue_url
}

output "model_arns" {
  description = "The inference profiles the investigator calls."
  value       = module.devops_agent.model_arns
}
