variable "investigator_role_arn" {
  description = "ARN of the agent's execution role in the tooling account (the agent module's role_arn output); the only principal the read-only role trusts."
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/", var.investigator_role_arn))
    error_message = "investigator_role_arn must be an IAM role ARN."
  }
}

variable "central_event_bus_arn" {
  description = "ARN of the central event bus in the tooling account (the agent module's central_event_bus_arn output)."
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:events:[a-z0-9-]+:[0-9]{12}:event-bus/", var.central_event_bus_arn))
    error_message = "central_event_bus_arn must be an EventBridge event bus ARN."
  }
}

variable "role_name" {
  description = "Name of the read-only role; the agent module's member_role_name must match it."
  type        = string
  default     = "devops-agent-read"

  validation {
    condition     = can(regex("^[\\w+=,.@-]{1,64}$", var.role_name))
    error_message = "role_name must be an IAM role name."
  }
}

variable "external_id" {
  description = "External id the read-only role requires (the agent module's member_external_id). Null trusts the investigator's role without one."
  type        = string
  default     = null
}

variable "name_prefix" {
  description = "Prefix of the forwarding rule and its role, and an alarm name prefix the rule never forwards. Must match the agent module's name_prefix."
  type        = string
  default     = "devops-agent"

  validation {
    condition     = can(regex("^devops-agent[a-z0-9-]{0,27}$", var.name_prefix))
    error_message = "name_prefix must start with devops-agent and contain at most 27 more lowercase letters, digits or hyphens."
  }
}

variable "catalog_json" {
  description = "The agent's catalog document as JSON, when it sets its own agent.exclude_alarm_prefixes; null uses devops_agent/catalog.json."
  type        = string
  default     = null

  validation {
    condition     = var.catalog_json == null || can(jsondecode(var.catalog_json).agent.exclude_alarm_prefixes)
    error_message = "catalog_json must be a JSON catalog document with an agent section."
  }
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
