variable "exclude_alarm_prefixes" {
  description = "Alarm name prefixes the agent never investigates: the catalog's agent.exclude_alarm_prefixes plus the agent's name_prefix."
  type        = list(string)
}

variable "catalog_parameter_arn" {
  description = "The catalog parameter the role may read; null denies every parameter read."
  type        = string
  default     = null
}

variable "agent_queue_arns" {
  description = "The queues whose messages the role may receive: the agent's own alarms and work queues. Empty denies every receive."
  type        = list(string)
  default     = []
}

variable "assumable_role_arns" {
  description = "The roles the role may assume: the member accounts' read-only roles. Empty denies every AssumeRole."
  type        = list(string)
  default     = []
}

variable "assumable_role_org_id" {
  description = "The organization (o-...) every assumable role's account must belong to; null sets no organization boundary."
  type        = string
  default     = null
}
