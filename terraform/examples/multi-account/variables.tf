variable "region" {
  description = "The one region of the agent and every member account it reads. Bedrock must offer the configured models here."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "dev, qa, staging or prod."
  type        = string
  default     = "prod"
}

variable "package_path" {
  description = "Path of the Lambda zip built by just build."
  type        = string
  default     = "../../../dist/devops-agent.zip"
}

variable "organization_id" {
  description = "The AWS Organization id (o-...) whose accounts may put events on the central bus."
  type        = string
}

variable "external_id" {
  description = "External id the agent sends and every member role requires."
  type        = string
}

variable "member_a_account_id" {
  description = "Account id of the first member account."
  type        = string
}

variable "member_a_deploy_role_arn" {
  description = "A role in the first member account that this configuration assumes to deploy there."
  type        = string
}

variable "member_b_account_id" {
  description = "Account id of the second member account."
  type        = string
}

variable "member_b_deploy_role_arn" {
  description = "A role in the second member account that this configuration assumes to deploy there."
  type        = string
}

variable "alarm_actions" {
  description = "SNS topic ARNs for the agent's own queue and token alarms and its Bedrock budget."
  type        = list(string)
  default     = []
}
