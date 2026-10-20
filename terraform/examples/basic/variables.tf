variable "region" {
  description = "AWS region to deploy into. Bedrock must offer the configured models here."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "dev, qa, staging or prod."
  type        = string
  default     = "dev"
}

variable "package_path" {
  description = "Path of the Lambda zip built by make build."
  type        = string
  default     = "../../../dist/devops-agent.zip"
}

variable "alarm_actions" {
  description = "SNS topic ARNs for the agent's own queue and token alarms and its Bedrock budget."
  type        = list(string)
  default     = []
}
