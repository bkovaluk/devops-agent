variable "name_prefix" {
  description = "Prefix of every resource name. Must start with devops-agent: the EventBridge rule and triage skip alarms named with it, so the agent never investigates its own alarms."
  type        = string
  default     = "devops-agent"

  validation {
    condition     = can(regex("^devops-agent[a-z0-9-]{0,27}$", var.name_prefix))
    error_message = "name_prefix must start with devops-agent and contain at most 27 more lowercase letters, digits or hyphens."
  }
}

variable "environment" {
  description = "Deployment environment: dev, qa, staging or prod. Sets ENVIRONMENT, the default severity floor, and resource names."
  type        = string

  validation {
    condition     = contains(["dev", "qa", "staging", "prod"], var.environment)
    error_message = "environment must be one of dev, qa, staging or prod."
  }
}

variable "package_path" {
  description = "Path of the Lambda zip built by scripts/build.sh."
  type        = string
}

variable "model_id" {
  description = "Bedrock model id, cross-region inference profile id, or application inference profile ARN. An id gets an application inference profile copied from it, which MODEL_ID then names."
  type        = string
  default     = "us.anthropic.claude-opus-5-5"
}

variable "fallback_model_id" {
  description = "Bedrock model used when model_id is throttled, not ready, or not granted. Same forms, and the same profile copy, as model_id."
  type        = string
  default     = "us.anthropic.claude-opus-5"
}

variable "bedrock_foundation_models" {
  description = "Foundation model ids that an application inference profile ARN in model_id or fallback_model_id routes to. Ids the module can derive from model_id and fallback_model_id need not be listed."
  type        = list(string)
  default     = []
}

variable "input_tokens_per_hour" {
  description = "Hourly InputTokenCount on the primary model's inference profile above which its token alarm fires."
  type        = number
  default     = 3000000
}

variable "output_tokens_per_hour" {
  description = "Hourly OutputTokenCount on the primary model's inference profile above which its token alarm fires."
  type        = number
  default     = 200000
}

variable "bedrock_budget_usd" {
  description = "Monthly cost budget in USD for bedrock_budget_services in the account."
  type        = number
  default     = 200
}

variable "bedrock_budget_services" {
  description = "Cost Explorer service names the Bedrock budget counts. Anthropic models bill as Marketplace services named after the model."
  type        = list(string)
  default = [
    "Amazon Bedrock",
    "Claude Opus 5.5 (Amazon Bedrock Edition)",
    "Claude Opus 5 (Amazon Bedrock Edition)",
  ]
}

variable "catalog_json" {
  description = "The deployment's catalog document as JSON, in the shape of devops_agent/catalog.json. When set, the module stores it in SSM and points CATALOG_PARAMETER at it; when null, both functions run on the bundled catalog."
  type        = string
  default     = null

  validation {
    condition     = var.catalog_json == null || can(jsondecode(var.catalog_json).agent.exclude_alarm_prefixes)
    error_message = "catalog_json must be a JSON catalog document with an agent section."
  }
}

variable "datadog_event_source_name" {
  description = "Datadog partner event source (aws.partner/datadog.com/...) whose monitor notifications feed the alarms queue. Null leaves Datadog signals off."
  type        = string
  default     = null
}

variable "notifications_enabled" {
  description = "Publish critical and high findings to notifications_topic_arn."
  type        = bool
  default     = false
}

variable "notifications_topic_arn" {
  description = "Existing SNS topic for notifications. Required when notifications_enabled is true."
  type        = string
  default     = null
}

variable "notifications_channel" {
  description = "Channel name passed in each notification for the subscriber to route on."
  type        = string
  default     = ""
}

variable "prompt_notes" {
  description = "Operator text appended to the system prompt: conventions the tools cannot show."
  type        = string
  default     = ""
}

variable "datadog_api_key" {
  description = "Datadog API key. The Datadog tools are offered, and triage verifies Datadog signals, only when this and datadog_app_key are set."
  type        = string
  default     = null
  sensitive   = true
}

variable "datadog_app_key" {
  description = "Datadog application key of a read-only service account."
  type        = string
  default     = null
  sensitive   = true
}

variable "datadog_site" {
  description = "Datadog site, such as datadoghq.eu or us5.datadoghq.com."
  type        = string
  default     = "datadoghq.com"
}

variable "github_app_id" {
  description = "GitHub App id of a read-only App. The GitHub tools are offered only when the three App settings and github_org are set."
  type        = string
  default     = null
}

variable "github_app_installation_id" {
  description = "The GitHub App's installation id on github_org."
  type        = string
  default     = null
}

variable "github_app_private_key" {
  description = "The GitHub App's PEM private key."
  type        = string
  default     = null
  sensitive   = true
}

variable "github_org" {
  description = "The only GitHub org the GitHub tools read."
  type        = string
  default     = null
}

variable "log_level" {
  description = "LOG_LEVEL of both functions."
  type        = string
  default     = "INFO"
}

variable "hourly_budget" {
  description = "Investigations per UTC hour (HOURLY_BUDGET). Null keeps the code default of 10."
  type        = number
  default     = null
}

variable "daily_budget" {
  description = "Investigations per UTC day (DAILY_BUDGET). Null keeps the code default of 50."
  type        = number
  default     = null
}

variable "daily_token_budget" {
  description = "Cost-weighted tokens all investigations may spend per UTC day (DAILY_TOKEN_BUDGET). Null keeps the code default of 3000000."
  type        = number
  default     = null
}

variable "run_token_budget" {
  description = "Cost-weighted tokens one investigation may spend before its final step (RUN_TOKEN_BUDGET). Null keeps the code default of 250000."
  type        = number
  default     = null
}

variable "account_hourly_budget" {
  description = "With member_role_name set, investigations one account may use per UTC hour (ACCOUNT_HOURLY_BUDGET). Null keeps the code default of 5."
  type        = number
  default     = null
}

variable "account_daily_budget" {
  description = "With member_role_name set, investigations one account may use per UTC day (ACCOUNT_DAILY_BUDGET). Null keeps the code default of 25."
  type        = number
  default     = null
}

variable "member_role_name" {
  description = "Name of the read-only role terraform/member creates in every member account (MEMBER_ROLE_NAME). The agent assumes it to read a member account's alarm. Null reads only this account."
  type        = string
  default     = null

  validation {
    condition     = var.member_role_name == null || can(regex("^[\\w+=,.@-]{1,64}$", var.member_role_name))
    error_message = "member_role_name must be an IAM role name."
  }
}

variable "member_external_id" {
  description = "External id the agent sends when it assumes a member role (MEMBER_EXTERNAL_ID); set it, and the member module's external_id to the same value, so the member roles' trust policies require it. It reaches both functions as a plaintext environment variable."
  type        = string
  default     = null
  sensitive   = true
}

variable "allowed_account_ids" {
  description = "Accounts the agent investigates (ALLOWED_ACCOUNT_IDS); signals from any other are refused, and the role may assume member roles in these only. Recommended. Empty refuses no signal by account and lets the role assume the member role name in any account: with organization_id set, any account of that organization; without it, any account at all. List this account too when its own alarms are to be investigated."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for id in var.allowed_account_ids : can(regex("^[0-9]{12}$", id))])
    error_message = "allowed_account_ids must be 12-digit account ids."
  }
}

variable "organization_id" {
  description = "AWS Organization id (o-...). When set, the module creates the central event bus member accounts forward their alarms to, accepting events from this organization only, and the role may assume member roles only in accounts of this organization (aws:ResourceOrgID)."
  type        = string
  default     = null

  validation {
    condition     = var.organization_id == null || can(regex("^o-[a-z0-9]{10,32}$", var.organization_id))
    error_message = "organization_id must be an organization id such as o-a1b2c3d4e5."
  }
}

variable "extra_environment" {
  description = "Other environment variables from the README's Configuration tables, set on both functions. Variables the module sets itself take precedence."
  type        = map(string)
  default     = {}
}

variable "log_retention_days" {
  description = "Retention of the two functions' CloudWatch log groups."
  type        = number
  default     = 400
}

variable "alarm_actions" {
  description = "Actions, such as SNS topic ARNs, for the dead-letter, backlog and token alarms. The SNS topics among them also get the Bedrock budget's notifications."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
