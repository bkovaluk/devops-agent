data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  triage_function_name       = "${var.name_prefix}-triage-${var.environment}"
  investigator_function_name = "${var.name_prefix}-${var.environment}"

  # The catalog both functions run on: catalog_json when set, else the one bundled with
  # the package. The EventBridge rules read their filters from it.
  catalog = jsondecode(coalesce(var.catalog_json, file("${path.module}/../devops_agent/catalog.json")))

  # Alarm names the rules never forward: the catalog's prefixes and the agent's own.
  exclude_alarm_prefixes = distinct(concat(local.catalog.agent.exclude_alarm_prefixes, [var.name_prefix]))

  catalog_parameter_name = "/${var.name_prefix}/${var.environment}/catalog"
  catalog_parameter_arn  = "arn:${local.partition}:ssm:${local.region}:${local.account_id}:parameter${local.catalog_parameter_name}"

  # The SNS topics among alarm_actions, for the budget's notifications.
  alarm_topic_arns = [for arn in var.alarm_actions : arn if can(regex("^arn:aws[a-z-]*:sns:", arn))]
}
