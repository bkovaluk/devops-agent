locals {
  # The models the investigator calls, by role. A model id that is not already an ARN
  # gets an application inference profile copied from it, so the agent's token usage is
  # metered under its own profile.
  models = {
    primary  = var.model_id
    fallback = var.fallback_model_id
  }

  model_arns = {
    for role, id in local.models :
    role => startswith(id, "arn:") ? id : aws_bedrock_inference_profile.model[role].arn
  }
}

resource "aws_bedrock_inference_profile" "model" {
  for_each = { for role, id in local.models : role => id if !startswith(id, "arn:") }

  name = "${var.name_prefix}-${each.key}-${var.environment}"
  # Bedrock allows only letters, digits, ':' '.' and single ' ', '_' or '-' separators
  # here: no commas.
  description = "${var.name_prefix} ${each.key} model copied from ${each.value}"

  model_source {
    copy_from = (
      length(regexall(local.profile_id_pattern, each.value)) > 0
      ? "arn:${local.partition}:bedrock:${local.region}:${local.account_id}:inference-profile/${each.value}"
      : "arn:${local.partition}:bedrock:${local.region}::foundation-model/${each.value}"
    )
  }

  tags = var.tags
}

# For invocations through an application inference profile, AWS/Bedrock reports the
# ModelId dimension as the profile ARN; the alarm also reads the bare profile id in case
# the dimension carries the id instead. Metrics Insights rejects OR in WHERE, so each
# candidate is its own metric and the alarm sums them with FILL, so a series that never
# reports counts as 0. Named with the prefix, so the agent never investigates them.
resource "aws_cloudwatch_metric_alarm" "tokens" {
  for_each = {
    input  = { metric = "InputTokenCount", threshold = var.input_tokens_per_hour }
    output = { metric = "OutputTokenCount", threshold = var.output_tokens_per_hour }
  }

  alarm_name          = "${var.name_prefix}-${each.key}-tokens-${var.environment}"
  alarm_description   = "${each.value.metric} of the ${var.name_prefix} primary model above ${each.value.threshold} in an hour."
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_actions

  dynamic "metric_query" {
    for_each = {
      by_arn = local.model_arns["primary"]
      by_id  = element(split("/", local.model_arns["primary"]), length(split("/", local.model_arns["primary"])) - 1)
    }

    content {
      id          = metric_query.key
      return_data = false

      metric {
        namespace   = "AWS/Bedrock"
        metric_name = each.value.metric
        dimensions  = { ModelId = metric_query.value }
        period      = 3600
        stat        = "Sum"
      }
    }
  }

  metric_query {
    id          = "tokens"
    label       = "${var.name_prefix} ${each.value.metric}"
    return_data = true
    expression  = "FILL(by_arn, 0) + FILL(by_id, 0)"
  }

  tags = var.tags
}

# Anthropic models on Bedrock bill as AWS Marketplace line items named
# "Claude <model> (Amazon Bedrock Edition)", not under "Amazon Bedrock", so the filter
# names those as well. It counts every caller of these services in the account, not only
# the agent.
resource "aws_budgets_budget" "bedrock" {
  name         = "${var.name_prefix}-bedrock-${var.environment}"
  budget_type  = "COST"
  limit_amount = tostring(var.bedrock_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "Service"
    values = var.bedrock_budget_services
  }

  dynamic "notification" {
    for_each = length(local.alarm_topic_arns) == 0 ? {} : {
      ACTUAL     = 80
      FORECASTED = 100
    }

    content {
      comparison_operator       = "GREATER_THAN"
      threshold                 = notification.value
      threshold_type            = "PERCENTAGE"
      notification_type         = notification.key
      subscriber_sns_topic_arns = local.alarm_topic_arns
    }
  }

  tags = var.tags
}
