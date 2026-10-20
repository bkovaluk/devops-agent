locals {
  # Both functions: triage verifies Datadog signals with the same keys the investigator's
  # Datadog tools use.
  shared_optional = {
    SLACK_TOPIC_ARN   = var.notifications_topic_arn
    SLACK_CHANNEL     = var.notifications_channel == "" ? null : var.notifications_channel
    CATALOG_PARAMETER = var.catalog_json == null ? null : aws_ssm_parameter.catalog[0].name
    DD_API_KEY        = var.datadog_api_key
    DATADOG_APP_KEY   = var.datadog_app_key
    DATADOG_SITE      = var.datadog_site
  }

  shared_environment = merge(
    {
      ENVIRONMENT             = var.environment
      FINDINGS_TABLE          = aws_dynamodb_table.findings.name
      SLACK_ENABLED           = tostring(var.notifications_enabled)
      LOG_LEVEL               = var.log_level
      POWERTOOLS_SERVICE_NAME = "devops-agent"
    },
    { for name, value in local.shared_optional : name => value if value != null },
  )

  triage_optional = {
    HOURLY_BUDGET      = var.hourly_budget
    DAILY_BUDGET       = var.daily_budget
    DAILY_TOKEN_BUDGET = var.daily_token_budget
  }

  triage_environment = merge(
    var.extra_environment,
    { for name, value in local.triage_optional : name => tostring(value) if value != null },
    local.shared_environment,
    {
      WORK_QUEUE_URL   = aws_sqs_queue.work.url
      ALARMS_QUEUE_URL = aws_sqs_queue.alarms.url
    },
  )

  investigator_optional = {
    MODEL_ID               = local.model_arns["primary"]
    FALLBACK_MODEL_ID      = local.model_arns["fallback"]
    RUN_TOKEN_BUDGET       = var.run_token_budget == null ? null : tostring(var.run_token_budget)
    PROMPT_NOTES           = var.prompt_notes == "" ? null : var.prompt_notes
    GH_APP_ID              = var.github_app_id
    GH_APP_INSTALLATION_ID = var.github_app_installation_id
    GH_APP_PRIVATE_KEY     = var.github_app_private_key
    GH_ORG                 = var.github_org
  }

  investigator_environment = merge(
    var.extra_environment,
    { for name, value in local.investigator_optional : name => value if value != null },
    local.shared_environment,
  )
}

resource "aws_cloudwatch_log_group" "triage" {
  name              = "/aws/lambda/${local.triage_function_name}"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "investigator" {
  name              = "/aws/lambda/${local.investigator_function_name}"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

resource "aws_lambda_function" "triage" {
  function_name    = local.triage_function_name
  description      = "Triages CloudWatch alarms and Datadog monitor alerts into investigation jobs, without a model."
  role             = aws_iam_role.lambda.arn
  filename         = var.package_path
  source_code_hash = filebase64sha256(var.package_path)
  handler          = "devops_agent.triage.handler"
  runtime          = "python3.12"
  architectures    = ["x86_64"]
  timeout          = 120
  memory_size      = 512

  environment {
    variables = local.triage_environment
  }

  tags = var.tags

  depends_on = [
    aws_cloudwatch_log_group.triage,
    aws_iam_role_policy.logs,
  ]
}

resource "aws_lambda_function" "investigator" {
  function_name    = local.investigator_function_name
  description      = "Investigates one alarm, monitor alert or incident with read-only tools and records a finding."
  role             = aws_iam_role.lambda.arn
  filename         = var.package_path
  source_code_hash = filebase64sha256(var.package_path)
  handler          = "devops_agent.handler.handler"
  runtime          = "python3.12"
  architectures    = ["x86_64"]
  timeout          = 900
  memory_size      = 512

  environment {
    variables = local.investigator_environment
  }

  tags = var.tags

  lifecycle {
    precondition {
      condition     = !var.notifications_enabled || var.notifications_topic_arn != null
      error_message = "notifications_topic_arn is required when notifications_enabled is true."
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.investigator,
    aws_iam_role_policy.logs,
  ]
}

resource "aws_lambda_event_source_mapping" "alarms" {
  event_source_arn                   = aws_sqs_queue.alarms.arn
  function_name                      = aws_lambda_function.triage.arn
  batch_size                         = 25
  maximum_batching_window_in_seconds = 60
  function_response_types            = ["ReportBatchItemFailures"]

  scaling_config {
    maximum_concurrency = 2
  }

  depends_on = [aws_iam_role_policy.own_resources]
}

resource "aws_lambda_event_source_mapping" "work" {
  event_source_arn        = aws_sqs_queue.work.arn
  function_name           = aws_lambda_function.investigator.arn
  batch_size              = 1
  function_response_types = ["ReportBatchItemFailures"]

  scaling_config {
    maximum_concurrency = 2
  }

  depends_on = [aws_iam_role_policy.own_resources]
}
