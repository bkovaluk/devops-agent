locals {
  # Cross-region inference profile ids: a geography prefix on a foundation model id.
  profile_id_pattern = "^(?:us|eu|apac|global|jp|au|ca|us-gov)\\.(.+)$"
  model_ids          = distinct([var.model_id, var.fallback_model_id])

  bedrock_foundation_models = distinct(concat(var.bedrock_foundation_models, [
    for id in local.model_ids :
    length(regexall(local.profile_id_pattern, id)) > 0 ? regex(local.profile_id_pattern, id)[0] : id
    if !startswith(id, "arn:")
  ]))

  bedrock_profile_arns = [
    for id in local.model_ids :
    startswith(id, "arn:") ? id : "arn:${local.partition}:bedrock:*:${local.account_id}:inference-profile/${id}"
    if startswith(id, "arn:") || length(regexall(local.profile_id_pattern, id)) > 0
  ]

  log_group_arns = [
    aws_cloudwatch_log_group.triage.arn,
    aws_cloudwatch_log_group.investigator.arn,
  ]

  agent_queue_arns = [aws_sqs_queue.alarms.arn, aws_sqs_queue.work.arn]

  # The member accounts' read-only roles: in every account of the organization, or only
  # in the allowed ones.
  member_role_accounts = length(var.allowed_account_ids) == 0 ? ["*"] : var.allowed_account_ids
  member_role_arns = var.member_role_name == null ? [] : [
    for account in local.member_role_accounts :
    "arn:${local.partition}:iam::${account}:role/${var.member_role_name}"
  ]
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${var.name_prefix}-lambda-${var.environment}"
  description        = "Execution role of the ${var.name_prefix} triage and investigator functions."
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = var.tags
}

# The read access the agent's role shares with the member accounts' read-only roles: the
# managed policy, the read grants and the deny list.
module "shared" {
  source = "./modules/shared"

  exclude_alarm_prefixes = local.exclude_alarm_prefixes
  catalog_parameter_arn  = var.catalog_json == null ? null : local.catalog_parameter_arn
  agent_queue_arns       = local.agent_queue_arns
  assumable_role_arns    = local.member_role_arns
}

# AWS's own policy for its DevOps Agent, for the generic aws_call tool. The deny policy
# below still wins; it blocks the reads in this policy that return data or secrets.
resource "aws_iam_role_policy_attachment" "aws_view" {
  role       = aws_iam_role.lambda.name
  policy_arn = module.shared.managed_policy_arn
}

data "aws_iam_policy_document" "logs" {
  statement {
    sid       = "CreateLogGroups"
    actions   = ["logs:CreateLogGroup"]
    resources = local.log_group_arns
  }

  statement {
    sid       = "WriteLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [for arn in local.log_group_arns : "${arn}:*"]
  }
}

resource "aws_iam_role_policy" "logs" {
  name   = "logs"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.logs.json
}

resource "aws_iam_role_policy" "read" {
  name   = "read"
  role   = aws_iam_role.lambda.id
  policy = module.shared.read_policy_json
}

data "aws_iam_policy_document" "bedrock" {
  # Converse is authorized by InvokeModel. Cross-region profiles route to several
  # regions, so the foundation model ARNs take any region.
  statement {
    sid     = "InvokeConfiguredModels"
    actions = ["bedrock:InvokeModel"]
    resources = concat(
      [for model in local.bedrock_foundation_models : "arn:${local.partition}:bedrock:*::foundation-model/${model}"],
      local.bedrock_profile_arns,
    )
  }

  dynamic "statement" {
    for_each = length(aws_bedrock_inference_profile.model) == 0 ? [] : [true]

    content {
      sid       = "InvokeAgentInferenceProfiles"
      actions   = ["bedrock:InvokeModel"]
      resources = [for profile in aws_bedrock_inference_profile.model : profile.arn]
    }
  }
}

resource "aws_iam_role_policy" "bedrock" {
  name   = "bedrock"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.bedrock.json
}

data "aws_iam_policy_document" "own_resources" {
  statement {
    sid = "FindingsTable"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
    ]
    resources = [aws_dynamodb_table.findings.arn]
  }

  statement {
    sid       = "QueryFindings"
    actions   = ["dynamodb:Query"]
    resources = ["${aws_dynamodb_table.findings.arn}/index/*"]
  }

  statement {
    sid = "ConsumeAgentQueues"
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]
    resources = local.agent_queue_arns
  }

  statement {
    sid       = "EnqueueInvestigations"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.work.arn]
  }

  statement {
    sid       = "RetryDeferredAlarms"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.alarms.arn]
  }

  dynamic "statement" {
    for_each = var.notifications_topic_arn == null ? [] : [var.notifications_topic_arn]

    content {
      sid       = "PublishNotifications"
      actions   = ["sns:Publish"]
      resources = [statement.value]
    }
  }
}

# Reaching member accounts. The external id is not a condition here: callers cannot be
# made to send one by their own policy, so each member role's trust policy requires it.
data "aws_iam_policy_document" "member_roles" {
  count = var.member_role_name == null ? 0 : 1

  statement {
    sid       = "AssumeMemberReadRoles"
    actions   = ["sts:AssumeRole"]
    resources = local.member_role_arns
  }
}

resource "aws_iam_role_policy" "member_roles" {
  count = var.member_role_name == null ? 0 : 1

  name   = "member-roles"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.member_roles[0].json
}

resource "aws_iam_role_policy" "own_resources" {
  name   = "own-resources"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.own_resources.json
}

# The explicit deny list, shared with the member accounts' read-only roles. Nothing the
# role is granted covers these, and aws_guard.py refuses the same operations before they
# reach AWS.
resource "aws_iam_role_policy" "deny" {
  name   = "deny"
  role   = aws_iam_role.lambda.id
  policy = module.shared.deny_policy_json
}
