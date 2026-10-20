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

# AWS's own policy for its DevOps Agent: Describe, List and Get across most services,
# kept current by AWS, for the generic aws_call tool. The deny policy below still wins; it
# blocks the reads in this policy that return data or secrets.
resource "aws_iam_role_policy_attachment" "aws_view" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AIDevOpsAgentAccessPolicy"
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

# The operations the curated tools and the context bundle call. These APIs either take
# no resource ARN or are called on whatever resource an alarm watches, so they are
# granted on all resources unless noted.
data "aws_iam_policy_document" "read" {
  statement {
    sid = "ReadAlarmsAndMetrics"
    actions = [
      "cloudwatch:DescribeAlarms",
      "cloudwatch:DescribeAlarmHistory",
      "cloudwatch:GetMetricData",
      "cloudwatch:ListTagsForResource",
    ]
    resources = ["*"]
  }

  statement {
    sid = "ReadLogsInsights"
    actions = [
      "logs:StartQuery",
      "logs:GetQueryResults",
      "logs:StopQuery",
      "logs:DescribeLogGroups",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "ReadCloudTrail"
    actions   = ["cloudtrail:LookupEvents"]
    resources = ["*"]
  }

  statement {
    sid = "InspectServices"
    actions = [
      "lambda:ListEventSourceMappings",
      "sqs:GetQueueUrl",
      "sqs:GetQueueAttributes",
      "kinesis:DescribeStreamSummary",
      "kinesis:ListStreamConsumers",
      "rds:DescribeDBClusters",
      "rds:DescribeDBInstances",
      "rds:DescribeEvents",
      "es:DescribeDomain",
      "es:DescribeDomainHealth",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticache:DescribeReplicationGroups",
      "elasticache:DescribeCacheClusters",
      "states:DescribeStateMachine",
      "states:ListExecutions",
      "states:ListStateMachines",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "InspectEksClusters"
    actions   = ["eks:DescribeCluster", "eks:ListNodegroups", "eks:DescribeNodegroup"]
    resources = ["*"]
  }

  # EC2 alarms name an instance id; the agent reads its type and tags to tell an EKS node
  # from a plain host.
  statement {
    sid       = "DescribeInstances"
    actions   = ["ec2:DescribeInstances"]
    resources = ["*"]
  }

  # Error logs name a bucket and key; the agent checks whether the key exists and its
  # version history. Listing only: object reads stay denied below.
  statement {
    sid = "ListS3Keys"
    actions = [
      "s3:ListBucket",
      "s3:ListBucketVersions",
      "s3:GetBucketVersioning",
    ]
    resources = ["arn:${local.partition}:s3:::*"]
  }

  # Time-of-day alarms: which EventBridge rules and Scheduler schedules fired.
  statement {
    sid = "ReadScheduledJobs"
    actions = [
      "events:ListRules",
      "events:ListTargetsByRule",
      "scheduler:ListSchedules",
      "scheduler:GetSchedule",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "InspectPerformanceInsights"
    actions   = ["pi:GetResourceMetrics"]
    resources = ["arn:${local.partition}:pi:${local.region}:${local.account_id}:metrics/rds/*"]
  }

  statement {
    sid       = "InspectApiStages"
    actions   = ["apigateway:GET"]
    resources = ["arn:${local.partition}:apigateway:${local.region}::/apis/*/stages*"]
  }

  dynamic "statement" {
    for_each = var.catalog_json == null ? [] : [local.catalog_parameter_arn]

    content {
      sid       = "ReadCatalog"
      actions   = ["ssm:GetParameter"]
      resources = [statement.value]
    }
  }
}

resource "aws_iam_role_policy" "read" {
  name   = "read"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.read.json
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

resource "aws_iam_role_policy" "own_resources" {
  name   = "own-resources"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.own_resources.json
}

# A backstop: nothing above grants these, and aws_guard.py refuses the same operations
# before they reach AWS. The Lambda configuration reads would return the Datadog and
# GitHub keys in plaintext. kms:Decrypt stays allowed by omission because Lambda decrypts
# the functions' environment variables as this role.
data "aws_iam_policy_document" "deny" {
  statement {
    sid    = "DenySecretReadsAndIdentityChanges"
    effect = "Deny"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:BatchGetSecretValue",
      "s3:GetObject",
      "s3:GetObjectVersion",
      "lambda:GetFunctionConfiguration",
      "lambda:GetFunction",
      "lambda:ListFunctions",
      "ec2:GetPasswordData",
      "ecs:DescribeTaskDefinition",
      "states:DescribeExecution",
      "states:GetExecutionHistory",
      "kinesis:GetRecords",
      "kinesis:GetShardIterator",
      "iam:*",
      "sts:AssumeRole",
      "sts:GetFederationToken",
      "sts:GetSessionToken",
    ]
    resources = ["*"]
  }

  # Parameters can hold credentials. The one the agent may read is its catalog.
  statement {
    sid    = "DenySsmReadsExceptCatalog"
    effect = "Deny"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
      "ssm:GetParameterHistory",
    ]
    not_resources = [local.catalog_parameter_arn]
  }

  # Reads AIDevOpsAgentAccessPolicy grants that return user data, code, command output,
  # configuration contents, environment variables, arguments or credentials, and its one
  # write. aws_guard.py blocks the same operations.
  statement {
    sid    = "DenyDataReadsInAwsViewPolicy"
    effect = "Deny"
    actions = [
      "ec2:DescribeInstanceAttribute",
      "ec2:DescribeLaunchTemplateVersions",
      "ec2:DescribeVpnConnections",
      "ec2:DescribeVerifiedAccessTrustProviders",
      "autoscaling:DescribeLaunchConfigurations",
      "lambda:GetLayerVersion",
      "lambda:ListVersionsByFunction",
      "ssm:GetCommandInvocation",
      "ssm:ListCommandInvocations",
      "ssm:ListCommands",
      "ssm:GetDocument",
      "appconfig:GetHostedConfigurationVersion",
      "cloudformation:GetTemplate",
      "cloudformation:DescribeStackResourceDrifts",
      "cloudfront:GetFunction",
      "datapipeline:GetPipelineDefinition",
      "amplify:GetApp",
      "amplify:GetBranch",
      "elasticbeanstalk:DescribeConfigurationSettings",
      "airflow:GetEnvironment",
      "glue:GetJob",
      "glue:GetJobs",
      "glue:BatchGetJobs",
      "glue:GetTrigger",
      "glue:ListStatements",
      "sagemaker:DescribeModel",
      "sagemaker:DescribeTrainingJob",
      "sagemaker:DescribeProcessingJob",
      "sagemaker:DescribeTransformJob",
      "sagemaker:DescribePipeline",
      "sagemaker:DescribePipelineDefinitionForExecution",
      "sagemaker:DescribeOptimizationJob",
      "mq:DescribeConfigurationRevision",
      "eks:AccessKubernetesApi",
      "support:CreateCase",
    ]
    resources = ["*"]
  }

  # apigateway:GET covers every REST read; these paths return API key values.
  statement {
    sid     = "DenyApiKeyValues"
    effect  = "Deny"
    actions = ["apigateway:GET"]
    resources = [
      "arn:${local.partition}:apigateway:*::/apikeys",
      "arn:${local.partition}:apigateway:*::/apikeys/*",
      "arn:${local.partition}:apigateway:*::/usageplans/*/keys",
      "arn:${local.partition}:apigateway:*::/usageplans/*/keys/*",
    ]
  }

  statement {
    sid           = "DenyQueueReadsOutsideAgentQueues"
    effect        = "Deny"
    actions       = ["sqs:ReceiveMessage"]
    not_resources = local.agent_queue_arns
  }
}

resource "aws_iam_role_policy" "deny" {
  name   = "deny"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.deny.json
}
