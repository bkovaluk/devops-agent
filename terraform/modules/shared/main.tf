# What the agent's own execution role and every member account's read-only role share:
# the read grants, the managed policy, the explicit deny list, and the pattern of the
# alarm events the agent investigates. Defined once so the roles cannot drift apart.

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region
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
    for_each = var.catalog_parameter_arn == null ? [] : [var.catalog_parameter_arn]

    content {
      sid       = "ReadCatalog"
      actions   = ["ssm:GetParameter"]
      resources = [statement.value]
    }
  }
}

# A backstop: nothing in the read grants allows these, and aws_guard.py refuses the same
# operations before they reach AWS. The Lambda configuration reads would return the
# Datadog and GitHub keys in plaintext. kms:Decrypt stays allowed by omission because
# Lambda decrypts the functions' environment variables as the agent's role.
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
      "sts:GetFederationToken",
      "sts:GetSessionToken",
    ]
    resources = ["*"]
  }

  # The only roles a role may assume are the member accounts' read-only roles.
  statement {
    sid           = "DenyAssumingOtherRoles"
    effect        = "Deny"
    actions       = ["sts:AssumeRole"]
    resources     = length(var.assumable_role_arns) == 0 ? ["*"] : null
    not_resources = length(var.assumable_role_arns) == 0 ? null : var.assumable_role_arns
  }

  # And only in the organization's accounts: a role whose account is outside it, or in no
  # organization at all (the key is then absent, which StringNotEquals matches), is denied.
  dynamic "statement" {
    for_each = var.assumable_role_org_id == null ? [] : [var.assumable_role_org_id]

    content {
      sid       = "DenyAssumingRolesOutsideOrganization"
      effect    = "Deny"
      actions   = ["sts:AssumeRole"]
      resources = ["*"]

      condition {
        test     = "StringNotEquals"
        variable = "aws:ResourceOrgID"
        values   = [statement.value]
      }
    }
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
    resources     = var.catalog_parameter_arn == null ? ["*"] : null
    not_resources = var.catalog_parameter_arn == null ? null : [var.catalog_parameter_arn]
  }

  # Reads AIDevOpsAgentAccessPolicy grants, or a later version of it could, that return
  # user data, code, command output, configuration contents, environment variables,
  # arguments, query results, sampled requests, traces or credentials, and its one write.
  # aws_guard.py blocks those of the services aws_call covers.
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
      "xray:BatchGetTraces",
      "wafv2:GetSampledRequests",
      "waf:GetSampledRequests",
      "waf-regional:GetSampledRequests",
      "appsync:GetGraphqlApiEnvironmentVariables",
      "codecommit:GetDifferences",
      "codecommit:GetCommit",
      "codecommit:GetBlob",
      "codecommit:GetFile",
      "codecommit:GetFolder",
      "codecommit:BatchGet*",
      "iot:GetThingShadow",
      "athena:GetNamedQuery",
      "athena:BatchGetNamedQuery",
      "athena:GetPreparedStatement",
      "athena:GetQueryResults",
      "imagebuilder:GetComponent",
      "ses:GetTemplate",
      "ses:GetEmailTemplate",
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

  # Message bodies: only the agent's own queues, which its event source mappings read.
  statement {
    sid           = "DenyQueueReadsOutsideAgentQueues"
    effect        = "Deny"
    actions       = ["sqs:ReceiveMessage"]
    resources     = length(var.agent_queue_arns) == 0 ? ["*"] : null
    not_resources = length(var.agent_queue_arns) == 0 ? null : var.agent_queue_arns
  }
}
