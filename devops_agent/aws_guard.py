"""Which AWS operations aws_call may run.

A second layer under IAM: the execution role is the real boundary. ALLOWED_SERVICES is
the primary control: only the services an investigation of this stack needs are
covered. Inside them, the blocked tables mirror the role's explicit deny policy
(terraform/iam.tf), keyed by botocore service name (``stepfunctions`` is IAM
``states``, ``elbv2`` and ``elb`` are IAM ``elasticloadbalancing``, ``opensearch`` and
``es`` are IAM ``es``) and PascalCase operation name. A deny wins over the read
prefixes.
"""

from __future__ import annotations

# Botocore service names aws_call covers. Adding one is a reviewed change: read its
# Describe, List and Get operations for anything that returns contents, secrets or
# payloads and block those below first.
ALLOWED_SERVICES = frozenset(
    {
        "ec2",
        "autoscaling",
        "application-autoscaling",
        "ecs",
        "eks",
        "elbv2",
        "elb",
        "rds",
        "elasticache",
        "memorydb",
        "opensearch",
        "es",
        "opensearchserverless",
        "sqs",
        "sns",
        "kinesis",
        "firehose",
        "lambda",
        "stepfunctions",
        "events",
        "scheduler",
        "pipes",
        "glue",
        "s3",
        "dynamodb",
        "cloudwatch",
        "logs",
        "cloudtrail",
        "apigateway",
        "apigatewayv2",
        "route53",
        "acm",
        "cloudfront",
        "kafka",
        "sagemaker",
        "bedrock",
        "ecr",
        "efs",
        "backup",
        "health",
        "service-quotas",
        "transfer",
        "ssm",
        "secretsmanager",
        "kms",
        "docdb",
        "neptune",
        "mq",
        "wafv2",
        "network-firewall",
        "cloudformation",
        "xray",
        "application-signals",
        "resourcegroupstaggingapi",
    }
)

# An operation is a read only when its name starts with one of these. Query and Scan
# are not here: they read items.
READ_PREFIXES = ("Describe", "List", "Get", "BatchGet", "BatchDescribe", "Search", "Lookup")

NOT_COVERED = "service not covered by aws_call"
FILE_BODY = "returns a file body"
OBJECT_CONTENTS = "reads object contents"
SECRET_VALUES = "returns secret values"
CREDENTIALS = "returns credentials"
ENVIRONMENT = "returns environment variables"
USER_DATA = "returns instance user data"
CONSOLE_OUTPUT = "returns console output"
PAYLOADS = "reads payload data"
CODE = "returns code"
CONFIGURATION = "returns configuration contents"
KEY_MATERIAL = "key material or cryptographic operation"
NOT_READ = "not a read operation"

BLOCKED_OPERATIONS: dict[str, str] = {
    "secretsmanager:GetSecretValue": SECRET_VALUES,
    "secretsmanager:BatchGetSecretValue": SECRET_VALUES,
    "ssm:GetParameter": SECRET_VALUES,
    "ssm:GetParameters": SECRET_VALUES,
    "ssm:GetParametersByPath": SECRET_VALUES,
    "ssm:GetParameterHistory": SECRET_VALUES,
    "ssm:GetCommandInvocation": CONSOLE_OUTPUT,
    "ssm:ListCommandInvocations": CONSOLE_OUTPUT,
    "ssm:ListCommands": PAYLOADS,
    "ssm:GetDocument": CODE,
    "ssm:GetAutomationExecution": PAYLOADS,
    "ssm:GetMaintenanceWindowTask": PAYLOADS,
    "ssm:GetMaintenanceWindowExecutionTaskInvocation": PAYLOADS,
    "ssm:GetAccessToken": CREDENTIALS,
    "s3:GetObject": OBJECT_CONTENTS,
    "s3:GetObjectTorrent": OBJECT_CONTENTS,
    "s3:SelectObjectContent": OBJECT_CONTENTS,
    "lambda:GetFunction": ENVIRONMENT,
    "lambda:GetFunctionConfiguration": ENVIRONMENT,
    "lambda:ListFunctions": ENVIRONMENT,
    "lambda:ListVersionsByFunction": ENVIRONMENT,
    "mq:DescribeConfigurationRevision": CONFIGURATION,
    "lambda:GetLayerVersion": CODE,
    "lambda:GetLayerVersionByArn": CODE,
    "cloudfront:GetFunction": CODE,
    "ec2:GetPasswordData": SECRET_VALUES,
    "ec2:DescribeInstanceAttribute": USER_DATA,
    "ec2:DescribeLaunchTemplateVersions": USER_DATA,
    "ec2:GetConsoleOutput": CONSOLE_OUTPUT,
    "ec2:GetConsoleScreenshot": CONSOLE_OUTPUT,
    "ec2:GetVpnConnectionDeviceSampleConfiguration": SECRET_VALUES,
    "ec2:DescribeVpnConnections": SECRET_VALUES,
    "ec2:DescribeVerifiedAccessTrustProviders": SECRET_VALUES,
    "autoscaling:DescribeLaunchConfigurations": USER_DATA,
    "ecs:DescribeTaskDefinition": ENVIRONMENT,
    "stepfunctions:DescribeExecution": PAYLOADS,
    "stepfunctions:GetExecutionHistory": PAYLOADS,
    "stepfunctions:GetActivityTask": PAYLOADS,
    "kinesis:GetRecords": PAYLOADS,
    "kinesis:GetShardIterator": PAYLOADS,
    "dynamodb:GetItem": PAYLOADS,
    "dynamodb:BatchGetItem": PAYLOADS,
    "cloudformation:GetTemplate": CONFIGURATION,
    "cloudformation:GetTemplateSummary": CONFIGURATION,
    "cloudformation:DescribeStackResourceDrifts": CONFIGURATION,
    "glue:GetJob": ENVIRONMENT,
    "glue:GetJobs": ENVIRONMENT,
    "glue:BatchGetJobs": ENVIRONMENT,
    "glue:GetJobRun": ENVIRONMENT,
    "glue:GetJobRuns": ENVIRONMENT,
    "glue:GetTrigger": ENVIRONMENT,
    "glue:GetTriggers": ENVIRONMENT,
    "glue:GetDevEndpoint": CREDENTIALS,
    "glue:GetDevEndpoints": CREDENTIALS,
    "glue:GetSession": CODE,
    "glue:GetStatement": CODE,
    "glue:ListStatements": CODE,
    "glue:GetConnection": SECRET_VALUES,
    "glue:GetConnections": SECRET_VALUES,
    "sagemaker:DescribeModel": ENVIRONMENT,
    "sagemaker:DescribeTrainingJob": ENVIRONMENT,
    "sagemaker:DescribeProcessingJob": ENVIRONMENT,
    "sagemaker:DescribeTransformJob": ENVIRONMENT,
    "sagemaker:DescribePipeline": CONFIGURATION,
    "sagemaker:DescribePipelineDefinitionForExecution": CONFIGURATION,
    "sagemaker:DescribeOptimizationJob": ENVIRONMENT,
    "apigateway:GetApiKey": SECRET_VALUES,
    "apigateway:GetApiKeys": SECRET_VALUES,
    "apigateway:GetUsagePlanKey": SECRET_VALUES,
    "apigateway:GetUsagePlanKeys": SECRET_VALUES,
    "apigateway:GetExport": CONFIGURATION,
    "ecr:GetAuthorizationToken": CREDENTIALS,
    "ecr:GetDownloadUrlForLayer": OBJECT_CONTENTS,
    "ecr:BatchGetImage": OBJECT_CONTENTS,
}

# Services where only operations with these prefixes are allowed.
SERVICE_READ_PREFIXES: dict[str, tuple[tuple[str, ...], str]] = {
    "secretsmanager": (("Describe", "List"), SECRET_VALUES),
    "cloudformation": (("Describe", "List"), CONFIGURATION),
}

# Services where only these operations are allowed.
SERVICE_READ_OPERATIONS: dict[str, tuple[frozenset[str], str]] = {
    "kms": (
        frozenset(
            {"DescribeKey", "ListAliases", "ListKeys", "GetKeyRotationStatus", "GetKeyPolicy"}
        ),
        KEY_MATERIAL,
    ),
}


def check(service: str, operation: str, returns_body: bool = False) -> str | None:
    """Why ``service`` (botocore name) ``operation`` (PascalCase) is refused, or None.

    ``returns_body`` is whether the operation's output streams a file body.
    """
    if service not in ALLOWED_SERVICES:
        return NOT_COVERED
    if reason := BLOCKED_OPERATIONS.get(f"{service}:{operation}"):
        return reason
    if not operation.startswith(READ_PREFIXES):
        return NOT_READ
    if returns_body:
        return FILE_BODY
    if service in SERVICE_READ_PREFIXES:
        prefixes, reason = SERVICE_READ_PREFIXES[service]
        if not operation.startswith(prefixes):
            return reason
    if service in SERVICE_READ_OPERATIONS:
        operations, reason = SERVICE_READ_OPERATIONS[service]
        if operation not in operations:
            return reason
    return None
