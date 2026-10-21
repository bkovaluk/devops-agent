# Terraform contract

What a deployment of devops-agent needs, for the Terraform module in `terraform/`. One
deployment serves one region: its own AWS account, and optionally the member accounts
of an AWS Organization, each of which deploys `terraform/member` (see Member accounts).
Names below use a `name_prefix` variable (default `devops-agent`) and an `environment`
variable (`dev`, `qa`, `staging` or `prod`); `<prefix>` is `${name_prefix}` and `<env>`
is `${environment}`.

## Inputs the module should take

| Input | Default | Used for |
|-------|---------|----------|
| `name_prefix` | `devops-agent` | every resource name; must start with `devops-agent` (see EventBridge rules) |
| `environment` | required | `ENVIRONMENT` and names |
| `package_path` or S3 key | required | the Lambda zip (the `devops_agent` package and its dependencies) |
| `model_id`, `fallback_model_id` | `us.anthropic.claude-opus-5-5`, `us.anthropic.claude-opus-5` | the application inference profiles, `MODEL_ID`, `FALLBACK_MODEL_ID` and the Bedrock policy |
| `input_tokens_per_hour`, `output_tokens_per_hour` | `3000000`, `200000` | the token alarms |
| `bedrock_budget_usd`, `bedrock_budget_services` | `200`, the Bedrock and Claude Opus services | the Bedrock cost budget |
| `catalog_json` | `null` | the catalog parameter, `CATALOG_PARAMETER` and the rules' filters |
| `datadog_event_source_name` | `null` | the Datadog partner event bus and its rule |
| `notifications_enabled` | `false` | `SLACK_ENABLED` |
| `notifications_topic_arn` | `null` | `SLACK_TOPIC_ARN` and the `sns:Publish` grant; required when notifications are enabled |
| `notifications_channel` | `""` | `SLACK_CHANNEL` |
| `prompt_notes` | `""` | `PROMPT_NOTES` |
| `datadog_api_key`, `datadog_app_key` | `null` (sensitive) | `DD_API_KEY`, `DATADOG_APP_KEY` |
| `datadog_site` | `datadoghq.com` | `DATADOG_SITE` |
| `github_app_id`, `github_app_installation_id`, `github_app_private_key` | `null` (private key sensitive) | `GH_APP_ID`, `GH_APP_INSTALLATION_ID`, `GH_APP_PRIVATE_KEY` |
| `github_org` | `null` | `GH_ORG` |
| `member_role_name` | `null` | `MEMBER_ROLE_NAME` on both functions and the `sts:AssumeRole` grant |
| `member_external_id` | `null` (sensitive) | `MEMBER_EXTERNAL_ID` on both functions |
| `allowed_account_ids` | `[]` | `ALLOWED_ACCOUNT_IDS` on both functions, and the accounts the `sts:AssumeRole` grant names (any account when empty) |
| `organization_id` | `null` | the central event bus, its organization-only policy and its rule; with `member_role_name`, the organization boundary on `sts:AssumeRole` |
| `account_hourly_budget`, `account_daily_budget`, `account_p1_daily_overflow` | `null` | `ACCOUNT_HOURLY_BUDGET`, `ACCOUNT_DAILY_BUDGET`, `ACCOUNT_P1_DAILY_OVERFLOW` on triage |
| `extra_environment` | `{}` | any other variable in the tables below (budgets, throttles, steps, log level) |
| `alarm_actions` | `[]` | the queue and token alarms, and the budget's notifications (its SNS topics) |
| `tags` | `{}` | all resources |

Unset optional values are left out of the Lambda environment rather than set to empty
strings.

## Lambda functions

Both run as the one execution role, Python 3.12, from the same zip, with no VPC.

| Function | Handler | Timeout | Memory | Event source |
|----------|---------|---------|--------|--------------|
| `<prefix>-triage-<env>` | `devops_agent.triage.handler` | 120 s | 512 MB | alarms queue: batch size 25, maximum batching window 60 s, maximum concurrency 2 |
| `<prefix>-<env>` (investigator) | `devops_agent.handler.handler` | 900 s | 512 MB | work queue: batch size 1, maximum concurrency 2 |

Both handlers return `batchItemFailures`, so both event source mappings need
`function_response_types = ["ReportBatchItemFailures"]`.

Each function has a CloudWatch log group `/aws/lambda/<function name>`; create both in
Terraform with a retention period.

### Environment, both functions

| Variable | Value |
|----------|-------|
| `ENVIRONMENT` | `<env>` |
| `FINDINGS_TABLE` | the findings table name (required) |
| `SLACK_ENABLED` | `"true"` or `"false"` from `notifications_enabled` |
| `SLACK_TOPIC_ARN` | `notifications_topic_arn`, when set |
| `SLACK_CHANNEL` | `notifications_channel`, when set |
| `CATALOG_PARAMETER` | the catalog parameter's name, when `catalog_json` is set |
| `DD_API_KEY`, `DATADOG_APP_KEY`, `DATADOG_SITE` | the Datadog settings, when set: the investigator's Datadog tools and triage's monitor verification use them |
| `MEMBER_ROLE_NAME`, `MEMBER_EXTERNAL_ID`, `ALLOWED_ACCOUNT_IDS` | the member account settings, when set (`ALLOWED_ACCOUNT_IDS` comma-separated): triage reads a member's alarm and the investigator a member's account through the role |
| `LOG_LEVEL` | `INFO` unless overridden |
| `POWERTOOLS_SERVICE_NAME` | `devops-agent` (optional, a log field only) |

Triage's settings extend the shared ones, so triage validates `FINDINGS_TABLE` and the
notification settings too: set the shared variables on both functions.

### Environment, investigator only

| Variable | Value |
|----------|-------|
| `MODEL_ID`, `FALLBACK_MODEL_ID` | the ARNs of the module's application inference profiles (or the ARNs given as model ids) |
| `RUN_TOKEN_BUDGET` | optional, default 250000 |
| `PROMPT_NOTES` | `prompt_notes`, when set |
| `GH_APP_ID`, `GH_APP_INSTALLATION_ID`, `GH_APP_PRIVATE_KEY`, `GH_ORG` | the GitHub settings, when set |

Optional with code defaults (see the README's Configuration table): `MAX_STEPS`,
`MAX_TOKENS`, `PROMPT_CACHING`, `CAPTURE_SNAPSHOTS`, `SERVICE_NOTES_FILE`, and on both
functions `DATADOG_ACCOUNT_TAG`. `AWS_REGION` is set by Lambda.

### Environment, triage only

| Variable | Value |
|----------|-------|
| `WORK_QUEUE_URL` | the work queue URL (required) |
| `ALARMS_QUEUE_URL` | the alarms queue URL (required) |
| `HOURLY_BUDGET` | optional, default 10 |
| `DAILY_BUDGET` | optional, default 50 |
| `DAILY_TOKEN_BUDGET` | optional, default 3000000 |
| `P1_DAILY_OVERFLOW` | optional, default 10 |
| `RESERVE_FRACTION` | optional, default 0.3 |
| `DATADOG_HOURLY_SHARE` | optional, default 6 |
| `STORM_THRESHOLD` | optional, default 5 |
| `STORM_RATE` | optional, default 30 |
| `ALARM_COOLDOWN_MINUTES` | optional, default 120 |
| `RESOURCE_COOLDOWN_MINUTES` | optional, default 60 |
| `MAX_DEFERRED_RETRIES` | optional, default 8 |
| `ACCOUNT_HOURLY_BUDGET` | optional, default 5; applies with `MEMBER_ROLE_NAME` set |
| `ACCOUNT_DAILY_BUDGET` | optional, default 25; applies with `MEMBER_ROLE_NAME` set |
| `ACCOUNT_P1_DAILY_OVERFLOW` | optional, default 5; applies with `MEMBER_ROLE_NAME` set |

## SQS queues

All four use SQS-managed server-side encryption.

| Queue | Visibility timeout | Retention | Redrive |
|-------|-------------------:|----------:|---------|
| `<prefix>-alarms-<env>` | 780 s | 1 day | to `<prefix>-alarms-dlq-<env>` after 3 receives |
| `<prefix>-alarms-dlq-<env>` | default | 14 days | redrive-allow from the alarms queue only |
| `<prefix>-work-<env>` | 5400 s | 1 day | to `<prefix>-work-dlq-<env>` after 2 receives |
| `<prefix>-work-dlq-<env>` | default | 14 days | redrive-allow from the work queue only |

The visibility timeouts are six times each consumer's timeout (120 s and 900 s), plus
the 60 s batching window on the alarms queue. Triage sends budget-deferred alarms back
to the alarms queue with `DelaySeconds` 900, so leave the alarms queue's delay settings
at their defaults.

The alarms queue policy allows `sqs:SendMessage` from `events.amazonaws.com` with
`aws:SourceArn` equal to the CloudWatch alarm rule's ARN, the central bus rule's or the
Datadog rule's.

### Queue alarms

Named with `<prefix>` first, so the agent never investigates its own alarms. Missing
data is not breaching; the actions are `alarm_actions`.

| Alarm | Metric | Rule |
|-------|--------|------|
| `<prefix>-alarms-dlq-<env>`, `<prefix>-work-dlq-<env>` | `ApproximateNumberOfMessagesVisible` on the DLQ | Maximum >= 1 over 300 s, 1 period: the agent dropped work |
| `<prefix>-alarms-backlog-<env>`, `<prefix>-work-backlog-<env>` | `ApproximateAgeOfOldestMessage` on the queue | Maximum > 1800 s over 300 s, 3 periods: its consumer is not draining it |

## DynamoDB findings table

`<prefix>-findings-<env>`, on-demand billing, point-in-time recovery on.

| Setting | Value |
|---------|-------|
| Hash key | `pk` (S) |
| Range key | none |
| TTL attribute | `ttl` (epoch seconds), enabled |

Global secondary indexes, both with projection `ALL`:

| Index | Hash key | Range key | Used by |
|-------|----------|-----------|---------|
| `by_resource` | `resource_key` (S) | `created_at` (S) | the agent (`findings.py`): prior findings on a resource, newest first, and triage's lookups of an open investigation and of the cooldown after a close |
| `by_status` | `status` (S) | `created_at` (S) | review tools listing findings by status; the agent never queries it |

Declare `pk`, `resource_key`, `status` and `created_at` as attributes. Items share the
table by `pk` prefix: `finding#<id>` (findings), `snap#<id>` (eval snapshots),
`active#<resource_key>` (running-job claims, `active.py`), `budget#<YYYY-MM-DDTHH>`,
`budget#<YYYY-MM-DD>`, `budget#tokens#day#<YYYY-MM-DD>`, `budget#datadog#<YYYY-MM-DDTHH>`,
`budget#p1#day#<YYYY-MM-DD>` and, with member accounts,
`budget#account#<account>#<YYYY-MM-DDTHH>`, `budget#account#<account>#<YYYY-MM-DD>` and
`budget#account#<account>#p1#day#<YYYY-MM-DD>` (budget counters, `gate.py`), `rate#<YYYY-MM-DDTHH:MM>` and
`rate#<account>#<YYYY-MM-DDTHH:MM>` (the signal rate), `storm#active` and
`storm#active#<account>` (the open storm) and `obs#<resource_key>` (sources that
returned data). A member account's `resource_key` is `<account id>|<key>`; the agent's
own account's keys carry no account. Only `finding#` items carry `resource_key` and
`status`, so only findings appear in the indexes.

## EventBridge rules

`<prefix>-alarms-<env>` on the default bus, targeting the alarms queue:

```json
{
  "source": ["aws.cloudwatch"],
  "detail-type": ["CloudWatch Alarm State Change"],
  "detail": {
    "state": { "value": ["ALARM"] },
    "alarmName": [
      { "anything-but": { "prefix": ["TargetTracking-", "devops-agent", "<prefix>"] } }
    ]
  }
}
```

The prefixes are the catalog's `agent.exclude_alarm_prefixes` plus `<prefix>`.
`TargetTracking-` alarms are autoscaling alarms that enter ALARM as part of normal
scaling. The agent's own alarms are excluded so a failing agent does not investigate
itself. Triage drops the catalog's prefixes too, which is why `name_prefix` must start
with `devops-agent`.

With `datadog_event_source_name` set, the module also creates the partner event bus
for that Datadog event source and `<prefix>-datadog-<env>` on it, targeting the same
queue:

```json
{
  "detail-type": ["Datadog Alert Notification"],
  "detail": { "tags": ["devops_agent:true"] }
}
```

The tags are the catalog's `agent.datadog_monitor_tags`. Triage reads each monitor back
and keeps only alerting groups of monitors that carry them.

With `organization_id` set, the module also creates the central event bus
`<prefix>-alarms-<env>`, with a resource policy that allows `events:PutEvents` to any
principal whose `aws:PrincipalOrgID` is `organization_id`, and the rule
`<prefix>-member-alarms-<env>` on it, with the same pattern as `<prefix>-alarms-<env>`,
targeting the alarms queue. The member accounts' rules put their alarm events there.

## Catalog parameter

With `catalog_json` set, an SSM String parameter `/<prefix>/<env>/catalog` holds it
(Advanced tier past 4 KB), and both functions read it through `CATALOG_PARAMETER`.
Without it they run on `devops_agent/catalog.json`, which the module also reads for the
rules' filters.

## Bedrock

For each of `model_id` and `fallback_model_id` that is not already an ARN, an
application inference profile `<prefix>-primary-<env>` or `<prefix>-fallback-<env>`
copied from it (from the system cross-region profile for a `us.`-style id, else from
the foundation model), so the agent's tokens are metered under its own profiles.

Two alarms, `<prefix>-input-tokens-<env>` and `<prefix>-output-tokens-<env>`, sum the
primary profile's hourly `InputTokenCount` and `OutputTokenCount` in `AWS/Bedrock`
(read under `ModelId` as both the profile ARN and its id) against
`input_tokens_per_hour` and `output_tokens_per_hour`.

A monthly cost budget `<prefix>-bedrock-<env>` of `bedrock_budget_usd` on the
`bedrock_budget_services` (Anthropic models bill as Marketplace services named after
the model), notifying the SNS topics in `alarm_actions` at 80% actual and 100%
forecasted spend.

## IAM execution role

`<prefix>-lambda-<env>`, assumed by `lambda.amazonaws.com`.

### Managed policy

`arn:aws:iam::aws:policy/AIDevOpsAgentAccessPolicy`: Describe, List and Get across most
services, kept current by AWS, for the generic `aws_call` tool. The explicit deny below
still wins over it.

The managed policy, the Read statements and the Explicit deny below are defined once,
in `terraform/modules/shared`, which both this role and every member account's
read-only role use.

### Logs

- `logs:CreateLogGroup` on the two log group ARNs
- `logs:CreateLogStream`, `logs:PutLogEvents` on `<log group ARN>:*` for both

### Read (resource `*` unless noted)

- `cloudwatch:DescribeAlarms`, `cloudwatch:DescribeAlarmHistory`,
  `cloudwatch:GetMetricData`, `cloudwatch:ListTagsForResource`
- `logs:StartQuery`, `logs:GetQueryResults`, `logs:StopQuery`, `logs:DescribeLogGroups`
- `cloudtrail:LookupEvents`
- `lambda:ListEventSourceMappings`
- `sqs:GetQueueUrl`, `sqs:GetQueueAttributes`
- `kinesis:DescribeStreamSummary`, `kinesis:ListStreamConsumers`
- `rds:DescribeDBClusters`, `rds:DescribeDBInstances`, `rds:DescribeEvents`
- `es:DescribeDomain`, `es:DescribeDomainHealth`
- `elasticloadbalancing:DescribeLoadBalancers`,
  `elasticloadbalancing:DescribeTargetGroups`,
  `elasticloadbalancing:DescribeTargetHealth`
- `elasticache:DescribeReplicationGroups`, `elasticache:DescribeCacheClusters`
- `states:DescribeStateMachine`, `states:ListExecutions`, `states:ListStateMachines`
- `eks:DescribeCluster`, `eks:ListNodegroups`, `eks:DescribeNodegroup`
- `ec2:DescribeInstances`
- `s3:ListBucket`, `s3:ListBucketVersions`, `s3:GetBucketVersioning` on
  `arn:aws:s3:::*` (listing only; object reads are denied below)
- `events:ListRules`, `events:ListTargetsByRule`, `scheduler:ListSchedules`,
  `scheduler:GetSchedule`
- `pi:GetResourceMetrics` on `arn:aws:pi:<region>:<account>:metrics/rds/*`
- `apigateway:GET` on `arn:aws:apigateway:<region>::/apis/*/stages*`
- `ssm:GetParameter` on the catalog parameter, only when `catalog_json` is set

These cover every boto3 operation in `READ_ONLY_OPERATIONS` in
`devops_agent/tools.py`; the Datadog and GitHub reads in that list need no IAM.

### Bedrock

`bedrock:InvokeModel` (Converse is authorized by it) on:

- `arn:aws:bedrock:*::foundation-model/<model>` for each foundation model the two model
  ids route to (for the defaults, `anthropic.claude-opus-5-5` and
  `anthropic.claude-opus-5`). The region is `*` because `us.` cross-region profiles
  route to several US regions.
- `arn:aws:bedrock:*:<account>:inference-profile/<id>` for each model id that is a
  cross-region profile id, or the ARN itself when a model id is an application
  inference profile ARN.
- the module's application inference profiles.

### Writes on the agent's own resources

- `dynamodb:GetItem`, `dynamodb:PutItem`, `dynamodb:UpdateItem` on the findings table
- `dynamodb:Query` on `<table ARN>/index/*`
- `sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:GetQueueAttributes` on the alarms and
  work queues (the event source mappings)
- `sqs:SendMessage` on the work queue (triage's jobs) and the alarms queue (triage's
  delayed retries)
- `sns:Publish` on `notifications_topic_arn`, only when it is set

### Member roles

Only with `member_role_name` set, in its own policy `member-roles`: `sts:AssumeRole` on
`arn:aws:iam::<account>:role/<member_role_name>` for each of `allowed_account_ids`, or
`arn:aws:iam::*:role/<member_role_name>` when that list is empty. With `organization_id`
set, the statement has the condition `StringEquals` `aws:ResourceOrgID` =
`organization_id`, so the role's account must belong to the organization either way.
No `sts:ExternalId` condition: a caller's own policy cannot require it, so each member
role's trust policy does when `external_id` is set.

### Explicit deny

A backstop; nothing above grants these, and `devops_agent/aws_guard.py` refuses the
same operations before they reach AWS. Resource `*`:

```
secretsmanager:GetSecretValue
secretsmanager:BatchGetSecretValue
s3:GetObject
s3:GetObjectVersion
lambda:GetFunctionConfiguration
lambda:GetFunction
lambda:ListFunctions
ec2:GetPasswordData
ecs:DescribeTaskDefinition
states:DescribeExecution
states:GetExecutionHistory
kinesis:GetRecords
kinesis:GetShardIterator
iam:*
sts:GetFederationToken
sts:GetSessionToken
```

`sts:AssumeRole` with `NotResource` set to the member role ARNs above, or on `*` when
there are none: the only roles the role may assume are the member roles. With
`member_role_name` and `organization_id` set, also `sts:AssumeRole` on `*` with
`StringNotEquals` `aws:ResourceOrgID` = `organization_id`: a role in an account outside
the organization, or in no organization (the key is then absent), is denied.

`ssm:GetParameter`, `ssm:GetParameters`, `ssm:GetParametersByPath` and
`ssm:GetParameterHistory` with `NotResource` set to the catalog parameter's ARN (on `*`
without one): parameters can hold credentials.

The reads `AIDevOpsAgentAccessPolicy` grants, or a later version of it could, that
return user data, code, command output, configuration contents, environment variables,
arguments, query results, sampled requests, traces or credentials, and its one write,
resource `*`:

```
ec2:DescribeInstanceAttribute
ec2:DescribeLaunchTemplateVersions
ec2:DescribeVpnConnections
ec2:DescribeVerifiedAccessTrustProviders
autoscaling:DescribeLaunchConfigurations
lambda:GetLayerVersion
lambda:ListVersionsByFunction
ssm:GetCommandInvocation
ssm:ListCommandInvocations
ssm:ListCommands
ssm:GetDocument
appconfig:GetHostedConfigurationVersion
cloudformation:GetTemplate
cloudformation:DescribeStackResourceDrifts
cloudfront:GetFunction
datapipeline:GetPipelineDefinition
amplify:GetApp
amplify:GetBranch
elasticbeanstalk:DescribeConfigurationSettings
airflow:GetEnvironment
glue:GetJob
glue:GetJobs
glue:BatchGetJobs
glue:GetTrigger
glue:ListStatements
sagemaker:DescribeModel
sagemaker:DescribeTrainingJob
sagemaker:DescribeProcessingJob
sagemaker:DescribeTransformJob
sagemaker:DescribePipeline
sagemaker:DescribePipelineDefinitionForExecution
sagemaker:DescribeOptimizationJob
mq:DescribeConfigurationRevision
xray:BatchGetTraces
wafv2:GetSampledRequests
waf:GetSampledRequests
waf-regional:GetSampledRequests
appsync:GetGraphqlApiEnvironmentVariables
codecommit:GetDifferences
codecommit:GetCommit
codecommit:GetBlob
codecommit:GetFile
codecommit:GetFolder
codecommit:BatchGet*
iot:GetThingShadow
athena:GetNamedQuery
athena:BatchGetNamedQuery
athena:GetPreparedStatement
athena:GetQueryResults
imagebuilder:GetComponent
ses:GetTemplate
ses:GetEmailTemplate
eks:AccessKubernetesApi
support:CreateCase
```

`apigateway:GET` on the paths that return API key values: `/apikeys`, `/apikeys/*`,
`/usageplans/*/keys` and `/usageplans/*/keys/*` in any region.

And `sqs:ReceiveMessage` with `NotResource` set to the alarms and work queue ARNs.

Do not deny `kms:Decrypt`: Lambda decrypts the function's own environment variables as
this role. The role grants no `kms:Decrypt` of its own.

## Member accounts

`terraform/member`, deployed once in every member account, in the agent's region, with
the agent module's `role_arn` as `investigator_role_arn` and its
`central_event_bus_arn`.

| Input | Default | Used for |
|-------|---------|----------|
| `investigator_role_arn` | required | the only principal the read-only role trusts |
| `central_event_bus_arn` | required | the forwarding rule's target and its role's grant |
| `role_name` | `devops-agent-read` | the read-only role; the agent's `member_role_name` |
| `external_id` | `null` (sensitive) | the `sts:ExternalId` the trust policy requires; the agent's `member_external_id`. Set it |
| `name_prefix` | `devops-agent` | the rule and its role, and an excluded alarm name prefix; the agent's `name_prefix` |
| `catalog_json` | `null` | the excluded alarm name prefixes, when the agent's catalog sets its own |
| `tags` | `{}` | all resources |

It creates:

- The read-only role `<role_name>`, maximum session 1 hour, trusting only
  `investigator_role_arn` for `sts:AssumeRole`, with `StringEquals` on `sts:ExternalId`
  when `external_id` is set. It has the managed policy, the Read statements and the
  Explicit deny of the agent's own role (from `terraform/modules/shared`), with no
  catalog parameter (every SSM parameter read denied), no queue
  (`sqs:ReceiveMessage` denied everywhere) and `sts:AssumeRole` denied everywhere.
- The rule `<prefix>-forward-alarms` on the default bus, with the pattern of
  `<prefix>-alarms-<env>` (state ALARM, the same excluded prefixes), targeting
  `central_event_bus_arn` as the role `<prefix>-forward-alarms`, which
  `events.amazonaws.com` assumes and which may `events:PutEvents` on that bus only.

Outputs: `role_arn`, `role_name`, `forward_rule_arn`.

## Not in the module

- The SNS topic and whatever posts its messages to Slack: the module takes an existing
  topic ARN.
- The AWS Organization and the roles that deploy `terraform/member` into each member
  account.
- The Datadog service account, the Datadog EventBridge integration that creates the
  partner event source, and the GitHub App: the module takes their credentials and the
  event source name.
- A findings review tool: anything that reads the table and writes only a finding's
  `status`, acknowledgement and resolution fields (see the Resolution contract in
  [architecture.md](architecture.md)).
