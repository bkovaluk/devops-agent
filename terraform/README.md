# devops-agent Terraform module

Deploys devops-agent into one AWS account and region: the triage and investigator
Lambdas, the alarms and work queues with their dead-letter queues, a dead-letter and a
backlog alarm on each queue, the findings table, the EventBridge rule that feeds
CloudWatch alarms to triage, one execution role and its policies, an application
inference profile per model with hourly token alarms, and a monthly Bedrock cost
budget. Optionally it adds the Datadog partner event bus and rule that feed Datadog
monitor alerts to triage, and an SSM parameter holding your catalog. It implements
[docs/terraform-contract.md](../docs/terraform-contract.md).

The module takes a prebuilt zip. Build it from the repo root with `just build`, which
writes `dist/devops-agent.zip`. It also reads `../devops_agent/catalog.json` for the
EventBridge filters when `catalog_json` is not set, so use it from a checkout of the
whole repo (a `git::` or `github.com/...//terraform` source fetches the whole repo).

## Usage

```hcl
module "devops_agent" {
  source = "github.com/<owner>/devops-agent//terraform"

  environment  = "prod"
  package_path = "${path.root}/dist/devops-agent.zip"

  notifications_enabled   = true
  notifications_topic_arn = "arn:aws:sns:us-east-1:123456789012:devops-findings"
  notifications_channel   = "#ops-alerts"

  prompt_notes = "Lambda repos are named <service>-lambda; infrastructure lives in platform-infra."

  datadog_api_key           = var.datadog_api_key
  datadog_app_key           = var.datadog_app_key
  datadog_event_source_name = "aws.partner/datadog.com/example-1a2b3c"

  alarm_actions = ["arn:aws:sns:us-east-1:123456789012:platform-alerts"]

  tags = { Team = "platform" }
}
```

[examples/basic](examples/basic) is a complete root module with a provider block.

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.6 |
| aws | >= 6.0 |

## Inputs

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `environment` | `string` | required | `dev`, `qa`, `staging` or `prod`; sets `ENVIRONMENT` and resource names |
| `package_path` | `string` | required | path of the Lambda zip |
| `name_prefix` | `string` | `"devops-agent"` | prefix of every resource name; must start with `devops-agent` |
| `model_id` | `string` | `"us.anthropic.claude-opus-5-5"` | a foundation model id, cross-region inference profile id, or application inference profile ARN; an id gets an application inference profile copied from it, whose ARN becomes `MODEL_ID` |
| `fallback_model_id` | `string` | `"us.anthropic.claude-opus-5"` | `FALLBACK_MODEL_ID`, same forms and the same profile copy |
| `bedrock_foundation_models` | `list(string)` | `[]` | foundation model ids an application inference profile ARN given as a model id routes to |
| `input_tokens_per_hour` | `number` | `3000000` | hourly `InputTokenCount` on the primary profile above which its token alarm fires |
| `output_tokens_per_hour` | `number` | `200000` | hourly `OutputTokenCount` on the primary profile above which its token alarm fires |
| `bedrock_budget_usd` | `number` | `200` | monthly cost budget in USD on `bedrock_budget_services` |
| `bedrock_budget_services` | `list(string)` | Amazon Bedrock and the two Claude Opus Marketplace services | Cost Explorer service names the budget counts |
| `catalog_json` | `string` | `null` | your catalog document as JSON; stored in SSM, named by `CATALOG_PARAMETER`, and used for the EventBridge filters |
| `datadog_event_source_name` | `string` | `null` | the Datadog partner event source (`aws.partner/datadog.com/...`); creates the partner event bus and the rule that feeds its monitor alerts to triage |
| `notifications_enabled` | `bool` | `false` | `SLACK_ENABLED` |
| `notifications_topic_arn` | `string` | `null` | `SLACK_TOPIC_ARN` and the `sns:Publish` grant; required when notifications are enabled |
| `notifications_channel` | `string` | `""` | `SLACK_CHANNEL` |
| `prompt_notes` | `string` | `""` | `PROMPT_NOTES` |
| `datadog_api_key` | `string` (sensitive) | `null` | `DD_API_KEY` on both functions |
| `datadog_app_key` | `string` (sensitive) | `null` | `DATADOG_APP_KEY` on both functions |
| `datadog_site` | `string` | `"datadoghq.com"` | `DATADOG_SITE` on both functions |
| `github_app_id` | `string` | `null` | `GH_APP_ID` |
| `github_app_installation_id` | `string` | `null` | `GH_APP_INSTALLATION_ID` |
| `github_app_private_key` | `string` (sensitive) | `null` | `GH_APP_PRIVATE_KEY` |
| `github_org` | `string` | `null` | `GH_ORG` |
| `log_level` | `string` | `"INFO"` | `LOG_LEVEL` on both functions |
| `hourly_budget` | `number` | `null` | `HOURLY_BUDGET`; null keeps the code default |
| `daily_budget` | `number` | `null` | `DAILY_BUDGET`; null keeps the code default |
| `daily_token_budget` | `number` | `null` | `DAILY_TOKEN_BUDGET`; null keeps the code default |
| `run_token_budget` | `number` | `null` | `RUN_TOKEN_BUDGET`; null keeps the code default |
| `extra_environment` | `map(string)` | `{}` | any other variable from the README's Configuration tables, set on both functions; the module's own variables take precedence |
| `log_retention_days` | `number` | `400` | retention of both log groups |
| `alarm_actions` | `list(string)` | `[]` | actions for the dead-letter, backlog and token alarms; its SNS topics also get the budget's notifications |
| `tags` | `map(string)` | `{}` | tags on every resource |

Unset optional values are left out of the Lambda environment. The model, prompt and
GitHub settings go on the investigator only; the Datadog settings and
`CATALOG_PARAMETER` on both, since triage verifies Datadog signals and reads the
catalog; the budgets on triage only, except `run_token_budget`, which is per
investigation.

## Outputs

| Name | Description |
|------|-------------|
| `triage_function_name`, `triage_function_arn` | the triage function |
| `investigator_function_name`, `investigator_function_arn` | the investigator function |
| `alarms_queue_url`, `alarms_queue_arn` | the alarms queue |
| `alarms_dlq_url`, `alarms_dlq_arn` | the alarms dead-letter queue |
| `work_queue_url`, `work_queue_arn` | the work queue |
| `work_dlq_url`, `work_dlq_arn` | the work dead-letter queue |
| `findings_table_name`, `findings_table_arn` | the findings table |
| `role_arn` | the execution role both functions run as |
| `event_rule_arn` | the CloudWatch alarm EventBridge rule |
| `datadog_event_rule_arn` | the Datadog partner bus rule, or null |
| `model_arns` | the primary and fallback model ARNs the investigator calls |
| `catalog_parameter_name` | the catalog parameter, or null |

## Secrets

The agent reads the Datadog keys and the GitHub App private key from its environment, so
the role is denied every Secrets Manager read and every Parameter Store read but its
catalog. Terraform therefore stores these values in its state and in the functions'
configuration. Keep the
state in an encrypted backend with restricted access, and pass the values from your
secret store (for example a `TF_VAR_` variable set by CI) rather than committing them.
The role is also denied `lambda:GetFunction` and `lambda:GetFunctionConfiguration`, so
the agent cannot read them back.

Lambda caps a function's environment at 4 KB in total. A GitHub App private key takes
about 1.7 KB of it, which leaves room for `prompt_notes` of roughly 2 KB.

## Bedrock grants

`bedrock:InvokeModel` is granted on the foundation model and the inference profile each
model id names. A cross-region profile id such as `us.anthropic.claude-opus-5-5` grants
`inference-profile/us.anthropic.claude-opus-5-5` in this account and
`foundation-model/anthropic.claude-opus-5-5` in any region, since the profile routes to
several. A plain foundation model id grants that model only. An application inference
profile ARN grants the ARN; list the foundation model it routes to in
`bedrock_foundation_models`.

For each model id that is not an ARN the module also creates an application inference
profile (`<name_prefix>-primary-<environment>` and `<name_prefix>-fallback-<environment>`)
copied from it, grants `bedrock:InvokeModel` on it, and passes its ARN as `MODEL_ID` or
`FALLBACK_MODEL_ID`, so the agent's token use is metered under its own profiles and the
token alarms read exactly the agent's usage.

## Catalog

Without `catalog_json` both functions run on `devops_agent/catalog.json`, and the role
reads no parameter. With it, the module stores the document in the String parameter
`/<name_prefix>/<environment>/catalog` (Advanced tier past 4 KB), sets
`CATALOG_PARAMETER`, and grants `ssm:GetParameter` on that parameter alone. In both
cases the CloudWatch alarm rule excludes the catalog's `agent.exclude_alarm_prefixes`
plus `name_prefix`, and the Datadog rule matches its `agent.datadog_monitor_tags`. The
document's shape is in the repo README's Catalog section.
