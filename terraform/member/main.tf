# One member account of a multi-account deployment: the read-only role the agent assumes
# to read this account, and the rule that forwards its alarms to the central event bus.
# Deploy it once in every member account, in the agent's region.

locals {
  catalog = jsondecode(coalesce(var.catalog_json, file("${path.module}/../../devops_agent/catalog.json")))
}

# The same read grants, managed policy and deny list as the agent's own execution role.
# This role reads no catalog parameter and receives from no queue.
module "shared" {
  source = "../modules/shared"

  exclude_alarm_prefixes = distinct(concat(local.catalog.agent.exclude_alarm_prefixes, [var.name_prefix]))
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.investigator_role_arn]
    }

    dynamic "condition" {
      for_each = var.external_id == null ? [] : [var.external_id]

      content {
        test     = "StringEquals"
        variable = "sts:ExternalId"
        values   = [condition.value]
      }
    }
  }
}

resource "aws_iam_role" "read" {
  name                 = var.role_name
  description          = "Read-only access for the devops-agent investigator in the tooling account."
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "aws_view" {
  role       = aws_iam_role.read.name
  policy_arn = module.shared.managed_policy_arn
}

resource "aws_iam_role_policy" "read" {
  name   = "read"
  role   = aws_iam_role.read.id
  policy = module.shared.read_policy_json
}

resource "aws_iam_role_policy" "deny" {
  name   = "deny"
  role   = aws_iam_role.read.id
  policy = module.shared.deny_policy_json
}

# Alarms entering ALARM go to the central bus, which accepts events from the
# organization only. A rule that targets a bus in another account puts events there as
# a role of its own.
resource "aws_cloudwatch_event_rule" "forward" {
  name          = "${var.name_prefix}-forward-alarms"
  description   = "CloudWatch alarms entering ALARM, for the devops-agent central event bus."
  event_pattern = module.shared.alarm_event_pattern

  tags = var.tags
}

data "aws_iam_policy_document" "events_trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "forward" {
  name               = "${var.name_prefix}-forward-alarms"
  description        = "Lets the alarm forwarding rule put events on the devops-agent central event bus."
  assume_role_policy = data.aws_iam_policy_document.events_trust.json

  tags = var.tags
}

data "aws_iam_policy_document" "forward" {
  statement {
    actions   = ["events:PutEvents"]
    resources = [var.central_event_bus_arn]
  }
}

resource "aws_iam_role_policy" "forward" {
  name   = "put-central-bus"
  role   = aws_iam_role.forward.id
  policy = data.aws_iam_policy_document.forward.json
}

resource "aws_cloudwatch_event_target" "forward" {
  rule     = aws_cloudwatch_event_rule.forward.name
  arn      = var.central_event_bus_arn
  role_arn = aws_iam_role.forward.arn
}
