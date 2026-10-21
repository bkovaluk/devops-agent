# Every alarm entering ALARM on the default bus lands on the alarms queue, except the
# catalog's excluded prefixes and the agent's own alarms: a failing agent must not
# investigate itself in a loop.
resource "aws_cloudwatch_event_rule" "alarms" {
  name          = "${var.name_prefix}-alarms-${var.environment}"
  description   = "CloudWatch alarms entering ALARM, except excluded prefixes and the agent's own alarms."
  event_pattern = module.shared.alarm_event_pattern

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "alarms" {
  rule = aws_cloudwatch_event_rule.alarms.name
  arn  = aws_sqs_queue.alarms.arn
}

# Many accounts: the member accounts' rules (terraform/member) forward their alarm events
# to this bus, which accepts events only from the organization. Its rule applies the same
# pattern and feeds the same alarms queue; an event keeps its member account in `account`.
resource "aws_cloudwatch_event_bus" "central" {
  count = var.organization_id == null ? 0 : 1

  name = "${var.name_prefix}-alarms-${var.environment}"

  tags = var.tags
}

data "aws_iam_policy_document" "central_bus" {
  count = var.organization_id == null ? 0 : 1

  statement {
    sid       = "OrganizationAlarmEvents"
    actions   = ["events:PutEvents"]
    resources = [aws_cloudwatch_event_bus.central[0].arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [var.organization_id]
    }
  }
}

resource "aws_cloudwatch_event_bus_policy" "central" {
  count = var.organization_id == null ? 0 : 1

  event_bus_name = aws_cloudwatch_event_bus.central[0].name
  policy         = data.aws_iam_policy_document.central_bus[0].json
}

resource "aws_cloudwatch_event_rule" "central" {
  count = var.organization_id == null ? 0 : 1

  name           = "${var.name_prefix}-member-alarms-${var.environment}"
  description    = "Member accounts' CloudWatch alarms entering ALARM, except excluded prefixes and the agent's own alarms."
  event_bus_name = aws_cloudwatch_event_bus.central[0].name
  event_pattern  = module.shared.alarm_event_pattern

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "central" {
  count = var.organization_id == null ? 0 : 1

  rule           = aws_cloudwatch_event_rule.central[0].name
  event_bus_name = aws_cloudwatch_event_bus.central[0].name
  arn            = aws_sqs_queue.alarms.arn
}

# Datadog monitors tagged with the catalog's datadog_monitor_tags notify the partner
# event source. Their notifications land on the same alarms queue as CloudWatch alarms;
# triage reads each monitor back and keeps only alerting ones.
resource "aws_cloudwatch_event_bus" "datadog" {
  count = var.datadog_event_source_name == null ? 0 : 1

  name              = var.datadog_event_source_name
  event_source_name = var.datadog_event_source_name

  tags = var.tags
}

resource "aws_cloudwatch_event_rule" "datadog" {
  count = var.datadog_event_source_name == null ? 0 : 1

  name           = "${var.name_prefix}-datadog-${var.environment}"
  description    = "Datadog monitor notifications for the agent; triage keeps only alerting groups."
  event_bus_name = aws_cloudwatch_event_bus.datadog[0].name

  event_pattern = jsonencode({
    detail-type = ["Datadog Alert Notification"]
    detail = {
      tags = local.catalog.agent.datadog_monitor_tags
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "datadog" {
  count = var.datadog_event_source_name == null ? 0 : 1

  rule           = aws_cloudwatch_event_rule.datadog[0].name
  event_bus_name = aws_cloudwatch_event_bus.datadog[0].name
  arn            = aws_sqs_queue.alarms.arn
}
