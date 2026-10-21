resource "aws_sqs_queue" "alarms" {
  name = "${var.name_prefix}-alarms-${var.environment}"
  # Six times the triage timeout plus the batching window.
  visibility_timeout_seconds = 780
  message_retention_seconds  = 86400
  sqs_managed_sse_enabled    = true

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.alarms_dlq.arn
    maxReceiveCount     = 3
  })

  tags = var.tags
}

resource "aws_sqs_queue" "alarms_dlq" {
  name                      = "${var.name_prefix}-alarms-dlq-${var.environment}"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true

  tags = var.tags
}

resource "aws_sqs_queue_redrive_allow_policy" "alarms_dlq" {
  queue_url = aws_sqs_queue.alarms_dlq.id

  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.alarms.arn]
  })
}

resource "aws_sqs_queue" "work" {
  name = "${var.name_prefix}-work-${var.environment}"
  # Six times the investigator timeout.
  visibility_timeout_seconds = 5400
  message_retention_seconds  = 86400
  sqs_managed_sse_enabled    = true

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.work_dlq.arn
    maxReceiveCount     = 2
  })

  tags = var.tags
}

resource "aws_sqs_queue" "work_dlq" {
  name                      = "${var.name_prefix}-work-dlq-${var.environment}"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true

  tags = var.tags
}

resource "aws_sqs_queue_redrive_allow_policy" "work_dlq" {
  queue_url = aws_sqs_queue.work_dlq.id

  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.work.arn]
  })
}

data "aws_iam_policy_document" "alarms_queue" {
  statement {
    sid       = "EventBridgeRules"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.alarms.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values = concat(
        [aws_cloudwatch_event_rule.alarms.arn],
        aws_cloudwatch_event_rule.central[*].arn,
        aws_cloudwatch_event_rule.datadog[*].arn,
      )
    }
  }
}

resource "aws_sqs_queue_policy" "alarms" {
  queue_url = aws_sqs_queue.alarms.id
  policy    = data.aws_iam_policy_document.alarms_queue.json
}

resource "aws_cloudwatch_metric_alarm" "dlq" {
  for_each = {
    alarms = aws_sqs_queue.alarms_dlq.name
    work   = aws_sqs_queue.work_dlq.name
  }

  alarm_name          = each.value
  alarm_description   = "Messages in ${each.value}: the ${each.key} queue's consumer failed them repeatedly."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = each.value }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_actions

  tags = var.tags
}

# A queue that stops draining means the agent stopped investigating. Named with the
# prefix, so the agent never investigates them.
resource "aws_cloudwatch_metric_alarm" "backlog" {
  for_each = {
    alarms = aws_sqs_queue.alarms.name
    work   = aws_sqs_queue.work.name
  }

  alarm_name          = "${var.name_prefix}-${each.key}-backlog-${var.environment}"
  alarm_description   = "Oldest message in ${each.value} older than 30 minutes: its consumer is not draining it."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateAgeOfOldestMessage"
  dimensions          = { QueueName = each.value }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 3
  threshold           = 1800
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_actions

  tags = var.tags
}
