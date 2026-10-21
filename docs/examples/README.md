# Example findings

Each file is one `finding#` item exactly as the agent writes it to the findings table,
for synthetic accounts (210987654321 runs the agent, 345678901234 is a member account).
`scripts/examples.py` builds them with the agent's own builders; regenerate them with
`just examples`, and a test fails when they no longer match the model.

| File | Written when |
|------|--------------|
| [`finding-reported.json`](finding-reported.json) | an investigation of one alarm ends with the model's report (`kind` `alarm`, `outcome` `reported`) |
| [`finding-incomplete.json`](finding-incomplete.json) | an investigation hits a limit (here the time reserve) without a report (`outcome` `incomplete`) |
| [`finding-account-refused.json`](finding-account-refused.json) | the investigator cannot assume a member account's role; triage's own refusals are decisions only and store nothing |
| [`finding-incident.json`](finding-incident.json) | an investigation of an incident: 5 or more alarms of one account in one batch, investigated as one job (`kind` `incident`) |
| [`finding-skipped.json`](finding-skipped.json) | triage drops an alarm tagged `DevOpsAgent=off` (`kind` `skipped`, `outcome` `triaged`) |
| [`finding-linked.json`](finding-linked.json) | triage links an alarm to a running investigation holding one of its resource keys (`kind` `linked`) |
| [`finding-grouped.json`](finding-grouped.json) | triage groups an alarm onto an incident (`kind` `grouped`, `incident_id` set) |
| [`finding-storm.json`](finding-storm.json) | triage opens a storm: the signal rate ran too high, and later priority 3 and 4 signals are counted on it (`kind` `storm`) |
| [`finding-deferred-skipped.json`](finding-deferred-skipped.json) | the budgets refuse a priority 3 or 4 job: recorded once per resource an hour and never retried (`kind` `skipped`) |
| [`finding-datadog.json`](finding-datadog.json) | the budgets refuse a priority 1 or 2 job, here about a Datadog monitor group, which is retried later (`kind` `deferred`) |

## Field guide

- **Identity.** `pk` (`finding#<finding_id>`), `finding_id`, `created_at` (ISO 8601
  UTC), `env`, `kind` (what wrote it) and `outcome` (`reported`, `incomplete` or
  `triaged`).
- **Signal.** `source` (`cloudwatch` or `datadog`), `account_id` and `region` (where the
  resource lives), `alarm_name` (for Datadog the monitor name with its group),
  `alarm_arn` (for Datadog `datadog:monitor/<id>/<group>`), `alarm_reason`,
  `alarm_time`, and `resource_key`, the primary key, `<account id>|<key>` for a member
  account. Relations to other signals: `linked_to`, `linked_alarms`, `incident_id`,
  `member_alarms` and `alarm_count`; a storm counts its signals in `alarm_count`,
  `source_counts` and `resource_counts`. `recurrence_count` and `last_seen_at` count
  later firings recorded on the finding.
- **Verdict.** `severity` (never below `severity_floor`), `proposed_severity` (the
  model's), `title`, `summary`, `likely_cause`, `error_signature`, `fix_effort` with
  `fix_effort_reason`, and `confidence` with `confidence_reason`.
- **Reasoning.** `evidence` (`kind`, `detail` and the trail `steps` it came from; no
  steps means the context bundle), `checked` (facts the agent verified, with their
  steps) and `hypotheses` (`likely`, `ruled_out` or `unverified`, with the steps that
  tested them).
- **Actions.** `actions`, each `change`, `code`, `read` or `approval` with `text` and an
  optional `detail` and `command`; `suggested_actions` repeats each as one line for
  notifications.
- **Tool trail.** `tool_trail`, one step per tool call: the step number, the tool,
  `status` (`data`, `empty` or `error`), the redacted `input` and `args`, and `call`, a
  descriptor (provider, service, action, label, subject) a reader can render without
  knowing the tool. `tools_used`, `tool_call_count` and `sources_with_data` summarise
  it. Tool outputs are never stored.
- **Context and memory.** `context_summary` (which context bundle sections were
  available and how many items each listed, never their content),
  `previous_finding_id` (the newest earlier finding on the key) and
  `prior_finding_ids` (the reviewed findings the model was shown).
- **Run.** `run` (`stop_reason`, turns against `max_turns`, `duration_seconds`,
  `weighted_tokens` against `token_budget`), `steps`, `model_id`, `tokens_used` and
  `weighted_tokens`. Triage findings have no run and 0 steps.
- **Review and lifetime.** `status` is `open` when written; a review tool sets
  `acknowledged` or `closed` with `resolution`, `resolved_at` and `resolved_by`. `ttl`
  expires the item 90 days after it is written.
