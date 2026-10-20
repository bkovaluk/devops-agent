# devops-agent: architecture

The DevOps agent investigates a CloudWatch alarm, or a Datadog monitor alert, the
moment it fires and records what it found. It reads; it never changes anything. A person acts on a finding
through the tools they already use (a review dashboard, a CLI, the AWS console).

## Review tools

Findings are reviewed outside the agent. A review tool (a dashboard, a CLI or a
script) reads the findings table and writes only a finding's `status`,
acknowledgement and resolution fields and, on close, its snapshot's `ttl` (see
Resolution contract). The investigation runs in these separate Lambdas on their own
read-only role, which a review tool never shares. The infrastructure (the execution
role, the findings table, the alarms and work queues, the EventBridge alarm rule and
the optional Datadog partner event bus rule) is described in
[terraform-contract.md](terraform-contract.md).

## Hard constraints

1. **No write permission anywhere except its own findings table, its alarms and
   work queues and its optional notification topic.** This is enforced by IAM, not by
   the prompt. The agent has no write tools and holds no token for any system it could
   change. Even a model fully steered by a hostile log line has nowhere to write.
2. **Everything it reads is untrusted data.** Alarm descriptions, log lines and
   CloudTrail records can carry text written to steer a model. Constraint 1 is
   what makes that survivable; the prompt also says so.
3. **Never reads a secret.** No Secrets Manager values, no SSM parameters but its
   own catalog, no KMS decrypt, no S3 object bodies, no Lambda environment
   variable values. Log lines are redacted for obvious credential shapes before
   the model sees them and before anything is published.
4. **Severity has a fixed floor the model cannot lower.**

## Shape

One deployment per environment account (dev, qa, staging, prod).
Each deployment investigates only its own account, so no cross-account role is
needed and one env's agent cannot read another's.

```
CloudWatch alarm enters ALARM            Datadog monitor group enters Alert or Warn
  EventBridge rule devops-agent-alarms-{env} (aws.cloudwatch,
               "CloudWatch Alarm State Change", state ALARM, alarm name not
               prefixed by the catalog's exclude_alarm_prefixes)
                                         Datadog partner event bus rule, optional
                                         ("Datadog Alert Notification")
    SQS devops-agent-alarms-{env}  (redrive to its DLQ after 3 receives)
      Lambda devops-agent-triage-{env}  (batch of up to 25 within 60 s,
                                                at most 2 concurrent, 120 s
                                                timeout, no model)
        triage: parse signals, settle (alarm keys and tags, or Datadog
                verification), opt-out, repeat, cooldown, link, storm, budgets,
                emit; a deferred P1 or P2 signal goes back to the alarms queue,
                delayed 900 s
    SQS devops-agent-work-{env}  (redrive to its DLQ after 2 receives)
      Lambda devops-agent-{env}  (batch size 1, at most 2 concurrent,
                                         900 s timeout)
        1. recall:   up to 3 human-reviewed findings on the job's resource key
        2. precheck: code gathers the context bundle (no model, 60 s budget)
        3. inspect:  Bedrock Converse tool loop over read-only AWS, Datadog and GitHub
                     tools (max 14 steps, 250,000 weighted-token run budget,
                     prompt caching), hypotheses first
        4. report:   the model ends by calling report_finding (structured); the
                     last step is told to call report_finding (no forced toolChoice)
        5. record:   the run's weighted tokens added to the day's counter; finding
                     written to DynamoDB under the pre-allocated id
        6. notify:   when SLACK_ENABLED, critical and high published to the
                     SLACK_TOPIC_ARN SNS topic (a subscriber posts to Slack)
        7. remember: a reported investigation's tool calls that returned data go
                     to obs#<resource_key>
```

The rule excludes the alarm name prefixes in the catalog's
`agent.exclude_alarm_prefixes`: autoscaling alarms, which enter ALARM as part of normal
scaling, and the agent's own alarms, so a failing agent does not investigate itself in
a loop. Triage re-checks every alarm name against the same list.

### Catalog

The catalog is one JSON document with the rules that differ between deployments:

- `version`: 1.
- `env` (optional): the env the document was written for. A document naming another
  env is refused.
- `severity.default`: per env, the floor of an alarm whose `Severity` tag names no
  level (`{"prod": "high", "staging": "medium", "qa": "low", "dev": "low"}`); an env
  left out is low.
- `resources`: the resource types, each an `id`, the `namespaces` whose alarms judge
  it, the `dimensions` that name it (most specific first) and an optional
  `key_namespace` (see Resource keys).
- `agent.exclude_alarm_prefixes`: alarm name prefixes never investigated
  (`TargetTracking-` and the agent's own `devops-agent`).
- `agent.opt_out_tag`: the tag that opts an alarm or monitor out
  (`{"key": "DevOpsAgent", "value": "off"}`).
- `agent.notify`: the finding severities that are published (`critical`, `high`).
- `agent.datadog_monitor_tags`: the tags a Datadog monitor must carry before triage
  acts on it (`devops_agent:true`).

`devops_agent/catalog.json` is the catalog every deployment starts from, with the values
above and the resource types of Lambda, ECS, EKS, EC2, SageMaker, Step Functions,
Bedrock, RDS and DocumentDB, DynamoDB, OpenSearch, ElastiCache, SQS, Kinesis, MSK,
application and network load balancers, API Gateway and Transfer Family. A deployment
replaces it by storing its own document in an SSM String parameter and naming that
parameter in `CATALOG_PARAMETER` (the Terraform module does both from `catalog_json`).
`catalog.py` reads it with boto3 once per process; it is agent code, never a model
tool, and `aws_call` still refuses `ssm:GetParameter`. A missing, unreadable or
malformed parameter, or one whose `env` names another env, logs a warning and the agent
runs on the bundled catalog.

### Signals

Triage works on signals, whichever source raised them. Two sources reach the alarms
queue: the EventBridge alarm rule's CloudWatch "Alarm State Change" events, and Datadog
monitor notifications ("Datadog Alert Notification", `source`
`aws.partner/datadog.com/<generator>-<suffix>`) that Datadog's Amazon EventBridge
integration puts on a partner event bus whose rule targets the same queue.
`signals.py` holds the `Signal` model (`source` `cloudwatch` or `datadog`, `name`,
`env`, `observed_at`, `resource_keys`, `priority` 1 to 4, `subject`, a source-specific
`ref` and the `raw` event) and a parser registry keyed by `detail-type`;
`parse_signal` dispatches to `cloudwatch_alarm` or `datadog_monitor` and returns None
for anything else. Everything after parsing (opt-out, repeat, cooldown, links, storms,
budgets, emit) is the same for both sources.

- **CloudWatch.** An alarm entering ALARM, not the agent's own. `name` is the alarm
  name, `ref` the ARN, account, region and state reason. Its priority comes from its
  severity floor: critical 1, high 2, medium 3, low 4 (`severity.priority`).
- **Datadog.** A notification whose `states.dest_state` (else `alert_type`) is Alert
  or Warn; recoveries and No Data are dropped. The payload is read defensively: every
  field is optional, a field of the wrong type reads as empty, unknown fields are
  ignored. The group is read from the event's `tags` (then string entries of
  `meta.result.metadata`) for the tag keys the monitor's query groups by (`by {...}` or
  `.by(...)`); a monitor without a by-clause has the simple group `*`. `name` is the
  monitor name with its group, `ref` holds the monitor id, group, group tags, query,
  type, tags and states, and the identity stored as a finding's `alarm_arn` is
  `datadog:monitor/<id>/<group>`. A group the parser cannot resolve fails
  verification.

A work-queue job carries its signals (`signals`, the job's signal first) beside the
CloudWatch events among them (`alarms`); a job without `signals` takes them from its
alarms.

### Datadog verification

A Datadog payload is untrusted. Triage reads the monitor back through the Datadog
client (`GET /api/v1/monitor/{id}?group_states=alert,warn`, read-only, the keys the
investigator uses) and drops the signal, as a `skipped_unverified` decision with no
finding, unless:

- the monitor exists (a 404 drops; any other failure fails the record, so SQS retries);
- its tags include every tag in the catalog's `agent.datadog_monitor_tags`
  (`devops_agent:true` by default);
- its `env:` tag is this env (a mismatch is also logged as a warning, "misrouted");
- the signal's group is still in Alert per `state.groups` (or `overall_state` for a
  simple monitor), or in Warn when the monitor's priority is 1.

Monitor reads are cached per monitor id in the process: 60 s for an answer (a 404
included), so a flood costs one call per monitor a minute, and 30 s for a failed read,
which is raised again from the cache. After the first failed read in an invocation, its
remaining Datadog signals fail (`batchItemFailures`) without a call, so an outage costs
one call per invocation and SQS retries the rest; CloudWatch signals in the same batch
are triaged as usual. Without `DD_API_KEY` and `DATADOG_APP_KEY`, every Datadog signal
is silently dropped as `skipped_unverified` ("the Datadog keys are not configured"),
logged once at WARNING per cold start. The monitor Datadog returns, never the payload,
gives the signal's name and subject (the monitor's name, so a spoofed or renamed payload
cannot split the repeat and cooldown lineage), the priority (the monitor's P1 to P5, P5
counting as 4; the env floor when it has none), the query, the tags (including
`DevOpsAgent:off`, which opts the monitor out) and the resource key.

### Resource keys

One scheme for both sources, `<namespace>:<dimension>=<value>`, so a CloudWatch alarm
and a Datadog monitor on one resource link and cool down together.

- **CloudWatch.** From the alarm's metric namespace and the dimension that names the
  resource: the first of the catalog resource's `dimensions` the alarm carries (for
  example `AWS/Lambda:FunctionName=x`, `AWS/RDS:DBClusterIdentifier=c`, the cluster
  before an instance), and for namespaces the catalog does not list the first
  dimension. The key uses the alarm's own namespace (a DocumentDB alarm keys as
  `AWS/DocDB`) unless the resource sets `key_namespace`: `ECS/ContainerInsights` alarms
  key as `AWS/ECS:ServiceName=s`. A metric-math alarm is keyed by the first of its
  `Metrics[]` with a `MetricStat` and dimensions, so a Fargate task-deficit alarm
  (`desired - running` over Container Insights) keys as
  `AWS/ECS:ServiceName=<service>`. Composite alarms, metric-math alarms without such a
  metric, and alarms that cannot be read are keyed `alarm:<name>`. An SQS queue or
  Kinesis stream adds the keys of the Lambdas consuming it (the consumer chain). The
  first key is the alarm's primary key.
- **Datadog.** A `service` tag (the group's before the monitor's) on a monitor tagged or
  querying `source:ecs` keys as `AWS/ECS:ServiceName=<service>`: the ECS service name is
  the Datadog service. Any other group keys as `datadog:monitor=<id>/<group>`.
  Kubernetes workload keys (from `kube_deployment`, `kube_namespace` and the cluster)
  are future work; EKS signals use the fallback key until then.

### Triage

Triage runs no model and considers every signal that reaches it; only the
`DevOpsAgent=off` tag opts one out. Per distinct signal in a batch, in order:

1. **Parse.** See Signals. A signal in the batch twice (same alarm name, or same
   monitor id and group) is triaged once.
2. **Settle.** A CloudWatch alarm is read (`DescribeAlarms`) for its resource keys and
   its tags (`ListTagsForResource`) for its floor; a retried alarm that has left the
   ALARM episode it was deferred in is dropped (see Deferred retries). A Datadog
   signal is verified and keyed from its monitor (see Datadog verification).
3. **Opt-out.** A signal tagged `DevOpsAgent=off` (value in any case) gets a
   `skipped` finding ("opted out by tag") and no job (see Opt-out tag).
4. **Repeat.** When the signal already has an unclosed investigation (status
   `open` or `acknowledged`, kind `alarm` or `incident`, outcome `reported`) at
   the same or a higher floor, that finding's `recurrence_count` goes up by one
   and its `last_seen_at` is set. Acknowledging a finding does not restart the
   investigation; only closing it does. Triage-written and incomplete findings
   never count, so a deferred signal is investigated on its next firing. The lookup
   queries GSI `by_resource` on the primary key, newest first, filtered on the
   signal's name, status, kind and outcome, at most 2 pages of 50. A floor
   escalation is investigated again. With no unclosed investigation, a firing
   within the cooldown of a closed one is a repeat too (see Cost controls).
5. **Link.** When a running job holds an `active#<key>` item for any of the
   signal's keys, the signal is appended to that item's `linked_alarms` and gets a
   `linked` finding with `linked_to` set to the job's finding id. Within the
   batch, highest floor first, the first signal on a key leads a job, and a later
   one sharing any of its keys (consumer chain included) gets a `linked` finding to
   the job's pre-allocated finding id and is appended to its `active#` items'
   `linked_alarms` once the job is sent.
6. **Storm.** The signals left are added to the signal rate (see Storm mode). While
   a storm is open they are grouped onto it and only its head is investigated.
   Otherwise, when `STORM_THRESHOLD` (5) or more distinct jobs remain, they become one
   `incident` job; the signal with the highest floor leads it, and each of the others
   gets a `grouped` finding with `incident_id` set to the incident's finding id. The
   job lists at most 50 signals and carries the full count.
7. **Budget.** See Throttles. A refused priority 1 or 2 job gets a `deferred` finding
   and is retried (see Deferred retries); a refused priority 3 or 4 job is skipped. A
   refused or unsent job is refunded, so the counters keep only jobs that reached the
   work queue. A deferred incident's other signals are grouped under the deferred
   finding, and a deferred job's in-batch links point at it.
8. **Emit.** An `active#<key>` item is claimed for each of the job's keys (20
   minute TTL, holding the finding id and an empty `linked_alarms`) with a
   conditional put. A key a concurrent invocation's job already holds is not
   taken: the job's signals become `linked` findings to that job instead. The job
   is then counted against the budgets and sent to the work queue. If the send
   fails, the budgets are refunded and the active items expired. Once the job is
   sent, a failure to store its grouped or linked findings is logged and does
   not fail its records.

Finding ids derive from the SQS message id: a job's id from its leading
signal's message, every other finding's from its own. A redelivered record
writes the same finding (the conditional put is a no-op) and recognises its own
emitted job, so redelivery duplicates neither jobs nor findings.

A record whose signal fails in triage is reported in `batchItemFailures`, so SQS
redelivers only that record; after 3 receives it goes to the DLQ. Triage stops
settling signals with 20 s left and reports every record it has not settled.

### Throttles

Every threshold is a `TriageSettings` field, overridable by its environment variable.

| Setting | Default | Rule |
|---------|---------|------|
| `HOURLY_BUDGET` | 10 | jobs per UTC hour (`budget#<YYYY-MM-DDTHH>`) |
| `DAILY_BUDGET` | 50 | jobs per UTC day (`budget#<YYYY-MM-DD>`), every priority |
| `DAILY_TOKEN_BUDGET` | 3,000,000 | weighted tokens per UTC day; at or above it every job is refused ("daily token budget reached") |
| `P1_DAILY_OVERFLOW` | 10 | priority 1 jobs a UTC day may run past the hourly budget or the Datadog share (`budget#p1#day#<YYYY-MM-DD>`) |
| `RESERVE_FRACTION` | 0.3 | priority 3 and 4 jobs are refused once the hour's count reaches `HOURLY_BUDGET x (1 - RESERVE_FRACTION)` (7 of 10) |
| `DATADOG_HOURLY_SHARE` | 6 | jobs about a Datadog signal per UTC hour, within the hourly budget (`budget#datadog#<YYYY-MM-DDTHH>`) |
| `STORM_THRESHOLD` | 5 | distinct jobs in one batch that make one incident |
| `STORM_RATE` | 30 | accepted signals per 5-minute bucket; see Storm mode |
| `ALARM_COOLDOWN_MINUTES` | 120 | see Cost controls |
| `RESOURCE_COOLDOWN_MINUTES` | 60 | see Cost controls |
| `MAX_DEFERRED_RETRIES` | 8 | see Deferred retries |

Besides these, a low-floor job is refused once the hour's count is half the hourly
budget. The order is: the low floor rule, the reserve and the token budget (no counter
moves), then the `active#` claim, then the hourly budget (and the Datadog share for a
Datadog job; a priority 1 job past either takes the overflow), then the daily budget.

Drop, don't churn: when the budgets refuse, a priority 1 or 2 job is deferred and sent
back for retry; a priority 3 or 4 job is recorded as a `skipped` finding ("over
budget, <reason>") once per primary resource key per UTC hour (its id derives from the
key and the hour) and is never requeued.

### Storm mode

Triage adds the first firings each batch leaves after linking to a 5-minute bucket
(`rate#<YYYY-MM-DDTHH:MM>`, an atomic `ADD` like the budgets). A deferred signal sent
back for retry is not counted again; a redelivered SQS record is, and that rare double
count is accepted because the rate only detects floods. When the previous and the
current bucket both hold more than `STORM_RATE` (30), triage opens a storm:
`storm#active` (a conditional put, so concurrent invocations agree on one) names a
`storm` finding and its head, the batch's highest-priority signal, by the id its
deferral would be recorded under, so a deferred head that comes back is still the head.

The head is dispatched first, through the budgets like any job. The storm finding links
to the head's job and says it "is investigated as <id>" only when the job was sent;
otherwise it links to the deferral, over-budget or owning job and says so, and a head
that is sent on a later retry updates it. Priority 1 and 2 signals never join a storm:
they keep going through the budgets (overflow, Datadog share and deferral included).
Every priority 3 or 4 signal, in that batch and later ones, gets a `grouped` finding
with `incident_id` set to the storm finding, which counts them atomically in
`alarm_count`, `source_counts` (by source) and `resource_counts` (by primary resource
key). The storm ends when a full bucket (the previous one) holds `STORM_RATE` or fewer:
`storm#active` is expired and triage plans jobs as usual.

### Decision metrics

Every triage decision emits one CloudWatch EMF metric through Powertools: `Decision`
(Count) in namespace `DevOpsAgent`, dimensions `env`, `source` and `decision`,
and one structured log line with the decision, source, signal name and priority.

| Decision | When |
|----------|------|
| `investigated` | a job was sent for the signal |
| `linked` | the signal joined a running job, an in-batch job or a concurrent job's key |
| `cooldown` | a repeat on an unclosed finding, or a firing within a cooldown |
| `deferred` | a priority 1 or 2 job the budgets refused, sent back for retry |
| `skipped_budget` | a priority 3 or 4 job the budgets refused |
| `skipped_unverified` | a Datadog signal that failed verification, or a retried alarm out of its episode |
| `storm_grouped` | a member of an in-batch incident, or a priority 3 or 4 signal during an open storm |
| `opted_out` | a `DevOpsAgent=off` signal |

### Deferred retries

EventBridge sends an alarm's state change once, and the agent polls nothing. An
alarm whose job a budget refused would otherwise stay in ALARM uninvestigated
until it fired again, so triage sends it back to itself. After writing the
deferred finding, it sends each alarm of the job (an incident's members and the
job's in-batch followers too) to the alarms queue (`ALARMS_QUEUE_URL`) with
`DelaySeconds` 900, SQS's longest delay. The message is the alarm event as
received plus two top-level fields: `devops_agent_retry`, the retry count (1 on the
first), and `devops_agent_finding_id`, the id the alarm's deferral was recorded under
(the deferred finding for the job's head, the grouped or linked finding for the
others). Parsing ignores both fields, so the event reads as any event of its
source. Only priority 1 and 2 jobs are deferred and retried; a priority 3 or 4 job
the budgets refuse is skipped instead (see Throttles).

A retried Datadog signal is verified again like any notification: once its group is
no longer in Alert it is dropped as `skipped_unverified`.

On a retry of a CloudWatch alarm, triage reads the alarm with `DescribeAlarms` (the same call that
keys it) and drops the event, with a log line and no finding, unless the alarm
is still in ALARM and its `StateTransitionedTimestamp` equals the event's
`detail.state.timestamp` (to the millisecond): an alarm back in OK needs nothing,
and a newer episode came with its own event. Otherwise the retry runs every step
like any firing. Deferred again, it is sent back with `devops_agent_retry` one higher,
up to `MAX_DEFERRED_RETRIES` (8, two hours at 15 minutes); past that it is logged
and left to its next firing.

An episode keeps one deferred finding. A retry's deferral, grouped and linked
findings are written under the ids its message carries, so the conditional put
writes nothing new and the first deferral's rows stand. A retry that passes the
budgets is investigated under its own id, derived from its message id like any
job's: the investigator stores a job's finding only when its id is not taken,
so the deferred finding stays as the record that the episode waited, and the
investigation is the newer finding on the same resource key. A failed send back
fails the record, and SQS redelivers it; the redelivered deferral writes nothing
new.

### Opt-out tag

An alarm carrying the catalog's `agent.opt_out_tag` (`DevOpsAgent=off`; key and value
in any case) is never investigated: triage records a `skipped` finding with the summary "opted out by
tag" and sends no job. The tag is read in the same `ListTagsForResource` call as
the Severity tag. Set it where the alarm is defined, in Terraform or your deploy
tool's alarm definitions, never by hand: the next apply removes a hand-added tag.

### Investigation

The work-queue job carries the finding id, the kind (`alarm` or `incident`), the
signals, the CloudWatch alarm events among them, the count, the resource keys and
the floor. An incident's floor is the highest of its signals', and its prompt says
it is a storm of N alarms, lists them (a Datadog member with its query), and asks for
their common cause. A Datadog signal's prompt describes the monitor (name, id, type,
query, group tags, from and to state, priority, evaluation time) instead of an alarm;
the context bundle marks the `alarm`, `metric`, `log_sources` and `log_patterns`
sections not applicable, and the Datadog tools do the reading. The newest 25 findings on the
job's primary key are read (the job's own grouped and linked findings left out);
the newest becomes the finding's `previous_finding_id` whatever its status. Of
those, up to 3 reported findings that a person closed as `confirmed` or
`false_positive` go into the prompt, and their ids are stored on the new finding
as `prior_finding_ids`: a confirmed one as a "confirmed past cause" (created_at, severity,
title, effort, likely cause), a false positive as a "past false alarm"
(created_at, severity, title). Open findings and findings resolved `wrong` never
reach the model: feeding an agent its own unreviewed verdicts compounds wrong
confidence. At report time the job's `active#` items are read back, and their
`linked_alarms` are stored on the finding.

### Context bundle

Before the first Converse call, `precheck.py` gathers a bundle by code, the way
incident tools precompute context before a model looks: the model starts from
the facts and spends its steps testing causes. It goes into the opening message
after the alarm or storm description, framed as tool output and untrusted data.
Sections, in order:

1. `alarm`: the alarm's config, tags and state reason, and its last 10 history
   items cut to state changes in the last 24 h.
2. `metric`: the alarm's metric (its stat; period the alarm's, at least 300 s)
   over the last 3 h, and the same 3 h on each of the previous 7 days, from one
   `GetMetricData` call: min, max, p50 and last now, and each averaged over the
   days with data. Composite and metric-math alarms get a note instead.
3. `log_sources`: the log groups for the resource the alarm watches, mapped
   from each metric's namespace and dimensions and checked to exist with
   `DescribeLogGroups`; at most 10 groups, or an empty list with a reason
   (composite alarm, unmapped namespace, no resource dimension, no group):
   - `AWS/Lambda` FunctionName: `/aws/lambda/{name}`
   - `AWS/RDS` DBClusterIdentifier: `/aws/rds/cluster/{id}/*`;
     DBInstanceIdentifier: `/aws/rds/instance/{id}/*`
   - `AWS/DocDB` DBClusterIdentifier: `/aws/docdb/{id}/*`
   - `AWS/ES` DomainName: the enabled log publishing groups of the domain
   - `AWS/ElastiCache` ReplicationGroupId, or CacheClusterId through its
     replication group: the CloudWatch Logs log delivery destinations
   - `AWS/States` StateMachineArn: the state machine's logging destinations
   - `AWS/ApiGateway` ApiId: `/aws/apigateway/{id}*` and each stage's access
     log destination
   - `AWS/SQS` QueueName and `AWS/Kinesis` StreamName: the consumer Lambdas
     from their event source mappings, as `/aws/lambda/{name}`
   - `AWS/SageMaker` EndpointName: `/aws/sagemaker/Endpoints/{name}`
   - `AWS/EKS` ClusterName: `/aws/eks/{name}/cluster` (the control plane;
     workload logs are in Datadog)
4. `log_patterns`: for up to 3 of those groups, one Logs Insights query run by
   code from 15 minutes before the alarm to now (at most 1 h):
   `filter @message like /(?i)(error|exception|fail|timeout|denied)/ | pattern
   @message | sort @sampleCount desc | limit 10`. Each pattern line is redacted,
   then cut to 300 chars, like `query_logs` rows.
5. `changes`: CloudTrail write events in the last 6 h, the newest 20.
6. `siblings`: other alarms in ALARM whose primary key (the triage key rule) is
   one of the job's keys, at most 10.
7. `database_events`: when the primary key is an `AWS/RDS` or `AWS/DocDB` key,
   `rds:DescribeEvents` for the cluster or instance over the last 24 h.
8. `instance`: when the primary key is an `AWS/EC2` `InstanceId` key, one
   `ec2:DescribeInstances` for it, projected to type, state, launch time, the
   `Name` and `aws:autoscaling:groupName` tags, and for an EKS node
   (`eks:cluster-name` or `aws:eks:cluster-name` tag) `eks_cluster` and
   `eks_nodegroup`; no other tag, and never IPs, profiles, security groups or
   user data. A missing instance records `unavailable: instance '<id>' not
   found`. The system prompt tells the model that an instance with an
   `eks_cluster` is an EKS node, to read the cluster with `aws_call` (`eks`
   `describe_cluster` and `list_nodegroups`) and, when the Datadog tools are
   offered, to call `datadog_top_pods` with the instance id as host.
9. `service_notes`: the entries of the service notes file (`SERVICE_NOTES_FILE`, or
   `devops_agent/service_notes.toml` when that exists; none otherwise; the format is
   in `devops_agent/service_notes.example.toml`) (facts the team keeps about a service that the tools cannot show) with any
   `match` substring in one of the job's alarm names or its primary resource key,
   lowercased; at most 3 entries and 1,000 chars of notes, not applicable when
   none match. The system prompt says the notes are team-maintained, may be stale
   and are background, not evidence; findings still cite tool results.
10. `sources_last_time`: the `obs#<resource_key>` entries whose tool this run
    offers; an entry naming a tool that does not exist or is not configured is
    left out.

Each section is read on its own; a failure records `unavailable: <error code>`
and the others still run. The precheck has a 60 s wall-time budget, checked
before each section and each pattern query; once it is spent the rest are
recorded as skipped. The rendered bundle is redacted and then capped at 12,000
characters. Precheck reads are not model steps.

The system prompt tells the model the bundle is already gathered, and to state
2 to 4 hypotheses, each with the tool call that would confirm or rule it out,
before testing them. Every tool result the model reads starts with a `[step N]`
line, N being the call's `step` on the tool trail, so the report can cite it.
`report_finding` carries, besides the finding text, `hypotheses` (at most 8
`{text, state, steps}`, `state` `likely`, `ruled_out` or `unverified`, ruled-out
ones kept), `steps` on each evidence item (empty when the fact came from the
bundle), and `confidence` (`high`, `medium` or `low`) with a one-sentence
`confidence_reason`; at low confidence the title and likely cause hedge. These
fields never fail a report: cited steps not on the stored trail are dropped,
text is cut to 200 chars, an unknown state becomes `unverified`, an unknown
confidence null, and hypotheses past 8 are dropped.

The model runs every read check itself and never asks a person for a read it
can run or already ran. `report_finding` lists what it verified in `checked`
(at most 6 `{text, steps}`, text at most 300 chars, cited steps validated like
evidence steps) and requires `actions`, only what needs a person: at most 6
`{kind, text, detail, command}`. `kind` is `change` (a change to a live
system: redrive, purge, scale, config), `code` (a code or config fix in a
repo), `read` (a read the agent is denied: message bodies, object contents,
secrets) or `approval` (someone's sign-off); `text` is one line of at most 200
chars, `detail` at most 400 and `command`, the exact CLI or console command, at
most 500. These never fail a report either: an unknown kind becomes `change`,
long text is cut and items past 6 are dropped. A report that gives only a
`suggested_actions` text list gets each line as a `change` action.

The finding stores `context_summary`: each section's status
(`available`, `unavailable`, `skipped`, `not_applicable`), the item count of
each available section, the bundle's length and whether it was cut. The bundle
itself is kept only in the finding's eval snapshot (see Eval snapshots).

### Useful sources

After a `reported` investigation, the tool calls whose result was a success and
not empty (a result whose lists are all empty, such as no log rows or no metric
points, does not count) are written to `obs#<resource_key>` with UpdateItem:
`entries`, a list of `{tool, input, at}` newest first, at most 10, a repeated
call keeping its newest entry; `input` is the call's input with each string
redacted and cut to 200 chars (log group, metric name, query text). The item's
`ttl` is 90 days from the write. The next investigation of the key gets the
entries as "sources that returned data last time": where to look, never what was
concluded. A failure to write them is logged and does not fail the job.

The finding is stored with a conditional put under the pre-allocated id, so a
redelivered job whose finding exists does nothing. A failure during the
investigation stores an incomplete finding naming the exception class under the
same id. If that store fails too, the record is reported in `batchItemFailures`
and SQS redelivers it; after 2 receives it goes to the DLQ. An incident is published
once, headlined "Storm: N alarms in 60 s".

### Eval snapshots

After the finding is stored, and when `CAPTURE_SNAPSHOTS` is true (the default),
the investigator puts `snap#<finding_id>`: what the model read, so an eval can
replay the investigation with another prompt, model or tool set. The snapshot is
JSON: `env`, the `job` (alarm events, keys, floor, kind), the `context` bundle
text, the reviewed `prior` findings passed to the model (only the fields the
opening message reads), the `tools` offered, the `model_id`, `tokens_used`,
`weighted_tokens`, and `calls`: every tool call in order as `{name, input, status,
output}`, where `output` is the result text the model read (projected, redacted,
capped at 8,000 chars) and `input` is redacted. Up to 300 KB it is stored as the `snapshot` attribute;
larger, gzipped and base64-encoded as `snapshot_gz`; over 380 KB encoded it is
not stored and the size is logged. The item's `ttl` is 90 days from the write;
a review tool extends it when it closes the finding (see Resolution contract). A
failure to write it is logged and does not fail the job.

Evals never run in Lambda. The harness under `evals/` (not in the deployed
package, which is the `devops_agent` wheel only) runs from a developer's
machine: `evals.export` reads a finding and its snapshot into a case file for a
person to label, and `evals.run` replays each labelled case against Bedrock with
the recorded tool results (a call with no recording gets "no recorded data for
this call" and counts as a miss) and grades the new finding with a model judge
on 100 (bullseye), 65 (one hop short), 35 (miss) or 0 (unrelated). See
`evals/README.md`.

### Finding kinds

- `alarm`: one alarm, investigated
- `incident`: a storm of alarms in one triage batch, investigated together
- `grouped`: an alarm of a storm, recorded under the incident (`incident_id`)
- `linked`: an alarm on a resource a running investigation covers (`linked_to`)
- `deferred`: an alarm the budgets did not allow; one per ALARM episode however
  often it is retried
- `skipped`: a signal opted out by its `DevOpsAgent=off` tag, or a priority 3 or 4
  job the budgets refused (once per resource key an hour)
- `storm`: the priority 3 and 4 signals grouped while the signal rate ran above
  `STORM_RATE`, counted in `alarm_count`, `source_counts` and `resource_counts`;
  `linked_to` is what became of its head (its job, or its deferral)

Every finding records its `source` (`cloudwatch` or `datadog`).

## Cost controls

- **Prompt caching.** With `PROMPT_CACHING` true (the default), every Converse
  request carries at most four `cachePoint` blocks, Bedrock's limit: after the
  last tool in `toolConfig.tools`, after the system prompt, at the end of the
  newest message, and, from the second step on, at the end of the previous
  request's newest message (the third from last). The newest-message checkpoint
  rolls forward each step and writes the cache; the previous request's one sits
  exactly where the last step wrote, so a step reads the conversation before it
  from the cache however many blocks its parallel tool calls added, without
  relying on the cache lookback window. Nothing that changes per step (no timestamp, no step text) comes
  before a checkpoint, so the cached prefix is byte-identical across steps. A
  `ValidationException` that mentions caching is retried once without
  checkpoints and logged as a warning, and caching stays off for the rest of the
  run. Each model call logs its input, output, cache read and cache write token
  counts.
- **Weighted tokens.** Both token budgets count cost-weighted tokens against an
  uncached input token: input x 1, cache write x 1.25, cache read x 0.1, output
  x 5 (`weighted_tokens` in `agent.py`). A finding and its snapshot store the
  raw total of the four counts as `tokens_used` and the weighted total as
  `weighted_tokens`.
- **Run token budget.** When a step would start with the run's weighted total
  above `RUN_TOKEN_BUDGET` (250,000), it is the final step: the model is told to
  call `report_finding` now, as at the step cap. A cached 10-step run stays well
  under it; an uncached run re-sending large tool results reaches it in about 8
  steps.
- **Daily token budget.** After a run, the investigator adds its `weighted_tokens` to
  `budget#tokens#day#<YYYY-MM-DD>` with one atomic `ADD` (a failed add is logged
  and never fails the job). Triage defers every job once that counter is at or
  above `DAILY_TOKEN_BUDGET` (3,000,000). The count budgets apply as well.
- **Cooldown after close.** When an alarm has no unclosed investigation but an
  `alarm` or `incident` finding on its primary key was closed (its
  `resolved_at`, else `created_at`) within `ALARM_COOLDOWN_MINUTES` (120) on the
  same alarm ARN, or within `RESOURCE_COOLDOWN_MINUTES` (60) on any alarm,
  triage starts no investigation: the firing raises that finding's
  `recurrence_count` and sets its `last_seen_at`, and the finding stays closed.
  The lookup reads the newest 50 findings on the key from `by_resource`.
- **Opt-out tag.** `DevOpsAgent=off` alarms are never investigated (see Opt-out
  tag).
- **Priority, share and storm throttles.** The priority 1 overflow, the priority 3
  and 4 reserve, the Datadog share and storm mode are in Throttles and Storm mode.
- **Lower-env caps.** Lower environments can run triage with smaller budgets, for
  example `HOURLY_BUDGET` 3, `DAILY_BUDGET` 10 and `DAILY_TOKEN_BUDGET` 1,000,000.
- **Inference profiles.** The Terraform module copies an application inference
  profile from each model id and sets the investigator's `MODEL_ID` and
  `FALLBACK_MODEL_ID` to the profile ARNs, so the agent's tokens are metered under
  its own profiles; Converse takes a profile ARN as its model id. The code defaults
  are the plain cross-region ids.
- **Token alarms and budget.** The module alarms on the primary profile's hourly
  input and output tokens and keeps a monthly cost budget on the Bedrock services
  (see [terraform-contract.md](terraform-contract.md)).

## IAM

One Lambda execution role is the only role; both functions run as it. Its policy is
described below and listed exactly in [terraform-contract.md](terraform-contract.md);
`terraform/iam.tf` implements it. `aws_call` reads through the AWS managed policy
`AIDevOpsAgentAccessPolicy` attached to the role, under the explicit deny policy.

Allowed:
- CloudWatch: `DescribeAlarms`, `DescribeAlarmHistory`, `GetMetricData`,
  `ListTagsForResource`
- Logs Insights: `StartQuery`, `GetQueryResults`, `StopQuery`,
  `DescribeLogGroups`
- CloudTrail: `LookupEvents`
- Inspection: `lambda:ListEventSourceMappings`; `sqs:GetQueueUrl`,
  `sqs:GetQueueAttributes`; `kinesis:DescribeStreamSummary`,
  `kinesis:ListStreamConsumers`; `rds:DescribeDBClusters`,
  `rds:DescribeDBInstances`, `rds:DescribeEvents`; `pi:GetResourceMetrics`
  (on `metrics/rds/*`); `es:DescribeDomain`, `es:DescribeDomainHealth`;
  `elasticloadbalancing:DescribeLoadBalancers`, `DescribeTargetGroups`,
  `DescribeTargetHealth`; `elasticache:DescribeReplicationGroups`,
  `elasticache:DescribeCacheClusters`; `states:DescribeStateMachine`,
  `states:ListExecutions`, `states:ListStateMachines`; `apigateway:GET` on
  `/apis/*/stages*`; `eks:DescribeCluster`, `eks:ListNodegroups`,
  `eks:DescribeNodegroup`; `ec2:DescribeInstances`; `events:ListRules`,
  `events:ListTargetsByRule`; `scheduler:ListSchedules`,
  `scheduler:GetSchedule`
- SSM: `GetParameter` on the catalog parameter, only when the deployment has one
- Bedrock: `InvokeModel` / Converse on the configured application inference
  profiles and the models they route to
- DynamoDB: `GetItem`, `PutItem`, `UpdateItem` on the findings table, and
  `Query` on its indexes (`by_status`, `by_resource`)
- SQS: `ReceiveMessage`, `DeleteMessage`, `GetQueueAttributes` on the alarms and
  work queues (not their DLQs);
  `SendMessage` on the work queue (jobs) and the alarms queue (triage's delayed
  retries of budget-deferred alarms) only
- SNS: `Publish` on the `SLACK_TOPIC_ARN` topic only, when notifications are on
- Standard Lambda logging

Explicit deny (a backstop; nothing above grants them):
`secretsmanager:GetSecretValue`, `secretsmanager:BatchGetSecretValue`,
`s3:GetObject`, `s3:GetObjectVersion`, `lambda:GetFunctionConfiguration`,
`lambda:GetFunction`, `lambda:ListFunctions`, `ec2:GetPasswordData`,
`ecs:DescribeTaskDefinition`, `states:DescribeExecution`,
`states:GetExecutionHistory`, `kinesis:GetRecords`, `kinesis:GetShardIterator`,
`iam:*`, `sts:AssumeRole`, `sts:GetFederationToken`, `sts:GetSessionToken`.
`ssm:GetParameter`, `ssm:GetParameters`, `ssm:GetParametersByPath` and
`ssm:GetParameterHistory` are denied on every parameter but the catalog's. The reads
`AIDevOpsAgentAccessPolicy` grants that return user data, code, command output,
configuration contents, environment variables, arguments or credentials are denied
in their own statement (the list is in [terraform-contract.md](terraform-contract.md)),
as is `apigateway:GET` on the API key paths. `sqs:ReceiveMessage` is denied in its
own statement on every queue except the alarms and work queues, which the event
source mappings read as this role. Every other write is simply never allowed: IAM
denies what no statement grants.

`kms:Decrypt` is not explicitly denied: Lambda decrypts the function's own
environment variables as this role, and every scoping of that Deny we tried
still blocked it. The role grants no `kms:Decrypt`, and the APIs that would
return secret material through KMS stay explicitly denied above.

Lambda configuration reads are denied outright. `GetFunctionConfiguration`,
`GetFunction` and `ListFunctions` all return a function's environment variables
in plaintext, and the deployment puts secrets (the Datadog keys and the GitHub App
key) there. Stripping the block in a tool would leave the role able to read them, so
the role cannot make those calls at all.

SSM reads stay denied but for the catalog parameter: the deployment passes the queue
URLs and every other setting as environment variables.

The Lambdas are not attached to a VPC. Every call they make is a public AWS API,
and managing network interfaces would be a write outside the agent's resources.

Datadog is reached outside IAM, with two keys in both functions' environment:
`DD_API_KEY` and `DATADOG_APP_KEY`. The app key should belong to a Datadog service
account that has logs, events, monitors and metrics read only (`logs_read_data`,
`events_read`, `monitors_read`, `metrics_read`), issued to the agent alone. Without
both keys the investigator runs without the Datadog tools and triage drops Datadog
signals. The keys go only into the
request headers: never into a log line, an error or a tool result.

GitHub is reached outside IAM too, as a read-only GitHub App issued to the agent
alone. Install the App on the org named by `GH_ORG` with repository permissions
Contents, Actions, Pull requests and Metadata, all read-only, and nothing else. The
investigator reads `GH_APP_ID`, `GH_APP_INSTALLATION_ID` and `GH_APP_PRIVATE_KEY` (the
App's PEM key) from its environment; without them, or without `GH_ORG`, it runs
without the GitHub tools. The key signs a short-lived RS256 JWT (iat 60 s back, exp
9 minutes on) that is exchanged for an installation token, cached in memory until 5
minutes before it expires. The key, the JWT and the token go only into request
headers: never into a log line, an error or a tool result.

## Severity

Levels: critical, high, medium, low.

Floor, computed before the model runs:
- the alarm's `Severity` tag, when it holds one of the four levels;
- otherwise the env's default, the catalog's `severity.default`.

The model proposes a severity in `report_finding`. The recorded severity is the
higher of the proposal and the floor. Only the catalog's `agent.notify` severities
are published to the notification topic; the others are stored only.

## Findings table

`FINDINGS_TABLE`, DynamoDB, single table (see
[terraform-contract.md](terraform-contract.md) for its keys and indexes).

- `pk = finding#{id}`: the finding. Fields: `finding_id`, `created_at`,
  `env`, `alarm_name`, `alarm_arn`, `severity`, `severity_floor`,
  `proposed_severity`, `title`, `summary`, `likely_cause`, `evidence` (list of
  `{kind, detail, steps}`, `steps` the trail steps the fact came from),
  `checked` (list of `{text, steps}`, the facts the agent verified, `steps`
  limited to the stored trail), `actions` (list of `{kind, text, detail,
  command}`, `kind` `change`, `code`, `read` or `approval`, `detail` and
  `command` null when absent), `suggested_actions` (list of text: each
  action's text, then `: ` and its command when it has one, for the notification),
  `fix_effort`,
  `fix_effort_reason` (one line), `status` (`open`; a review tool sets
  `acknowledged` and `closed`), `steps`, `model_id`, `tokens_used` (the run's
  input, output and cache tokens; 0 when no model ran), `weighted_tokens` (the
  same weighted by cost, see Cost controls),
  `outcome` (`reported`, `incomplete`, or `triaged` for a finding triage wrote
  without an investigation), `ttl` (epoch seconds), and:
  - `kind`: `alarm`, `incident`, `grouped`, `linked`, `deferred` or `skipped`
  - `resource_key`: the alarm's (or incident's) primary key, on every kind
  - `incident_id` (grouped), `linked_to` (linked), `linked_alarms` (list)
  - `recurrence_count` (default 0) and `last_seen_at`: later firings of the
    alarm while the finding is open or acknowledged, or within its cooldown
    after it was closed
  - `previous_finding_id`: the newest prior finding on the same key, if any
  - `error_signature`: model-reported exception or error type plus location,
    ids stripped; optional
  - `confidence` (`high`, `medium`, `low`) and `confidence_reason` (at most 200
    chars), and `hypotheses` (at most 8 `{text, state, steps}`, `state`
    `likely`, `ruled_out` or `unverified`): the model's reported reasoning,
    redacted like the other text. Null and empty on incomplete and
    triage-written findings
  - `member_alarms` (at most 50) and `alarm_count`: an incident's alarms and
    their full count, so its members need no index on `incident_id`
  - `context_summary`: the context bundle's section statuses, counts, length
    and whether it was cut
  - `alarm_reason` and `alarm_time`: the alarm event's state reason (redacted)
    and when it entered ALARM (ISO 8601 UTC); an incident's are its primary
    alarm's. Null when the event lacks them
  - `tools_used`: distinct tool names in first-use order; `tool_call_count`:
    the number of tool calls the loop ran (null on a triage-written finding);
    `sources_with_data`: distinct tool names whose call returned data
  - `tool_trail`: the tool calls in order, at most 50, each `{step, tool,
    status, input}`: `step` is the 1-based call index, `status` is `data` (a
    success that returned data, as for Useful sources), `empty` (a success with
    nothing in it) or `error`, `input` is the redacted input summary, at
    most 200 chars, and `args` the input arguments with the same redaction,
    each string cut to 300 chars, nested at most 3 deep (deeper values become
    a cut JSON string) and at most 1.5 KB per step, keys past that dropped,
    and `call` the call descriptor (see Call descriptors). Tool outputs are
    never stored on the finding
  - `prior_finding_ids`: the reviewed prior findings shown to the model
  - `run`: how the investigation ended, `{stop_reason, turns, max_turns,
    duration_seconds, weighted_tokens, token_budget}`. `stop_reason` is
    `chose` (the model reported on a turn no limit forced), `turn_limit`,
    `token_budget` or `time` (that limit forced the reporting turn; time
    outranks the token budget, which outranks the turn limit; `time` also when
    the time reserve ended the run before a final call), `no_report` (the
    forced turn gave no valid report) or `model_error` (a model call failed or
    returned nothing). `turns` is the model calls made, `max_turns`
    `MAX_STEPS`, `duration_seconds` the loop's wall time to 0.1 s, and
    `token_budget` `RUN_TOKEN_BUDGET`. Null on triage-written findings and on
    an incomplete finding whose run raised before the loop returned
  - `resolution`, `resolved_at`, `resolved_by`: written empty by the agent and
    set by a review tool; `resolution_note`, `acknowledged_at` and
    `acknowledged_by` are written only by a review tool (see Resolution contract)

  A triage-written or incomplete finding stores what is known: empty lists, a
  null `tool_call_count` when no loop ran, and the alarm fields from the event.
- `pk = obs#{resource_key}`: `entries` (at most 10 `{tool, input, at}`, newest
  first) and `ttl` (90 days from the last write). It carries no `resource_key`
  or `status` attribute, so it stays out of both indexes.
- `pk = snap#{finding_id}`: the eval snapshot of an investigation (see Eval
  snapshots): `finding_id`, `created_at`, `snapshot` or `snapshot_gz`, and `ttl`
  (90 days from the write). It carries no `resource_key` or `status` attribute,
  so it stays out of both indexes.
- `pk = active#{resource_key}`: the running job that covers a key: its
  `finding_id` and `linked_alarms`, 20 minute TTL. An item past its TTL counts as
  gone before DynamoDB deletes it.
- `pk = budget#{YYYY-MM-DD}` and `pk = budget#{YYYY-MM-DDTHH}`: atomic daily and
  hourly counters; past the cap a job is deferred.
- `pk = budget#tokens#day#{YYYY-MM-DD}`: the day's weighted model tokens, added by the
  investigator after each run; at or above `DAILY_TOKEN_BUDGET` a job is
  deferred. Budget items carry `count` and `ttl` (3 days) only, no
  `resource_key` or `status`, so they stay out of both indexes.

The TTL attribute is `ttl` for every item kind.

### Call descriptors

Every trail step carries `call`, from which a reader of the findings table renders a
step without interpreting a tool's own arguments:

- `provider`: `aws`, `datadog` or `github`
- `service` and `action`: what was read, e.g. `rds` and `describe_database`,
  `github` `contents` and `get`, or for `aws_call` the boto3 service and the
  snake_case operation
- `label`: `<provider>.<service>.<action>`, e.g. `aws.s3.list_object_versions`
- `subject`: the resource the input names (a queue name, `bucket/key`,
  `repo/path`, `repo#number`; for `aws_call` the most telling parameter:
  `Bucket` with its `Prefix` or `Key`, the queue in a `QueueUrl`, a function,
  job, cluster, table, database or domain name, a load balancer or target group
  name from its ARN, and so on), redacted and cut to 200 chars; null when the
  input names none
- `kind`: `evidence`, a read of the account or a provider
- `refused`: the short reason a policy refused the call (`aws_call` refused by
  `aws_guard.py`: `reads object contents`, `returns secret values`, `not a read
  operation`, ...), cut to 120 chars; the step's `status` stays `error`

Each tool declares its descriptor once in the registry (`CallSpec`), or derives
it from its input (`aws_call`, `github_get_change`). It is built from the
validated input, so a refused call of a known tool is described with its
reason. Invalid input is described too: a fixed descriptor as usual, and an
input-derived one with service and action `unknown` and the subject from the
raw input. Service and action are redacted and cut to 64 chars and the label to
140; a call of an unknown tool has no descriptor, and `call` is optional on a stored
step. Replay matches recorded calls on their inputs only and never on `call`.

### Effort to fix

The model grades the effort to fix from what the evidence shows, with a
one-line reason. It is an estimate for the reader, never an instruction to act,
and has no floor.

- `low`: a config change, restart, rollback or timeout bump, under an hour
- `medium`: a small code or Terraform fix, about a day
- `high`: a real change across a service, several days
- `very_high`: a design or multi-team change, a week or more
- `unknown`: the evidence does not show a cause

The grades are ordered `low` < `medium` < `high` < `very_high`; `unknown` sorts
apart. An incomplete finding is always `unknown` with an empty reason. The
notification shows the grade as the fact "Effort low" under the headline.

### Retention

A finding is written with `ttl` = `created_at` + 90 days
(`OPEN_FINDING_RETENTION_DAYS` in `findings.py`), so a finding nobody closes
expires. When a review tool closes a finding it sets `ttl` = `closed_at` + 365
days (`CLOSED_FINDING_RETENTION_DAYS`), so closed findings stay long enough to
serve as eval cases; the finding's `snap#` item gets the same `ttl`.

### Resolution contract

When a person acknowledges an open finding, the review tool sets `status` =
`acknowledged`, `acknowledged_at` (ISO 8601 UTC), `acknowledged_by` (the
person's identity) and `ttl` = acknowledged_at + 90 days. An acknowledged finding is still unclosed: a repeat firing of
its alarm counts on it.

When a person closes a finding, the review tool writes, in one UpdateItem on
`finding#{id}`:

- `status` = `closed`
- `resolution`: `confirmed` (the finding's cause was right), `false_positive`
  (the alarm fired but nothing was wrong), `wrong` (something was wrong but
  the finding's cause was not it), or `dismissed` (a finding without a reported
  cause, such as an incomplete or triage-written one, closed without a verdict)
- `resolution_note`: the person's note, at most 500 chars, required for
  `wrong`. It is exported into eval cases as a hint for the person labelling
  them and is never shown to the model
- `resolved_at`: ISO 8601 UTC time of the close
- `resolved_by`: the identity of the person who closed it
- `ttl` = `closed_at` + 365 days, as above

It then sets the same `ttl` on `snap#{id}` when that item exists, so the
snapshot lives as long as the closed finding it can be replayed against; a
failure there is logged and never fails the close.

The investigator passes a prior finding to the model only when `status` is
`closed`, `resolution` is `confirmed` or `false_positive`, and `outcome` is
`reported` (a finding stored without `outcome` counts as reported). Any other status (`open`, `acknowledged`), `wrong`, `dismissed` and
an incomplete finding are never shown, so a finding stays out of the agent's
memory until a person has judged its reported cause. `resolution_note` never
reaches the model.

GSI `by_status` (`status`, `created_at`) is for review tools listing findings. GSI
`by_resource` (`resource_key`, `created_at`, projection ALL) is the
investigator's memory of a resource and triage's lookup of an alarm's open
investigation. A review tool reads this table and writes only a
finding's `status` (`acknowledged`, `closed`), its acknowledgement fields and,
when it closes one, its resolution fields on a person's behalf, plus the
`snap#` `ttl` on close. The agent reads status only to find unclosed findings
and to pick the reviewed prior findings it shows the model. A closed finding with a resolution later
becomes a scored eval case.

## Tools

All read-only, all bounded, all projected to small JSON before the model sees
them.

The time-based tools (`get_metric`, `query_logs`, `recent_changes`,
`scheduled_jobs`, `search_datadog_logs`, `datadog_events`, `datadog_top_pods`
and `github_recent_changes`) compute their
window one way, in `time_window`:

- Optional `start` and `end` are ISO 8601 UTC (`2026-10-02T03:10:00Z`; an offset
  is converted, a time without one is UTC).
- Without either, the window is the tool's `minutes` (or `hours`) ending when
  the alarm entered ALARM, or now when that is unknown or later.
- With only `start`, it runs that length from it; with only `end`, that length
  before it. With both, they win over `minutes` or `hours`.
- Both must be within the last 14 days (CloudWatch Logs Insights and CloudTrail
  reach further, but 14 days bounds cost), `end` must follow `start`, an `end`
  in the future is cut to now, and the window is at most the tool's cap below.
  A window that breaks a rule is an error result naming the rule.
- Every result echoes the window read as `window: {start, end}`, so the model
  and the evals see exactly what was queried.

The tools:

- `get_metric`: one metric series over at most 6 hours (default 60 minutes),
  at most 200 points. The period is the one asked for (default 60 s), raised
  to 300 s when the window would need more than 200 points at 60 s; one-minute
  data is kept for 15 days, so it covers every allowed window
- `query_logs`: one Logs Insights query over one log group, at most 3 hours
  (default 60 minutes), 50 rows, each field cut to 500 chars, redacted
- `recent_changes`: CloudTrail write events over at most 3 hours (default 60
  minutes), projected to time, event name, source, user and resource names
- `describe_s3_key`: whether one exact S3 key exists, never reading the object:
  bucket versioning, up to 10 versions and delete markers of the key, and up to
  10 keys sharing its name without the extension
- `describe_database`: an RDS or DocumentDB cluster (with its members and
  writer) or instance: status, engine and version, class, multi-AZ,
  Performance Insights; the last 24 h of events (at most 20); with
  Performance Insights on, `db.load.avg` for the writer over a window (default
  60 minutes, at most 6 h, ending at the alarm time) grouped by `db.sql_tokenized` (top 5, statement
  redacted and cut to 300 chars) and by `db.wait_event` (top 5)
- `describe_search_domain`: OpenSearch processing and upgrade state, engine
  version, cluster and storage config, log publishing, and cluster health
  (state, nodes, shards, unassigned shards) when the domain reports it
- `describe_targets`: for a load balancer's target groups (at most 10) or one
  target group, health per target (id, port, state, reason, description),
  unhealthy first, at most 50 targets
- `recent_executions`: a Step Functions state machine's executions with one
  status (default `FAILED`), at most 20: name, status, start and stop
- `scheduled_jobs`: the scheduled work around an alarm, over `hours` (default
  2, at most 24), optionally only names containing `name_contains`
  (case-insensitive). Schedules come from EventBridge rules with a
  `ScheduleExpression` (UTC) and EventBridge Scheduler schedules (in their
  `ScheduleExpressionTimezone`, within their start and end dates); code computes
  each one's fire times in the window from its `cron(...)` (six fields with `*`,
  `?`, lists, ranges, steps and day and month names; `L`, `W` and `#` are
  marked `unsupported`), `rate(...)` or `at(...)` expression. A rate under an
  hour is marked `frequent`; a longer one is timed from a Scheduler schedule's
  start or creation date, and a rule's is `fire_times_unknown`. Up to 20
  schedules, those that fire in the window first; a disabled one only when it
  would have fired. A rule's target is its target ARNs only, never `Input` or
  `InputTransformer`; a Scheduler target is its ARN and, for an
  `aws-sdk:<service>:<action>` universal target, the service, action and only
  the `JobName`, `StateMachineArn`, `FunctionName`, `TaskDefinition`,
  `Cluster`, `JobQueue`, `JobDefinition` and `Name` input keys. A source that
  fails (rules, scheduler, rule targets) is named with its error code in
  `errors` and the others still return; both rules and scheduler failing is an
  error
- `search_datadog_logs`: Datadog logs, where ECS and EKS application logs live
  (they are not in CloudWatch). Input: `service`, `name`, `env`, `status`
  (`error`, `warn` or `info`; default `status:(error OR warn)`), `text` (at
  most 100 chars of plain words and quoted phrases: no `:`, `*`, `?`, brackets,
  backslashes, `OR`, `AND`, `NOT` or a leading `-` or `+`), `minutes` (default
  30, at most 180), `start`, `end` and `limit` (default 25, at most 50). Code
  builds the query from those fields; the model never passes a raw Datadog
  query. With `service`, one `POST
  https://api.{DATADOG_SITE}/api/v2/logs/events/search` with a 10 s timeout,
  sorted newest first. Each log is projected to timestamp, service, status, host
  (the kube `pod_name` or ECS task id from its tags when present, else the
  host) and message (redacted, cut to 500 chars), with the count returned and a
  `truncated` flag. An HTTP failure (403, 429, timeout) is an error result with
  the status code. The tool is offered, and the prompt tells the model to use it
  for ECS services, load balancer targets in front of container services and EKS
  workloads, only when both Datadog keys are set (see IAM). Without `service`,
  it returns the services that logged errors or warnings instead, so the model
  can find the exact service name and see which services are erroring:
  optionally only those whose name contains `name` (at most 50 chars, a plain
  part of a service name with the same operator rejection as `text`; code turns
  it into `service:*<name>*`, lowercased), with `env` and `text` narrowing the
  logs counted; `name` is refused with `service`, and `status` without it. One
  `POST https://api.{DATADOG_SITE}/api/v2/logs/analytics/aggregate` counting
  logs grouped by `service` (26 buckets, by count) and then `status`. Returns up
  to 25 rows of service, error and warn counts (0 when a status has no bucket),
  most errors first, and `truncated` when more services matched or Datadog
  returned a next page
- `datadog_events`: Datadog events for exactly one of `service` or
  `kube_namespace` (plain tokens, no operators), where pod restarts, BackOff,
  OOM kills, image pull failures and deploys show up. Optional `env` and
  `source` (`change_tracking` by default, `alert` or `deployment_analysis`),
  `minutes` (default 60, at most 360), `start`, `end` and `limit` (default 20,
  at most 50). Code builds the query, for example
  `source:change_tracking kube_namespace:checkout`. One `POST
  https://api.{DATADOG_SITE}/api/v2/events/search`, newest first. Each event is
  projected to timestamp, title, the `kube_namespace`, `kube_deployment`,
  `pod_name`, `service`, `env` and `kube_cluster` tags, and message with
  Datadog's `%%%` markdown fences stripped, redacted and cut to 400 chars, with
  the count and a `truncated` flag
- `datadog_top_pods`: the pods using the most CPU or memory on exactly one of
  `host` (an EC2 instance id, the EKS node) or `cluster` (a `kube_cluster_name`,
  `[A-Za-z0-9_.-]{1,100}`), optionally in one `kube_namespace` (same pattern);
  `metric` `cpu` (default) or `memory`, `minutes` (default 60, at most 180),
  `start` and `end`. Code builds the query, for example
  `sum:kubernetes.cpu.usage.total{host:i-0123456789abcdef0} by
  {kube_namespace,pod_name}` (`kubernetes.memory.usage` for memory). One `GET
  https://api.{DATADOG_SITE}/api/v1/query?from=<epoch s>&to=<epoch s>&query=<query>`.
  Each series becomes one pod: kube_namespace, pod_name (redacted), max,
  max_at (UTC), avg, last, and before (the average over the first quarter of
  the window, so a jump shows). CPU is reported in cores (nanocores / 1e9),
  memory in MiB, named by `unit`. Up to 10 pods ranked by max, with a
  `truncated` flag when more series came back. A query error Datadog reports in
  the payload is an error result like an HTTP failure
- `github_list_repos`: the repos in `GH_ORG` (`GET /orgs/{org}/repos`, up to 3
  pages of 100, read once per investigation), optionally only names containing
  `name` (repo-name characters), sorted by last push (default) or name, `limit`
  default 20, at most 50: name, description (120 chars), default branch,
  archived, last push and language. Repo naming conventions and where
  infrastructure code lives are deployment-specific: put them in `PROMPT_NOTES`
- `github_search_code`: `GET /search/code` with the text-match media type.
  `query` is at most 128 chars of plain words and quoted phrases: no `:`, no
  `org`, `repo`, `path`, `language`, `extension` or `filename`, no `OR`, `AND`,
  `NOT` or leading `-`. Code builds `<query> org:{org}`, adding
  `repo:{org}/{repo}` and `path:<path>` when given; `limit` default 10, at most
  20. Each result is repo, path and up to 2 text-match fragments cut to 300
  chars and redacted (no URLs). GitHub allows about 10 code searches a minute; a
  rate limit (403 or 429) or a rejected query (422) is an error result
- `github_get_file`: `GET /repos/{org}/{repo}/contents/{path}?ref=`, the base64
  content decoded. `path` is a file path of `[A-Za-z0-9_./-]` relative to the
  repo root, without `..`; `ref` (branch, tag or sha) has the same characters.
  Directories, binary files and files over 200 KB are refused. With `line`,
  returns that line and `context` lines either side (default 30, at most 40);
  without, the first 80 lines. Each line is numbered, cut to 200 chars and
  redacted
- `github_recent_changes`: for one repo and an optional path prefix, over
  `hours` (default 24, at most 168) or `start` and `end`, up to
  `limit` (default 15, at most 30) of each of: default-branch commits
  (`GET .../commits?since&until&path`) as sha7, date, author login and first
  message line (200 chars); merged pull requests (`GET .../pulls?state=closed
  &sort=updated&direction=desc&per_page=30`, kept when `merged_at` is in the
  window) as number, title (200 chars), merged_at, base and author; and GitHub
  Actions runs (`GET .../actions/runs?created=<from>..<to>&per_page=20`) as
  name, event, head branch or tag, status, conclusion, created_at and run
  number. One tool call makes three
  requests; a failed one is reported under `errors` and the others still
  return, and the call is an error only when all three fail
- `github_get_change`: one change in a repo, given exactly one of `sha` (7 to
  40 hex chars) or `number`. A commit is `GET .../commits/{sha}`: sha7, date,
  author, message (1,000 chars) and up to 30 files with filename, status,
  additions, deletions and patch (1,500 chars, redacted), `truncated` when more
  files changed. Patches stop at 3,000 chars in total; later files are listed
  with `patch_omitted`. A pull request is `GET .../pulls/{number}` and
  `GET .../pulls/{number}/files?per_page=30`: number, title, body (1,500
  chars, redacted), state, merged_at, base, head, author, changed file count,
  and the files as for a commit. Its call descriptor is `github.commits.get`
  (subject `repo@sha`) or `github.pulls.get` (subject `repo#number`)
- `aws_call`: one page of one read-only operation by boto3 service name and
  operation (snake_case, or PascalCase normalised through the model). The
  handler builds one client per service on first use, from a boto3 session on
  the same botocore session the guard reads, with a 5 s connect and 20 s read
  timeout and at most 2 attempts. An unknown service is an error naming the
  closest covered services; an unknown service or operation also names up to 5
  of the closest operations `aws_call` allows (in the service, or as
  `service.operation` across the covered services when the service is unknown):
  close spellings alternating with the operations whose names and first 300
  chars of documentation share the most words with it. That catalog is read
  from botocore's bundled models file by file once per container, so the full
  set of service models is never held in memory, and calls no AWS API.
  `aws_call` covers what the curated tools do not, among them SQS queue
  attributes, Kinesis streams, Lambda event source mappings, ElastiCache
  groups, EKS clusters and node groups, and EC2 instances; `aws_guard.py` refuses a service outside
  `ALLOWED_SERVICES`, then a blocked operation, then anything that is not a
  Describe, List, Get, BatchGet, BatchDescribe, Search or Lookup operation, then
  any operation whose output streams a file body or an event stream (a deny
  wins over the prefix). botocore validates `params` and its message comes
  back as the error; a pagination parameter over 4 KB is refused. The result is
  `{call, result, next_token}`: `ResponseMetadata` dropped; at any depth the
  value of every key matching `SENSITIVE_KEY_PARTS` (a substring of the
  lowercased name: password, passwd, secret, token, credential, privatekey,
  presharedkey, authkey, environment, userdata, arguments,
  connectorconfiguration, providerdetails, basicauth, kdcadmin, apikey) or
  `SENSITIVE_KEYS` (`env`, `environmentvariables`) replaced with `<removed>`;
  a string over 200 chars that parses as a JSON object or array under an
  `EMBEDDED_DOCUMENT_KEYS` key (configuration, definition, pipelinedefinition,
  properties, actualproperties, expectedproperties, parameters, content)
  replaced with `<removed: embedded document>`; datetimes as ISO, bytes as
  `<bytes N>`, every string redacted, and the next page's request parameters
  lifted into `next_token` before stripping. Past 7,000 chars the largest list
  with more than one item is cut to the leading items that fit (at least one),
  descending into a lone item that is too large by itself, then strings are cut
  to 500 chars, then single-item lists are emptied; `truncated` and
  `items_total` (original lengths by path) say what was cut

`aws_call` returns resource metadata as AWS describes it, so unlike the
curated tools it can include endpoints, usernames, ARNs (secret ARNs listed by
Secrets Manager among them), subscriber endpoints and access policies; it never
returns the values the stripping and the blocked operations above withhold.

`aws_guard.py` holds the tables as data. `ALLOWED_SERVICES` is the primary
control: the botocore services an investigation of this stack reads (EC2, Auto
Scaling, ECS, EKS, ELB, RDS, DocumentDB, Neptune, ElastiCache, MemoryDB,
OpenSearch, SQS, SNS, Kinesis, Firehose, Lambda, Step Functions, EventBridge,
Scheduler, Pipes, Glue, S3, DynamoDB, CloudWatch, Logs, CloudTrail, API
Gateway, Route 53, ACM, CloudFront, MSK, SageMaker, Bedrock, ECR, EFS, Backup,
Health, Service Quotas, Transfer, SSM, Secrets Manager, KMS, Amazon MQ, WAF,
Network Firewall, CloudFormation, X-Ray, Application Signals and the tagging
API); every other service is refused as `service not covered by aws_call`, and
the suggestions for an unknown operation come only from these. Inside them, the
blocked tables mirror the role's deny policy (`terraform/iam.tf`) in botocore
service names (`stepfunctions` is IAM `states`, `elbv2` and `elb` are
`elasticloadbalancing`). It refuses every operation the allowlist test forbids
in `tools.py`, and tests check that each blocked entry names a real operation
of a covered service and that every streaming operation of a covered service is
refused. To cover another service, add it to `ALLOWED_SERVICES` only after
reading its Describe, List and Get operations and blocking every one that
returns contents, secrets, credentials, environment variables or payloads, in
`BLOCKED_OPERATIONS` and in the IAM deny. IAM stays the boundary: the role reads through the AWS managed
policy `AIDevOpsAgentAccessPolicy` under that deny list. `aws_call` is
offered, and named in the prompt, only when the context has a client factory;
the prompt tells the model to prefer the curated tools.

Every GitHub request is under `https://api.github.com` and inside `GH_ORG`: the
client builds the owner, the model passes only a repo name (an `owner/repo` is
refused), and repo names, paths and refs reject `..`. The tools are offered, and
named in the prompt, only when all three App credentials and `GH_ORG` are set. Commit
messages, pull request titles and bodies, patches and file contents are
untrusted data.

Every investigation starts from the context bundle, which holds the alarm, its
sibling alarms, its log sources and the top error patterns in those groups; the
model then tests its hypotheses with `query_logs` over the groups and the
describe tool (or `aws_call`) for the resource the alarm watches. The prompt asks it to follow the
chain: when the alarm is on a failure sink (a dead-letter queue, an on-failure
destination, an error metric), find when the failing event happened from the
metric or the alarm history, query the producer's logs at that time with an
explicit `start` and `end`, and, when GitHub is offered and the logs name a file
and line or an exception, read that code with `github_search_code` and
`github_get_file`. It concludes that the cause is not shown only after trying.
The `query_logs` validator allows the
`pattern` command and rejects `parse` and the string functions (`substr`,
`replace`, `concat`, `trim`, `ltrim`, `rtrim`, `toupper`, `tolower`,
`strlen`), which could cut a secret below what redaction recognizes.

No curated tool returns an endpoint, a master username, a secret ARN, an
access policy or anything shaped like a credential (`aws_call`'s output is
described above), and the whole result is redacted before the model sees it. No tool calls an operation that returns secrets or
payload data: Lambda `GetFunction`, `GetFunctionConfiguration` and
`ListFunctions`, ECS `DescribeTaskDefinition`, SQS `ReceiveMessage`, Kinesis
`GetRecords` and `GetShardIterator`, Step Functions `DescribeExecution` and
`GetExecutionHistory`, and any Secrets Manager or SSM read. A test pins this.
`READ_ONLY_OPERATIONS` also names the Datadog client's four operations,
`search_logs`, `aggregate_logs`, `search_events` and `query_metrics`, and the
GitHub client's, `list_org_repos`, `search_code`, `get_contents`,
`list_commits`, `get_commit`, `list_pulls`, `get_pull`, `list_pull_files` and
`list_workflow_runs`. A test pins their endpoints (logs search, logs aggregate,
events search, one monitor (triage's verification read), metrics query, and
the GitHub paths above plus the installation token exchange) as the only outbound URLs; the token exchange is the only GitHub
POST.

Suggested fixes are text: what to do and the exact console page or CLI command.
A person carries them out through the normal approval flow.

## Rollout

Shadow mode first: leave `SLACK_ENABLED` off, or point `SLACK_CHANNEL` at a quiet
channel, for a couple of weeks, and compare findings against what actually happened
before the team's main channel sees any.
