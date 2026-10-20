# Evals

Measure a prompt, model or tool change by replaying past investigations. The
investigator stores `snap#<finding_id>` next to each finding: the job, the context
bundle, the reviewed prior findings, the tools it offered and every tool call with the
result text the model read. A replay feeds the same opening message to the model and
answers its tool calls from that recording, so a run needs Bedrock and nothing else.
A model judge then grades the new finding against a person's label.

This harness runs from a developer's machine only. It is not in the Lambda package
(the build installs the `devops_agent` wheel, which holds that package alone),
and it is not part of `uv run pytest`; its unit tests there use fakes.

## 1. Export a case

Pick a finding whose real cause is known, ideally one a person closed as `confirmed`.

```bash
uv run python -m evals.export --table <findings-table> --profile <profile> \
    --finding-id <finding_id> --out evals/cases/<name>.json
```

`--table` defaults to `FINDINGS_TABLE`. Without `--profile`, boto3's default credential
chain applies (`AWS_PROFILE` included). The export makes two read-only `GetItem` calls
on the findings table and writes the snapshot, an empty `label`, an empty `exclude`, and the original
finding's title, cause and evidence under `finding` for reference. A finding with no
`snap#` item (capture was off, or the snapshot was too large) cannot be exported.

## 2. Label it

Fill in `label`:

- `root_cause`: what actually caused the alarm, in one or two sentences. A case with
  an empty `root_cause` is skipped.
- `key_evidence`: the facts that prove it (a log line, a change, a metric jump).
- `notes`: anything the judge should know, such as what counts as one hop short.

Then add to `exclude` any text in the snapshot that gives the answer away, such as an
alarm description or a log line that states the cause outright. Each string is
removed from the context bundle, the alarm, the prior findings and every recorded
tool result before the replay. Recorded call inputs are kept, so calls still match.

`evals/cases/example.json.sample` shows a complete case; the runner reads `*.json`
only, so the sample is never run. Case files contain redacted production output:
review them before committing.

## 3. Run

```bash
uv run python -m evals.run --profile <profile>
uv run python -m evals.run --profile <profile> --model us.anthropic.claude-opus-5 --repeat 3
uv run python -m evals.run --profile <profile> --min-mean 65
```

Options: `--profile` (default: boto3's credential chain), `--model` (the agent model,
default the agent's `MODEL_ID` default), `--judge-model` (same default), `--cases`
(default `evals/cases`), `--results` (default `evals/results`), `--repeat` (runs per
case, default 1), `--min-mean` (exit 1 when the mean score is below it), `--region`
(default `us-east-1`).

The judge scores each run:

- 100: bullseye, the labelled root cause with the key evidence
- 65: one hop short, the right failure or component but not the root cause
- 35: miss, the symptom right and the cause wrong or absent
- 0: unrelated, or the investigation did not finish

The judge answers through a forced `grade` tool (score and reason); a reply without a
valid grade scores 0.

The table lists each case's scores, mean, pass@k (passed when any of the k runs
scored 65 or more), tool misses and approximate answers. A replayed call first
matches a recorded one exactly (same tool and input after filling defaults and
sorting keys). Otherwise it takes the recorded call of the same tool on the same
resource (its identity fields, such as the log group, queue or repo) sharing the most
other inputs, and is counted as approximate. Only a call with no such recording gets
"no recorded data for this call" and counts as a miss. Many misses mean the new
behaviour explores beyond the recording, so its score says less. Every run is also written to
`evals/results/<timestamp>.json` (ignored by git).
